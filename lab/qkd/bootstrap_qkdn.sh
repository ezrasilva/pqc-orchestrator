#!/usr/bin/env bash
# Sobe a QKDN do QuDitto nos containers já em execução.
#
# POR QUE ISSO EXISTE em vez de `qd2_orchestrator start config.yaml inventory.yaml`:
#
# O `install()` do orchestrator é incompatível com este lab por dois motivos
# independentes (lidos em qd2_orchestrator/orchestratorlib.py 2.1.2):
#
#   1. Ele exige as chaves `netsquid_user`/`netsquid_pwd` no config.yaml
#      (KeyError sem elas) e monta com elas um
#      `pip install --extra-index-url https://USER:PWD@pypi.netsquid.org netsquid`.
#      Esse índice retorna HTTP 401 com as credenciais do repositório
#      original, e o backend de simulação aqui é o SeQUeNCe — o NetSquid
#      nunca é chamado. A task falharia e abortaria o resto do play.
#   2. As tasks usam `/usr/bin/pip` (pip do sistema), enquanto os pacotes
#      desta imagem vivem no venv `/opt/venv`. Também reinstalariam
#      qd2_node/qd2_controller do PyPI, que já vêm na imagem.
#
# Fora o `install()`, o orchestrator só faz via Ansible/SSH o que este
# script faz via `docker exec` — e o código executado é o do próprio
# QuDitto (receive_qd2.py, http_receptor.py, controller.py), sem patch.
# Só o transporte da orquestração muda, o que também dispensa manter as
# credenciais SSH do inventory em sincronia com a imagem.
#
# Equivalências, play por play:
#   configuring_rmq_play  -> start_rabbitmq()      (sem o apt: a imagem já traz)
#   provisioning_play     -> provision_config()
#   start_receive_play    -> start_node_daemons()
#   start_http_receptor_play -> start_node_daemons()
#   start_controller_play -> start_controller()

set -euo pipefail

DOCKER=${DOCKER:-"sudo docker"}
LAB_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
CONFIG=${CONFIG:-"$LAB_DIR/config.yaml"}

VENV=/opt/venv
SITE=$VENV/lib/python3.10/site-packages
PY=$VENV/bin/python3

# Nós: "<container> <node_name> <node_ip>". Tem de bater com o config.yaml.
NODES=(
    "qkdn-node-a A 172.20.0.11"
    "qkdn-node-b B 172.20.0.12"
)
# Container onde roda o RabbitMQ e o controller.py. O controller.py conecta
# no broker por `localhost`, então ele precisa ser co-residente; e os nós
# conectam em `ip_controller` do config.yaml, que tem de ser este IP.
CONTROLLER_CONTAINER=qkdn-node-a
CONTROLLER_NODE=A

log() { printf '\n== %s\n' "$*"; }

start_rabbitmq() {
    log "RabbitMQ em $CONTROLLER_CONTAINER"
    if $DOCKER exec "$CONTROLLER_CONTAINER" rabbitmqctl status >/dev/null 2>&1; then
        echo "   já de pé"
    else
        # rabbitmq-server em background; o container não tem init system.
        $DOCKER exec -d "$CONTROLLER_CONTAINER" rabbitmq-server
        for _ in $(seq 1 60); do
            $DOCKER exec "$CONTROLLER_CONTAINER" rabbitmqctl status >/dev/null 2>&1 && break
            sleep 2
        done
        $DOCKER exec "$CONTROLLER_CONTAINER" rabbitmqctl status >/dev/null 2>&1 \
            || { echo "   ERRO: broker não subiu" >&2; return 1; }
        echo "   de pé"
    fi
    # Usuário node/node: é o que receive_qd2.py e functions.py usam,
    # hardcoded (amqp://node:node@<ip_controller>:5672/).
    $DOCKER exec "$CONTROLLER_CONTAINER" rabbitmqctl add_user node node 2>/dev/null \
        || echo "   usuário 'node' já existia"
    $DOCKER exec "$CONTROLLER_CONTAINER" rabbitmqctl set_user_tags node administrator
    $DOCKER exec "$CONTROLLER_CONTAINER" rabbitmqctl set_permissions -p / node '.*' '.*' '.*'
}

provision_config() {
    log "Provisionando quditto_v2.yaml"
    # Os três programas fazem open("quditto_v2.yaml") com caminho relativo,
    # e são iniciados com cwd no diretório do próprio pacote — por isso a
    # cópia vai para dentro de site-packages, e não para /app.
    for entry in "${NODES[@]}"; do
        read -r container _ _ <<<"$entry"
        for pkg in qd2_node qd2_controller; do
            $DOCKER exec -i "$container" tee "$SITE/$pkg/quditto_v2.yaml" \
                >/dev/null <"$CONFIG"
        done
        echo "   $container: qd2_node + qd2_controller"
    done
}

start_node_daemons() {
    log "Daemons dos nós"
    for entry in "${NODES[@]}"; do
        read -r container node ip <<<"$entry"
        # pkill para idempotência: rodar o script duas vezes não deixa
        # dois receptores disputando a mesma fila/porta.
        $DOCKER exec "$container" pkill -f 'receive_qd2.py|http_receptor.py' 2>/dev/null || true
        $DOCKER exec -d -w "$SITE/qd2_node" "$container" \
            sh -c "exec $PY receive_qd2.py $node >/tmp/receive_qd2.out 2>&1"
        $DOCKER exec -d -w "$SITE/qd2_node" "$container" \
            sh -c "exec $PY http_receptor.py $ip 8000 $node >/tmp/http_receptor.out 2>&1"
        echo "   $container: receive_qd2.py $node + http_receptor.py $ip:8000"
    done
}

start_controller() {
    log "Controller em $CONTROLLER_CONTAINER (nó $CONTROLLER_NODE)"
    $DOCKER exec "$CONTROLLER_CONTAINER" pkill -f 'controller.py' 2>/dev/null || true
    $DOCKER exec -d -w "$SITE/qd2_controller" "$CONTROLLER_CONTAINER" \
        sh -c "exec $PY controller.py >/tmp/controller.out 2>&1"
    echo "   controller.py"
}

verify() {
    log "Verificação"
    sleep 5
    local ok=0
    for entry in "${NODES[@]}"; do
        read -r container node ip <<<"$entry"
        local procs
        procs=$($DOCKER exec "$container" pgrep -fc 'receive_qd2.py|http_receptor.py' || echo 0)
        printf '   %-14s processos=%s  ' "$node" "$procs"
        # Teto do ETSI 014: /api/v1/keys/<SAE>/enc_keys?size=...
        if $DOCKER exec "$container" "$PY" -c "
import urllib.request,sys
try:
    urllib.request.urlopen('http://$ip:8000/openapi.json', timeout=5).read()
except Exception as e:
    sys.exit(str(e))
" 2>/dev/null; then
            echo "API ETSI 014 responde em $ip:8000"
        else
            echo "API NÃO responde em $ip:8000"; ok=1
        fi
    done
    if $DOCKER exec "$CONTROLLER_CONTAINER" pgrep -f controller.py >/dev/null; then
        echo "   controller.py: rodando"
    else
        echo "   controller.py: NÃO está rodando"; ok=1
    fi
    return $ok
}

main() {
    start_rabbitmq
    provision_config
    start_node_daemons
    start_controller
    verify
    cat <<EOF

Pronto. Pedir uma chave (o par master/slave do ETSI 014):

  $DOCKER exec qkdn-node-a $PY -c "import urllib.request,json; \\
    print(urllib.request.urlopen('http://172.20.0.11:8000/api/v1/keys/B/enc_keys?size=256').read())"

Logs: /tmp/{receive_qd2,http_receptor,controller}.out nos containers e
node_<N>.log / controller.log nos diretórios de pacote.
EOF
}

main "$@"
