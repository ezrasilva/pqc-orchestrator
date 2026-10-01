#!/usr/bin/env bash
# Fase 4: carrega as conexões/segredos vici (conf.d/connections.conf +
# conf.d/secrets.conf, já bind-montados por start-ipsec-side.sh) e inicia
# as três SAs N3 (urllc/embb/miot), em ambos os lados. Rodar depois que
# start-ipsec-side.sh já subiu cu-ns e 5gc-edge-ns (F1 e N2 sobem
# sozinhos via auto=start; as N3 não, porque start_action=none —
# equivalente vici do auto=add clássico, pensado pro "Agente de
# Segurança" iniciar sob demanda quando o Módulo 2 vir a fatia).
#
# Uso: sudo bash load-and-initiate-n3.sh
set -euo pipefail

find_charon_pid() {
    local ns="$1"
    ip netns pids "$ns" | while read -r p; do
        if [ "$(ps -p "$p" -o comm= 2>/dev/null)" = "charon" ]; then
            echo "$p"
            break
        fi
    done
}

CU_PID=$(find_charon_pid cu-ns)
EDGE_PID=$(find_charon_pid 5gc-edge-ns)

if [ -z "$CU_PID" ] || [ -z "$EDGE_PID" ]; then
    echo "charon não encontrado em cu-ns ou 5gc-edge-ns — rode start-ipsec-side.sh primeiro" >&2
    exit 1
fi

echo "[load-and-initiate-n3] carregando config vici em 5gc-edge-ns (pid $EDGE_PID)..."
nsenter --mount="/proc/${EDGE_PID}/ns/mnt" --net="/proc/${EDGE_PID}/ns/net" swanctl --load-all

echo "[load-and-initiate-n3] carregando config vici em cu-ns (pid $CU_PID)..."
nsenter --mount="/proc/${CU_PID}/ns/mnt" --net="/proc/${CU_PID}/ns/net" swanctl --load-all

for conn in n3-urllc-cu-edge n3-embb-cu-edge n3-miot-cu-edge; do
    echo "[load-and-initiate-n3] iniciando $conn..."
    nsenter --mount="/proc/${CU_PID}/ns/mnt" --net="/proc/${CU_PID}/ns/net" swanctl --initiate --child "$conn"
done

echo "[load-and-initiate-n3] status final:"
nsenter --mount="/proc/${CU_PID}/ns/mnt" --net="/proc/${CU_PID}/ns/net" swanctl --list-sas
