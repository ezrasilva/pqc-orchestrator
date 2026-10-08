"""Cenário 1 — IPsec PQC Estático Tradicional: um único túnel ML-KEM-768
protegendo TODO o tráfego do enlace CU<->borda-do-5GC (controle E dado de
usuário juntos, sem diferenciar fatia), com rekey em intervalo FIXO —
mostra o problema do "rekeying cego à fatia" (ver
CENARIOS-TESTE-AVALIACAO.md seção 1).

**Por que via vici, não ipsec.conf clássico**: ML-KEM exige o plugin
`openssl`/proposta `mlkem768`, que o parser clássico entende — mas pra
não reabrir o achado da Fase 4 (conexões que compartilham endereço
externo com perfis diferentes podem sofrer downgrade silencioso), esta
conexão usa um endereço externo PRÓPRIO (`10.97.0.41`/`10.97.0.42`), não
compartilhado com mais nada. F1 continua intocado (clássico, fora do
escopo deste cenário — o documento fala em "todo o tráfego do enlace",
e o F1 é um enlace separado do N2/N3).

**Achado real migrando pro testbed OCUDU (strongSwan 6.0.4)**: a
sintaxe de proposta PQC mudou — ML-KEM entra como round HÍBRIDO
adicional via prefixo `ke1_` junto de um grupo clássico de base
(`modp2048`), não mais como único método de KE. A sintaxe antiga
(`...-mlkem768` sem `ke1_`/`modp2048`) dava `NO_PROPOSAL_CHOSEN` nesta
versão — confirmado isolando outras duas causas reais antes de achar
essa (mount órfão do bind do charon, endereços não espelhados entre os
dois lados; ver `~/oai-lab-conf/swanctl-cu/conf.d/connections.conf`).

**Achado real rodando a primeira campanha longa**: a primeira versão
usava `10.96.0.1`/`10.96.0.2` — fora do `/24` que já tem rota automática
via o endereço base `10.97.0.1/24` de `veth-cu-n2`. Sem rota explícita
pra esse novo range, `cu-ns` não alcançava `10.96.0.2` de jeito nenhum
("Network is unreachable"), e o IKE_SA_INIT nunca saía do lugar — a SA
ficava presa em `CONNECTING` pra sempre, retransmitindo até desistir
("peer not responding"). Dois bugs se mascaravam um ao outro aqui: esse
problema de rota, e `lab_control.wait_for_sa_established` que checava
"ESTABLISHED" em QUALQUER lugar da saída do `swanctl --list-sas` (não
nessa conexão especificamente) — como F1/N2 já estavam `ESTABLISHED`,
dava falso positivo e o setup "passava" com a SA nunca tendo subido de
verdade. Corrigido nos dois lugares: endereço dentro do `/24` já
roteado (sem precisar de rota nova), e checagem específica da conexão
em `lab_control.py`."""

from __future__ import annotations

import subprocess
import threading
import time

from evaluation import lab_control
from evaluation.collectors.resource import find_charon_pid
from evaluation.instrumentation import emit

NAME = "cenario1_pqc_estatico"

FIXED_REKEY_INTERVAL_SECONDS = 30  # ver CENARIOS-TESTE-AVALIACAO.md seção 1
CONN_NAME = "n2n3-static-pqc-cu-edge"

# Versão do ipsec.conf clássico SEM n2-cu-edge — pra não competir com a
# conexão estática pelo mesmo tráfego de controle (ver achado
# documentado em setup()). Sem F1 nesta topologia (gNB combinado CU+DU
# num processo só, ver ~/ocudu-lab/) — fica só o stanza de config.
_CU_CLASSIC_WITHOUT_N2 = """config setup
    charondebug="ike 1, knl 1, cfg 1"
"""

_EDGE_CLASSIC_WITHOUT_N2 = """config setup
    charondebug="ike 1, knl 1, cfg 1"
"""

_CU_CONNECTIONS_CONF = f"""connections {{
    {CONN_NAME} {{
        local_addrs = 10.97.0.41
        remote_addrs = 10.97.0.42
        proposals = aes256gcm16-prfsha256-modp2048-ke1_mlkem768
        local {{ auth = psk }}
        remote {{ auth = psk }}
        children {{
            {CONN_NAME} {{
                local_ts = 10.98.0.98/32,172.18.0.99/32
                remote_ts = 10.98.0.0/24,172.18.0.0/16
                esp_proposals = aes256gcm16-ke1_mlkem768
                mode = tunnel
                start_action = __START_ACTION__
            }}
        }}
        version = 2
    }}
}}
"""

_CU_SECRETS_CONF = f"""secrets {{
    ike-{CONN_NAME} {{
        id-1 = 10.97.0.41
        id-2 = 10.97.0.42
        secret = "{{SECRET}}"
    }}
}}
"""


def _mirror(conf: str) -> str:
    """Troca não só os endereços IKE (10.97.0.41/.42) como também
    `local_ts`/`remote_ts` entre os dois lados — **achado real rodando a
    campanha de 30 iterações**: a versão anterior só trocava os
    endereços, deixando o lado da borda com os MESMOS `local_ts`
    (10.98.0.98/32,172.18.0.99/32) que o CU também anuncia. O narrowing
    do strongSwan então negocia a intersecção entre o `remote_ts` do CU
    (10.98.0.0/24,172.18.0.0/16) e o `local_ts` da borda — que, por não
    ter sido espelhado, também era 10.98.0.98/32,172.18.0.99/32 — e
    instala uma política cobrindo só esses dois hosts exatos, não a
    sub-rede real. Resultado: SA sobe "ESTABLISHED" normalmente, mas o
    tráfego GTP real (que não tem esses IPs exatos como destino) nunca
    bate na política — `0 bytes, 0 packets` do início ao fim,
    confirmado em `swanctl --list-sas` e nos 30/30 `xfrm_snapshot` da
    campanha. Corrigido trocando também os pares de traffic selector."""
    out = conf.replace("10.97.0.41", "__TMP_ADDR__").replace("10.97.0.42", "10.97.0.41").replace("__TMP_ADDR__", "10.97.0.42")
    out = out.replace(
        "10.98.0.98/32,172.18.0.99/32", "__TMP_TS__"
    ).replace(
        "10.98.0.0/24,172.18.0.0/16", "10.98.0.98/32,172.18.0.99/32"
    ).replace("__TMP_TS__", "10.98.0.0/24,172.18.0.0/16")
    return out


_rekey_thread_stop = threading.Event()
_rekey_thread: "threading.Thread | None" = None


def _rekey_loop(charon_pid: int) -> None:
    while not _rekey_thread_stop.wait(FIXED_REKEY_INTERVAL_SECONDS):
        start = time.monotonic()
        subprocess.run(
            ["nsenter", f"--mount=/proc/{charon_pid}/ns/mnt", f"--net=/proc/{charon_pid}/ns/net",
             "swanctl", "--rekey", "--ike", CONN_NAME],
            capture_output=True,
        )
        emit("fixed_interval_rekey", connection=CONN_NAME, duration_seconds=time.monotonic() - start)


_backup: dict[str, str] = {}


def setup() -> None:
    """**Achado real rodando a primeira campanha longa**: `start-ipsec-
    side.sh` bind-monta `connections.conf`/`secrets.conf` **arquivo por
    arquivo** (não o diretório `conf.d/` inteiro) — um terceiro arquivo
    novo (`scenario1.conf`) escrito no mesmo diretório fonte nunca fica
    visível dentro do mount namespace isolado do charon, porque nada
    liga esse caminho extra a `/etc/swanctl/conf.d/` lá dentro
    (`swanctl --load-conns --file ...` confirmou: "no files found
    matching"). A primeira versão deste setup escrevia um arquivo à
    parte e nunca conseguia subir a conexão — confirmado, silenciou a
    campanha inteira (ver docstring de `run_experiment.run_once`).
    Corrigido: sobrescreve `connections.conf`/`secrets.conf` (que JÁ têm
    bind mount) diretamente, com backup pro `teardown()` restaurar."""
    import secrets

    psk = __import__("base64").b64encode(secrets.token_bytes(32)).decode()

    # endereços dedicados pra este túnel, dentro do mesmo /24 já roteado
    # entre cu-ns e 5gc-edge-ns (mesmo padrão da Fase 4, ver
    # ipsec_agent/config.py) — não precisa de proxy-ARP novo.
    subprocess.run(["ip", "netns", "exec", "cu-ns", "ip", "addr", "add", "10.97.0.41/32", "dev", "veth-cu-n2"])
    subprocess.run(["ip", "netns", "exec", "5gc-edge-ns", "ip", "addr", "add", "10.97.0.42/32", "dev", "veth-edge-cu"])

    # derruba a topologia da Fase 3/4 (N2 + 3 N3) — este cenário usa uma
    # única conexão cobrindo tudo.
    lab_control.kill_ipsec_instance("cu-ns")
    lab_control.kill_ipsec_instance("5gc-edge-ns")
    lab_control.flush_xfrm("cu-ns")
    lab_control.flush_xfrm("5gc-edge-ns")

    # **Achado real**: `start_ipsec_instance` reinicia a instância INTEIRA
    # do charon, que sobe automaticamente tudo que está no `ipsec.conf`
    # clássico com `auto=start` — inclusive `n2-cu-edge` (controle), que
    # continuaria protegendo o MESMO leftsubnet (10.98.0.98/32) que a
    # conexão estática também cobre. Duas políticas XFRM competindo pelo
    # mesmo tráfego de controle tornaria os dados deste cenário ambíguos
    # (não dá pra saber com certeza qual SA o kernel escolheu pro
    # tráfego de controle). Remove `n2-cu-edge` do `ipsec.conf` clássico
    # temporariamente — F1 continua intocado (fora do escopo do cenário).
    cu_classic = lab_control.LIVE_LAB_IPSEC_DIR / "ipsec-cu" / "ipsec.conf"
    edge_classic = lab_control.LIVE_LAB_IPSEC_DIR / "ipsec-edge" / "ipsec.conf"
    _backup["cu_classic"] = cu_classic.read_text()
    _backup["edge_classic"] = edge_classic.read_text()
    cu_classic.write_text(_CU_CLASSIC_WITHOUT_N2)
    edge_classic.write_text(_EDGE_CLASSIC_WITHOUT_N2)

    cu_conn = lab_control.LIVE_LAB_IPSEC_DIR / "swanctl-cu" / "conf.d" / "connections.conf"
    cu_secrets = lab_control.LIVE_LAB_IPSEC_DIR / "swanctl-cu" / "conf.d" / "secrets.conf"
    edge_conn = lab_control.LIVE_LAB_IPSEC_DIR / "swanctl-edge" / "conf.d" / "connections.conf"
    edge_secrets = lab_control.LIVE_LAB_IPSEC_DIR / "swanctl-edge" / "conf.d" / "secrets.conf"

    _backup["cu_conn"] = cu_conn.read_text()
    _backup["cu_secrets"] = cu_secrets.read_text()
    _backup["edge_conn"] = edge_conn.read_text()
    _backup["edge_secrets"] = edge_secrets.read_text()

    # **Hipótese investigada rodando a campanha de 10 iterações**: com
    # `start_action = start` nos DOIS lados, CU e borda tentam iniciar a
    # IKE_SA simultaneamente a cada setup() — uma corrida de iniciação
    # que o strongSwan tolera na maior parte das vezes, mas que pode
    # explicar a degradação progressiva observada (iterações 1-5 limpas,
    # 6 degradando, 7-10 mortas desde o início: `fixed_interval_rekey`
    # ficou visivelmente mais rápido, ~0.025s vs ~0.046-0.049s, bem no
    # instante em que o tráfego parou — sugerindo que o `swanctl --rekey`
    # passou a falhar rápido, não ter sucesso). Não validado ao vivo
    # ainda (não dava pra reproduzir sem colidir com a campanha em
    # andamento nos mesmos netns) — só CU inicia agora, borda só
    # responde, prática padrão do strongSwan pra evitar essa corrida.
    cu_conn.write_text(_CU_CONNECTIONS_CONF.replace("__START_ACTION__", "start"))
    cu_secrets.write_text(_CU_SECRETS_CONF.replace("{SECRET}", psk))
    edge_conn.write_text(_mirror(_CU_CONNECTIONS_CONF).replace("__START_ACTION__", "none"))
    edge_secrets.write_text(_mirror(_CU_SECRETS_CONF).replace("{SECRET}", psk))

    cu_pid = lab_control.start_ipsec_instance("cu-ns")
    edge_pid = lab_control.start_ipsec_instance("5gc-edge-ns")
    for pid in (edge_pid, cu_pid):
        subprocess.run(
            ["nsenter", f"--mount=/proc/{pid}/ns/mnt", f"--net=/proc/{pid}/ns/net", "swanctl", "--load-all"],
            capture_output=True,
        )

    if not lab_control.wait_for_sa_established("cu-ns", CONN_NAME):
        raise RuntimeError(f"{CONN_NAME} não estabeleceu — ver logs do charon em cu-ns")

    # Mesmo raciocínio do cenário 0 (ver scenario0_baseline_native.py):
    # a única SA aqui (CONN_NAME) não tem mark_in/mark_out nem
    # diferenciação por fatia — B.3 já retorna N/A pra este cenário de
    # qualquer forma. Só limpa a tabela mangle, sem a captura de TEID
    # frágil que não contribui pra nenhuma métrica real aqui.
    lab_control.flush_slice_marks("cu-ns")

    global _rekey_thread
    _rekey_thread_stop.clear()
    _rekey_thread = threading.Thread(target=_rekey_loop, args=(cu_pid,), daemon=True)
    _rekey_thread.start()


def teardown() -> None:
    _rekey_thread_stop.set()
    if _rekey_thread is not None:
        _rekey_thread.join(timeout=FIXED_REKEY_INTERVAL_SECONDS + 2)

    # restaura connections.conf/secrets.conf originais (backup feito no
    # setup) — se o setup falhou antes de chegar a fazer o backup,
    # _backup fica vazio e não há nada pra restaurar (restart_ipsec_lab
    # abaixo já vai recarregar o que estiver em disco, que nesse caso
    # nunca foi sobrescrito).
    if _backup:
        cu_dir = lab_control.LIVE_LAB_IPSEC_DIR / "swanctl-cu" / "conf.d"
        edge_dir = lab_control.LIVE_LAB_IPSEC_DIR / "swanctl-edge" / "conf.d"
        (cu_dir / "connections.conf").write_text(_backup["cu_conn"])
        (cu_dir / "secrets.conf").write_text(_backup["cu_secrets"])
        (edge_dir / "connections.conf").write_text(_backup["edge_conn"])
        (edge_dir / "secrets.conf").write_text(_backup["edge_secrets"])
        (lab_control.LIVE_LAB_IPSEC_DIR / "ipsec-cu" / "ipsec.conf").write_text(_backup["cu_classic"])
        (lab_control.LIVE_LAB_IPSEC_DIR / "ipsec-edge" / "ipsec.conf").write_text(_backup["edge_classic"])
        _backup.clear()

    subprocess.run(["ip", "netns", "exec", "cu-ns", "ip", "addr", "del", "10.97.0.41/32", "dev", "veth-cu-n2"], capture_output=True)
    subprocess.run(["ip", "netns", "exec", "5gc-edge-ns", "ip", "addr", "del", "10.97.0.42/32", "dev", "veth-edge-cu"], capture_output=True)

    lab_control.restart_ipsec_lab(("cu-ns", "5gc-edge-ns"))
    lab_control.load_and_initiate_n3()


def traffic_plan() -> list[dict]:
    return [
        {"label": "urllc", "netns": "ue-urllc", "iface": "tun_srsue", "dest": "10.45.1.1", "profile": "latency"},
        {"label": "embb", "netns": "ue-embb", "iface": "tun_srsue", "dest": "10.45.0.1", "profile": "throughput_tcp"},
        {"label": "miot", "netns": "ue-miot", "iface": "tun_srsue", "dest": "10.45.2.1", "profile": "throughput_udp_sparse", "port": 5202},
    ]
