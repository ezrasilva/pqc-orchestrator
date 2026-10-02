"""Cenário 1 — IPsec PQC Estático Tradicional: um único túnel ML-KEM-768
protegendo TODO o tráfego do enlace CU<->borda-do-5GC (controle E dado de
usuário juntos, sem diferenciar fatia), com rekey em intervalo FIXO —
mostra o problema do "rekeying cego à fatia" (ver
CENARIOS-TESTE-AVALIACAO.md seção 1).

**Por que via vici, não ipsec.conf clássico**: ML-KEM exige o plugin
`openssl`/proposta `mlkem768`, que o parser clássico entende — mas pra
não reabrir o achado da Fase 4 (conexões que compartilham endereço
externo com perfis diferentes podem sofrer downgrade silencioso), esta
conexão usa um endereço externo PRÓPRIO (10.96.0.1/10.96.0.2, fora do
range já usado por n2-cu-edge/n3-*-cu-edge), não compartilhado com mais
nada. F1 continua intocado (clássico, fora do escopo deste cenário —
o documento fala em "todo o tráfego do enlace", e o F1 é um enlace
separado do N2/N3)."""

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

_CU_CONNECTIONS_CONF = f"""connections {{
    {CONN_NAME} {{
        local_addrs = 10.96.0.1
        remote_addrs = 10.96.0.2
        proposals = aes256gcm16-prfsha256-mlkem768
        local {{ auth = psk }}
        remote {{ auth = psk }}
        children {{
            {CONN_NAME} {{
                local_ts = 10.98.0.98/32,172.18.0.99/32
                remote_ts = 10.98.0.0/24,172.18.0.0/16
                esp_proposals = aes256gcm16-mlkem768
                mode = tunnel
                start_action = start
            }}
        }}
        version = 2
    }}
}}
"""

_CU_SECRETS_CONF = f"""secrets {{
    ike-{CONN_NAME} {{
        id-1 = 10.96.0.1
        id-2 = 10.96.0.2
        secret = "{{SECRET}}"
    }}
}}
"""


def _mirror(conf: str) -> str:
    return conf.replace("10.96.0.1", "__TMP__").replace("10.96.0.2", "10.96.0.1").replace("__TMP__", "10.96.0.2")


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


def setup() -> None:
    import secrets

    psk = __import__("base64").b64encode(secrets.token_bytes(32)).decode()

    # endereços dedicados pra este túnel, dentro do mesmo /24 já roteado
    # entre cu-ns e 5gc-edge-ns (mesmo padrão da Fase 4, ver
    # ipsec_agent/config.py) — não precisa de proxy-ARP novo.
    subprocess.run(["ip", "netns", "exec", "cu-ns", "ip", "addr", "add", "10.96.0.1/32", "dev", "veth-cu-n2"])
    subprocess.run(["ip", "netns", "exec", "5gc-edge-ns", "ip", "addr", "add", "10.96.0.2/32", "dev", "veth-edge-cu"])

    # derruba a topologia da Fase 3/4 (N2 + 3 N3) — este cenário usa uma
    # única conexão cobrindo tudo.
    lab_control.kill_ipsec_instance("cu-ns")
    lab_control.kill_ipsec_instance("5gc-edge-ns")
    lab_control.flush_xfrm("cu-ns")
    lab_control.flush_xfrm("5gc-edge-ns")

    cu_dir = lab_control.LIVE_LAB_IPSEC_DIR / "swanctl-cu" / "conf.d"
    edge_dir = lab_control.LIVE_LAB_IPSEC_DIR / "swanctl-edge" / "conf.d"
    (cu_dir / "scenario1.conf").write_text(_CU_CONNECTIONS_CONF + _CU_SECRETS_CONF.replace("{SECRET}", psk))
    (edge_dir / "scenario1.conf").write_text(_mirror(_CU_CONNECTIONS_CONF) + _mirror(_CU_SECRETS_CONF).replace("{SECRET}", psk))

    cu_pid = lab_control.start_ipsec_instance("cu-ns")
    edge_pid = lab_control.start_ipsec_instance("5gc-edge-ns")
    for pid in (edge_pid, cu_pid):
        subprocess.run(
            ["nsenter", f"--mount=/proc/{pid}/ns/mnt", f"--net=/proc/{pid}/ns/net", "swanctl", "--load-all"],
            capture_output=True,
        )

    if not lab_control.wait_for_sa_established("cu-ns", CONN_NAME):
        raise RuntimeError(f"{CONN_NAME} não estabeleceu — ver logs do charon em cu-ns")

    lab_control.capture_and_apply_slice_marks()

    global _rekey_thread
    _rekey_thread_stop.clear()
    _rekey_thread = threading.Thread(target=_rekey_loop, args=(cu_pid,), daemon=True)
    _rekey_thread.start()


def teardown() -> None:
    _rekey_thread_stop.set()
    if _rekey_thread is not None:
        _rekey_thread.join(timeout=FIXED_REKEY_INTERVAL_SECONDS + 2)

    cu_dir = lab_control.LIVE_LAB_IPSEC_DIR / "swanctl-cu" / "conf.d"
    edge_dir = lab_control.LIVE_LAB_IPSEC_DIR / "swanctl-edge" / "conf.d"
    (cu_dir / "scenario1.conf").unlink(missing_ok=True)
    (edge_dir / "scenario1.conf").unlink(missing_ok=True)

    lab_control.restart_ipsec_lab(("cu-ns", "du-ns", "5gc-edge-ns"))
    lab_control.load_and_initiate_n3()


def traffic_plan() -> list[dict]:
    return [
        {"label": "urllc", "iface": "oaitun_ue1p2", "profile": "latency"},
        {"label": "embb", "iface": "oaitun_ue1", "profile": "throughput_tcp"},
        {"label": "miot", "iface": "oaitun_ue1p3", "profile": "throughput_udp_sparse"},
    ]
