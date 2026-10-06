"""Cenário 0 — Baseline Nativo: sem IPsec, sem PQC. Estabelece o piso de
latência/teto de vazão do hardware/VM (ver CENARIOS-TESTE-AVALIACAO.md
seção 1). F1/N2/N3 continuam roteáveis normalmente — IPsec é uma camada
OPCIONAL por cima da rede já montada (ver docs/RUNBOOK-OAI.md seção 4),
então só precisamos derrubar o strongSwan, não desmontar netns/veth."""

from __future__ import annotations

from evaluation import lab_control

NAME = "cenario0_baseline_nativo"


def setup() -> None:
    for ns in ("cu-ns", "5gc-edge-ns"):
        lab_control.kill_ipsec_instance(ns)
    for ns in ("cu-ns", "5gc-edge-ns"):
        lab_control.flush_xfrm(ns)
    # Sem SA por fatia neste cenário (sem IPsec nenhum) — a métrica B.3
    # (isolamento) já retorna N/A aqui de qualquer forma (não há
    # sa_packets_total pra comparar, ver analyze.py). Só limpa a tabela
    # mangle (não recaptura TEID real) — mantém classification_snapshot
    # no mesmo formato dos outros cenários, sem a parte frágil que não
    # contribui pra nenhuma métrica real aqui (ver lab_control.flush_slice_marks).
    lab_control.flush_slice_marks("cu-ns")


def teardown() -> None:
    """Restaura o estado padrão (N2 clássico + 3 N3 PQC/PPK via vici)
    pros próximos cenários. Sem F1 nesta topologia (gNB combinado CU+DU
    num processo só, ver ~/ocudu-lab/) — só cu-ns e 5gc-edge-ns."""
    lab_control.restart_ipsec_lab(("cu-ns", "5gc-edge-ns"))
    lab_control.load_and_initiate_n3()


def traffic_plan() -> list[dict]:
    """Mesmas três fatias, mesmos netns/interfaces/endereços de sempre —
    só sem cifragem nenhuma no caminho."""
    return [
        {"label": "urllc", "netns": "ue-urllc", "iface": "tun_srsue", "dest": "10.45.1.1", "profile": "latency"},
        {"label": "embb", "netns": "ue-embb", "iface": "tun_srsue", "dest": "10.45.0.1", "profile": "throughput_tcp"},
        {"label": "miot", "netns": "ue-miot", "iface": "tun_srsue", "dest": "10.45.2.1", "profile": "throughput_udp_sparse", "port": 5202},
    ]
