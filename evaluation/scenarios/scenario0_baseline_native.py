"""Cenário 0 — Baseline Nativo: sem IPsec, sem PQC. Estabelece o piso de
latência/teto de vazão do hardware/VM (ver CENARIOS-TESTE-AVALIACAO.md
seção 1). F1/N2/N3 continuam roteáveis normalmente — IPsec é uma camada
OPCIONAL por cima da rede já montada (ver docs/RUNBOOK-OAI.md seção 4),
então só precisamos derrubar o strongSwan, não desmontar netns/veth."""

from __future__ import annotations

from evaluation import lab_control

NAME = "cenario0_baseline_nativo"


def setup() -> None:
    for ns in ("cu-ns", "du-ns", "5gc-edge-ns"):
        lab_control.kill_ipsec_instance(ns)
    for ns in ("cu-ns", "du-ns", "5gc-edge-ns"):
        lab_control.flush_xfrm(ns)
    # mesmo sem IPsec, o classification_snapshot (mangle OUTPUT) continua
    # sendo coletado por consistência entre cenários — recaptura os
    # TEIDs reais pra não ficar com regras órfãs (ver docstring
    # equivalente em scenario2_diff_no_risk.py).
    lab_control.capture_and_apply_slice_marks()


def teardown() -> None:
    """Restaura o estado padrão (F1 + N2 clássicos + 3 N3 PQC/PPK via
    vici) pros próximos cenários — mesmo procedimento do RUNBOOK."""
    lab_control.restart_ipsec_lab(("cu-ns", "du-ns", "5gc-edge-ns"))
    lab_control.load_and_initiate_n3()


def traffic_plan() -> list[dict]:
    """Mesmas três fatias, mesmas interfaces/endereços de sempre — só
    sem cifragem nenhuma no caminho."""
    return [
        {"label": "urllc", "iface": "oaitun_ue1p2", "profile": "latency"},
        {"label": "embb", "iface": "oaitun_ue1", "profile": "throughput_tcp"},
        {"label": "miot", "iface": "oaitun_ue1p3", "profile": "throughput_udp_sparse"},
    ]
