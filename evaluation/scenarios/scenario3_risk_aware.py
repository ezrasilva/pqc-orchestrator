"""Cenário 3 — Proposta Completa: mapeamento dinâmico PFCP->eBPF/mangle
->XFRM com SAs diferenciadas (URLLC: ML-KEM-768+PPK/QKD; eMBB/mIoT:
ML-KEM-512) e o Scheduler aplicando a fórmula de risco
(`SchedulingPolicy.RISK_AWARE`, ver
orchestrator/scheduler/policy.py) pra decidir a ordem de rotação — a
mesma infraestrutura já validada nas Fases 3/4/5 desta engenharia, sem
nenhuma mudança: este cenário É o estado padrão do laboratório."""

from __future__ import annotations

from evaluation import lab_control
from scheduler.models import SchedulingPolicy

NAME = "cenario3_risk_aware"
scheduling_policy = SchedulingPolicy.RISK_AWARE


def setup() -> None:
    """Idempotente — ver docstring equivalente em
    scenario2_diff_no_risk.py sobre a recaptura de TEIDs."""
    lab_control.restart_ipsec_lab(("cu-ns", "5gc-edge-ns"))
    lab_control.load_and_initiate_n3()
    lab_control.capture_and_apply_slice_marks()


def teardown() -> None:
    pass


def traffic_plan() -> list[dict]:
    return [
        {"label": "urllc", "netns": "ue-urllc", "iface": "tun_srsue", "dest": "10.45.1.1", "profile": "latency"},
        {"label": "embb", "netns": "ue-embb", "iface": "tun_srsue", "dest": "10.45.0.1", "profile": "throughput_tcp"},
        {"label": "miot", "netns": "ue-miot", "iface": "tun_srsue", "dest": "10.45.2.1", "profile": "throughput_udp_sparse"},
    ]
