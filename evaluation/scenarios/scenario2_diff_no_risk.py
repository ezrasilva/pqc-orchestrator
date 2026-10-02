"""Cenário 2 — Diferenciado por fatia + Escalonador Tradicional
(EDF/idade): a diferenciação criptográfica por fatia do Módulo 3/4 já
está ativa (três SAs reais, perfis PQC/PPK da Fase 4), mas a ordem de
rotação segue `SchedulingPolicy.WEIGHTED_EDF` — mais próxima do limite
de vida útil rotaciona primeiro, sem olhar risco/SLA/classe de tráfego
(ver CENARIOS-TESTE-AVALIACAO.md seção 1). Isola o efeito "só ter SAs
separadas não basta" do efeito do escalonador por risco (Cenário 3)."""

from __future__ import annotations

from evaluation import lab_control
from scheduler.models import SchedulingPolicy

NAME = "cenario2_diferenciado_edf"
scheduling_policy = SchedulingPolicy.WEIGHTED_EDF


def setup() -> None:
    """Garante a topologia padrão (Fase 3/4) de pé — idempotente, mesmo
    procedimento usado nos smoke tests desta sessão. Recaptura e reaplica
    os TEIDs reais das sessões PDU ativas: se a UE foi reiniciada desde a
    última vez (TEIDs mudam a cada sessão PDU nova), as regras `mangle`
    antigas ficam órfãs e o tráfego de teste sai sem mark — achado
    confirmado rodando esta avaliação pela primeira vez (ver
    lab_control.capture_and_apply_slice_marks)."""
    lab_control.restart_ipsec_lab(("cu-ns", "5gc-edge-ns"))
    lab_control.load_and_initiate_n3()
    lab_control.capture_and_apply_slice_marks()


def teardown() -> None:
    pass  # próximo cenário cuida do próprio setup


def traffic_plan() -> list[dict]:
    return [
        {"label": "urllc", "iface": "oaitun_ue1p2", "profile": "latency"},
        {"label": "embb", "iface": "oaitun_ue1", "profile": "throughput_tcp"},
        {"label": "miot", "iface": "oaitun_ue1p3", "profile": "throughput_udp_sparse"},
    ]
