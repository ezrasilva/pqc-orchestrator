"""Cenário 4 — Contenção / Carga Concorrente: mesma infraestrutura do
Cenário 3 (ou, como contraponto, do Cenário 2), mas com uma rotação
forçada simultânea nas três SAs no meio da janela de coleta — simula um
gatilho de "suspeita de comprometimento" expirando as três ao mesmo
tempo (ver CENARIOS-TESTE-AVALIACAO.md seção 1, "por que este cenário é
necessário": sem contenção real, EDF e risco tendem a produzir números
quase idênticos).

Parametrizado por `scheduling_policy` — rode este módulo duas vezes
(RISK_AWARE e WEIGHTED_EDF) pra comparar as duas políticas SOB
contenção, não só isoladas."""

from __future__ import annotations

from evaluation import lab_control
from evaluation.instrumentation import emit
from scheduler.models import EnqueueTaskRequest
from scheduler.models import InterfaceType as SchedInterfaceType
from scheduler.models import SchedulingPolicy
from scheduler.models import SliceType as SchedSliceType
from scheduler.models import TaskPriority, TaskType

NAME = "cenario4_contencao"
scheduling_policy = SchedulingPolicy.RISK_AWARE  # troque antes de chamar run_experiment pra comparar


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
        {"label": "urllc", "iface": "oaitun_ue1p2", "profile": "latency"},
        {"label": "embb", "iface": "oaitun_ue1", "profile": "throughput_tcp"},
        {"label": "miot", "iface": "oaitun_ue1p3", "profile": "throughput_udp_sparse"},
    ]


def trigger_contention(smo, scheduler) -> None:
    """Chamado pelo `run_experiment.py` no meio da janela de coleta —
    enfileira as três rotações como EMERGENCY **antes** de processar
    qualquer uma (não usa `smo.force_rotate`, que enfileira e já
    processa na hora — isso impediria a disputa real: as três task
    precisam estar na fila AO MESMO TEMPO pra a política ativa
    (RISK_AWARE/WEIGHTED_EDF) decidir a ordem entre elas, não só
    "quem chegou primeiro na chamada de função"). Drena a fila
    processando uma de cada vez, registrando a ordem escolhida."""
    for slice in (SchedSliceType.URLLC, SchedSliceType.EMBB, SchedSliceType.MIOT):
        scheduler.enqueue_task(
            EnqueueTaskRequest(
                slice=slice,
                interface=SchedInterfaceType.N3,
                task_type=TaskType.ROTATE,
                priority=TaskPriority.EMERGENCY,
                slack_seconds=0.0,
                estimated_cost_seconds=1.0,
                reason="cenário 4 — rotação forçada simultânea (suspeita de comprometimento)",
            )
        )

    order = []
    while scheduler.queue_size() > 0:
        result = smo.process_next_task()
        if result.task_found:
            order.append(result.slice.value if result.slice else None)
    emit("contention_resolution_order", policy=scheduler.get_policy().value, order=order)
