"""Tipos de domínio do Global Scheduler.

Deliberadamente independentes dos stubs gerados a partir de
scheduler.proto — mesmo motivo do KMS (ver kms/models.py): isolado e
testável sem servidor gRPC, que fica pra quando o SMO amarrar os
componentes. Ver ../docs/ARQUITETURA-ORQUESTRADOR.md seção 2 pra fórmula
de risco e as três políticas de escalonamento.
"""

from __future__ import annotations

import enum
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Optional


class SliceType(enum.Enum):
    URLLC = "URLLC"
    EMBB = "EMBB"
    MIOT = "MIOT"


class InterfaceType(enum.Enum):
    """N2 (controle) e N3 (dado de usuário, por fatia) são conexões
    distintas desde a Fase 3/4 do protótipo — ver kms/models.py."""

    F1 = "F1"
    N2 = "N2"
    N3 = "N3"
    FRONTHAUL = "FRONTHAUL"  # reservado, ver kms/models.py


class TaskType(enum.Enum):
    ROTATE = "ROTATE"
    REVOKE = "REVOKE"


class TaskPriority(enum.Enum):
    NORMAL = "NORMAL"
    CRITICAL = "CRITICAL"
    EMERGENCY = "EMERGENCY"


# Ordem de prioridade (maior primeiro) — EMERGENCY > CRITICAL > NORMAL é
# sempre respeitada, independente da política ativa (ver scheduler.proto:
# "fila de tarefas... classificadas em EMERGENCY > CRITICAL > NORMAL, e
# dentro de cada classe ordena pelo maior risco"). A política ativa decide
# só a ordenação DENTRO de cada classe — ver policy.py.
PRIORITY_RANK: dict[TaskPriority, int] = {
    TaskPriority.EMERGENCY: 2,
    TaskPriority.CRITICAL: 1,
    TaskPriority.NORMAL: 0,
}


class SchedulingPolicy(enum.Enum):
    RISK_AWARE = "RISK_AWARE"
    WEIGHTED_EDF = "WEIGHTED_EDF"
    FIFO = "FIFO"


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


@dataclass
class Task:
    """Uma tarefa de rotação/revogação na fila. `risk_score` é sempre
    calculado na hora de enfileirar (ver policy.compute_risk) e atualizado
    via aging enquanto a tarefa espera — mesmo quando a política ativa não
    é RISK_AWARE, porque o campo existe pra observabilidade (é o que o
    PeekQueue expõe) independente de qual política está ordenando a fila
    agora."""

    task_id: str
    slice: SliceType
    interface: InterfaceType
    task_type: TaskType
    priority: TaskPriority
    slack_seconds: float
    estimated_cost_seconds: float
    enqueued_at: datetime
    deadline: Optional[datetime] = None
    reason: str = ""
    risk_score: float = 0.0


@dataclass
class EnqueueTaskRequest:
    slice: SliceType
    interface: InterfaceType
    task_type: TaskType
    priority: TaskPriority
    slack_seconds: float
    estimated_cost_seconds: float
    deadline: Optional[datetime] = None
    reason: str = ""
