"""Núcleo do Global Scheduler — fila priorizada de tarefas de rotação/
revogação, sem gRPC/sem rede (mesmo padrão do kms/service.py: "a peça
isolada e testável", servidor gRPC fica pra quando o SMO amarrar os
componentes). Ver ../docs/ARQUITETURA-ORQUESTRADOR.md seção 2 e
policy.py pra fórmula de risco e as três políticas.
"""

from __future__ import annotations

import threading
import uuid
from typing import Optional

from scheduler.exceptions import TaskNotFoundError
from scheduler.models import (
    PRIORITY_RANK,
    EnqueueTaskRequest,
    SchedulingPolicy,
    Task,
    utcnow,
)
from scheduler.policy import compute_risk, sort_key
from evaluation.instrumentation import emit


def _new_task_id() -> str:
    return f"task-{uuid.uuid4().hex[:12]}"


class SchedulerCore:
    """Lock global — mesma justificativa do KMS: volume de tarefas de
    rotação é baixo, não tráfego de dados, um lock por chamada não é
    gargalo real."""

    def __init__(self, policy: SchedulingPolicy = SchedulingPolicy.RISK_AWARE):
        self._tasks: dict[str, Task] = {}
        self._policy = policy
        self._lock = threading.Lock()

    def enqueue_task(self, request: EnqueueTaskRequest) -> Task:
        now = utcnow()
        task = Task(
            task_id=_new_task_id(),
            slice=request.slice,
            interface=request.interface,
            task_type=request.task_type,
            priority=request.priority,
            slack_seconds=request.slack_seconds,
            estimated_cost_seconds=request.estimated_cost_seconds,
            enqueued_at=now,
            deadline=request.deadline,
            reason=request.reason,
        )
        task.risk_score = compute_risk(task, now=now)
        with self._lock:
            self._tasks[task.task_id] = task
        return task

    def _ordered_tasks(self, now=None) -> list[Task]:
        """Reaplica aging em risk_score de todas as tarefas pendentes antes
        de ordenar — é por isso que uma tarefa de baixo risco parada na
        fila eventualmente sobe (ver policy.py, AGING_RATE_PER_SECOND),
        mesmo que a política ativa não seja RISK_AWARE (risk_score
        continua existindo pra observabilidade via PeekQueue)."""
        now = now or utcnow()
        tasks = list(self._tasks.values())
        for task in tasks:
            task.risk_score = compute_risk(task, now=now)
        tasks.sort(
            key=lambda t: (
                -PRIORITY_RANK[t.priority],  # EMERGENCY > CRITICAL > NORMAL sempre
                sort_key(self._policy, t),
            )
        )
        return tasks

    def get_next_task(self) -> Optional[Task]:
        """O ponto de instrumentação da "decisão do scheduler" (ver
        CENARIOS-TESTE-AVALIACAO.md seção 6) é aqui, não dentro de
        `compute_risk` — `compute_risk` roda a cada reordenação da fila
        (inclusive em `peek_queue`, só pra observabilidade), o que geraria
        ruído sem sinal; o evento que interessa pro pipeline de avaliação
        é qual tarefa foi de fato escolhida, com qual risco, sob qual
        política."""
        with self._lock:
            ordered = self._ordered_tasks()
            if not ordered:
                return None
            next_task = ordered[0]
            del self._tasks[next_task.task_id]
        emit(
            "scheduler_decision",
            task_id=next_task.task_id,
            slice=next_task.slice.value,
            interface=next_task.interface.value,
            priority=next_task.priority.value,
            risk_score=next_task.risk_score,
            policy=self._policy.value,
            queue_depth_after=len(self._tasks),
        )
        return next_task

    def peek_queue(self, limit: int = 0) -> list[Task]:
        with self._lock:
            ordered = self._ordered_tasks()
        if limit and limit > 0:
            return ordered[:limit]
        return ordered

    def cancel_task(self, task_id: str) -> None:
        with self._lock:
            if task_id not in self._tasks:
                raise TaskNotFoundError(task_id)
            del self._tasks[task_id]

    def set_policy(self, policy: SchedulingPolicy) -> None:
        with self._lock:
            self._policy = policy

    def get_policy(self) -> SchedulingPolicy:
        with self._lock:
            return self._policy

    def queue_size(self) -> int:
        with self._lock:
            return len(self._tasks)
