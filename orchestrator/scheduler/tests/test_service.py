from datetime import timedelta

import pytest

from scheduler.exceptions import TaskNotFoundError
from scheduler.models import (
    EnqueueTaskRequest,
    InterfaceType,
    SchedulingPolicy,
    SliceType,
    TaskPriority,
    TaskType,
    utcnow,
)


def _req(**overrides) -> EnqueueTaskRequest:
    defaults = dict(
        slice=SliceType.EMBB,
        interface=InterfaceType.F1,
        task_type=TaskType.ROTATE,
        priority=TaskPriority.NORMAL,
        slack_seconds=0.0,
        estimated_cost_seconds=10.0,
    )
    defaults.update(overrides)
    return EnqueueTaskRequest(**defaults)


def test_enqueue_computes_risk_score(core):
    task = core.enqueue_task(_req())
    # slack=0 -> urgência 0; EMBB slice_bonus=0.5; F1 interface_bonus=0;
    # aging ~0 (acabou de entrar na fila).
    assert task.risk_score == pytest.approx(0.5, abs=0.01)
    assert task.task_id.startswith("task-")


def test_empty_queue_get_next_returns_none(core):
    assert core.get_next_task() is None


def test_get_next_task_dequeues(core):
    core.enqueue_task(_req())
    assert core.queue_size() == 1
    task = core.get_next_task()
    assert task is not None
    assert core.queue_size() == 0


def test_priority_class_always_wins_over_risk(core):
    """Uma EMERGENCY de risco baixo sai antes de uma NORMAL de risco alto —
    a classe de prioridade nunca é sobreposta pela política (ver
    scheduler.proto e policy.py)."""
    core.enqueue_task(
        _req(priority=TaskPriority.NORMAL, slack_seconds=-99999.0, slice=SliceType.URLLC)
    )
    emergency = core.enqueue_task(
        _req(priority=TaskPriority.EMERGENCY, slack_seconds=99999.0, slice=SliceType.MIOT)
    )
    next_task = core.get_next_task()
    assert next_task.task_id == emergency.task_id


def test_risk_aware_policy_orders_by_risk_within_class(core):
    core.set_policy(SchedulingPolicy.RISK_AWARE)
    low = core.enqueue_task(_req(slack_seconds=100.0))
    high = core.enqueue_task(_req(slack_seconds=-100.0))
    assert core.get_next_task().task_id == high.task_id
    assert core.get_next_task().task_id == low.task_id


def test_fifo_policy_orders_by_enqueue_order_within_class(core):
    core.set_policy(SchedulingPolicy.FIFO)
    # risco inverso da ordem de chegada — se FIFO estiver funcionando,
    # ignora o risco e respeita só a ordem de enfileiramento.
    first = core.enqueue_task(_req(slack_seconds=100.0))
    second = core.enqueue_task(_req(slack_seconds=-100.0))
    assert core.get_next_task().task_id == first.task_id
    assert core.get_next_task().task_id == second.task_id


def test_weighted_edf_orders_by_deadline_within_class(core):
    core.set_policy(SchedulingPolicy.WEIGHTED_EDF)
    now = utcnow()
    far = core.enqueue_task(_req(deadline=now + timedelta(seconds=1000)))
    near = core.enqueue_task(_req(deadline=now + timedelta(seconds=10)))
    assert core.get_next_task().task_id == near.task_id
    assert core.get_next_task().task_id == far.task_id


def test_cancel_removes_task(core):
    task = core.enqueue_task(_req())
    core.cancel_task(task.task_id)
    assert core.queue_size() == 0
    assert core.get_next_task() is None


def test_cancel_unknown_task_raises(core):
    with pytest.raises(TaskNotFoundError):
        core.cancel_task("task-does-not-exist")


def test_set_and_get_policy_roundtrip(core):
    core.set_policy(SchedulingPolicy.WEIGHTED_EDF)
    assert core.get_policy() is SchedulingPolicy.WEIGHTED_EDF


def test_peek_queue_does_not_consume(core):
    core.enqueue_task(_req())
    core.enqueue_task(_req())
    peeked = core.peek_queue()
    assert len(peeked) == 2
    assert core.queue_size() == 2


def test_peek_queue_respects_limit(core):
    for _ in range(5):
        core.enqueue_task(_req())
    assert len(core.peek_queue(limit=2)) == 2
    assert core.queue_size() == 5


def test_aging_eventually_promotes_starved_task(core):
    """Uma tarefa NORMAL de baixo risco, enfileirada há muito tempo, deve
    acabar subindo de posição dentro da própria classe por causa do
    aging — mesmo sem nenhuma nova tarefa chegar."""
    core.set_policy(SchedulingPolicy.RISK_AWARE)
    stale = core.enqueue_task(_req(slack_seconds=0.0, estimated_cost_seconds=1.0))
    # força o relógio pra trás como se a tarefa estivesse na fila há 1h
    stale.enqueued_at = utcnow() - timedelta(hours=1)

    fresh = core.enqueue_task(_req(slack_seconds=0.0, estimated_cost_seconds=1.0))

    assert core.get_next_task().task_id == stale.task_id
    assert core.get_next_task().task_id == fresh.task_id
