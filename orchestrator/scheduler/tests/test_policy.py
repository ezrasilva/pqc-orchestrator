from datetime import timedelta

import pytest

from scheduler.models import (
    InterfaceType,
    SchedulingPolicy,
    SliceType,
    Task,
    TaskPriority,
    TaskType,
    utcnow,
)
from scheduler.policy import AGING_RATE_PER_SECOND, compute_risk, sort_key


def _task(**overrides) -> Task:
    defaults = dict(
        task_id="t1",
        slice=SliceType.EMBB,
        interface=InterfaceType.F1,
        task_type=TaskType.ROTATE,
        priority=TaskPriority.NORMAL,
        slack_seconds=0.0,
        estimated_cost_seconds=10.0,
        enqueued_at=utcnow(),
    )
    defaults.update(overrides)
    return Task(**defaults)


def test_negative_slack_increases_risk():
    """Tarefa atrasada (deadline já passou, slack negativo) deve ter risco
    maior que uma tarefa no prazo, tudo o mais igual."""
    overdue = _task(slack_seconds=-50.0, estimated_cost_seconds=10.0)
    on_time = _task(slack_seconds=50.0, estimated_cost_seconds=10.0)
    now = utcnow()
    assert compute_risk(overdue, now=now) > compute_risk(on_time, now=now)


def test_slice_bonus_favors_urllc():
    urllc = _task(slice=SliceType.URLLC)
    embb = _task(slice=SliceType.EMBB)
    miot = _task(slice=SliceType.MIOT)
    now = utcnow()
    assert compute_risk(urllc, now=now) > compute_risk(embb, now=now) > compute_risk(miot, now=now)


def test_interface_bonus_favors_n3_over_f1():
    n3_task = _task(interface=InterfaceType.N3)
    f1 = _task(interface=InterfaceType.F1)
    now = utcnow()
    assert compute_risk(n3_task, now=now) > compute_risk(f1, now=now)


def test_aging_increases_risk_score_over_time():
    task = _task(enqueued_at=utcnow() - timedelta(seconds=100))
    risk_now = compute_risk(task, now=task.enqueued_at)
    risk_later = compute_risk(task, now=task.enqueued_at + timedelta(seconds=100))
    assert risk_later - risk_now == pytest.approx(AGING_RATE_PER_SECOND * 100)


def test_zero_cost_does_not_crash_and_drops_urgency_term():
    task = _task(estimated_cost_seconds=0.0, slack_seconds=-999.0)
    # não deve levantar ZeroDivisionError; a parcela de urgência vira 0
    risk = compute_risk(task, now=task.enqueued_at)
    assert risk == 0.0 + 0.5  # só slice_bonus(EMBB) + interface_bonus(F1)=0 + aging=0


def test_sort_key_risk_aware_is_descending_risk():
    low = _task(task_id="low", slack_seconds=100.0)
    high = _task(task_id="high", slack_seconds=-100.0)
    now = utcnow()
    low.risk_score = compute_risk(low, now=now)
    high.risk_score = compute_risk(high, now=now)
    assert sort_key(SchedulingPolicy.RISK_AWARE, high) < sort_key(SchedulingPolicy.RISK_AWARE, low)


def test_sort_key_weighted_edf_orders_by_deadline_then_no_deadline_last():
    now = utcnow()
    soon = _task(task_id="soon", deadline=now + timedelta(seconds=10))
    later = _task(task_id="later", deadline=now + timedelta(seconds=100))
    none_deadline = _task(task_id="none")
    keys = sorted(
        [none_deadline, later, soon],
        key=lambda t: sort_key(SchedulingPolicy.WEIGHTED_EDF, t),
    )
    assert [t.task_id for t in keys] == ["soon", "later", "none"]


def test_sort_key_fifo_orders_by_enqueued_at():
    now = utcnow()
    first = _task(task_id="first", enqueued_at=now - timedelta(seconds=10))
    second = _task(task_id="second", enqueued_at=now)
    ordered = sorted([second, first], key=lambda t: sort_key(SchedulingPolicy.FIFO, t))
    assert [t.task_id for t in ordered] == ["first", "second"]
