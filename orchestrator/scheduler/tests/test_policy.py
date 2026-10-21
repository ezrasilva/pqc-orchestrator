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
from criticality import ordem_de_prioridade
from scheduler.policy import AGING_RATE_PER_SECOND, SLICE_BONUS, compute_risk, sort_key


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


def test_slice_bonus_segue_o_vetor_de_criticidade():
    """A ordem é URLLC > mIoT > eMBB, derivada do vetor I > H > D.

    **Invertido em 21/10.** A versão anterior afirmava
    URLLC > eMBB > mIoT, herdado de um documento anterior ao vetor de
    criticidade. eMBB e mIoT empatam em I (média) e o desempate é H: a
    mIoT tem H alta (telemetria com horizonte de confidencialidade
    longo, mais exposta a harvest-now-decrypt-later) contra H baixa da
    eMBB. A divergência apareceu nos dados da Fase B — no C3 a eMBB
    levou 464 chaves de QKD contra 336 da mIoT, o inverso do previsto.

    O teste compara contra `ordem_de_prioridade()` em vez de fixar a
    sequência: se os níveis mudarem no documento, o teste acompanha em
    vez de virar uma segunda fonte de verdade divergente.
    """
    now = utcnow()
    riscos = [compute_risk(_task(slice=SliceType(nome)), now=now)
              for nome in ordem_de_prioridade()]
    assert riscos == sorted(riscos, reverse=True), (
        f"risco deveria cair na ordem {ordem_de_prioridade()}, veio {riscos}")
    assert len(set(riscos)) == len(riscos), "fatias distintas não devem empatar"


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
    # Só slice_bonus(EMBB) + interface_bonus(F1)=0 + aging=0. O valor
    # vem da tabela derivada, não de uma constante repetida aqui — foi
    # repetir o número que fez este teste quebrar quando a ordem mudou.
    assert risk == SLICE_BONUS[SliceType.EMBB]


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
