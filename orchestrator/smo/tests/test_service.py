import pytest

from ipsec_agent.models import ConnectionName
from kms.models import InterfaceType, KeyState, SliceType
from scheduler.models import EnqueueTaskRequest
from scheduler.models import InterfaceType as SchedInterfaceType
from scheduler.models import SliceType as SchedSliceType
from scheduler.models import TaskPriority, TaskType
from smo.exceptions import UnsupportedConnectionError
from smo.service import resolve_connection

from .fakes import FakeIpsecAgent


def test_resolve_connection_f1_ignores_slice():
    for slice in SliceType:
        assert resolve_connection(slice, InterfaceType.F1) is ConnectionName.F1_CU_DU


def test_resolve_connection_n2_ignores_slice():
    for slice in SliceType:
        assert resolve_connection(slice, InterfaceType.N2) is ConnectionName.N2_CU_EDGE


def test_resolve_connection_n3_depends_on_slice():
    assert resolve_connection(SliceType.URLLC, InterfaceType.N3) is ConnectionName.N3_URLLC_CU_EDGE
    assert resolve_connection(SliceType.EMBB, InterfaceType.N3) is ConnectionName.N3_EMBB_CU_EDGE
    assert resolve_connection(SliceType.MIOT, InterfaceType.N3) is ConnectionName.N3_MIOT_CU_EDGE


def test_resolve_connection_fronthaul_unsupported():
    with pytest.raises(UnsupportedConnectionError):
        resolve_connection(SliceType.URLLC, InterfaceType.FRONTHAUL)


def _enqueue(scheduler_core, slice=SchedSliceType.URLLC, interface=SchedInterfaceType.N3):
    return scheduler_core.enqueue_task(
        EnqueueTaskRequest(
            slice=slice,
            interface=interface,
            task_type=TaskType.ROTATE,
            priority=TaskPriority.NORMAL,
            slack_seconds=0.0,
            estimated_cost_seconds=1.0,
            reason="teste",
        )
    )


def test_process_next_task_empty_queue(smo):
    result = smo.process_next_task()
    assert result.task_found is False


def test_process_next_task_success_activates_key_and_applies(smo, scheduler_core, fake_ipsec_agent, kms_core):
    _enqueue(scheduler_core)
    result = smo.process_next_task()

    assert result.task_found is True
    assert result.success is True
    assert result.key_id

    # a chave tem que estar ACTIVE no KMS depois do sucesso
    assert kms_core.get_state(result.key_id).state is KeyState.ACTIVE
    # e o IPsec Agent (fake) tem que ter recebido a chamada certa
    assert len(fake_ipsec_agent.applied_calls) == 1
    conn, key_id, psk, ppk = fake_ipsec_agent.applied_calls[0]
    assert conn is ConnectionName.N3_URLLC_CU_EDGE
    assert key_id == result.key_id
    assert ppk is not None  # URLLC sempre carrega ppk


def test_process_next_task_non_urllc_has_no_ppk(smo, scheduler_core, fake_ipsec_agent):
    _enqueue(scheduler_core, slice=SchedSliceType.EMBB)
    smo.process_next_task()
    _, _, _, ppk = fake_ipsec_agent.applied_calls[0]
    assert ppk is None


def test_process_next_task_failure_marks_failed_and_quarantines_old(smo, scheduler_core, kms_core):
    failing_agent = FakeIpsecAgent(fail_connections=frozenset({ConnectionName.N3_URLLC_CU_EDGE}))
    from smo.service import SmoCore

    smo_with_failure = SmoCore(kms_core, scheduler_core, failing_agent)

    # primeira rotação: sucesso simulado via agente que não falha pra
    # estabelecer uma chave ACTIVE antes de testar a falha
    _enqueue(scheduler_core)
    first_key_id = smo.process_next_task().key_id
    assert kms_core.get_state(first_key_id).state is KeyState.ACTIVE

    _enqueue(scheduler_core)
    result = smo_with_failure.process_next_task()

    assert result.success is False
    assert result.error_message == "falha simulada"
    assert kms_core.get_state(result.key_id).state is KeyState.FAILED
    assert kms_core.get_state(first_key_id).state is KeyState.QUARANTINED


def test_process_next_task_unsupported_connection_does_not_touch_kms(smo, scheduler_core, kms_core):
    _enqueue(scheduler_core, interface=SchedInterfaceType.FRONTHAUL)
    result = smo.process_next_task()
    assert result.success is False
    assert "sem conexão" in result.error_message


def test_force_rotate_enqueues_as_emergency_and_processes_immediately(smo, fake_ipsec_agent):
    result = smo.force_rotate(SliceType.MIOT, InterfaceType.N3, reason="forçado pelo teste")
    assert result.task_found is True
    assert result.success is True
    conn = fake_ipsec_agent.applied_calls[0][0]
    assert conn is ConnectionName.N3_MIOT_CU_EDGE


def test_revoke_key(smo, scheduler_core, kms_core):
    _enqueue(scheduler_core)
    key_id = smo.process_next_task().key_id
    info = smo.revoke_key(key_id, "teste de revogação")
    assert info.state is KeyState.REVOKED


def test_quarantine_and_release(smo, scheduler_core, kms_core):
    _enqueue(scheduler_core)
    key_id = smo.process_next_task().key_id
    quarantined = smo.quarantine_key(key_id, "suspeita")
    assert quarantined.state is KeyState.QUARANTINED
    released = smo.release_quarantine(key_id)
    assert released.state is KeyState.ACTIVE


def test_get_system_status_reflects_queue_and_tunnels(smo, scheduler_core):
    _enqueue(scheduler_core)
    _enqueue(scheduler_core, slice=SchedSliceType.EMBB)
    status = smo.get_system_status()
    assert status.queue_depth == 2
    assert len(status.tunnels) == len(ConnectionName)


def test_audit_log_records_successful_rotation(smo, scheduler_core):
    _enqueue(scheduler_core)
    smo.process_next_task()
    events = smo.list_audit_log()
    assert len(events) == 1
    assert events[0].event_type == "rotate"
    assert events[0].success is True


def test_audit_log_filters_by_slice(smo, scheduler_core):
    _enqueue(scheduler_core, slice=SchedSliceType.URLLC)
    smo.process_next_task()
    _enqueue(scheduler_core, slice=SchedSliceType.EMBB)
    smo.process_next_task()

    urllc_events = smo.list_audit_log(slice=SliceType.URLLC)
    assert len(urllc_events) == 1
    assert urllc_events[0].slice is SliceType.URLLC
