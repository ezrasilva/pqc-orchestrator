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


def test_todas_as_fatias_recebem_ppk(smo, scheduler_core, fake_ipsec_agent):
    """Invertido em 16/10. A versão anterior afirmava que fatia
    não-URLLC NÃO recebia PPK, o que era verdade quando só a urllc tinha
    `ppk_id`. A seção de arquitetura de chaves da campanha é explícita:
    dois níveis de rotação POR FATIA, com Tr_ppk próprio cada, e o
    modelo de consumo soma sobre as fatias. As três passaram a ter
    `ppk_id`/`ppk_required = yes` (ver
    lab/ipsec/swanctl-*/conf.d/connections.conf), e as três sobem
    negociando `/PPK` — confirmado ao vivo."""
    _enqueue(scheduler_core, slice=SchedSliceType.EMBB)
    smo.process_next_task()
    _, _, ppk = fake_ipsec_agent.reauth_calls[0]
    assert ppk is not None and len(ppk) == 32


def test_process_next_task_failure_marks_failed_and_quarantines_old(smo, scheduler_core, kms_core, ppk_provider):
    failing_agent = FakeIpsecAgent(fail_connections=frozenset({ConnectionName.N3_URLLC_CU_EDGE}))
    from smo.service import SmoCore

    smo_with_failure = SmoCore(kms_core, scheduler_core, failing_agent, ppk_provider)

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


# --- os dois níveis de rotação -----------------------------------------
# A separação existe porque a Fase A mediu três ordens de grandeza entre
# eles: rekey de Child SA sem perda de pacote, reauth de ~1,8 a 163 ms.

def _enfileira_tipo(scheduler_core, task_type, slice=SchedSliceType.URLLC):
    from scheduler.models import EnqueueTaskRequest, InterfaceType, TaskPriority
    scheduler_core.enqueue_task(
        EnqueueTaskRequest(
            slice=slice, interface=InterfaceType.N3, task_type=task_type,
            priority=TaskPriority.NORMAL, slack_seconds=-1.0,
            estimated_cost_seconds=0.01, reason="teste",
        )
    )


def test_rekey_child_nao_consome_chave_de_qkd(smo, scheduler_core, fake_ipsec_agent,
                                              ppk_provider):
    """O caminho barato não passa pelo KMS: não há segredo novo para
    provisionar, e gastar uma chave de QKD a cada Tr_child era
    exatamente o defeito da versão com um único TaskType.ROTATE."""
    from scheduler.models import TaskType
    antes = ppk_provider.depth(SliceType.URLLC)
    _enfileira_tipo(scheduler_core, TaskType.REKEY_CHILD)
    r = smo.process_next_task()
    assert r.success
    assert fake_ipsec_agent.rekey_child_calls, "deveria ter chamado rekey_child"
    assert not fake_ipsec_agent.reauth_calls, "não deveria reautenticar"
    assert ppk_provider.depth(SliceType.URLLC) == antes, "não deveria gastar QKD"
    # Sem chave nova, não há key_id para reportar.
    assert r.key_id == ""


def test_reauth_ppk_consome_chave_de_qkd(smo, scheduler_core, fake_ipsec_agent,
                                         ppk_provider):
    from scheduler.models import TaskType
    antes = ppk_provider.depth(SliceType.URLLC)
    _enfileira_tipo(scheduler_core, TaskType.REAUTH_PPK)
    r = smo.process_next_task()
    assert r.success
    assert fake_ipsec_agent.reauth_calls, "deveria ter reautenticado"
    assert not fake_ipsec_agent.rekey_child_calls
    assert ppk_provider.depth(SliceType.URLLC) == antes - 1, "deveria gastar uma chave"
    assert r.key_id


def test_reauth_sem_qkd_adia_em_vez_de_degradar(smo_sem_qkd, scheduler_core):
    """Poço vazio adia a rotação. Degradar para "rotaciona sem PPK" não
    é opção: com `ppk_required = yes` nas três fatias o charon não
    negocia isso."""
    from scheduler.models import TaskType
    _enfileira_tipo(scheduler_core, TaskType.REAUTH_PPK)
    r = smo_sem_qkd.process_next_task()
    assert r.task_found and not r.success
    assert "escassez de QKD" in r.error_message
