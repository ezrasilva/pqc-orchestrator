"""Integração ponta a ponta contra o laboratório real: Scheduler enfileira
-> SMO consulta -> KMS gera material de verdade (ML-KEM real via liboqs)
-> IPsec Agent aplica via VICI de verdade -> SA reestabelece. É o
"item 5 amarrando os quatro" descrito na arquitetura, testado contra o
ambiente real, não um fake — mesmo padrão rigoroso usado em
ipsec_agent/tests/test_agent.py e scheduler/live_demo.py."""

from kms.models import InterfaceType, KeyState, SliceType

from scheduler.models import EnqueueTaskRequest
from scheduler.models import InterfaceType as SchedInterfaceType
from scheduler.models import SliceType as SchedSliceType
from scheduler.models import TaskPriority, TaskType

from .conftest import requires_live_lab


@requires_live_lab
def test_process_next_task_rotates_real_urllc_connection_with_ppk(live_smo, scheduler_core, kms_core):
    scheduler_core.enqueue_task(
        EnqueueTaskRequest(
            slice=SchedSliceType.URLLC,
            interface=SchedInterfaceType.N3,
            task_type=TaskType.ROTATE,
            priority=TaskPriority.NORMAL,
            slack_seconds=0.0,
            estimated_cost_seconds=1.0,
            reason="teste de integração real",
        )
    )

    result = live_smo.process_next_task()

    assert result.success, result.error_message
    assert kms_core.get_state(result.key_id).state is KeyState.ACTIVE
    # URLLC é a única fatia com ppk — confirma que o KMS gerou e que o
    # IPsec Agent recebeu (a prova de que o charon realmente usou vem do
    # mesmo sinal já validado na Fase 4: swanctl --list-sas mostra "ppk:
    # yes"; aqui confirmamos só que o material existe e foi marcado
    # ACTIVE, o resto já tem teste dedicado em ipsec_agent/tests).
    assert kms_core.get_ppk(result.key_id) is not None


@requires_live_lab
def test_force_rotate_real_embb_connection(live_smo):
    result = live_smo.force_rotate(SliceType.EMBB, InterfaceType.N3, reason="forçado — teste de integração")
    assert result.success, result.error_message


@requires_live_lab
def test_get_system_status_reports_all_five_tunnels_established(live_smo):
    status = live_smo.get_system_status()
    assert len(status.tunnels) == 5
    assert all(t.state == "ESTABLISHED" for t in status.tunnels)
