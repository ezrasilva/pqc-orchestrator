"""SmoCore — amarra KMS + Scheduler + IPsec Agent (item 5 da ordem de
construção). Mesmo padrão dos outros três: núcleo Python isolado,
testável com fakes, sem gRPC ainda (a Admin API foi deliberadamente
deixada de fora desta fase — ver docs/ARQUITETURA-ORQUESTRADOR.md: pro
objetivo do artigo, o valor de pesquisa está na coordenação SMO/KMS/
Scheduler/IPsec Agent com rotação por risco, não numa fronteira
administrativa externa).

Não guarda lógica de política nem de kernel (ver seção 1 da arquitetura)
— só coordena: pede a próxima tarefa ao Scheduler, pede material novo ao
KMS, manda o IPsec Agent aplicar, atualiza o estado no KMS conforme o
resultado, registra no audit log.

**Resolução de conexão** (slice, interface) -> ConnectionName do IPsec
Agent — não está na arquitetura original com esse nível de detalhe
(decisão desta implementação, documentada aqui): F1 não é diferenciado
por fatia (sempre F1_CU_DU, slice ignorado); N2 também não (sempre
N2_CU_EDGE, é controle compartilhado, sem perfil PQC por fatia); só N3
realmente seleciona uma conexão diferente por fatia (ver
ipsec_agent/config.py pros endereços reais de cada uma, Fase 3/4 do
protótipo)."""

from __future__ import annotations

import threading
from typing import Optional

from ipsec_agent.agent import IpsecAgentCore
from ipsec_agent.models import ConnectionName
from kms.models import InterfaceType, SliceType
from kms.service import KeyManagementCore
from scheduler.models import EnqueueTaskRequest, SchedulingPolicy
from scheduler.models import InterfaceType as SchedulerInterfaceType
from scheduler.models import SliceType as SchedulerSliceType
from scheduler.models import Task, TaskPriority, TaskType
from scheduler.service import SchedulerCore
from smo.exceptions import UnsupportedConnectionError
from smo.models import AuditEvent, ProcessTaskResult, SystemStatus, TunnelSummary, new_event_id, utcnow

_CONNECTION_BY_SLICE_N3: dict[SliceType, ConnectionName] = {
    SliceType.URLLC: ConnectionName.N3_URLLC_CU_EDGE,
    SliceType.EMBB: ConnectionName.N3_EMBB_CU_EDGE,
    SliceType.MIOT: ConnectionName.N3_MIOT_CU_EDGE,
}


def resolve_connection(slice: SliceType, interface: InterfaceType) -> ConnectionName:
    if interface is InterfaceType.F1:
        return ConnectionName.F1_CU_DU
    if interface is InterfaceType.N2:
        return ConnectionName.N2_CU_EDGE
    if interface is InterfaceType.N3:
        try:
            return _CONNECTION_BY_SLICE_N3[slice]
        except KeyError:
            raise UnsupportedConnectionError(slice, interface) from None
    raise UnsupportedConnectionError(slice, interface)


def _to_scheduler_slice(s: SliceType) -> SchedulerSliceType:
    return SchedulerSliceType(s.value)


def _to_scheduler_interface(i: InterfaceType) -> SchedulerInterfaceType:
    return SchedulerInterfaceType(i.value)


def _from_scheduler_slice(s: SchedulerSliceType) -> SliceType:
    return SliceType(s.value)


def _from_scheduler_interface(i: SchedulerInterfaceType) -> InterfaceType:
    return InterfaceType(i.value)


class SmoCore:
    def __init__(
        self,
        kms: KeyManagementCore,
        scheduler: SchedulerCore,
        ipsec_agent: IpsecAgentCore,
    ):
        self._kms = kms
        self._scheduler = scheduler
        self._ipsec_agent = ipsec_agent
        self._audit_lock = threading.Lock()
        self._audit_log: list[AuditEvent] = []

    def _audit(
        self,
        event_type: str,
        *,
        slice: Optional[SliceType],
        interface: Optional[InterfaceType],
        key_id: str,
        actor: str,
        detail: str,
        success: bool,
    ) -> None:
        event = AuditEvent(
            event_id=new_event_id(),
            timestamp=utcnow(),
            event_type=event_type,
            slice=slice,
            interface=interface,
            key_id=key_id,
            actor=actor,
            detail=detail,
            success=success,
        )
        with self._audit_lock:
            self._audit_log.append(event)

    def _process_task(self, task: Task, actor: str) -> ProcessTaskResult:
        slice = _from_scheduler_slice(task.slice)
        interface = _from_scheduler_interface(task.interface)

        try:
            connection = resolve_connection(slice, interface)
        except UnsupportedConnectionError as exc:
            self._audit(
                "apply_failed", slice=slice, interface=interface, key_id="",
                actor=actor, detail=str(exc), success=False,
            )
            return ProcessTaskResult(
                task_found=True, success=False, task_id=task.task_id,
                slice=slice, interface=interface, error_message=str(exc),
            )

        old_active = self._kms.get_active_key(slice, interface)
        if old_active is not None:
            self._kms.mark_renewing(old_active.key_id, f"substituída pela task {task.task_id}")

        material = self._kms.generate(slice, interface, reason=task.reason or f"task {task.task_id}")

        apply_result = self._ipsec_agent.apply_key_material(
            connection, material.key_id, material.psk, ppk=material.ppk
        )

        if apply_result.success:
            self._kms.activate(material.key_id, reason="aplicado com sucesso pelo IPsec Agent")
            if old_active is not None:
                self._kms.revoke(old_active.key_id, reason="substituída por rotação bem-sucedida")
            self._audit(
                task.task_type.value.lower(), slice=slice, interface=interface,
                key_id=material.key_id, actor=actor,
                detail=f"conexão={connection.value} task={task.task_id}", success=True,
            )
            return ProcessTaskResult(
                task_found=True, success=True, task_id=task.task_id,
                key_id=material.key_id, slice=slice, interface=interface,
            )

        self._kms.mark_failed(material.key_id, reason=apply_result.error_message)
        if old_active is not None:
            # a conexão pode ter ficado num estado incerto — quarentena
            # sinaliza "precisa de atenção humana", não revoga sozinho
            # (ver kms/models.py VALID_TRANSITIONS).
            self._kms.quarantine(old_active.key_id, reason=f"rotação falhou: {apply_result.error_message}")
        self._audit(
            "apply_failed", slice=slice, interface=interface, key_id=material.key_id,
            actor=actor, detail=f"conexão={connection.value} task={task.task_id}", success=False,
        )
        return ProcessTaskResult(
            task_found=True, success=False, task_id=task.task_id, key_id=material.key_id,
            slice=slice, interface=interface, error_message=apply_result.error_message,
        )

    def process_next_task(self) -> ProcessTaskResult:
        task = self._scheduler.get_next_task()
        if task is None:
            return ProcessTaskResult(task_found=False, success=False)
        return self._process_task(task, actor="scheduler")

    def force_rotate(self, slice: SliceType, interface: InterfaceType, reason: str) -> ProcessTaskResult:
        """Sempre EMERGENCY — nunca despriorizada por acidente (ver
        scheduler.proto). Processa imediatamente: num sistema síncrono
        como este protótipo, não há motivo pra enfileirar e não
        consumir; numa fila concorrente de verdade, outra EMERGENCY já
        enfileirada poderia sair primeiro — comportamento correto do
        scheduler, não um bug desta chamada."""
        self._scheduler.enqueue_task(
            EnqueueTaskRequest(
                slice=_to_scheduler_slice(slice),
                interface=_to_scheduler_interface(interface),
                task_type=TaskType.ROTATE,
                priority=TaskPriority.EMERGENCY,
                slack_seconds=0.0,
                estimated_cost_seconds=1.0,
                reason=reason,
            )
        )
        return self.process_next_task()

    def revoke_key(self, key_id: str, reason: str):
        info = self._kms.revoke(key_id, reason)
        self._audit(
            "revoke", slice=info.slice, interface=info.interface, key_id=key_id,
            actor="admin", detail=reason, success=True,
        )
        return info

    def quarantine_key(self, key_id: str, reason: str):
        info = self._kms.quarantine(key_id, reason)
        self._audit(
            "quarantine", slice=info.slice, interface=info.interface, key_id=key_id,
            actor="admin", detail=reason, success=True,
        )
        return info

    def release_quarantine(self, key_id: str, reason: str = "released"):
        info = self._kms.release_quarantine(key_id, reason)
        self._audit(
            "release", slice=info.slice, interface=info.interface, key_id=key_id,
            actor="admin", detail=reason, success=True,
        )
        return info

    def set_scheduling_policy(self, policy: SchedulingPolicy) -> None:
        self._scheduler.set_policy(policy)

    def get_system_status(self) -> SystemStatus:
        tunnels = [
            TunnelSummary(
                connection_name=status.connection.value,
                state=status.state.value,
                current_key_id=status.current_key_id,
            )
            for status in self._ipsec_agent.list_connections()
        ]
        # F1/N2 não são diferenciados por fatia de verdade, mas o KMS
        # chaveia por (slice, interface) sempre — então uma chave de F1/N2
        # só aparece sob o slice exato que foi passado quando ela foi
        # gerada (qualquer um, já que não importa pra essas duas
        # interfaces). Varrer as 3 fatias pra cada interface é o jeito
        # correto de não perder nenhuma, mesmo que pareça redundante pra
        # F1/N2.
        active_keys = []
        for slice in SliceType:
            for interface in (InterfaceType.F1, InterfaceType.N2, InterfaceType.N3):
                key = self._kms.get_active_key(slice, interface)
                if key is not None:
                    active_keys.append(key)
        return SystemStatus(
            tunnels=tunnels,
            active_keys=active_keys,
            queue_depth=self._scheduler.queue_size(),
            scheduling_policy=self._scheduler.get_policy().value,
            checked_at=utcnow(),
        )

    def list_audit_log(
        self,
        slice: Optional[SliceType] = None,
        interface: Optional[InterfaceType] = None,
        limit: int = 100,
    ) -> list[AuditEvent]:
        with self._audit_lock:
            events = list(self._audit_log)
        if slice is not None:
            events = [e for e in events if e.slice == slice]
        if interface is not None:
            events = [e for e in events if e.interface == interface]
        return events[-limit:] if limit > 0 else events
