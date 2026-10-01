"""Tipos de domínio do SMO. Mesmo padrão dos outros três componentes
(ver kms/models.py): independentes dos stubs gerados a partir de
smo.proto, isolado e testável sem gRPC.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Optional

from kms.models import InterfaceType, SliceType


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


def new_event_id() -> str:
    return f"evt-{uuid.uuid4().hex[:12]}"


@dataclass
class ProcessTaskResult:
    task_found: bool
    success: bool
    task_id: str = ""
    key_id: str = ""
    slice: Optional[SliceType] = None
    interface: Optional[InterfaceType] = None
    error_message: str = ""


@dataclass
class AuditEvent:
    """Nunca inclui o material de chave em si, só `key_id` — mesma regra
    do `KeyStateInfo` do KMS. `actor` distingue ações automáticas
    ("scheduler", "smo") de administrativas ("admin:<quem>")."""

    event_id: str
    timestamp: datetime
    event_type: str
    slice: Optional[SliceType]
    interface: Optional[InterfaceType]
    key_id: str
    actor: str
    detail: str
    success: bool


@dataclass
class TunnelSummary:
    connection_name: str
    state: str
    current_key_id: Optional[str]


@dataclass
class SystemStatus:
    tunnels: list[TunnelSummary]
    active_keys: list  # list[kms.models.KeyStateInfo]
    queue_depth: int
    scheduling_policy: str
    checked_at: datetime
