"""Tipos de domínio do IPsec Agent — independentes dos stubs gerados a
partir de ipsec_agent.proto, mesmo padrão do `kms/models.py` (ver aquele
módulo pra justificativa).
"""

from __future__ import annotations

import enum
from dataclasses import dataclass
from datetime import datetime
from typing import Optional


class ConnectionName(enum.Enum):
    F1_CU_DU = "f1-cu-du"
    N2N3_CU_EDGE = "n2n3-cu-edge"


class ConnectionState(enum.Enum):
    DOWN = "DOWN"
    CONNECTING = "CONNECTING"
    ESTABLISHED = "ESTABLISHED"


@dataclass
class ConnectionStatus:
    connection: ConnectionName
    state: ConnectionState
    local_id: str
    remote_id: str
    established_since: Optional[datetime]
    current_key_id: Optional[str]


@dataclass
class ApplyResult:
    success: bool
    error_message: str
    applied_at: Optional[datetime]
