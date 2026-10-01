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
    """Desde a Fase 3/4 do protótipo SBRC (ver
    docs/ARQUITETURA-PROTOTIPO-COMPLETA.md seção 5), a antiga
    N2N3_CU_EDGE não existe mais como uma conexão só — virou N2_CU_EDGE
    (controle, não diferenciado por fatia) e três N3_<fatia>_CU_EDGE
    (dado de usuário, uma por fatia, cada uma com perfil PQC próprio e a
    URLLC com PPK real). Atualizado aqui pra bater com o laboratório de
    verdade, não com o desenho original de 2 conexões."""

    F1_CU_DU = "f1-cu-du"
    N2_CU_EDGE = "n2-cu-edge"
    N3_URLLC_CU_EDGE = "n3-urllc-cu-edge"
    N3_EMBB_CU_EDGE = "n3-embb-cu-edge"
    N3_MIOT_CU_EDGE = "n3-miot-cu-edge"


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
