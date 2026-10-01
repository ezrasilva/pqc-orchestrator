"""Tipos de domínio do KMS.

Deliberadamente independentes dos stubs gerados a partir de kms.proto —
o item 2 da ordem de construção (ver ../docs/ARQUITETURA-ORQUESTRADOR.md) pede o
KMS "isolado e testável... sem nenhuma dependência de rede real ainda". A
tradução pra/de mensagens protobuf (SliceType etc.) fica pra quando o
servidor gRPC for ligado por cima disso (item 5, SMO amarrando os quatro).
"""

from __future__ import annotations

import enum
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Optional


class SliceType(enum.Enum):
    URLLC = "URLLC"
    EMBB = "EMBB"
    MIOT = "MIOT"


class InterfaceType(enum.Enum):
    """Desde a Fase 3/4 do protótipo SBRC, N2 (controle) e N3 (dado de
    usuário, por fatia) são conexões IPsec distintas — N2N3 combinado não
    existe mais no laboratório real (ver ipsec_agent/models.py). N2 não é
    diferenciado por fatia (é controle, compartilhado); N3 é a única
    interface onde SliceType realmente seleciona uma SA diferente."""

    F1 = "F1"
    N2 = "N2"
    N3 = "N3"
    FRONTHAUL = "FRONTHAUL"  # reservado — nenhum código ativo usa isto ainda


class KeyState(enum.Enum):
    PENDING = "PENDING"
    ACTIVE = "ACTIVE"
    RENEWING = "RENEWING"
    REVOKED = "REVOKED"
    QUARANTINED = "QUARANTINED"
    ZEROIZED = "ZEROIZED"
    FAILED = "FAILED"


# Transições válidas de estado. Qualquer transição fora deste mapa é
# rejeitada por InvalidTransitionError (ver kms/exceptions.py) — inclui
# propositalmente a possibilidade de ir de QUARANTINED ou FAILED direto pra
# ZEROIZED (não força passar por REVOKED antes, já que "descartar de vez"
# faz sentido a partir de qualquer estado não-terminal).
VALID_TRANSITIONS: dict[KeyState, frozenset[KeyState]] = {
    KeyState.PENDING: frozenset({KeyState.ACTIVE, KeyState.FAILED, KeyState.ZEROIZED}),
    KeyState.ACTIVE: frozenset({KeyState.RENEWING, KeyState.REVOKED, KeyState.QUARANTINED}),
    KeyState.RENEWING: frozenset({KeyState.REVOKED, KeyState.QUARANTINED, KeyState.ACTIVE}),
    KeyState.QUARANTINED: frozenset({KeyState.ACTIVE, KeyState.ZEROIZED}),
    KeyState.REVOKED: frozenset({KeyState.ZEROIZED}),
    KeyState.FAILED: frozenset({KeyState.ZEROIZED}),
    KeyState.ZEROIZED: frozenset(),  # terminal
}

# Estados em que a chave está genuinamente protegendo o túnel agora —
# GetActiveKey considera os dois (RENEWING é "ainda em uso, mas já marcada
# pra troca em breve").
LIVE_STATES: frozenset[KeyState] = frozenset({KeyState.ACTIVE, KeyState.RENEWING})


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


@dataclass
class KeyMaterial:
    """Material completo, incluindo o(s) segredo(s) — só existe em memória
    entre a geração e a entrega ao IPsec Agent; nunca é serializado em
    logs. `ppk` só é preenchido pra URLLC (ver kms/crypto.py pro porquê de
    ser um campo separado do `psk`)."""

    key_id: str
    slice: SliceType
    interface: InterfaceType
    psk: bytes
    kem_algorithm: str
    has_quantum_component: bool
    generated_at: datetime
    ppk: Optional[bytes] = None


@dataclass
class KeyStateInfo:
    """Snapshot sem o material — é o que persiste indefinidamente pra
    auditoria, mesmo depois da chave ser zeroizada (psk desaparece, o
    registro de que ela existiu e por quais estados passou não)."""

    key_id: str
    slice: SliceType
    interface: InterfaceType
    kem_algorithm: str
    has_quantum_component: bool
    state: KeyState
    created_at: datetime
    updated_at: datetime
    reason: str
