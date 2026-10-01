"""Lógica de ciclo de vida do KMS — a peça "isolada e testável" do item 2
da ordem de construção. Sem gRPC, sem rede: uma classe Python que combina
kms/crypto.py (geração) com kms/store.py (persistência) e valida as
transições de estado definidas em kms/models.py.

O servidor gRPC (KeyManagementService, de kms.proto) é uma casca fina por
cima disto, a ser escrita quando o SMO amarrar os componentes (item 5) —
não existe ainda de propósito.
"""

from __future__ import annotations

import threading
import uuid
from typing import Optional

from kms.crypto import generate_hybrid_material
from kms.exceptions import InvalidTransitionError
from kms.models import (
    VALID_TRANSITIONS,
    InterfaceType,
    KeyMaterial,
    KeyState,
    KeyStateInfo,
    SliceType,
    utcnow,
)
from kms.store import KeyStore


def _new_key_id() -> str:
    return f"key-{uuid.uuid4().hex[:12]}"


class KeyManagementCore:
    """Um lock global simples é suficiente aqui — o volume de operações do
    KMS (rotação de chave, não tráfego de dados) nunca vai ser alto o
    bastante pra um lock por chave valer a complexidade extra."""

    def __init__(self, store: KeyStore):
        self._store = store
        self._lock = threading.Lock()

    def close(self) -> None:
        self._store.close()

    def generate(
        self, slice: SliceType, interface: InterfaceType, reason: str = "scheduled"
    ) -> KeyMaterial:
        """Gera material novo e registra em PENDING. Não mexe em nenhuma
        chave existente pra essa fatia/interface — quem decide o que fazer
        com a chave ACTIVE anterior (marcar RENEWING, revogar depois que
        esta for ativada) é o chamador (SMO), via os métodos de transição
        abaixo."""
        material = generate_hybrid_material(slice)
        key_id = _new_key_id()
        with self._lock:
            self._store.insert(
                key_id=key_id,
                slice=slice,
                interface=interface,
                kem_algorithm=material.kem_algorithm,
                has_quantum_component=material.has_quantum_component,
                psk=material.psk,
                ppk=material.ppk,
                state=KeyState.PENDING,
                reason=reason,
            )
        return KeyMaterial(
            key_id=key_id,
            slice=slice,
            interface=interface,
            psk=material.psk,
            kem_algorithm=material.kem_algorithm,
            has_quantum_component=material.has_quantum_component,
            generated_at=utcnow(),
            ppk=material.ppk,
        )

    def _transition(self, key_id: str, to_state: KeyState, reason: str) -> KeyStateInfo:
        with self._lock:
            current = self._store.get(key_id)
            if to_state not in VALID_TRANSITIONS[current.state]:
                raise InvalidTransitionError(key_id, current.state, to_state)
            updated = self._store.update_state(key_id, to_state, reason)
            if to_state is KeyState.ZEROIZED:
                self._store.wipe_secret(key_id)
            return updated

    def activate(self, key_id: str, reason: str = "applied") -> KeyStateInfo:
        return self._transition(key_id, KeyState.ACTIVE, reason)

    def mark_renewing(self, key_id: str, reason: str = "replacement generated") -> KeyStateInfo:
        return self._transition(key_id, KeyState.RENEWING, reason)

    def revoke(self, key_id: str, reason: str) -> KeyStateInfo:
        return self._transition(key_id, KeyState.REVOKED, reason)

    def quarantine(self, key_id: str, reason: str) -> KeyStateInfo:
        return self._transition(key_id, KeyState.QUARANTINED, reason)

    def release_quarantine(self, key_id: str, reason: str = "released") -> KeyStateInfo:
        return self._transition(key_id, KeyState.ACTIVE, reason)

    def mark_failed(self, key_id: str, reason: str) -> KeyStateInfo:
        return self._transition(key_id, KeyState.FAILED, reason)

    def zeroize(self, key_id: str, reason: str = "zeroized") -> KeyStateInfo:
        return self._transition(key_id, KeyState.ZEROIZED, reason)

    def get_state(self, key_id: str) -> KeyStateInfo:
        return self._store.get(key_id)

    def get_psk(self, key_id: str) -> bytes:
        """Só pra quem realmente precisa do segredo (o caminho que envia
        pro IPsec Agent) — não confundir com get_state, que nunca inclui
        o material."""
        return self._store.get_psk(key_id)

    def get_ppk(self, key_id: str) -> Optional[bytes]:
        """None pra toda fatia exceto URLLC — ver kms/crypto.py."""
        return self._store.get_ppk(key_id)

    def get_active_key(
        self, slice: SliceType, interface: InterfaceType
    ) -> Optional[KeyStateInfo]:
        return self._store.get_active(slice, interface)

    def list_history(
        self,
        slice: Optional[SliceType] = None,
        interface: Optional[InterfaceType] = None,
        limit: int = 100,
        before: Optional[str] = None,
    ) -> list[KeyStateInfo]:
        return self._store.list_history(slice, interface, limit, before)
