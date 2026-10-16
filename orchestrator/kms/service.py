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

from kms.crypto import fetch_ppk
from kms.qkd import PpkProvider
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

    def provision_ppk(
        self, slice: SliceType, interface: InterfaceType, provider: PpkProvider,
        reason: str = "scheduled"
    ) -> Optional[KeyMaterial]:
        """Tira do poço a próxima chave de QKD da fatia e registra em
        PENDING. Não mexe em nenhuma chave existente — quem decide o que
        fazer com a ACTIVE anterior é o chamador (SMO), pelos métodos de
        transição abaixo.

        **Substitui o antigo `generate()`**, que gerava PSK derivado de um
        ML-KEM executado dentro do KMS. Ver `kms/crypto.py` para por que
        o ML-KEM local saiu (o IKE já negocia ML-KEM a cada rekey) e por
        que o PSK saiu da rotação (é fixo, só autentica).

        **O `key_id` vem da QKDN, não é cunhado aqui.** Isso é essencial e
        não é detalhe de implementação: na ETSI GS QKD 014 é pelo
        `key_ID` que a outra ponta chama `dec_keys` e obtém a MESMA
        chave, sem que a chave trafegue. Cunhar um id local quebraria a
        distribuição — as duas pontas carregariam PPKs diferentes e a
        autenticação falharia com `ppk_required = yes`.

        Devolve `None` quando o poço está vazio. Não é erro: é escassez
        de QKD, um dos fenômenos que a campanha mede (`Σ k / Tr_ppk,i ≤
        R_qkd`). O evento já fica registrado por `fetch_ppk`.
        """
        material = fetch_ppk(slice, provider)
        if material is None:
            return None

        with self._lock:
            self._store.insert(
                key_id=material.key_id,
                slice=slice,
                interface=interface,
                key_source=f"QKD/BB84+Cascade via ETSI 014 ({material.source})",
                has_quantum_component=True,
                # O PSK é fixo e vive no secrets.conf do laboratório;
                # o KMS não o gera nem o rotaciona mais.
                psk=b"",
                ppk=material.ppk,
                state=KeyState.PENDING,
                reason=reason,
            )
        return KeyMaterial(
            key_id=material.key_id,
            slice=slice,
            interface=interface,
            psk=b"",
            key_source=f"QKD/BB84+Cascade via ETSI 014 ({material.source})",
            has_quantum_component=True,
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
