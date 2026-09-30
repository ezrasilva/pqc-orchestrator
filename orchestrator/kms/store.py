"""Persistência SQLite do KMS.

Duas tabelas: `keys` (metadados + estado, nunca apagada — é o audit trail)
e `key_secrets` (só o PSK, numa tabela separada e apagada linha a linha na
zeroização — separar as duas facilita garantir que "zeroizar" realmente
remove o segredo do disco sem discutir sobre podar linhas da tabela de
auditoria).
"""

from __future__ import annotations

import sqlite3
from contextlib import contextmanager
from datetime import datetime
from pathlib import Path
from typing import Iterator, Optional

from kms.exceptions import KeyNotFoundError
from kms.models import InterfaceType, KeyState, KeyStateInfo, SliceType, utcnow

_SCHEMA = """
CREATE TABLE IF NOT EXISTS keys (
    key_id               TEXT PRIMARY KEY,
    slice                TEXT NOT NULL,
    interface            TEXT NOT NULL,
    kem_algorithm         TEXT NOT NULL,
    has_quantum_component INTEGER NOT NULL,
    state                TEXT NOT NULL,
    created_at           TEXT NOT NULL,
    updated_at           TEXT NOT NULL,
    reason               TEXT NOT NULL DEFAULT ''
);

CREATE TABLE IF NOT EXISTS key_secrets (
    key_id TEXT PRIMARY KEY REFERENCES keys(key_id),
    psk    BLOB NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_keys_slice_interface_state
    ON keys(slice, interface, state);
"""


def _row_to_info(row: sqlite3.Row) -> KeyStateInfo:
    return KeyStateInfo(
        key_id=row["key_id"],
        slice=SliceType(row["slice"]),
        interface=InterfaceType(row["interface"]),
        kem_algorithm=row["kem_algorithm"],
        has_quantum_component=bool(row["has_quantum_component"]),
        state=KeyState(row["state"]),
        created_at=datetime.fromisoformat(row["created_at"]),
        updated_at=datetime.fromisoformat(row["updated_at"]),
        reason=row["reason"],
    )


class KeyStore:
    """Uma conexão SQLite por instância — não é thread-safe sozinha; o
    KeyManagementCore (kms/service.py) serializa acesso com um lock."""

    def __init__(self, db_path: str | Path):
        self._db_path = str(db_path)
        self._conn = sqlite3.connect(self._db_path, check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        self._conn.execute("PRAGMA foreign_keys = ON")
        self._conn.executescript(_SCHEMA)
        self._conn.commit()

    def close(self) -> None:
        self._conn.close()

    @contextmanager
    def _tx(self) -> Iterator[sqlite3.Connection]:
        try:
            yield self._conn
            self._conn.commit()
        except Exception:
            self._conn.rollback()
            raise

    def insert(
        self,
        key_id: str,
        slice: SliceType,
        interface: InterfaceType,
        kem_algorithm: str,
        has_quantum_component: bool,
        psk: bytes,
        state: KeyState,
        reason: str,
    ) -> KeyStateInfo:
        now = utcnow().isoformat()
        with self._tx() as conn:
            conn.execute(
                """INSERT INTO keys
                   (key_id, slice, interface, kem_algorithm, has_quantum_component,
                    state, created_at, updated_at, reason)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    key_id,
                    slice.value,
                    interface.value,
                    kem_algorithm,
                    int(has_quantum_component),
                    state.value,
                    now,
                    now,
                    reason,
                ),
            )
            conn.execute(
                "INSERT INTO key_secrets (key_id, psk) VALUES (?, ?)",
                (key_id, psk),
            )
        return self.get(key_id)

    def get(self, key_id: str) -> KeyStateInfo:
        row = self._conn.execute("SELECT * FROM keys WHERE key_id = ?", (key_id,)).fetchone()
        if row is None:
            raise KeyNotFoundError(key_id)
        return _row_to_info(row)

    def get_psk(self, key_id: str) -> bytes:
        """Levanta KeyNotFoundError tanto se a chave nunca existiu quanto
        se já foi zeroizada (a linha em key_secrets some nos dois casos do
        ponto de vista de quem chama — a distinção entre "nunca existiu" e
        "foi zeroizada" está em get(key_id).state, não aqui)."""
        row = self._conn.execute(
            "SELECT psk FROM key_secrets WHERE key_id = ?", (key_id,)
        ).fetchone()
        if row is None:
            raise KeyNotFoundError(key_id)
        return row["psk"]

    def update_state(self, key_id: str, new_state: KeyState, reason: str) -> KeyStateInfo:
        self.get(key_id)  # levanta KeyNotFoundError se não existir
        with self._tx() as conn:
            conn.execute(
                "UPDATE keys SET state = ?, updated_at = ?, reason = ? WHERE key_id = ?",
                (new_state.value, utcnow().isoformat(), reason, key_id),
            )
        return self.get(key_id)

    def wipe_secret(self, key_id: str) -> None:
        """Remove o PSK do armazenamento (zeroização) — o registro em
        `keys` permanece intacto pra auditoria."""
        with self._tx() as conn:
            conn.execute("DELETE FROM key_secrets WHERE key_id = ?", (key_id,))

    def get_active(self, slice: SliceType, interface: InterfaceType) -> Optional[KeyStateInfo]:
        """A chave ACTIVE ou RENEWING mais recente pra essa fatia/interface,
        ou None se nenhuma. Não deveria existir mais de uma ao mesmo tempo
        em operação normal, mas a query não assume isso — pega a mais
        recente por segurança."""
        row = self._conn.execute(
            """SELECT * FROM keys
               WHERE slice = ? AND interface = ? AND state IN ('ACTIVE', 'RENEWING')
               ORDER BY updated_at DESC LIMIT 1""",
            (slice.value, interface.value),
        ).fetchone()
        return _row_to_info(row) if row else None

    def list_history(
        self,
        slice: Optional[SliceType] = None,
        interface: Optional[InterfaceType] = None,
        limit: int = 100,
        before: Optional[str] = None,
    ) -> list[KeyStateInfo]:
        clauses = []
        params: list = []
        if slice is not None:
            clauses.append("slice = ?")
            params.append(slice.value)
        if interface is not None:
            clauses.append("interface = ?")
            params.append(interface.value)
        if before is not None:
            clauses.append("key_id < ?")
            params.append(before)
        where = f"WHERE {' AND '.join(clauses)}" if clauses else ""
        params.append(limit)
        rows = self._conn.execute(
            f"SELECT * FROM keys {where} ORDER BY key_id DESC LIMIT ?", params
        ).fetchall()
        return [_row_to_info(r) for r in rows]
