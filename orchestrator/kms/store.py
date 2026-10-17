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

import logging

from kms.exceptions import KeyNotFoundError
from kms.models import InterfaceType, KeyState, KeyStateInfo, SliceType, utcnow

# Versão do schema, gravada em `PRAGMA user_version`. INCREMENTAR a cada
# mudança incompatível de coluna — é o que dispara a recriação em
# `_recria_se_schema_incompativel`.
#   1: schema original, com a coluna `kem_algorithm`
#   2: `kem_algorithm` -> `key_source` (o material passou a vir da QKD)
_SCHEMA_VERSION = 2

_SCHEMA = """
CREATE TABLE IF NOT EXISTS keys (
    key_id               TEXT PRIMARY KEY,
    slice                TEXT NOT NULL,
    interface            TEXT NOT NULL,
    -- O que produziu o material desta chave. Era `kem_algorithm`,
    -- quando o KMS rodava um ML-KEM local; renomeado porque o material
    -- agora vem da QKDN (BB84+Cascade sobre SeQUeNCe, entregue pela API
    -- ETSI GS QKD 014) e guardar isso numa coluna chamada
    -- `kem_algorithm` enganaria quem lesse o banco. Ver kms/crypto.py.
    key_source           TEXT NOT NULL,
    has_quantum_component INTEGER NOT NULL,
    state                TEXT NOT NULL,
    created_at           TEXT NOT NULL,
    updated_at           TEXT NOT NULL,
    reason               TEXT NOT NULL DEFAULT ''
);

CREATE TABLE IF NOT EXISTS key_secrets (
    key_id TEXT PRIMARY KEY REFERENCES keys(key_id),
    -- Fica VAZIO (b"") desde que o PSK saiu da rotação: ele é fixo,
    -- serve só para autenticação, e vive no secrets.conf do laboratório
    -- (gerado por lab/ipsec/regen-secrets.py). A coluna continua
    -- NOT NULL para não exigir migração de schema. Ver kms/crypto.py.
    psk    BLOB NOT NULL,
    -- A chave de QKD, carregada no charon como PPK (RFC 8784). É ela
    -- que rotaciona agora.
    ppk    BLOB
);

CREATE INDEX IF NOT EXISTS idx_keys_slice_interface_state
    ON keys(slice, interface, state);
"""


def _row_to_info(row: sqlite3.Row) -> KeyStateInfo:
    return KeyStateInfo(
        key_id=row["key_id"],
        slice=SliceType(row["slice"]),
        interface=InterfaceType(row["interface"]),
        key_source=row["key_source"],
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
        self._recria_se_schema_incompativel()
        self._conn.executescript(_SCHEMA)
        self._conn.execute(f"PRAGMA user_version = {_SCHEMA_VERSION}")
        self._conn.commit()

    def _recria_se_schema_incompativel(self) -> None:
        """Recria as tabelas quando o arquivo existente é de um schema
        anterior.

        **Por que isto existe.** `CREATE TABLE IF NOT EXISTS` não migra:
        um arquivo criado com o schema antigo sobrevive à mudança e
        depois estoura na primeira leitura de coluna nova. Foi
        exatamente o que aconteceu ao renomear `kem_algorithm` para
        `key_source` — o banco da campanha anterior continuou no disco e
        o Cenário 4 morreu com `IndexError: No item with that key`
        vindo de `row["key_source"]`, a meia janela de coleta e com a
        causa a três níveis de distância do sintoma.

        **Por que recriar em vez de falhar.** O conteúdo é efêmero por
        natureza: metadados de material de chave de uma campanha que já
        terminou. As chaves em si vivem no charon, não aqui, e as desta
        tabela já foram aplicadas ou revogadas. Não há nada a preservar
        entre campanhas — e falhar deixaria o usuário tendo de apagar um
        arquivo à mão no meio de uma execução de horas. O aviso é alto
        de propósito, para a recriação nunca ser silenciosa.
        """
        atual = self._conn.execute("PRAGMA user_version").fetchone()[0]
        if atual == _SCHEMA_VERSION:
            return
        tabelas = [
            r[0] for r in self._conn.execute(
                "SELECT name FROM sqlite_master WHERE type='table'").fetchall()
        ]
        if not tabelas:
            return  # arquivo novo, nada a recriar
        logging.getLogger(__name__).warning(
            "banco do KMS em %s está no schema %d, esperado %d — recriando as "
            "tabelas (conteúdo é material efêmero de campanha encerrada)",
            self._db_path, atual, _SCHEMA_VERSION,
        )
        # As restrições de chave estrangeira têm de sair durante o
        # drop: `key_secrets` referencia `keys`, então apagar numa ordem
        # qualquer viola a FK (e depender da ordem seria frágil a cada
        # tabela nova).
        self._conn.execute("PRAGMA foreign_keys = OFF")
        try:
            for tabela in tabelas:
                self._conn.execute(f"DROP TABLE IF EXISTS {tabela}")
            self._conn.commit()
        finally:
            self._conn.execute("PRAGMA foreign_keys = ON")

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
        key_source: str,
        has_quantum_component: bool,
        psk: bytes,
        state: KeyState,
        reason: str,
        ppk: Optional[bytes] = None,
    ) -> KeyStateInfo:
        now = utcnow().isoformat()
        with self._tx() as conn:
            conn.execute(
                """INSERT INTO keys
                   (key_id, slice, interface, key_source, has_quantum_component,
                    state, created_at, updated_at, reason)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    key_id,
                    slice.value,
                    interface.value,
                    key_source,
                    int(has_quantum_component),
                    state.value,
                    now,
                    now,
                    reason,
                ),
            )
            conn.execute(
                "INSERT INTO key_secrets (key_id, psk, ppk) VALUES (?, ?, ?)",
                (key_id, psk, ppk),
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

    def get_ppk(self, key_id: str) -> Optional[bytes]:
        """None tanto pra fatia sem PPK quanto pra chave zeroizada/
        inexistente — quem precisa distinguir "nunca teve" de "foi
        apagado" usa get(key_id).state, igual get_psk()."""
        row = self._conn.execute(
            "SELECT ppk FROM key_secrets WHERE key_id = ?", (key_id,)
        ).fetchone()
        return row["ppk"] if row else None

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
