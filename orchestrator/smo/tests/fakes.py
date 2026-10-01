"""Dublê de teste do IPsec Agent — só o suficiente pra exercitar a lógica
de orquestração do SmoCore (sucesso, falha, quarentena) sem precisar de
root/VICI/laboratório de pé. Os testes de integração real (`test_live.py`)
usam o `IpsecAgentCore` de verdade."""

from __future__ import annotations

from datetime import datetime, timezone

from ipsec_agent.models import ApplyResult, ConnectionName, ConnectionState, ConnectionStatus


class FakeIpsecAgent:
    def __init__(self, fail_connections: frozenset[ConnectionName] = frozenset()):
        self._fail_connections = fail_connections
        self.applied_calls: list[tuple] = []
        self._current_key_id: dict[ConnectionName, str] = {}

    def apply_key_material(self, connection, key_id, psk, ppk=None):
        self.applied_calls.append((connection, key_id, psk, ppk))
        if connection in self._fail_connections:
            return ApplyResult(success=False, error_message="falha simulada", applied_at=None)
        self._current_key_id[connection] = key_id
        return ApplyResult(success=True, error_message="", applied_at=datetime.now(timezone.utc))

    def list_connections(self):
        return [
            ConnectionStatus(
                connection=name,
                state=ConnectionState.ESTABLISHED,
                local_id="local",
                remote_id="remote",
                established_since=datetime.now(timezone.utc),
                current_key_id=self._current_key_id.get(name),
            )
            for name in ConnectionName
        ]
