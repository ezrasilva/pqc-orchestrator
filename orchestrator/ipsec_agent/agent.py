"""IpsecAgentCore — a lógica do IPsec Agent isolada de gRPC, mesmo padrão
usado pro KMS (`kms/service.py`): testável diretamente, sem precisar subir
um servidor de rede pra validar o comportamento. A casca gRPC (servindo
`IpsecAgentService` de `ipsec_agent.proto`) fica pra quando o SMO amarrar
os componentes (item 5 da ordem de construção).

Único componente do sistema com acesso direto a VICI — ver
ARQUITETURA-ORQUESTRADOR.md seção 4.
"""

from __future__ import annotations

import logging
import threading
import time
from datetime import datetime, timedelta, timezone
from typing import Optional

from ipsec_agent.config import CONNECTIONS, ConnectionConfig
from ipsec_agent.models import ApplyResult, ConnectionName, ConnectionState, ConnectionStatus
from ipsec_agent.vici_client import ViciConnection
from evaluation.instrumentation import timed

logger = logging.getLogger(__name__)

# Quanto tempo esperar, depois de disparar o rekey com reauth, pela SA
# nova antes de desistir e reportar falha. Generoso de propósito: já
# observamos nesta VM (ver RUNBOOK-OAI.md, troubleshooting de SCTP/IKE)
# handshakes que só completam depois de um retransmit com backoff
# exponencial, levando dezenas de segundos — um timeout curto aqui gera
# falso negativo (a SA sobe, só que depois do Agent já ter desistido).
_APPLY_TIMEOUT_SECONDS = 60.0
_POLL_INTERVAL_SECONDS = 0.5


def _parse_state(sa_entry: dict) -> ConnectionState:
    state = sa_entry.get("state")
    if state == b"ESTABLISHED":
        return ConnectionState.ESTABLISHED
    if state == b"CONNECTING":
        return ConnectionState.CONNECTING
    return ConnectionState.DOWN


def _find_sa(sas: list[dict], conn_name: str) -> Optional[dict]:
    """`list_sas` devolve uma lista de dicts com uma entrada por IKE_SA,
    cada um chaveado pelo nome da conexão — pega a primeira que bate."""
    for entry in sas:
        if conn_name in entry:
            return entry[conn_name]
    return None


class IpsecAgentCore:
    def __init__(self, connections: dict[ConnectionName, ConnectionConfig] = CONNECTIONS):
        self._connections = connections
        self._lock = threading.Lock()
        # key_id do último material aplicado com sucesso, por conexão —
        # só em memória nesta fase (ver docstring do módulo pra por quê
        # isso é aceitável agora e o que falta pra produção).
        self._current_key_id: dict[ConnectionName, str] = {}

    def _config(self, connection: ConnectionName) -> ConnectionConfig:
        try:
            return self._connections[connection]
        except KeyError:
            raise ValueError(f"conexão desconhecida: {connection}") from None

    def apply_key_material(
        self, connection: ConnectionName, key_id: str, psk: bytes, ppk: Optional[bytes] = None
    ) -> ApplyResult:
        """`ppk` só se aplica a conexões com `ppk_id` configurado (hoje só
        N3_URLLC_CU_EDGE, ver config.py) — ignorado silenciosamente nas
        outras, mesmo que o chamador passe algo (o KMS já só gera ppk
        pra URLLC, ver kms/crypto.py, então isso não deveria acontecer na
        prática; não é motivo pra falhar a chamada toda)."""
        cfg = self._config(connection)
        owners = [cfg.local_id, cfg.remote_id]

        with self._lock:
            try:
                initiator = ViciConnection(cfg.initiator_socket)
                responder = ViciConnection(cfg.responder_socket)

                # Carrega o MESMO segredo nos dois lados antes de disparar
                # o reauth — se só o initiator tivesse o PSK novo, o
                # responder rejeitaria a reautenticação (ver config.py
                # pra por que isso não escala pra uma implantação
                # distribuída de verdade).
                responder.load_shared_psk(key_id, psk, owners)
                initiator.load_shared_psk(key_id, psk, owners)

                if cfg.ppk_id and ppk:
                    responder.load_shared_ppk(cfg.ppk_id, ppk)
                    initiator.load_shared_ppk(cfg.ppk_id, ppk)

                rekey_triggered_at = datetime.now(timezone.utc)
                initiator.rekey(cfg.conn_name, reauth=True)

                with timed("spi_confirmation", connection=connection.value, key_id=key_id):
                    established_at = self._wait_for_fresh_sa(
                        initiator, cfg.conn_name, after=rekey_triggered_at
                    )
                if established_at is None:
                    return ApplyResult(
                        success=False,
                        error_message=(
                            f"SA '{cfg.conn_name}' não reestabeleceu como ESTABLISHED "
                            f"dentro de {_APPLY_TIMEOUT_SECONDS}s após o reauth"
                        ),
                        applied_at=None,
                    )

                self._current_key_id[connection] = key_id
                return ApplyResult(success=True, error_message="", applied_at=established_at)

            except Exception as exc:  # noqa: BLE001 — reportar qualquer falha ao chamador, não derrubar o processo
                logger.exception("falha aplicando material em %s", cfg.conn_name)
                return ApplyResult(success=False, error_message=str(exc), applied_at=None)

    def _wait_for_fresh_sa(
        self, initiator: ViciConnection, conn_name: str, after: datetime
    ) -> Optional[datetime]:
        """Espera a SA aparecer ESTABLISHED com `established_since` depois
        de `after` (o instante em que disparamos o rekey) — não só "baixo
        o bastante", pra não aceitar por engano a entrada antiga que o
        VICI ainda não atualizou entre o pedido de rekey e a
        reautenticação completar."""
        deadline = time.monotonic() + _APPLY_TIMEOUT_SECONDS
        # pequena tolerância pro arredondamento de segundos do VICI e
        # pro tempo entre "rekey disparado" e "primeiro poll"
        tolerance = timedelta(seconds=_POLL_INTERVAL_SECONDS + 1)
        while time.monotonic() < deadline:
            sas = initiator.list_sas(conn_name)
            sa = _find_sa(sas, conn_name)
            if sa and _parse_state(sa) is ConnectionState.ESTABLISHED:
                established_seconds = int(sa.get("established", b"0"))
                established_since = datetime.now(timezone.utc) - timedelta(
                    seconds=established_seconds
                )
                if established_since >= after - tolerance:
                    return established_since
            time.sleep(_POLL_INTERVAL_SECONDS)
        return None

    def get_connection_status(self, connection: ConnectionName) -> ConnectionStatus:
        cfg = self._config(connection)
        initiator = ViciConnection(cfg.initiator_socket)
        sas = initiator.list_sas(cfg.conn_name)
        sa = _find_sa(sas, cfg.conn_name)

        if sa is None:
            return ConnectionStatus(
                connection=connection,
                state=ConnectionState.DOWN,
                local_id=cfg.local_id,
                remote_id=cfg.remote_id,
                established_since=None,
                current_key_id=self._current_key_id.get(connection),
            )

        established_since = None
        if _parse_state(sa) is ConnectionState.ESTABLISHED:
            established_seconds = int(sa.get("established", b"0"))
            established_since = datetime.now(timezone.utc) - timedelta(seconds=established_seconds)

        return ConnectionStatus(
            connection=connection,
            state=_parse_state(sa),
            local_id=cfg.local_id,
            remote_id=cfg.remote_id,
            established_since=established_since,
            current_key_id=self._current_key_id.get(connection),
        )

    def list_connections(self) -> list[ConnectionStatus]:
        return [self.get_connection_status(name) for name in self._connections]

    def terminate_connection(self, connection: ConnectionName, reason: str = "") -> None:
        cfg = self._config(connection)
        logger.info("encerrando conexão %s (motivo: %s)", cfg.conn_name, reason or "não informado")
        ViciConnection(cfg.initiator_socket).terminate(cfg.conn_name)
