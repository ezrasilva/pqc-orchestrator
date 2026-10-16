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


def _find_installed_child(payload, child_name: str) -> bool:
    """Procura, em qualquer profundidade do payload, uma Child SA com este
    nome já `INSTALLED`.

    **Por que busca recursiva e não um caminho fixo.** Os dois eventos de
    Child SA têm formas diferentes, confirmado capturando os dois contra
    o laboratório ao vivo (mesmo método que o repositório usou para
    descobrir a forma do `ike-updown`):

    * `child-rekey` aninha a SA sob a IKE_SA e ainda dentro de um wrapper
      `old`/`new` — a que interessa é a `new`;
    * `child-updown` entrega a entrada sem o wrapper.

    Fixar o caminho de um dos dois quebraria no outro, e qual deles o
    charon emite depende do modo de rekey. Procurar pela condição
    (`name` bate e `state == INSTALLED`) em vez de pela posição cobre os
    dois sem depender desse detalhe.

    **Atenção à tipagem do VICI**: as CHAVES dos dicts vêm como `str` e
    os VALORES como `bytes`. Procurar por `payload.get(b"name")` nunca
    casa, e o sintoma é um timeout de 60 s sem erro nenhum — o evento
    chega, só não é reconhecido. O `_parse_state` deste módulo já
    registrava essa assimetria (`sa_entry.get("state") == b"ESTABLISHED"`);
    eu a ignorei na primeira versão desta função e paguei o timeout.
    """
    alvo = child_name.encode()
    if isinstance(payload, dict):
        if payload.get("name") == alvo and payload.get("state") == b"INSTALLED":
            return True
        return any(_find_installed_child(v, child_name) for v in payload.values())
    if isinstance(payload, list):
        return any(_find_installed_child(v, child_name) for v in payload)
    return False


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
        prática; não é motivo pra falhar a chamada toda).

        **Caminho legado.** Rotaciona PSK e PPK juntos e sempre paga o
        reauth, inclusive quando só o material do ESP precisava ser
        renovado. A arquitetura SAPQ-IPsec separa as duas coisas — ver
        `rekey_child()` e `reauth_with_ppk()` — porque a Fase A mediu
        três ordens de grandeza de diferença entre elas. Fica aqui
        porque a campanha de 12-15/10 foi colhida por este caminho e os
        cenários antigos ainda o chamam."""
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

                # **Achado real**: `initiator.rekey()` é ASSÍNCRONO — só
                # confirma que o comando foi aceito (~2ms), não espera a
                # SA nova ficar pronta. Por isso o listener precisa estar
                # REGISTRADO antes de disparar o rekey (senão corre risco
                # de perder o evento numa corrida — o VICI não republica
                # eventos passados). `listen_rekey()` já garante isso.
                event_stream = initiator.listen_rekey()
                initiator.rekey(cfg.conn_name, reauth=True)

                with timed("spi_confirmation", connection=connection.value, key_id=key_id):
                    established_at = self._wait_for_fresh_sa(event_stream, cfg.conn_name)
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

    def rekey_child(self, connection: ConnectionName) -> ApplyResult:
        """Rotação BARATA: rederiva o material do ESP, sem tocar
        autenticação, IKE_SA nem PPK.

        **Por que existe separada de `reauth_with_ppk`.** Medido na
        Fase A (A.2, 400 eventos, dois sentidos, 0 a 40 ms de RTT): o
        rekey de Child SA não perde **um único pacote**, em nenhuma
        combinação de perfil, sentido ou RTT — a RFC 7296 obriga
        make-before-break aqui. A reautenticação custa de ~1,8 ms a
        163 ms. Três ordens de grandeza separam as duas, então tratá-las
        como a mesma operação (que é o que `apply_key_material` fazia)
        joga fora a rotação que sai de graça.

        Não carrega segredo nenhum: o PSK é fixo e serve só para
        autenticação, e o material do ESP é derivado pelo próprio IKE.
        """
        cfg = self._config(connection)
        with self._lock:
            try:
                initiator = ViciConnection(cfg.initiator_socket)
                # Listener registrado ANTES de disparar, pelo mesmo
                # motivo do caminho de reauth: o VICI não republica
                # eventos passados.
                event_stream = initiator.listen_child_rekey()
                with timed("child_rekey", connection=connection.value):
                    initiator.rekey_child(cfg.conn_name)
                    established_at = self._wait_for_fresh_child_sa(
                        event_stream, cfg.conn_name)
                if established_at is None:
                    return ApplyResult(
                        success=False,
                        error_message=(
                            f"Child SA '{cfg.conn_name}' não reinstalou dentro de "
                            f"{_APPLY_TIMEOUT_SECONDS}s após o rekey"
                        ),
                        applied_at=None,
                    )
                return ApplyResult(success=True, error_message="", applied_at=established_at)
            except Exception as exc:  # noqa: BLE001 — reportar ao chamador, não derrubar o processo
                logger.exception("falha no rekey de Child SA em %s", cfg.conn_name)
                return ApplyResult(success=False, error_message=str(exc), applied_at=None)

    def reauth_with_ppk(
        self, connection: ConnectionName, key_id: str, ppk: bytes
    ) -> ApplyResult:
        """Rotação CARA: instala um PPK novo (RFC 8784) e reautentica.

        **Por que o PPK obriga reauth.** O PPK entra na derivação de
        chaves no IKE_AUTH, não no rekey da Child SA nem no da IKE_SA.
        Logo não há como trocar o PPK sem reautenticar — e é por isso
        que esta é a operação caracterizada como caminho caro na A.2.

        **Custo medido e o que ele exige da configuração.** Com
        `charon.make_before_break = yes` a interrupção é ~1,8 ms, num
        sentido só (responder → initiator), e **não cresce com o RTT**.
        Sem ele, cresce: 3,5 ms a 0 ms de RTT, 43,5 ms a 10 ms e
        **163,7 ms a 40 ms** — exatamente 4 round-trips. Para a URLLC
        isso é a diferença entre caber e não caber no orçamento, então o
        `make_before_break` ligado não é afinação, é requisito.

        O PSK NÃO é tocado aqui: ele é fixo e serve apenas para
        autenticar. Quem rotaciona é o PPK, que é o material vindo da
        QKD.
        """
        cfg = self._config(connection)
        if not cfg.ppk_id:
            return ApplyResult(
                success=False,
                error_message=(
                    f"conexão '{connection.value}' não tem ppk_id configurado — "
                    f"não há como instalar PPK nela (ver ipsec_agent/config.py)"
                ),
                applied_at=None,
            )

        with self._lock:
            try:
                initiator = ViciConnection(cfg.initiator_socket)
                responder = ViciConnection(cfg.responder_socket)

                # Os DOIS lados precisam do mesmo PPK antes do reauth:
                # com `ppk_required = yes`, um lado sem o PPK novo
                # rejeita a autenticação.
                with timed("ppk_install", connection=connection.value, key_id=key_id):
                    responder.load_shared_ppk(cfg.ppk_id, ppk)
                    initiator.load_shared_ppk(cfg.ppk_id, ppk)

                event_stream = initiator.listen_rekey()
                with timed("reauth", connection=connection.value, key_id=key_id):
                    initiator.rekey(cfg.conn_name, reauth=True)
                    established_at = self._wait_for_fresh_sa(event_stream, cfg.conn_name)
                if established_at is None:
                    return ApplyResult(
                        success=False,
                        error_message=(
                            f"SA '{cfg.conn_name}' não reestabeleceu como ESTABLISHED "
                            f"dentro de {_APPLY_TIMEOUT_SECONDS}s após o reauth com PPK"
                        ),
                        applied_at=None,
                    )

                self._current_key_id[connection] = key_id
                return ApplyResult(success=True, error_message="", applied_at=established_at)
            except Exception as exc:  # noqa: BLE001 — reportar ao chamador, não derrubar o processo
                logger.exception("falha no reauth com PPK em %s", cfg.conn_name)
                return ApplyResult(success=False, error_message=str(exc), applied_at=None)

    def _wait_for_fresh_child_sa(self, event_stream, child_name: str) -> Optional[datetime]:
        """Espera a Child SA reinstalada, pelos eventos do VICI.

        Separado de `_wait_for_fresh_sa` porque aquele entende payload de
        IKE_SA (`state` na raiz da entrada da conexão) e o de Child SA tem
        outra forma — usar o de IKE aqui fez o `rekey_child` estourar os
        60 s de timeout em todas as conexões, embora o rekey em si
        tivesse sido aceito e executado pelo charon.

        O stream entrega `None` nos ticks de timeout do `listen()` e
        tuplas `(label, payload)` nos eventos reais; `label` também vem
        `None` no tick. Ignorar os ticks é o que mantém o laço acordado
        sem bloquear.
        """
        deadline = time.monotonic() + _APPLY_TIMEOUT_SECONDS
        for evento in event_stream:
            if time.monotonic() > deadline:
                return None
            if not evento or evento[0] is None:
                continue  # tick de timeout, não evento
            if _find_installed_child(evento[1], child_name):
                return datetime.now(timezone.utc)
        return None

    def _wait_for_fresh_sa(self, event_stream, conn_name: str) -> Optional[datetime]:
        """**Reescrito — era polling de `list_sas` a cada 500ms, achado
        real medindo contra a campanha oficial**: o tempo médio ficava
        consistentemente em ~510ms mesmo quando o reauth completa em
        poucos ms de verdade — não é limite do kernel/strongSwan, é
        artefato do polling: o loop só *descobre* o resultado no próximo
        tick do `sleep(0.5)`, não quando acontece. Confirmado isolando a
        causa: `initiator.rekey()` é assíncrono (~2ms pra retornar, só
        confirma que o comando foi aceito), e o VICI tem notificação de
        evento (`session.listen(["ike-rekey"])`) que entrega o resultado
        no instante exato em que a SA nova fica ESTABLISHED — testado ao
        vivo contra o laboratório real antes de reescrever isto.

        `event_stream` vem de `ViciConnection.listen_rekey()`, já
        registrado ANTES do rekey ser disparado (ver `apply_key_material`
        — a ordem importa, o VICI não republica eventos passados).

        **Dois formatos de payload, achado real testando os dois ao
        vivo**: `ike-rekey` vem com wrapper `old`/`new` (`new.state`);
        `ike-updown` (o que `reauth=True` realmente dispara, ver
        `listen_rekey()`) vem com `state` direto na raiz do payload, e
        só conta como "subiu" quando a mensagem tem `up: yes` — o
        charon também manda um `ike-updown` *sem* `up` pra marcar a
        IKE_SA antiga sendo deletada durante o mesmo reauth, que não
        pode ser confundido com sucesso."""
        deadline = time.monotonic() + _APPLY_TIMEOUT_SECONDS
        for event_type, msg in event_stream:
            if time.monotonic() > deadline:
                return None
            if event_type is None:  # tick de timeout do listen(), sem evento — continua esperando
                continue
            payload = msg.get(conn_name)
            if payload is None:
                continue
            new = payload.get("new")
            if new is not None:
                # formato ike-rekey
                state = new.get("state") or new.get(b"state")
            else:
                # formato ike-updown — só conta se for a SA subindo,
                # não a antiga sendo derrubada no mesmo reauth
                up = msg.get("up") or msg.get(b"up")
                if up not in (b"yes", "yes"):
                    continue
                state = payload.get("state") or payload.get(b"state")
            if state in (b"ESTABLISHED", "ESTABLISHED"):
                return datetime.now(timezone.utc)
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
