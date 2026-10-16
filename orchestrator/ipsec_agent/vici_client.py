"""Wrapper fino sobre a lib `vici` oficial — só os comandos que o IPsec
Agent precisa, com os nomes de campo exatos que o servidor (`vici_cred.c`/
`vici_control.c` do strongSwan) espera. Conferido contra o código-fonte
do strongSwan 6.0.4 nesta VM, não só contra documentação — em particular
o campo do segredo em `load-shared` chama `data`, não `secret` (pegadinha
fácil de errar, o nome do parâmetro Python do método `load_shared()` da
lib sugere o contrário).
"""

from __future__ import annotations

import socket
from typing import Optional

import vici


class ViciConnection:
    """Uma conexão de curta duração ao socket VICI de um charon. Não
    mantém a conexão aberta entre chamadas — o volume de operações do
    IPsec Agent é baixo (rotação de chave, não tráfego de dados), então
    não vale a complexidade de um pool de conexões persistente."""

    def __init__(self, socket_path: str, timeout: float = 5.0):
        self._socket_path = socket_path
        self._timeout = timeout

    def _session(self) -> vici.Session:
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        sock.settimeout(self._timeout)
        sock.connect(self._socket_path)
        return vici.Session(sock)

    def load_shared_psk(
        self, key_id: str, psk: bytes, owners: list[str]
    ) -> None:
        session = self._session()
        session.load_shared(
            {
                "id": key_id,
                "type": "IKE",
                "data": psk,
                "owners": owners,
            }
        )

    def load_shared_ppk(self, ppk_id: str, ppk: bytes) -> None:
        """PPK (RFC 8784) — diferente do PSK do IKE, não leva `owners`
        (endereço); é casado pelo `ppk_id` configurado na conexão
        (`ppk_id =` no swanctl.conf), não por identidade de peer.
        Testado contra o laboratório real carregando um PPK novo com o
        mesmo `id` já usado pelo swanctl.conf (`ppk-urllc-qkd`) e
        confirmando reauth bem-sucedido com `/PPK` ativo logo depois —
        não confirmei a nível de código-fonte se isso substitui o valor
        anterior no credential set do charon ou só adiciona um candidato
        extra que também autentica; pra produção, vale essa checagem
        antes de confiar que valores antigos de fato saem de circulação
        (zeroização — mesma preocupação que o KMS já trata pro PSK)."""
        session = self._session()
        session.load_shared(
            {
                "id": ppk_id,
                "type": "PPK",
                "data": ppk,
            }
        )

    def rekey(self, conn_name: str, reauth: bool = True) -> None:
        """reauth=True refaz a autenticação de verdade (reusa o PSK que
        acabou de ser carregado) — um rekey sem reauth só rederiva chaves
        da IKE_SA existente via DH, sem tocar a autenticação, então NÃO
        valida o PSK novo. Ver nota em config.py."""
        session = self._session()
        session.rekey({"ike": conn_name, "reauth": reauth})

    def rekey_child(self, child_name: str) -> None:
        """Rekey da Child SA: rederiva só o material do ESP, sem tocar a
        autenticação nem a IKE_SA.

        **Por que isto é um método separado de `rekey()`.** Medido na
        Fase A (A.2, 400 eventos nos dois sentidos, 0 a 40 ms de RTT):
        o rekey de Child SA **não perde um único pacote**, em nenhum
        sentido, perfil ou RTT — a RFC 7296 obriga make-before-break
        aqui. Já a reautenticação da IKE_SA, que é o que `rekey()` faz,
        custa de ~1,8 ms (com `charon.make_before_break = yes`) a 163 ms
        (sem ele, a 40 ms de RTT).

        Ou seja, as duas operações diferem em três ordens de grandeza de
        custo, e por isso o orquestrador tem de poder escolher. A
        renovação de material do ESP usa este caminho; só a renovação de
        PPK precisa do caro, porque o PPK entra na derivação no
        IKE_AUTH e portanto exige reautenticação.
        """
        session = self._session()
        session.rekey({"child": child_name})

    def listen_child_rekey(self, tick_timeout: float = 0.05):
        """Como `listen_rekey()`, mas para eventos de Child SA.

        Mesmo cuidado de corrida: o generator volta já registrado no
        charon, com o primeiro tick consumido, porque o VICI não
        republica eventos passados — se o evento acontecer entre
        "disparei" e "comecei a escutar", ele se perde para sempre.

        Escuta `child-rekey` e `child-updown` pelo mesmo motivo que o
        listener de IKE escuta dois tipos: qual dos dois o charon emite
        depende do modo de rekey, e cobrir os dois evita depender desse
        detalhe.
        """
        session = self._session()
        gen = session.listen(["child-rekey", "child-updown"], timeout=tick_timeout)
        next(gen)  # consome o tick de registro, ver docstring
        return gen

    def terminate(self, conn_name: str) -> None:
        session = self._session()
        session.terminate({"ike": conn_name})

    def list_sas(self, conn_name: Optional[str] = None) -> list[dict]:
        session = self._session()
        filt = {"ike": conn_name} if conn_name else None
        return list(session.list_sas(filt))

    def listen_rekey(self, tick_timeout: float = 0.05):
        """**Substitui o polling antigo** (`_wait_for_fresh_sa` em
        `agent.py` fazia `list_sas` a cada 500ms — achado real: isso
        dava um tempo medido de ~510ms mesmo quando o rekey real
        completa em poucos ms, porque o loop só DESCOBRE o resultado
        no próximo tick do poll, não quando acontece de verdade). O
        VICI tem um modo de evento (`session.listen()`) que notifica
        IMEDIATAMENTE quando uma IKE_SA muda de estado.

        **Achado real depurando isto contra o laboratório ao vivo**:
        `swanctl --rekey --ike` sem `--reauth` dispara `ike-rekey`
        (payload com wrapper `old`/`new`) — mas `rekey(reauth=True)`,
        que é o que este Agent SEMPRE usa (precisa validar o PSK novo,
        ver docstring de `rekey()`), dispara **`ike-updown`**, não
        `ike-rekey` — payload SEM wrapper (`state` direto na raiz) e
        com `up: yes` especificamente na entrada da SA que subiu (o
        charon também emite um `ike-updown` separado, sem `up`, pra
        deleção da IKE_SA antiga — tudo isolado e confirmado testando
        os dois casos lado a lado contra o lab real antes de escrever
        isto). Escuta os dois tipos pra cobrir qualquer modo de rekey
        que um chamador futuro venha a usar, não só o caminho atual.

        Retorna o generator já "aquecido" (registrado no charon) —
        quem chama precisa consumir um primeiro tick (ou usar este
        método, que já faz isso) ANTES de disparar o rekey, senão corre
        risco de uma corrida: o evento pode acontecer entre "disparei o
        rekey" e "comecei a escutar", e nesse caso o evento se perde
        pra sempre (o VICI não republica eventos passados). `tick_timeout`
        pequeno garante que o registro é confirmado quase
        instantaneamente, sem bloquear esperando um evento de verdade."""
        session = self._session()
        gen = session.listen(["ike-updown", "ike-rekey"], timeout=tick_timeout)
        next(gen)  # consome o primeiro tick (registro), ver docstring
        return gen
