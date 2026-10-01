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

    def terminate(self, conn_name: str) -> None:
        session = self._session()
        session.terminate({"ike": conn_name})

    def list_sas(self, conn_name: Optional[str] = None) -> list[dict]:
        session = self._session()
        filt = {"ike": conn_name} if conn_name else None
        return list(session.list_sas(filt))
