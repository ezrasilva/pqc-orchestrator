import os
import socket

import pytest

from ipsec_agent.config import CONNECTIONS
from ipsec_agent.agent import IpsecAgentCore

# Estes testes falam VICI de verdade com o charon rodando no laboratório
# (ver docs/RUNBOOK-OAI.md) — não são testes unitários puros, são
# integração contra o ambiente real. Pulam graciosamente fora dele (sem
# root, ou sem os sockets VICI do laboratório de pé) em vez de falhar,
# pra não quebrar quem rodar `pytest` sem o laboratório montado.


def _lab_available() -> bool:
    if os.geteuid() != 0:
        return False
    return all(
        os.path.exists(cfg.initiator_socket) and os.path.exists(cfg.responder_socket)
        for cfg in CONNECTIONS.values()
    )


requires_live_lab = pytest.mark.skipif(
    not _lab_available(),
    reason="precisa rodar como root com o laboratório IPsec de pé (ver RUNBOOK-OAI.md secao 4)",
)


@pytest.fixture
def core() -> IpsecAgentCore:
    return IpsecAgentCore()
