import os

import pytest

from ipsec_agent.agent import IpsecAgentCore
from ipsec_agent.config import CONNECTIONS
from kms.service import KeyManagementCore
from kms.store import KeyStore
from scheduler.service import SchedulerCore
from smo.service import SmoCore

from .fakes import FakeIpsecAgent


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
def kms_store(tmp_path):
    store = KeyStore(tmp_path / "smo-test.sqlite3")
    yield store
    store.close()


@pytest.fixture
def kms_core(kms_store):
    return KeyManagementCore(kms_store)


@pytest.fixture
def scheduler_core():
    return SchedulerCore()


@pytest.fixture
def fake_ipsec_agent():
    return FakeIpsecAgent()


@pytest.fixture
def smo(kms_core, scheduler_core, fake_ipsec_agent):
    return SmoCore(kms_core, scheduler_core, fake_ipsec_agent)


@pytest.fixture
def live_smo(kms_core, scheduler_core):
    """Mesmo KMS/Scheduler isolados de cima, mas o IPsec Agent de
    verdade — só usado pelos testes `requires_live_lab`."""
    return SmoCore(kms_core, scheduler_core, IpsecAgentCore())
