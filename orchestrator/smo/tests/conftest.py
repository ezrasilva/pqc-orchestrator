import os

import pytest

from ipsec_agent.agent import IpsecAgentCore
from ipsec_agent.config import CONNECTIONS
from kms.models import SliceType
from kms.qkd import PpkProvider, QkdKey
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


class FakeQkdClient:
    """QKDN falsa. Os testes não podem usar a de verdade: cada chave
    custa ~15,4 s de simulação BB84+Cascade."""

    def __init__(self):
        self.chamadas = 0

    def enc_keys(self, slave_sae_id, bits=256):
        self.chamadas += 1
        return QkdKey(key_id=f"fake-qkd-{self.chamadas}",
                      key=bytes([self.chamadas % 256]) * (bits // 8),
                      source="fake")


@pytest.fixture
def ppk_provider():
    """Poço com chaves já disponíveis, sem threads: `start()` não é
    chamado, as chaves entram direto nas filas. Assim o teste não
    depende do agendamento das threads de reposição para ser
    determinístico."""
    prov = PpkProvider(FakeQkdClient(), "B", tuple(SliceType), depth=8)
    for fatia in SliceType:
        for _ in range(4):
            prov._pools[fatia].put(prov._client.enc_keys("B"))
    return prov


@pytest.fixture
def ppk_provider_vazio():
    """Poço vazio, para exercitar o caminho de escassez de QKD."""
    return PpkProvider(FakeQkdClient(), "B", tuple(SliceType), depth=1)


@pytest.fixture
def fake_ipsec_agent():
    return FakeIpsecAgent()


@pytest.fixture
def smo(kms_core, scheduler_core, fake_ipsec_agent, ppk_provider):
    return SmoCore(kms_core, scheduler_core, fake_ipsec_agent, ppk_provider)


@pytest.fixture
def live_smo(kms_core, scheduler_core, ppk_provider):
    """Mesmo KMS/Scheduler isolados de cima, mas o IPsec Agent de
    verdade — só usado pelos testes `requires_live_lab`."""
    return SmoCore(kms_core, scheduler_core, IpsecAgentCore(), ppk_provider)
