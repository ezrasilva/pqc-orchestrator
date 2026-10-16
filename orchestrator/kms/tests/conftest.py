import pytest

from kms.models import SliceType
from kms.qkd import PpkProvider, QkdKey
from kms.service import KeyManagementCore
from kms.store import KeyStore


@pytest.fixture
def store(tmp_path):
    s = KeyStore(tmp_path / "kms-test.sqlite3")
    yield s
    s.close()


@pytest.fixture
def core(store):
    c = KeyManagementCore(store)
    yield c
    # store já é fechado pelo fixture `store` — não chamar c.close() de novo.


class FakeQkdClient:
    """QKDN falsa. A de verdade custa ~15,4 s de simulação por chave, o
    que tornaria a suíte inviável."""

    def __init__(self):
        self.chamadas = 0

    def enc_keys(self, slave_sae_id, bits=256):
        self.chamadas += 1
        return QkdKey(key_id=f"fake-qkd-{self.chamadas}",
                      key=bytes([self.chamadas % 256]) * (bits // 8),
                      source="fake")


@pytest.fixture
def ppk_provider():
    """Poço pré-carregado, sem `start()`: as chaves entram direto nas
    filas, para o teste não depender do agendamento das threads de
    reposição."""
    prov = PpkProvider(FakeQkdClient(), "B", tuple(SliceType), depth=16)
    for fatia in SliceType:
        for _ in range(8):
            prov._pools[fatia].put(prov._client.enc_keys("B"))
    return prov
