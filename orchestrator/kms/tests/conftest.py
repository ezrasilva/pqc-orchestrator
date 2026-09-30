import pytest

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
