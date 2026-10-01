import secrets

import pytest

from ipsec_agent.config import CONNECTIONS
from ipsec_agent.models import ConnectionName, ConnectionState
from ipsec_agent.vici_client import ViciConnection

from .conftest import requires_live_lab


def test_unknown_connection_raises(core):
    with pytest.raises(ValueError):
        core.get_connection_status("not-a-real-connection")  # type: ignore[arg-type]


ALL_CONNECTIONS = [
    ConnectionName.F1_CU_DU,
    ConnectionName.N2_CU_EDGE,
    ConnectionName.N3_URLLC_CU_EDGE,
    ConnectionName.N3_EMBB_CU_EDGE,
    ConnectionName.N3_MIOT_CU_EDGE,
]


@requires_live_lab
def test_list_connections_reports_all_five(core):
    statuses = core.list_connections()
    names = {s.connection for s in statuses}
    assert names == set(ALL_CONNECTIONS)


@requires_live_lab
@pytest.mark.parametrize("connection", ALL_CONNECTIONS)
def test_apply_key_material_rotates_live_connection(core, connection):
    """O teste "mínimo" do item 3: aplica uma SA manualmente via VICI a
    partir de material fixo, confirma que funciona — contra as cinco
    conexões reais do laboratório (F1, N2 de controle, e as três N3 por
    fatia), não só duas. Isso efetivamente rotaciona o PSK da conexão no
    laboratório ao vivo; seguro de rodar (já confirmamos manualmente que
    todas sobrevivem e o plano de dados continua), mas não é hermético —
    roda contra o estado real, não um fake."""
    before = core.get_connection_status(connection)
    assert before.state is ConnectionState.ESTABLISHED

    key_id = f"pytest-{connection.value}-{secrets.token_hex(4)}"
    psk = secrets.token_bytes(32)

    result = core.apply_key_material(connection, key_id, psk)

    assert result.success, result.error_message
    assert result.applied_at is not None

    after = core.get_connection_status(connection)
    assert after.state is ConnectionState.ESTABLISHED
    assert after.current_key_id == key_id
    # a nova SA tem que ter subido depois da antiga, não ser a mesma
    assert after.established_since >= before.established_since


@requires_live_lab
def test_apply_key_material_with_ppk_on_urllc(core):
    """A URLLC é a única conexão com `ppk_id` configurado — confirma que
    o PPK novo é aplicado de verdade (não só o PSK). O vici expõe isso
    direto no campo `ppk` da SA (visto via inspeção manual contra o
    laboratório real: `ppk: b'yes'` — é o campo cru por trás do `/PPK`
    que o `swanctl --list-sas` imprime)."""
    connection = ConnectionName.N3_URLLC_CU_EDGE
    key_id = f"pytest-ppk-{secrets.token_hex(4)}"
    psk = secrets.token_bytes(32)
    ppk = secrets.token_bytes(32)

    result = core.apply_key_material(connection, key_id, psk, ppk=ppk)

    assert result.success, result.error_message

    cfg = CONNECTIONS[connection]
    sas = ViciConnection(cfg.initiator_socket).list_sas(cfg.conn_name)
    sa = sas[0][cfg.conn_name] if sas else None
    assert sa is not None
    assert sa.get("ppk") == b"yes"
