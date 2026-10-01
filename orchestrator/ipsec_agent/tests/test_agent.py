import secrets

import pytest

from ipsec_agent.models import ConnectionName, ConnectionState

from .conftest import requires_live_lab


def test_unknown_connection_raises(core):
    with pytest.raises(ValueError):
        core.get_connection_status("not-a-real-connection")  # type: ignore[arg-type]


@requires_live_lab
def test_list_connections_reports_both(core):
    statuses = core.list_connections()
    names = {s.connection for s in statuses}
    assert names == {ConnectionName.F1_CU_DU, ConnectionName.N2N3_CU_EDGE}


@requires_live_lab
@pytest.mark.parametrize("connection", [ConnectionName.F1_CU_DU, ConnectionName.N2N3_CU_EDGE])
def test_apply_key_material_rotates_live_connection(core, connection):
    """O teste "mínimo" do item 3: aplica uma SA manualmente via VICI a
    partir de material fixo, confirma que funciona — contra as duas
    conexões reais do laboratório, não só uma. Isso efetivamente rotaciona
    o PSK da conexão no laboratório ao vivo; seguro de rodar (já
    confirmamos manualmente que F1/N2N3 e o plano de dados sobrevivem),
    mas não é hermético — roda contra o estado real, não um fake."""
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
