import pytest

from kms.exceptions import InvalidTransitionError, KeyNotFoundError
from kms.models import InterfaceType, KeyState, SliceType


def test_generate_starts_pending(core):
    material = core.generate(SliceType.URLLC, InterfaceType.F1, reason="test")
    info = core.get_state(material.key_id)
    assert info.state is KeyState.PENDING
    assert info.kem_algorithm == "ML-KEM-768"
    assert core.get_psk(material.key_id) == material.psk


def test_activate_then_appears_as_active_key(core):
    material = core.generate(SliceType.EMBB, InterfaceType.N3)
    core.activate(material.key_id)

    active = core.get_active_key(SliceType.EMBB, InterfaceType.N3)
    assert active is not None
    assert active.key_id == material.key_id
    assert active.state is KeyState.ACTIVE


def test_invalid_transition_rejected(core):
    material = core.generate(SliceType.MIOT, InterfaceType.N3)
    # PENDING não pode ir direto pra QUARANTINED (tem que passar por ACTIVE)
    with pytest.raises(InvalidTransitionError):
        core.quarantine(material.key_id, "teste")


def test_full_rotation_cycle(core):
    """Caminho principal descrito na arquitetura: gera substituta, marca a
    antiga como RENEWING, ativa a nova, revoga e zeroiza a antiga."""
    old = core.generate(SliceType.URLLC, InterfaceType.F1, reason="initial")
    core.activate(old.key_id)

    new = core.generate(SliceType.URLLC, InterfaceType.F1, reason="rotation")
    core.mark_renewing(old.key_id, "substituta gerada")
    assert core.get_state(old.key_id).state is KeyState.RENEWING
    # RENEWING ainda conta como "em uso" pra GetActiveKey
    assert core.get_active_key(SliceType.URLLC, InterfaceType.F1).key_id == old.key_id

    core.activate(new.key_id)
    core.revoke(old.key_id, "substituída")
    core.zeroize(old.key_id)

    assert core.get_active_key(SliceType.URLLC, InterfaceType.F1).key_id == new.key_id
    assert core.get_state(old.key_id).state is KeyState.ZEROIZED
    with pytest.raises(KeyNotFoundError):
        core.get_psk(old.key_id)  # material realmente sumiu


def test_quarantine_and_release(core):
    material = core.generate(SliceType.EMBB, InterfaceType.F1)
    core.activate(material.key_id)
    core.quarantine(material.key_id, "suspeita de comprometimento")
    assert core.get_state(material.key_id).state is KeyState.QUARANTINED
    # em quarentena não é "ativa" pro resto do sistema
    assert core.get_active_key(SliceType.EMBB, InterfaceType.F1) is None

    core.release_quarantine(material.key_id, "falso positivo")
    assert core.get_state(material.key_id).state is KeyState.ACTIVE
    assert core.get_active_key(SliceType.EMBB, InterfaceType.F1).key_id == material.key_id


def test_failed_key_can_be_zeroized_without_revoke(core):
    material = core.generate(SliceType.MIOT, InterfaceType.N3)
    core.mark_failed(material.key_id, "IPsec Agent recusou o material")
    core.zeroize(material.key_id)
    assert core.get_state(material.key_id).state is KeyState.ZEROIZED


def test_zeroized_is_terminal(core):
    material = core.generate(SliceType.MIOT, InterfaceType.N3)
    core.mark_failed(material.key_id, "teste")
    core.zeroize(material.key_id)
    with pytest.raises(InvalidTransitionError):
        core.activate(material.key_id)


def test_list_history_reflects_lifecycle(core):
    material = core.generate(SliceType.URLLC, InterfaceType.F1)
    core.activate(material.key_id)
    core.revoke(material.key_id, "fim do teste")

    history = core.list_history(slice=SliceType.URLLC, interface=InterfaceType.F1)
    assert any(e.key_id == material.key_id and e.state is KeyState.REVOKED for e in history)
