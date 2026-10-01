import pytest

from kms.exceptions import KeyNotFoundError
from kms.models import InterfaceType, KeyState, SliceType


def test_insert_and_get(store):
    info = store.insert(
        key_id="key-1",
        slice=SliceType.URLLC,
        interface=InterfaceType.F1,
        kem_algorithm="ML-KEM-768",
        has_quantum_component=True,
        psk=b"\x00" * 32,
        state=KeyState.PENDING,
        reason="test",
    )
    assert info.key_id == "key-1"
    assert info.state is KeyState.PENDING
    assert store.get_psk("key-1") == b"\x00" * 32


def test_get_unknown_key_raises(store):
    with pytest.raises(KeyNotFoundError):
        store.get("does-not-exist")


def test_update_state(store):
    store.insert(
        key_id="key-2",
        slice=SliceType.EMBB,
        interface=InterfaceType.N3,
        kem_algorithm="ML-KEM-512",
        has_quantum_component=False,
        psk=b"\x01" * 32,
        state=KeyState.PENDING,
        reason="test",
    )
    updated = store.update_state("key-2", KeyState.ACTIVE, "applied")
    assert updated.state is KeyState.ACTIVE
    assert updated.reason == "applied"
    assert updated.updated_at >= updated.created_at


def test_wipe_secret_removes_psk_but_keeps_record(store):
    store.insert(
        key_id="key-3",
        slice=SliceType.MIOT,
        interface=InterfaceType.N3,
        kem_algorithm="ML-KEM-512",
        has_quantum_component=False,
        psk=b"\x02" * 32,
        state=KeyState.REVOKED,
        reason="test",
    )
    store.wipe_secret("key-3")
    with pytest.raises(KeyNotFoundError):
        store.get_psk("key-3")
    # o registro de auditoria continua existindo
    assert store.get("key-3").state is KeyState.REVOKED


def test_get_active_prefers_active_and_renewing_only(store):
    store.insert(
        key_id="key-old",
        slice=SliceType.URLLC,
        interface=InterfaceType.F1,
        kem_algorithm="ML-KEM-768",
        has_quantum_component=True,
        psk=b"\x03" * 32,
        state=KeyState.REVOKED,
        reason="test",
    )
    assert store.get_active(SliceType.URLLC, InterfaceType.F1) is None

    store.insert(
        key_id="key-active",
        slice=SliceType.URLLC,
        interface=InterfaceType.F1,
        kem_algorithm="ML-KEM-768",
        has_quantum_component=True,
        psk=b"\x04" * 32,
        state=KeyState.ACTIVE,
        reason="test",
    )
    active = store.get_active(SliceType.URLLC, InterfaceType.F1)
    assert active is not None
    assert active.key_id == "key-active"


def test_list_history_filters_by_slice_and_interface(store):
    store.insert(
        key_id="a1",
        slice=SliceType.URLLC,
        interface=InterfaceType.F1,
        kem_algorithm="ML-KEM-768",
        has_quantum_component=True,
        psk=b"\x00",
        state=KeyState.PENDING,
        reason="",
    )
    store.insert(
        key_id="a2",
        slice=SliceType.EMBB,
        interface=InterfaceType.N3,
        kem_algorithm="ML-KEM-512",
        has_quantum_component=False,
        psk=b"\x00",
        state=KeyState.PENDING,
        reason="",
    )

    urllc_only = store.list_history(slice=SliceType.URLLC)
    assert {e.key_id for e in urllc_only} == {"a1"}

    n3_only = store.list_history(interface=InterfaceType.N3)
    assert {e.key_id for e in n3_only} == {"a2"}

    everything = store.list_history()
    assert {e.key_id for e in everything} == {"a1", "a2"}
