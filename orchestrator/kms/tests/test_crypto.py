import pytest

from kms.crypto import PSK_LENGTH_BYTES, generate_hybrid_material
from kms.models import SliceType


@pytest.mark.parametrize(
    "slice, expected_kem, expected_quantum",
    [
        (SliceType.URLLC, "ML-KEM-768", True),
        (SliceType.EMBB, "ML-KEM-512", False),
        (SliceType.MIOT, "ML-KEM-512", False),
    ],
)
def test_algorithm_and_quantum_component_by_slice(slice, expected_kem, expected_quantum):
    material = generate_hybrid_material(slice)
    assert material.kem_algorithm == expected_kem
    assert material.has_quantum_component is expected_quantum
    assert len(material.psk) == PSK_LENGTH_BYTES


def test_two_generations_never_repeat():
    a = generate_hybrid_material(SliceType.URLLC)
    b = generate_hybrid_material(SliceType.URLLC)
    assert a.psk != b.psk


def test_urllc_psk_differs_even_with_same_algorithm_family():
    # eMBB e mIoT usam o mesmo algoritmo (ML-KEM-512) mas isso não deveria
    # nunca produzir o mesmo PSK entre duas gerações independentes.
    a = generate_hybrid_material(SliceType.EMBB)
    b = generate_hybrid_material(SliceType.MIOT)
    assert a.psk != b.psk


def test_only_urllc_gets_a_separate_ppk():
    urllc = generate_hybrid_material(SliceType.URLLC)
    embb = generate_hybrid_material(SliceType.EMBB)
    miot = generate_hybrid_material(SliceType.MIOT)
    assert urllc.ppk is not None
    assert embb.ppk is None
    assert miot.ppk is None


def test_ppk_is_not_the_same_bytes_as_psk():
    # ppk precisa ser um segredo de verdade separado do psk — ver
    # docstring de kms/crypto.py pro porquê (RFC 8784 exige os dois
    # distintos).
    material = generate_hybrid_material(SliceType.URLLC)
    assert material.ppk != material.psk
    assert len(material.ppk) > 0


def test_two_urllc_generations_never_repeat_ppk():
    a = generate_hybrid_material(SliceType.URLLC)
    b = generate_hybrid_material(SliceType.URLLC)
    assert a.ppk != b.ppk
