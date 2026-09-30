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
