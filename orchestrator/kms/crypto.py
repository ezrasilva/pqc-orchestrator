"""Geração do material híbrido PQC(+QKD simulado) — ver
docs/ARQUITETURA-ORQUESTRADOR.md seção 3.

Por fatia:
- URLLC: ML-KEM-768 + componente "quântico" simulado, combinados via HKDF.
- eMBB / mIoT: só ML-KEM-512, sem componente quântico.

Sobre o ML-KEM aqui: numa troca de chaves real, encapsulamento e
decapsulamento acontecem em partes diferentes (cada lado com seu próprio
par de chaves). Aqui o KMS gera os dois lados sozinho porque o PSK final é
*distribuído* fora de banda pro IPsec Agent aplicar nos dois pontos da
conexão (ver "Mecanismo real de rotação" na arquitetura) — o papel do
ML-KEM neste desenho não é acordo de chave entre duas partes, é fonte de
segredo pós-quântico de alta entropia que entra no HKDF. Fazemos o ciclo
completo keygen -> encapsulate -> decapsulate (e conferimos que os dois
lados batem) só pra exercitar o algoritmo de verdade, não simular com
`os.urandom` puro.

O componente "quântico simulado" é só entropia aleatória rotulada como tal
— não existe hardware QKD neste laboratório. Isso está documentado como
simulação desde a primeira versão da arquitetura, não é um detalhe
escondido.
"""

from __future__ import annotations

import secrets
from dataclasses import dataclass

import oqs
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from kms.models import SliceType

PSK_LENGTH_BYTES = 32
_QUANTUM_COMPONENT_LENGTH_BYTES = 32
_HKDF_INFO = b"pqc-orchestrator-hybrid-psk-v1"

_KEM_BY_SLICE: dict[SliceType, str] = {
    SliceType.URLLC: "ML-KEM-768",
    SliceType.EMBB: "ML-KEM-512",
    SliceType.MIOT: "ML-KEM-512",
}


@dataclass
class HybridMaterial:
    psk: bytes
    kem_algorithm: str
    has_quantum_component: bool


def _ml_kem_shared_secret(kem_algorithm: str) -> bytes:
    """Executa um ciclo completo keygen/encapsulate/decapsulate do KEM e
    retorna o segredo compartilhado, depois de conferir que os dois lados
    (encapsulador e decapsulador) derivaram o mesmo valor."""
    with oqs.KeyEncapsulation(kem_algorithm) as kem_initiator:
        public_key = kem_initiator.generate_keypair()
        ciphertext, shared_secret_encap = kem_initiator.encap_secret(public_key)
        shared_secret_decap = kem_initiator.decap_secret(ciphertext)

    if shared_secret_encap != shared_secret_decap:
        # Não deveria acontecer com uma implementação correta do KEM — se
        # acontecer, é sinal de bug sério na lib nativa, não algo pra
        # engolir silenciosamente.
        raise RuntimeError(
            f"segredo compartilhado do {kem_algorithm} não bateu entre "
            "encapsulamento e decapsulamento"
        )
    return shared_secret_encap


def generate_hybrid_material(slice: SliceType) -> HybridMaterial:
    """Gera o material híbrido pra uma fatia. Determinístico só no
    *formato* (algoritmo, presença de componente quântico) — o valor em si
    é sempre novo, nunca reaproveita segredo de uma chamada anterior."""
    kem_algorithm = _KEM_BY_SLICE[slice]
    ml_kem_secret = _ml_kem_shared_secret(kem_algorithm)

    has_quantum_component = slice is SliceType.URLLC
    quantum_component = (
        secrets.token_bytes(_QUANTUM_COMPONENT_LENGTH_BYTES) if has_quantum_component else b""
    )

    ikm = ml_kem_secret + quantum_component
    psk = HKDF(
        algorithm=hashes.SHA384(),
        length=PSK_LENGTH_BYTES,
        salt=None,
        info=_HKDF_INFO,
    ).derive(ikm)

    return HybridMaterial(
        psk=psk,
        kem_algorithm=kem_algorithm,
        has_quantum_component=has_quantum_component,
    )
