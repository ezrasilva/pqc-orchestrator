"""Catálogo de perfis criptográficos da Fase A — ver
`docs/CAMPANHA-SAPQ-IPSEC.md` ("Catálogo de perfis da Fase A").

A Fase A varia **um eixo por vez** a partir de um perfil de referência
(K2 + AES-128-GCM no ESP + PSK), pra atribuir custo a cada escolha
isoladamente:

- eixo KE (K0-K5): muda só a troca de chaves do IKE, ESP fixo em
  AES-128-GCM;
- eixo ESP: muda só a cifra do ESP, KE fixo em K2.

**Achado real validando o catálogo contra o laboratório (14/10)**: o
documento da campanha trata K1/K2/K4 como "ML-KEM puro" e só K3 como
híbrido — confirmado que isso É expressável no strongSwan 6.0.4 desta
VM (`aes256gcm16-prfsha256-mlkem768` negocia
`IKE:AES_GCM_16_256/PRF_HMAC_SHA2_256/ML_KEM_768`, sem nenhum KE
clássico). Isso contraria o folclore herdado no repositório (comentários
em `scenario1_static_pqc.py`/`connections.conf` afirmando que ML-KEM só
entra como round híbrido adicional via `ke1_`, com um grupo clássico de
base obrigatório). O `ke1_` continua necessário pro caso HÍBRIDO (K3,
dois KEs na mesma negociação, RFC 9370) — não pro ML-KEM sozinho.

**Diferença estrutural medida entre puro e híbrido** (a razão de o eixo
KE existir): o perfil puro fecha em 2 trocas (IKE_SA_INIT → IKE_AUTH),
com a chave pública do ML-KEM indo no próprio IKE_SA_INIT (1384 B em
K2). O híbrido precisa de uma troca a mais (IKE_INTERMEDIATE) e, com
ML-KEM-768, ela sai FRAGMENTADA (1248 B + 66 B) — custo que só aparece
medindo no fio, não na documentação.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class Profile:
    """Um ponto do catálogo. `ike_proposal`/`esp_proposal` vão direto pro
    `connections.conf`; `needs_ppk` liga `ppk_id`/`ppk_required`."""

    name: str
    ike_proposal: str
    esp_proposal: str
    needs_ppk: bool = False
    # categoria de segurança NIST do KEM (None = clássico, quebrável por HNDL)
    nist_category: int | None = None
    note: str = ""


# Cifra do ESP de referência, mantida fixa enquanto o eixo KE varia.
_ESP_REF = "aes128gcm16"
# AEAD/PRF do IKE mantidos fixos no eixo KE — só o método de KE muda.
_IKE_BASE = "aes128gcm16-prfsha256"


KE_PROFILES: tuple[Profile, ...] = (
    Profile(
        name="K0",
        ike_proposal=f"{_IKE_BASE}-curve25519",
        esp_proposal=_ESP_REF,
        nist_category=None,
        note="linha de base clássica (x25519) — quebrável por HNDL",
    ),
    Profile(
        name="K1",
        ike_proposal=f"{_IKE_BASE}-mlkem512",
        esp_proposal=_ESP_REF,
        nist_category=1,
    ),
    Profile(
        name="K2",
        ike_proposal=f"{_IKE_BASE}-mlkem768",
        esp_proposal=_ESP_REF,
        nist_category=3,
        note="referência do catálogo",
    ),
    Profile(
        name="K3",
        ike_proposal=f"{_IKE_BASE}-curve25519-ke1_mlkem768",
        esp_proposal=_ESP_REF,
        nist_category=3,
        note="híbrido clássico+PQC (RFC 9370) — exige IKE_INTERMEDIATE",
    ),
    Profile(
        name="K4",
        ike_proposal=f"{_IKE_BASE}-mlkem1024",
        esp_proposal=_ESP_REF,
        nist_category=5,
    ),
    Profile(
        name="K5",
        ike_proposal=f"{_IKE_BASE}-curve25519-ke1_mlkem768",
        esp_proposal=_ESP_REF,
        needs_ppk=True,
        nist_category=3,
        note="K3 + PPK (RFC 8784) — perfil candidato da URLLC",
    ),
)


ESP_PROFILES: tuple[Profile, ...] = (
    Profile(
        name="ESP-AES128GCM",
        ike_proposal=f"{_IKE_BASE}-mlkem768",
        esp_proposal="aes128gcm16",
        nist_category=3,
        note="ESP de referência",
    ),
    Profile(
        name="ESP-AES256GCM",
        ike_proposal=f"{_IKE_BASE}-mlkem768",
        esp_proposal="aes256gcm16",
        nist_category=3,
    ),
    Profile(
        name="ESP-CHACHA20",
        ike_proposal=f"{_IKE_BASE}-mlkem768",
        esp_proposal="chacha20poly1305",
        nist_category=3,
        note="sem aceleração AES-NI — compara custo de CPU no plano de dados",
    ),
)


ALL_PROFILES: tuple[Profile, ...] = KE_PROFILES + ESP_PROFILES


def by_name(name: str) -> Profile:
    for profile in ALL_PROFILES:
        if profile.name == name:
            return profile
    raise KeyError(f"perfil desconhecido: {name!r} (conhecidos: {[p.name for p in ALL_PROFILES]})")
