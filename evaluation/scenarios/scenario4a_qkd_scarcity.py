"""Cenário C4a — escassez de entropia: quem perde o PPK novo.

Mesma infraestrutura e mesmos perfis do C3 (a proposta), mas com a taxa
da fonte de QKD **declarada abaixo da demanda total**. Mede o que
acontece quando `Σ k / Tr_ppk,i > R_qkd`: qual fatia continua renovando
PPK e quais são rebaixadas para renovar só o ML-KEM do ESP.

**Por que o `R_qkd` é declarado e não herdado da simulação.** Medido, o
tempo por chave depende da carga do hospedeiro — 15,2 s com o rádio
parado contra 38-39 s com ele rodando — e do backend de reconciliação.
Herdar a taxa faria a razão demanda/oferta, que é exatamente a variável
independente deste cenário, variar sozinha entre repetições. Declarar
torna o cenário reproduzível. Ver `kms/qkd.PpkProvider`.

**A conta.** Com PPK de 256 bits e os `Tr_ppk` da escala de teste
(30/90/180 s), a demanda é 256/30 + 256/90 + 256/180 ≈ **12,8 bit/s**. A
taxa usada aqui é **8,5 bit/s**, ou seja demanda ≈ 1,5× a oferta — o
valor que o desenho da campanha fixou.

**O que se espera observar, e que é a tese:** pela ordem lexicográfica
I > H > D do vetor de criticidade, a URLLC (impacto alto) fica com o PPK
e eMBB e mIoT são rebaixadas. O rebaixamento é registrado como
`rotation_downgraded` e o poço vazio como `ppk_pool_empty`, então a
análise pode relacionar escassez com SLA perdido por fatia.

Roda com risk-aware E com EDF (`--policy`), porque é aqui que há disputa
e portanto onde a política faz diferença.
"""

from __future__ import annotations

from evaluation import lab_control
from scheduler.models import SchedulingPolicy

NAME = "cenario4a_escassez_qkd"
scheduling_policy = SchedulingPolicy.RISK_AWARE

# Abaixo da demanda escalada de ~12,8 bit/s. Ver docstring.
r_qkd_bits_per_second = 8.5


def setup() -> None:
    """Igual ao C3 — mesma topologia, mesmos perfis por fatia. A única
    diferença do cenário está na taxa de QKD."""
    lab_control.restart_ipsec_lab(("cu-ns", "5gc-edge-ns"))
    lab_control.load_and_initiate_n3()
    lab_control.capture_and_apply_slice_marks()


def teardown() -> None:
    pass  # não altera configuração; o próximo cenário faz o próprio setup


def traffic_plan() -> list[dict]:
    return [
        {"label": "urllc", "netns": "ue-urllc", "iface": "tun_srsue", "dest": "10.45.1.1", "profile": "latency"},
        {"label": "embb", "netns": "ue-embb", "iface": "tun_srsue", "dest": "10.45.0.1", "profile": "throughput_tcp"},
        {"label": "miot", "netns": "ue-miot", "iface": "tun_srsue", "dest": "10.45.2.1", "profile": "throughput_udp_sparse", "port": 5202},
    ]
