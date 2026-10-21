"""Cenário C2 — proteção máxima sem critério.

Três SAs, uma por fatia, mas **todas com o perfil da fatia mais
exigente** (K5: AES-256-GCM, x25519 + ML-KEM-768 híbrido, PPK de QKD) e
**todas com os prazos de rotação mais curtos** (os da URLLC). Mede o
custo de proteger tudo no máximo em vez de diferenciar: CPU no plano de
dados, round-trip extra do híbrido em todo handshake, e consumo de QKD
triplicado.

É o contraponto superior à proposta — mais seguro que C3 em toda fatia,
e é justamente isso que se quer mostrar custando caro. C1 é o
contraponto inferior (um túnel para tudo).

**Substitui o antigo "diferenciado por fatia + EDF".** Naquele desenho o
EDF era um cenário próprio; na especificação atual ele virou **variante
de política** de C4a e C4b, onde há disputa e portanto onde a política
faz diferença. Comparar risk-aware com EDF sem disputa não mede nada: as
duas chegam à mesma ordem quando a fila tem no máximo uma tarefa.

O perfil uniforme é aplicado em `setup()` e desfeito em `teardown()`
pelo `connections.conf` versionado — ver
`lab_control.restore_versioned_n3_config` para por que a recuperação vem
do git e não de um backup em memória.
"""

from __future__ import annotations

from evaluation import lab_control
from evaluation.rotation_driver import TR_CHILD_SECONDS, TR_PPK_SECONDS
from kms.models import SliceType
from scheduler.models import SchedulingPolicy

NAME = "cenario2_protecao_maxima"

# Sem disputa a política é indiferente (ver docstring). Fica risk-aware
# para não introduzir uma segunda variável entre C2 e C3.
scheduling_policy = SchedulingPolicy.RISK_AWARE

# Perfil da URLLC (K5) para as três. O `ke1_` é necessário porque o
# híbrido tem dois KE na mesma negociação (RFC 9370); o ML-KEM puro
# dispensaria o grupo clássico, mas aqui o ponto é usar o perfil mais
# forte, não o mais enxuto.
IKE_PROPOSAL = "aes256gcm16-prfsha256-curve25519-ke1_mlkem768"
ESP_PROPOSAL = "aes256gcm16-ke1_mlkem768"

# Prazos da URLLC para todas as fatias. Isto é o que torna o cenário
# caro em QKD: a demanda passa de 256/30 + 256/90 + 256/180 ≈ 12,8 bit/s
# para 3 × 256/30 ≈ 25,6 bit/s, acima do que a QKDN entrega.
tr_child = {s: TR_CHILD_SECONDS[SliceType.URLLC] for s in SliceType}
tr_ppk = {s: TR_PPK_SECONDS[SliceType.URLLC] for s in SliceType}


def setup() -> None:
    # Garante o perfil por-fatia versionado ANTES de medir. C1 e C2
    # mutam o connections.conf vivo e desfazem no teardown; uma campanha
    # interrompida no meio de um deles deixaria este cenário medindo o
    # perfil do anterior, em silêncio. Custo nulo quando já está certo.
    lab_control.ensure_versioned_n3_config()
    lab_control.restart_ipsec_lab(("cu-ns", "5gc-edge-ns"))
    lab_control.load_and_initiate_n3()
    # Depois do load: aplicar o perfil uniforme reinicia o IPsec de novo,
    # e os marks têm de ser (re)aplicados DEPOIS disso, senão as regras
    # `mangle` ficam órfãs e o tráfego sai sem mark.
    lab_control.apply_uniform_n3_profile(IKE_PROPOSAL, ESP_PROPOSAL)
    lab_control.capture_and_apply_slice_marks()


def teardown() -> None:
    # Devolve o perfil por fatia, senão o próximo cenário mede C2 sem
    # saber. Os outros cenários têm teardown vazio porque não alteram a
    # config; este altera.
    lab_control.restore_versioned_n3_config()


def traffic_plan() -> list[dict]:
    return [
        {"label": "urllc", "netns": "ue-urllc", "iface": "tun_srsue", "dest": "10.45.1.1", "profile": "latency"},
        {"label": "embb", "netns": "ue-embb", "iface": "tun_srsue", "dest": "10.45.0.1", "profile": "throughput_tcp"},
        {"label": "miot", "netns": "ue-miot", "iface": "tun_srsue", "dest": "10.45.2.1", "profile": "throughput_udp_sparse", "port": 5202},
    ]
