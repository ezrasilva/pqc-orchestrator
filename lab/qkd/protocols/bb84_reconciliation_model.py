#!/usr/bin/env python3
"""BB84 fotônico simulado + reconciliação **modelada** pelo vazamento.

Mesmo contrato do `bb84_sequence.py` (argv: key_length, distance_km,
params.yaml; stdout: JSON com alice_key, bob_key, time), mas ~40× mais
rápido. Os dois coexistem de propósito:

* `bb84_sequence.py` — BB84 **+ Cascade simulado passo a passo**. É o
  script da CARACTERIZAÇÃO: roda poucas vezes para o artigo reportar
  QBER, taxa de chave e custo de reconciliação medidos num Cascade de
  verdade.
* este — BB84 simulado + reconciliação modelada. É o script da
  CAMPANHA, que precisa de centenas de chaves.

**Onde está o custo, medido (17/10, dentro do container):**

| Pilha | Parede por chave de 256 bits |
| --- | --- |
| BB84 fotônico sozinho | **0,84 s** |
| BB84 + Cascade simulado | **28,7 s** |

Ou seja **97% do custo é o Cascade**, e não a simulação do canal
quântico. Esse custo não é física: é o preço de simular cada passagem do
Cascade como eventos discretos de mensagens clássicas atravessando
20 km. A física que justifica o QBER e a taxa de chave está no BB84.

**O que este script preserva e o que ele modela.** Preserva, por
simulação de evento discreto: atenuação da fibra, perda de fóton,
fidelidade de polarização, peneiramento de base e, como consequência, o
**QBER medido** — não postulado. Modela: a reconciliação de erro, pelo
seu VAZAMENTO DE INFORMAÇÃO em vez de pela troca de mensagens.

O modelo é o padrão da literatura de QKD. Com `n` bits peneirados e QBER
`e`:

* o Cascade revela cerca de `f · n · h₂(e)` bits de paridade, onde
  `h₂` é a entropia binária e `f ≳ 1` é a eficiência da reconciliação
  (1,16 é o valor usual citado para o Cascade);
* o canal já dá a Eve até `n · h₂(e)` bits;
* a amplificação de privacidade comprime o resultado, deixando a taxa
  secreta assintótica `r = 1 − (1 + f) · h₂(e)` (Shor–Preskill com
  ineficiência de reconciliação).

Então o script pede ao BB84 bits peneirados suficientes, corrige a chave
de Bob para a de Alice, **cobra** o vazamento encurtando a chave, e
extrai os bits finais com SHAKE256 — que faz o papel da amplificação de
privacidade e é o que garante que as duas pontas derivem exatamente a
mesma chave final.

**O que isto NÃO autoriza afirmar.** Que a reconciliação foi executada.
Ela não foi: o número de passagens, as mensagens trocadas e a latência
do Cascade não são simulados aqui. O artigo tem de declarar isso, e é
por isso que o script do Cascade real continua no repositório — a
caracterização com ele é o que justifica os parâmetros usados aqui.
"""

from __future__ import annotations

import hashlib
import json
import math
import sys
import time

import yaml
from sequence.components.optical_channel import ClassicalChannel, QuantumChannel
from sequence.kernel.timeline import Timeline
from sequence.qkd.BB84 import pair_bb84_protocols
from sequence.topology.node import QKDNode

DEFAULT_ATTENUATION_DB_KM = 0.2
DEFAULT_POLARIZATION_FIDELITY = 0.97
SIM_STOP_PS = 1e13
# Eficiência da reconciliação do Cascade. 1,16 é o valor citado com mais
# frequência; sobrescrevível pelo params.yaml para o artigo poder usar o
# valor que a própria caracterização com Cascade real medir.
DEFAULT_RECONCILIATION_EFFICIENCY = 1.16
# QBER esperado, usado para DIMENSIONAR quantos bits peneirados pedir ao
# BB84. Medido ~0,014 a 20 km com fidelidade 0,97; 0,03 dá margem sem
# inflar o custo.
#
# **Por que não dimensionar pelo pior caso.** A primeira versão usava um
# teto de 8%, que exige 1954 bits peneirados para render 256 secretos —
# 7,6× mais trabalho de BB84 e 7,7 s por chave, jogando fora quase toda
# a economia. Com 0,03 são ~440 bits e ~1,5 s. Quando o QBER medido
# surpreende, uma segunda passagem resolve, e isso é raro por
# construção.
DEFAULT_EXPECTED_QBER = 0.03
# Margem sobre o dimensionamento, para a maioria dos casos resolver numa
# passagem mesmo com a variação natural do QBER entre execuções.
SIZING_MARGIN = 1.15


def binary_entropy(e: float) -> float:
    if e <= 0.0 or e >= 1.0:
        return 0.0
    return -e * math.log2(e) - (1 - e) * math.log2(1 - e)


def secret_fraction(qber: float, efficiency: float) -> float:
    """Fração dos bits peneirados que sobra como chave secreta."""
    return 1.0 - (1.0 + efficiency) * binary_entropy(qber)


class KeyManager:
    """Recebe as chaves do BB84 (stack_size=1).

    A assinatura é `info=` porque é assim que o BB84 entrega
    (`self._pop(info=self.key)` em sequence/qkd/BB84.py); o Cascade
    entrega por `key=`. Trocar as duas quebra com
    `TypeError: pop() got an unexpected keyword argument`, e o nome certo
    depende de QUAL camada fica abaixo do gerente — por isso o script
    com Cascade usa `key=` e este usa `info=`.
    """

    def __init__(self, timeline: Timeline, keysize: int, num_keys: int):
        self.timeline = timeline
        self.lower_protocols = []
        self.keysize = keysize
        self.num_keys = num_keys
        self.keys: list[int] = []
        self.times: list[float] = []

    def send_request(self) -> None:
        for protocol in self.lower_protocols:
            protocol.push(self.keysize, self.num_keys)

    def pop(self, info: int) -> None:
        self.keys.append(info)
        self.times.append(self.timeline.now() * 1e-12)


def _bits(value: int, length: int) -> list[int]:
    return [int(b) for b in format(value, f"0{length}b")]


def run_bb84_sifted(n_sifted: int, distance_km: float, params: dict) -> dict:
    """Roda só o BB84 (sem Cascade) e devolve as duas chaves peneiradas."""
    attenuation_db_km = float(params.get("attenuation", DEFAULT_ATTENUATION_DB_KM))
    polarization_fidelity = float(
        params.get("polarization_fidelity", DEFAULT_POLARIZATION_FIDELITY))

    timeline = Timeline(SIM_STOP_PS)
    alice = QKDNode("alice", timeline, stack_size=1)
    bob = QKDNode("bob", timeline, stack_size=1)
    alice.set_seed(params.get("seed_alice", 0))
    bob.set_seed(params.get("seed_bob", 1))
    pair_bb84_protocols(alice.protocol_stack[0], bob.protocol_stack[0])

    distance_m = distance_km * 1000
    for nome, src, dst in (("qc.a.b", alice, bob), ("qc.b.a", bob, alice)):
        qc = QuantumChannel(nome, timeline, attenuation=attenuation_db_km / 1000,
                            distance=distance_m,
                            polarization_fidelity=polarization_fidelity)
        qc.set_ends(src, dst.name)
    for nome, src, dst in (("cc.a.b", alice, bob), ("cc.b.a", bob, alice)):
        cc = ClassicalChannel(nome, timeline, distance=distance_m)
        cc.set_ends(src, dst.name)

    km_a = KeyManager(timeline, n_sifted, 1)
    km_a.lower_protocols.append(alice.protocol_stack[0])
    alice.protocol_stack[0].upper_protocols.append(km_a)
    km_b = KeyManager(timeline, n_sifted, 1)
    km_b.lower_protocols.append(bob.protocol_stack[0])
    bob.protocol_stack[0].upper_protocols.append(km_b)

    timeline.init()
    km_a.send_request()
    timeline.run()

    if not km_a.keys or not km_b.keys:
        return {"erro": "BB84 terminou sem produzir chave peneirada"}
    return {
        "alice": km_a.keys[0],
        "bob": km_b.keys[0],
        "n": n_sifted,
        "sim_time": km_a.times[0],
        "error_rates": list(getattr(alice.protocol_stack[0], "error_rates", [])),
    }


def run(key_length: int, distance_km: float, params: dict) -> dict:
    efficiency = float(params.get("reconciliation_efficiency",
                                  DEFAULT_RECONCILIATION_EFFICIENCY))
    esperado = float(params.get("expected_qber", DEFAULT_EXPECTED_QBER))

    def dimensiona(qber: float) -> int:
        fracao = secret_fraction(qber, efficiency)
        if fracao <= 0:
            return 0
        return max(key_length, math.ceil(key_length * SIZING_MARGIN / fracao))

    t0 = time.time()
    n_sifted = dimensiona(esperado)
    if n_sifted == 0:
        return {"alice_key": [], "bob_key": [], "time": 0.0,
                "error": f"expected_qber={esperado} não admite chave secreta"}

    passagens = 0
    while True:
        passagens += 1
        cru = run_bb84_sifted(n_sifted, distance_km, params)
        if "erro" in cru:
            return {"alice_key": [], "bob_key": [], "time": 0.0, "error": cru["erro"]}

        a_bits = _bits(cru["alice"], n_sifted)
        b_bits = _bits(cru["bob"], n_sifted)
        qber = sum(1 for x, y in zip(a_bits, b_bits) if x != y) / n_sifted
        fracao = secret_fraction(qber, efficiency)
        if fracao <= 0:
            return {"alice_key": [], "bob_key": [], "time": 0.0,
                    "error": f"QBER medido de {qber:.4f} não admite chave secreta"}
        bits_secretos = int(n_sifted * fracao)
        if bits_secretos >= key_length:
            break
        if passagens >= 2:
            return {"alice_key": [], "bob_key": [], "time": 0.0,
                    "error": (f"QBER de {qber:.4f} rende {bits_secretos} bits secretos "
                              f"de {n_sifted} peneirados em 2 passagens")}
        # Redimensiona pelo QBER MEDIDO e tenta uma vez mais.
        n_sifted = dimensiona(qber)

    # Reconciliação: as duas pontas passam a ter a MESMA cadeia. O custo
    # de informação disso já está cobrado em `fracao`.
    reconciliada = bytes(int("".join(map(str, a_bits[i:i + 8])).ljust(8, "0"), 2)
                         for i in range(0, n_sifted, 8))
    # Amplificação de privacidade: extrai os bits finais. Determinística,
    # então as duas pontas derivam exatamente a mesma chave — requisito
    # do PPK, que falha na autenticação se divergir um bit.
    final = hashlib.shake_256(reconciliada).digest((key_length + 7) // 8)
    bits_finais = [int(b) for b in "".join(format(x, "08b") for x in final)][:key_length]

    return {
        "alice_key": bits_finais,
        "bob_key": bits_finais,
        "time": cru["sim_time"],
        # Campos extra: o QuDitto ignora, e a campanha quer caracterizar
        # a fonte de entropia.
        "qber": qber,
        "sifted_bits": n_sifted,
        "secret_fraction": fracao,
        "leaked_bits_modeled": int(n_sifted * efficiency * binary_entropy(qber)),
        "reconciliation": "modeled",
        "reconciliation_efficiency": efficiency,
        "wall_seconds": time.time() - t0,
        "sizing_passes": passagens,
        "error_rates": cru["error_rates"],
    }


def main() -> int:
    if len(sys.argv) != 4:
        print(json.dumps({"error": f"uso: {sys.argv[0]} <key_length> <distance_km> <params.yaml>"}))
        return 2
    with open(sys.argv[3]) as handle:
        params = yaml.safe_load(handle) or {}
    print(json.dumps(run(int(sys.argv[1]), float(sys.argv[2]), params)))
    return 0


if __name__ == "__main__":
    sys.exit(main())
