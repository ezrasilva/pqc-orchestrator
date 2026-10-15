#!/usr/bin/env python3
"""BB84 sobre **SeQUeNCe** — substituto do `bb84_att.py` do QuDitto, que
depende do NetSquid.

**Por que existe**: o NetSquid não está no PyPI público e o índice privado
(`pypi.netsquid.org`) exige conta; as credenciais que vinham no repositório
do laboratório passaram a retornar HTTP 401. O SeQUeNCe (Argonne/
Northwestern) é aberto, instala direto do PyPI e traz BB84 + Cascade
prontos, então serve de backend sem mudar nada no QuDitto além de qual
script o `config.yaml` aponta.

**Por que a troca é localizada**: o `controller.py` do QuDitto NÃO importa
o simulador — ele invoca o protocolo como subprocesso e lê JSON do stdout:

    command = ['python3', <protocol>, <key_length>, <distance_km>, <params.yaml>]
    output  = json.loads(result.stdout)   # alice_key, bob_key, time

Este arquivo implementa exatamente esse contrato. Só os scripts de
protocolo do `qd2_controller` importam netsquid, e eles deixam de ser
chamados quando o `config.yaml` aponta para cá.

**Por que BB84 + Cascade, e não BB84 sozinho**: medido contra o SeQUeNCe —
o BB84 cru entrega chaves que DIFEREM entre Alice e Bob (QBER real do
canal; ~1,4% a 20 km, 3 bits divergentes numa chave de 128). Para uso como
PPK (RFC 8784) as duas pontas precisam da chave idêntica, senão a
autenticação do IKE falha. A pilha com Cascade (reconciliação de erro)
devolve chaves iguais — verificado, 0 bits divergentes.
"""

from __future__ import annotations

import json
import sys

import yaml
from sequence.components.optical_channel import ClassicalChannel, QuantumChannel
from sequence.kernel.timeline import Timeline
from sequence.qkd.BB84 import pair_bb84_protocols
from sequence.qkd.cascade import pair_cascade_protocols
from sequence.topology.node import QKDNode

# Padrões de fibra usados quando o params.yaml não traz o valor. 0,2 dB/km
# é a atenuação típica de fibra monomodo em 1550 nm.
DEFAULT_ATTENUATION_DB_KM = 0.2
DEFAULT_POLARIZATION_FIDELITY = 0.97
# Teto da simulação em ps. Precisa cobrir a reconciliação, que domina o
# tempo simulado (0,19 s para 128 bits a 20 km).
SIM_STOP_PS = 1e13


class KeyManager:
    """Recebe as chaves prontas do topo da pilha (Cascade).

    O SeQUeNCe entrega chave "para cima" por `pop`, mas a assinatura
    difere conforme a camada: o BB84 passa posicional, o Cascade passa
    `key=`. Como aqui o gerente fica sobre o Cascade, a assinatura é
    nomeada — montar sobre o BB84 direto quebra com
    `TypeError: pop() got an unexpected keyword argument 'key'`.
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

    def pop(self, key: int) -> None:
        self.keys.append(key)
        self.times.append(self.timeline.now() * 1e-12)  # ps -> s


def _int_to_bits(value: int, length: int) -> list[int]:
    """Int -> lista de bits (MSB primeiro), com zeros à esquerda.

    O `controller.py` do QuDitto concatena a lista num string de bits
    (`str(key).replace("[","")...`), então a largura fixa importa: sem o
    preenchimento, uma chave que comece com zero sairia curta e o
    controller pediria uma simulação a mais sem necessidade.
    """
    return [int(b) for b in format(value, f"0{length}b")]


def run_bb84(key_length: int, distance_km: float, params: dict) -> dict:
    attenuation_db_km = float(params.get("attenuation", DEFAULT_ATTENUATION_DB_KM))
    polarization_fidelity = float(
        params.get("polarization_fidelity", DEFAULT_POLARIZATION_FIDELITY)
    )

    timeline = Timeline(SIM_STOP_PS)
    alice = QKDNode("alice", timeline, stack_size=2)  # BB84 + Cascade
    bob = QKDNode("bob", timeline, stack_size=2)
    alice.set_seed(params.get("seed_alice", 0))
    bob.set_seed(params.get("seed_bob", 1))

    pair_bb84_protocols(alice.protocol_stack[0], bob.protocol_stack[0])
    pair_cascade_protocols(alice.protocol_stack[1], bob.protocol_stack[1])

    distance_m = distance_km * 1000
    attenuation_db_m = attenuation_db_km / 1000  # SeQUeNCe usa dB/m

    for name, src, dst in (("qc.a.b", alice, bob), ("qc.b.a", bob, alice)):
        qchannel = QuantumChannel(
            name, timeline, attenuation=attenuation_db_m, distance=distance_m,
            polarization_fidelity=polarization_fidelity,
        )
        qchannel.set_ends(src, dst.name)

    for name, src, dst in (("cc.a.b", alice, bob), ("cc.b.a", bob, alice)):
        cchannel = ClassicalChannel(name, timeline, distance=distance_m)
        cchannel.set_ends(src, dst.name)

    km_alice = KeyManager(timeline, key_length, 1)
    km_alice.lower_protocols.append(alice.protocol_stack[1])
    alice.protocol_stack[1].upper_protocols.append(km_alice)

    km_bob = KeyManager(timeline, key_length, 1)
    km_bob.lower_protocols.append(bob.protocol_stack[1])
    bob.protocol_stack[1].upper_protocols.append(km_bob)

    timeline.init()
    km_alice.send_request()
    timeline.run()

    if not km_alice.keys or not km_bob.keys:
        # Sem chave: o controller trata a ausência das chaves no JSON como
        # erro e registra no log dele, em vez de travar.
        return {"alice_key": [], "bob_key": [], "time": 0.0,
                "error": "simulação terminou sem produzir chave"}

    return {
        "alice_key": _int_to_bits(km_alice.keys[0], key_length),
        "bob_key": _int_to_bits(km_bob.keys[0], key_length),
        "time": km_alice.times[0],
        # QBER medido pelo próprio BB84 — não faz parte do contrato do
        # QuDitto, mas sai no JSON porque a campanha quer caracterizar a
        # fonte de entropia (R_qkd), e o controller ignora chaves extras.
        "error_rates": list(getattr(alice.protocol_stack[0], "error_rates", [])),
    }


def main() -> int:
    if len(sys.argv) != 4:
        print(json.dumps({"error": f"uso: {sys.argv[0]} <key_length> <distance_km> <params.yaml>"}))
        return 2

    key_length = int(sys.argv[1])
    distance_km = float(sys.argv[2])
    with open(sys.argv[3]) as handle:
        params = yaml.safe_load(handle) or {}

    print(json.dumps(run_bb84(key_length, distance_km, params)))
    return 0


if __name__ == "__main__":
    sys.exit(main())
