#!/usr/bin/env python3
"""A.6 — eixo de RTT do enlace N3, via `tc qdisc netem`.

**Por que isto é um eixo e não um detalhe.** A primeira execução da A.1
(14/10, 6 perfis × 30 repetições) mostrou que o tempo de handshake quase
não varia entre perfis (p50 de 29 a 32 ms) enquanto os bytes no fio
variam 4×. Isso acontece porque a bancada tem RTT de ~0,1 ms: o
round-trip EXTRA que o híbrido exige (IKE_INTERMEDIATE) sai praticamente
de graça. Num backhaul N3 real, com 5–20 ms, essa troca adicional
custaria de 10 a 40 ms — o que inverte a conclusão justamente para a
URLLC, a fatia que o catálogo quer atender com K5 (híbrido + PPK).

Medir só a 0,1 ms levaria o artigo a concluir que "o híbrido é barato"
por artefato da bancada. O eixo de RTT separa as duas componentes do
custo:

* **processamento** — constante, medida a 0 ms;
* **protocolo** — proporcional ao número de trocas, só aparece com RTT
  realista.

**Onde o netem é pendurado.** O N3 é o par veth
`cu-ns:veth-cu-n2` ↔ `5gc-edge-ns:veth-edge-cu` (10.97.0.0/24). O netem
atua só na SAÍDA de cada interface, então o atraso é aplicado nos DOIS
lados: cada um atrasa o que manda. Daí o parâmetro ser "por sentido" —
`delay_ms=5` resulta em RTT de ~10 ms.

**Por que não `tc ... ingress`**: exigiria um `ifb` com redirecionamento,
mais peças para dar errado, e o resultado é o mesmo com egress nas duas
pontas — que é também o que descreve um enlace real (cada ponta paga a
propagação do que transmite).
"""

from __future__ import annotations

import subprocess

from evaluation.instrumentation import emit

# Interfaces de saída do enlace N3, por netns. O netem vai na raiz de
# cada uma; ver docstring do módulo para por que nos dois lados.
N3_INTERFACES = {
    "cu-ns": "veth-cu-n2",
    "5gc-edge-ns": "veth-edge-cu",
}


def _tc(netns: str, *args: str, check: bool = True) -> subprocess.CompletedProcess:
    return subprocess.run(
        ["ip", "netns", "exec", netns, "tc", *args],
        capture_output=True, text=True, check=check,
    )


def clear(netns: str | None = None) -> None:
    """Remove o netem. Idempotente — `check=False` porque remover um
    qdisc que não existe é erro no `tc`, e aqui isso é o caso normal
    (limpar antes de aplicar, e limpar no `finally`)."""
    for ns in ([netns] if netns else N3_INTERFACES):
        _tc(ns, "qdisc", "del", "dev", N3_INTERFACES[ns], "root", check=False)


def apply(delay_ms: float, jitter_ms: float = 0.0) -> None:
    """Aplica `delay_ms` de atraso POR SENTIDO no enlace N3.

    `delay_ms=0` só limpa: pendurar um netem de 0 ms ainda adicionaria o
    custo de enfileiramento do qdisc, o que contaminaria o ponto de
    referência da bancada pura justamente onde a resolução importa.
    """
    clear()
    if delay_ms <= 0:
        emit("phase_a_netem", delay_ms=0.0, applied=False,
             note="0 ms = sem qdisc, para não pagar o enfileiramento do netem")
        return

    for ns, dev in N3_INTERFACES.items():
        cmd = ["qdisc", "add", "dev", dev, "root", "netem", "delay", f"{delay_ms}ms"]
        if jitter_ms:
            cmd.append(f"{jitter_ms}ms")
        _tc(ns, *cmd)
    emit("phase_a_netem", delay_ms=delay_ms, jitter_ms=jitter_ms, applied=True,
         expected_rtt_ms=2 * delay_ms)


def measured_rtt_ms(count: int = 20) -> float | None:
    """RTT medido de fato pelo túnel, para registrar ao lado do valor
    pedido ao netem.

    **Por que medir em vez de confiar no parâmetro**: o atraso efetivo
    inclui o RTT de base da bancada (~0,1 ms) e o próprio custo do
    qdisc. Registrar os dois permite mostrar na tabela final que o eixo
    é o que se pretendia, em vez de pedir fé no `tc`.
    """
    from evaluation.phase_a.bench_n3 import CU_TS, EDGE_TS

    res = subprocess.run(
        ["ip", "netns", "exec", "cu-ns", "ping", "-n", "-q",
         "-c", str(count), "-i", "0.05",
         "-I", CU_TS.split("/")[0], EDGE_TS.split("/")[0]],
        capture_output=True, text=True,
    )
    for line in res.stdout.splitlines():
        if "min/avg/max" in line:
            # rtt min/avg/max/mdev = 0.063/0.098/0.145/0.021 ms
            return float(line.split("=")[1].strip().split("/")[1])
    return None
