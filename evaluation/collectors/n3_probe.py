#!/usr/bin/env python3
"""Sonda de latência direto no N3, sem passar pelo rádio.

**Por que existe em paralelo às sondas de tráfego.** As sondas de
`traffic.py` atravessam o rádio simulado (netns da UE, `tun_srsue`,
destino 10.45.x.x) — é o caminho fim a fim que o cenário quer
representar. Mas o rádio por ZMQ tem RTT de ~57 ms e teto de
0,65 Mbps, enquanto o túnel N3 direto (`cu-ns` ↔ `5gc-edge-ns`) tem RTT
de ~0,1 ms. Medido na Fase A: **cerca de 580× de diferença de
resolução**.

A consequência prática é que um evento de rotação, que a Fase A mediu
entre 417 µs de sobreposição e ~1,8 ms de interrupção, **é invisível
pelo rádio** — fica afogado no ruído de 57 ms. As duas sondas respondem
perguntas diferentes e por isso rodam juntas:

| Sonda | Caminho | Responde |
| --- | --- | --- |
| `traffic.py` | UE → rádio → N3 → UPF | o usuário sente a rotação? |
| esta | CU → N3 → UPF | a rotação interrompe o túnel, e por quanto? |

**Taxa de 100 Hz, não 1 kHz.** A sonda da Fase A usa 1 kHz porque lá o
objetivo é dimensionar um evento isolado. Aqui ela roda pela janela
inteira de coleta (300 s na campanha), e 1 kHz geraria 300 mil eventos
por execução por fatia. A 100 Hz são 30 mil, que ainda resolve a
interrupção de ~1,8 ms com 2-3 amostras e mantém o `.jsonl` utilizável.
A caracterização fina do evento é trabalho da Fase A, não desta sonda.

Reusa o `PingProbe` de `phase_a/rekey_traffic.py` em vez de reimplementar:
ele já trata o desenrolamento do `icmp_seq` de 16 bits (que a 100 Hz dá a
volta a cada 655 s, dentro de uma janela de campanha longa) e lê a saída
linha a linha numa thread, sem o que o ping bloqueia quando o pipe enche.
"""

from __future__ import annotations

import threading
from typing import Optional

from evaluation.instrumentation import emit

# Endereços internos das duas pontas do N3 — os mesmos que a Fase A usa.
# São locais de cada netns e só se alcançam ATRAVÉS do túnel, então
# tráfego entre eles é necessariamente tráfego cifrado pelo IPsec.
CU_NETNS, EDGE_NETNS = "cu-ns", "5gc-edge-ns"
CU_ADDR, EDGE_ADDR = "172.18.0.99", "172.18.0.90"


class N3LatencyProbe:
    """`ping` contínuo pelo túnel N3, emitindo cada amostra.

    Emite por amostra, e não só o resumo, porque o uso principal é
    CORRELACIONAR: casar o instante de um `xfrm_event` ou de um
    `rotation_enqueued` com o pico de RTT que ele causou. Um resumo em
    percentis responde "quanto piorou", nunca "foi esta rotação que
    piorou".
    """

    def __init__(self, interval_seconds: float = 0.01, label: str = "n3"):
        self._interval = interval_seconds
        self._label = label
        self._probe = None
        self._thread: Optional[threading.Thread] = None
        self._stop = threading.Event()

    def start(self) -> None:
        from evaluation.phase_a.rekey_traffic import PingProbe

        self._probe = PingProbe(CU_NETNS, CU_ADDR, EDGE_ADDR, self._interval)
        self._probe.start()
        self._thread = threading.Thread(target=self._drena, daemon=True)
        self._thread.start()

    def _drena(self) -> None:
        """Converte as amostras acumuladas em eventos.

        O `PingProbe` acumula numa lista; este laço consome o que chegou
        desde a última passagem. Sem isso, a lista cresceria pela janela
        inteira e os eventos só sairiam no `stop()` — tarde demais para
        um `.jsonl` lido em progresso, e com risco de perder tudo se a
        execução falhar no meio.
        """
        vistos = 0
        while not self._stop.wait(1.0):
            vistos = self._emite_novas(vistos)
        self._emite_novas(vistos)

    def _emite_novas(self, vistos: int) -> int:
        assert self._probe is not None
        amostras = self._probe.samples
        for s in amostras[vistos:]:
            emit("n3_latency_sample", label=self._label,
                 wall_ts=s.ts, seq=s.seq, rtt_ms=s.rtt_ms)
        return len(amostras)

    def stop(self) -> None:
        self._stop.set()
        if self._probe is not None:
            self._probe.stop()
        if self._thread is not None:
            self._thread.join(timeout=5)
        if self._probe is None or not self._probe.samples:
            return
        rtts = sorted(s.rtt_ms for s in self._probe.samples)
        seqs = [s.seq for s in self._probe.samples]
        esperados = seqs[-1] - seqs[0] + 1

        def p(q: float) -> float:
            return rtts[min(len(rtts) - 1, int(round(q * (len(rtts) - 1))))]

        emit("n3_latency_summary", label=self._label,
             samples=len(rtts), expected=esperados, lost=esperados - len(rtts),
             rtt_p50_ms=p(0.50), rtt_p95_ms=p(0.95), rtt_p99_ms=p(0.99),
             rtt_min_ms=rtts[0], rtt_max_ms=rtts[-1],
             interval_seconds=self._interval)
