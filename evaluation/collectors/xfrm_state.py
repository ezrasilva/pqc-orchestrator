"""Coletor de estado do kernel IPsec — `ip -s xfrm state`, amostrado a
cada 500ms (ver CENARIOS-TESTE-AVALIACAO.md seção 4, "Monitor do
Kernel"). Alimenta a métrica B.3 (verificação de isolamento/zero-
leakage: contadores de pacotes/bytes por SPI confirmando 100% do
tráfego de cada fatia na SA correspondente).

Roda num processo/thread separado do resto do experimento (`ip netns
exec` tem custo de syscall não-trivial pra rodar a 2Hz por muito tempo
dentro do mesmo processo que também está gerando tráfego/decidindo
rotação — melhor isolar)."""

from __future__ import annotations

import re
import subprocess
import threading
import time
from dataclasses import dataclass
from typing import Optional

from evaluation.instrumentation import emit

_STATE_BLOCK_RE = re.compile(
    r"^src (?P<src>\S+) dst (?P<dst>\S+)\n"
    r"\tproto esp spi (?P<spi>0x[0-9a-f]+).*?mode (?P<mode>\S+)\n"
    r"(?:.*?\n)*?"  # zero ou mais linhas (replay-window, mark, aead/enc, anti-replay, dir, lifetime config...)
    r"(?:\tmark (?P<mark>0x[0-9a-f]+)/\S+ ?\n(?:.*?\n)*?)?"
    r"\tlifetime current:\n"
    r"\t  (?P<bytes>\d+)\(bytes\), *(?P<packets>\d+)\(packets\)",
    re.MULTILINE,
)


@dataclass
class SaCounters:
    src: str
    dst: str
    spi: str
    mode: str
    mark: Optional[str]
    bytes: int
    packets: int


def read_xfrm_state(netns: str) -> list[SaCounters]:
    result = subprocess.run(
        ["ip", "netns", "exec", netns, "ip", "-s", "xfrm", "state"],
        capture_output=True, text=True, check=True,
    )
    counters = []
    for match in _STATE_BLOCK_RE.finditer(result.stdout):
        counters.append(
            SaCounters(
                src=match.group("src"),
                dst=match.group("dst"),
                spi=match.group("spi"),
                mode=match.group("mode"),
                mark=match.group("mark"),
                bytes=int(match.group("bytes")),
                packets=int(match.group("packets")),
            )
        )
    return counters


class XfrmStatePoller:
    """Thread de fundo: amostra `read_xfrm_state(netns)` a cada
    `interval_seconds` e emite um evento `xfrm_snapshot` por SA
    observada, via `evaluation.instrumentation.emit` (mesmo sink
    compartilhado do run atual)."""

    def __init__(self, netns: str = "cu-ns", interval_seconds: float = 0.5):
        self._netns = netns
        self._interval = interval_seconds
        self._stop = threading.Event()
        self._thread: Optional[threading.Thread] = None

    def _loop(self) -> None:
        while not self._stop.is_set():
            try:
                for sa in read_xfrm_state(self._netns):
                    emit(
                        "xfrm_snapshot",
                        src=sa.src, dst=sa.dst, spi=sa.spi, mode=sa.mode,
                        mark=sa.mark, bytes=sa.bytes, packets=sa.packets,
                    )
            except subprocess.CalledProcessError:
                pass  # netns pode não existir ainda/mais — ignora essa amostra
            self._stop.wait(self._interval)

    def start(self) -> None:
        self._stop.clear()
        self._thread = threading.Thread(target=self._loop, daemon=True)
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()
        if self._thread is not None:
            self._thread.join(timeout=self._interval * 2)
