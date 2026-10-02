"""Coletor de contadores de classificação por fatia — ver
CENARIOS-TESTE-AVALIACAO.md seção 6, que aponta
`prototype/ebpf_classifier/loader.py` (`read_stats`) como fonte.

**Desvio deliberado do documento, documentado aqui**: o classificador
eBPF/TC do Módulo 3 não é o mecanismo que está de pé no laboratório —
ver `prototype/ebpf_classifier/README.md` e
`docs/ARQUITETURA-PROTOTIPO-COMPLETA.md` seção 4.1 (achado crítico #1):
TC egress não influencia a seleção de SA pra tráfego gerado localmente
pela CU, então a Fase 3 em diante usa `iptables -t mangle -A OUTPUT`
(regras `u32` por TEID) como o ponto real de marcação — confirmado
agora mesmo contra o laboratório: `tc filter show ... egress` não
mostra nada anexado, só as três regras `mangle OUTPUT`. Ler
`read_stats()` do classificador eBPF leria um programa que não está
rodando. Este coletor lê os contadores reais: `iptables -t mangle -L
OUTPUT -v -n -x` (o `-x` evita valores abreviados tipo "1.2K" que
quebrariam o parse)."""

from __future__ import annotations

import re
import subprocess
import threading
from dataclasses import dataclass
from typing import Optional

from evaluation.instrumentation import emit

_RULE_RE = re.compile(
    r"^\s*(?P<pkts>\d+)\s+(?P<bytes>\d+)\s+MARK\s+\S+.*?"
    r'u32 "(?P<u32_expr>[^"]+)".*?MARK set (?P<mark>0x[0-9a-f]+)',
    re.MULTILINE,
)


@dataclass
class MarkCounters:
    mark: str
    u32_expr: str
    packets: int
    bytes: int


def read_classification_counters(netns: str = "cu-ns") -> list[MarkCounters]:
    result = subprocess.run(
        ["ip", "netns", "exec", netns, "iptables", "-t", "mangle", "-L", "OUTPUT", "-v", "-n", "-x"],
        capture_output=True, text=True, check=True,
    )
    return [
        MarkCounters(
            mark=m.group("mark"), u32_expr=m.group("u32_expr"),
            packets=int(m.group("pkts")), bytes=int(m.group("bytes")),
        )
        for m in _RULE_RE.finditer(result.stdout)
    ]


class ClassificationStatsPoller:
    def __init__(self, netns: str = "cu-ns", interval_seconds: float = 0.5):
        self._netns = netns
        self._interval = interval_seconds
        self._stop = threading.Event()
        self._thread: Optional[threading.Thread] = None

    def _loop(self) -> None:
        while not self._stop.is_set():
            try:
                for mc in read_classification_counters(self._netns):
                    emit(
                        "classification_snapshot",
                        mark=mc.mark, u32_expr=mc.u32_expr,
                        packets=mc.packets, bytes=mc.bytes,
                    )
            except subprocess.CalledProcessError:
                pass
            self._stop.wait(self._interval)

    def start(self) -> None:
        self._stop.clear()
        self._thread = threading.Thread(target=self._loop, daemon=True)
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()
        if self._thread is not None:
            self._thread.join(timeout=self._interval * 2)
