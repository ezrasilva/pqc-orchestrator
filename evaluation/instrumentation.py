"""Instrumentação leve pro pipeline de coleta experimental — ver
CENARIOS-TESTE-AVALIACAO.md seção 6 ("Mapeamento com o repositório").

Cada evento é uma linha JSON (`{"ts": <epoch float>, "run_id": ..., "event": ...,
**campos}`) escrita num arquivo compartilhado por execução — formato
trivial de concatenar entre os três processos que emitem eventos
(scheduler/policy.py, kms/crypto.py, ipsec_agent/agent.py) sem precisar
de um barramento de mensagens só pra isso.

**Decisão de design**: em vez de instrumentar os módulos do orquestrador
direto com `print`/logging formatado (acoplando lógica de negócio a
detalhe de coleta), cada módulo chama `evaluation.instrumentation.emit()`
— uma função pura, sem estado por padrão (`NullSink`), que vira um sink
de verdade (`FileSink`) só quando `configure()` é chamado no início de um
run. Fora de um experimento (uso normal do orquestrador, testes
unitários), `emit()` não faz nada — custo zero, sem arquivo de log
poluindo o diretório de trabalho à toa.
"""

from __future__ import annotations

import json
import threading
import time
from contextlib import contextmanager
from pathlib import Path
from typing import Optional


class _Sink:
    def write(self, record: dict) -> None:  # pragma: no cover - interface
        raise NotImplementedError


class NullSink(_Sink):
    def write(self, record: dict) -> None:
        pass


class FileSink(_Sink):
    def __init__(self, path: Path):
        self._path = Path(path)
        self._path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()
        self._fh = open(self._path, "a", buffering=1)  # line-buffered

    def write(self, record: dict) -> None:
        line = json.dumps(record, default=str)
        with self._lock:
            self._fh.write(line + "\n")

    def close(self) -> None:
        with self._lock:
            self._fh.close()


_state = threading.local()
_default_sink: _Sink = NullSink()
_default_run_id: Optional[str] = None
_lock = threading.Lock()


def configure(path: Path, run_id: str) -> FileSink:
    """Chamado uma vez no início de um run pelo orquestrador
    (`evaluation/run_experiment.py`) — depois disso, `emit()` chamado de
    qualquer módulo/thread escreve nesse arquivo."""
    global _default_sink, _default_run_id
    sink = FileSink(path)
    with _lock:
        _default_sink = sink
        _default_run_id = run_id
    return sink


def reset() -> None:
    """Volta pro NullSink — usado nos testes, pra não vazar estado entre
    casos de teste nem entre runs de experimento diferentes."""
    global _default_sink, _default_run_id
    with _lock:
        if isinstance(_default_sink, FileSink):
            _default_sink.close()
        _default_sink = NullSink()
        _default_run_id = None


def emit(event: str, **fields) -> None:
    with _lock:
        sink = _default_sink
        run_id = _default_run_id
    sink.write({"ts": time.time(), "run_id": run_id, "event": event, **fields})


@contextmanager
def timed(event: str, **fields):
    """Emite `<event>_start` e `<event>_end` com `duration_seconds` —
    usado nos três pontos da seção 6 que precisam de duração, não só um
    timestamp isolado (geração de material PQC, espera por SPI novo)."""
    start = time.monotonic()
    emit(f"{event}_start", **fields)
    try:
        yield
    finally:
        duration = time.monotonic() - start
        emit(f"{event}_end", duration_seconds=duration, **fields)
