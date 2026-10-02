"""Coletor de CPU/memória — `pidstat -h -u -r` (ver
CENARIOS-TESTE-AVALIACAO.md seção C e 4). `-h` dá uma linha por amostra
com CPU e memória juntos (mais fácil de parsear que o formato padrão,
que intercala duas tabelas); `LC_ALL=C` evita separador decimal por
vírgula do locale pt-BR desta VM (achado ao testar — sem isso, "0,00"
quebraria o `float()`).

Monitora o `charon` de `cu-ns` (instância que o SMO/IPsec Agent falam
por VICI nos experimentos) e o próprio processo do experimento (onde
KMS/Scheduler/IPsec Agent/SMO rodam em processo, sem servidor gRPC
nesta fase — ver orchestrator/README.md)."""

from __future__ import annotations

import subprocess
import threading
from typing import Optional

from evaluation.instrumentation import emit


def find_charon_pid(netns: str) -> Optional[int]:
    out = subprocess.run(["ip", "netns", "pids", netns], capture_output=True, text=True, check=True).stdout.split()
    for pid in out:
        comm = subprocess.run(["ps", "-p", pid, "-o", "comm="], capture_output=True, text=True).stdout.strip()
        if comm == "charon":
            return int(pid)
    return None


class ResourcePoller:
    """`pids` é um dict `{label: pid}` — o label vira o campo `process`
    no evento emitido, pra diferenciar "charon" de "experiment" (o
    processo Python do próprio run_experiment.py) nos dados coletados."""

    def __init__(self, pids: dict[str, int], interval_seconds: int = 1):
        """`interval_seconds` precisa ser inteiro — `pidstat` rejeita
        frações (`1.0` gera erro de uso silencioso se stderr não for
        inspecionado, achado testando isto: `stderr=DEVNULL` escondia o
        "Usage: pidstat..." e o processo simplesmente não emitia nada)."""
        self._pids = pids
        self._interval = int(interval_seconds)
        self._proc: Optional[subprocess.Popen] = None
        self._thread: Optional[threading.Thread] = None
        self._stop = threading.Event()

    def _reader_loop(self) -> None:
        pid_to_label = {str(pid): label for label, pid in self._pids.items()}
        assert self._proc is not None and self._proc.stdout is not None
        for line in self._proc.stdout:
            line = line.strip()
            if not line or line.startswith("#") or line.startswith("Linux"):
                continue
            fields = line.split()
            # Time UID PID %usr %system %guest %wait %CPU CPU minflt/s majflt/s VSZ RSS %MEM Command
            if len(fields) < 14:
                continue
            pid_field = fields[2]
            label = pid_to_label.get(pid_field)
            if label is None:
                continue
            try:
                emit(
                    "resource_snapshot",
                    process=label,
                    pid=int(pid_field),
                    cpu_percent=float(fields[7]),
                    rss_kb=int(fields[12]),
                    mem_percent=float(fields[13]),
                )
            except (ValueError, IndexError):
                continue

    def start(self) -> None:
        if not self._pids:
            return
        pid_list = ",".join(str(p) for p in self._pids.values())
        env = {"LC_ALL": "C", "PATH": "/usr/bin:/bin"}
        # `stdbuf -oL` força saída por linha — sem isso, `pidstat` bloqueia
        # a saída em buffer de bloco (4KB) quando o stdout é um pipe (não
        # um terminal), e nada aparece até o buffer encher (achado
        # testando isto: sem stdbuf, nenhum evento era emitido em runs
        # curtos). Ver também coreutils `stdbuf`.
        self._proc = subprocess.Popen(
            ["stdbuf", "-oL", "pidstat", "-h", "-p", pid_list, "-u", "-r", str(self._interval)],
            stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True, env=env,
        )
        self._thread = threading.Thread(target=self._reader_loop, daemon=True)
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()
        if self._proc is not None:
            self._proc.terminate()
            try:
                self._proc.wait(timeout=2)
            except subprocess.TimeoutExpired:
                self._proc.kill()
        if self._thread is not None:
            self._thread.join(timeout=2)
