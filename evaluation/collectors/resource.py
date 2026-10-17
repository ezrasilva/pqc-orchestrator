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


# Processos do testbed que competem por CPU com o orquestrador e com a
# simulação de QKD. Casados por nome porque eles são iniciados fora do
# experimento (pelo watchdog do laboratório), então o PID muda entre
# campanhas e não dá para configurar à mão.
#
# **Por que medir estes.** A simulação BB84+Cascade da QKDN é CPU-bound e
# disputa os mesmos 8 núcleos: medido, a chave de 256 bits passa de
# 15,2 s com o rádio parado para 38-39 s com ele rodando, o que derruba
# o R_qkd de 16,8 para ~6,6 bit/s. Sem registrar a CPU destes processos
# junto de cada execução, não há como saber em que ponto dessa faixa a
# execução estava — e a razão demanda/oferta de QKD determina quais
# fatias são rebaixadas.
TESTBED_PROCESS_NAMES = ("gnb", "srsue", "open5gs-upfd", "open5gs-smfd")

# Subconjunto que a premissa da Fase A exclui: ela é especificada "sem
# OCUDU nem srsUE". O Open5GS fica de fora desta lista de propósito — é
# o núcleo, não o rádio, e não aparece entre os consumidores de CPU
# (medido: gNB a 203%, três srsUE a ~70% cada, Open5GS ausente do topo).
# Confundir os dois faria o aviso da Fase A disparar sempre, inclusive
# quando a condição estivesse correta, e um aviso que sempre dispara
# deixa de ser lido.
RADIO_PROCESS_NAMES = ("gnb", "srsue")


def find_pids_by_name(names: tuple[str, ...] = TESTBED_PROCESS_NAMES) -> dict[str, int]:
    """Resolve `{label: pid}` para os processos do testbed.

    Quando há mais de um processo com o mesmo nome (três `srsue`, um por
    fatia), o label recebe sufixo numérico — `srsue`, `srsue-2`,
    `srsue-3` — na ordem de PID, que é estável dentro de uma campanha.
    Agregar os três numa só linha esconderia uma UE consumindo o dobro
    das outras, que é informação útil quando o rádio satura.
    """
    encontrados: dict[str, int] = {}
    for nome in names:
        saida = subprocess.run(["pgrep", "-x", nome], capture_output=True, text=True).stdout
        pids = sorted(int(p) for p in saida.split() if p.isdigit())
        for i, pid in enumerate(pids, start=1):
            label = nome if i == 1 else f"{nome}-{i}"
            encontrados[label] = pid
    return encontrados


class SoftirqPoller:
    """Amostra os contadores de CPU de `/proc/stat`, com foco em softirq.

    **Por que softirq precisa de um coletor próprio.** A cifragem do ESP
    roda no kernel, em contexto de softirq, disparada pela pilha de rede
    — nenhum processo de userspace é creditado por ela, então o
    `pidstat` do `ResourcePoller` não a vê. Medido na A.3: o softirq
    sobe de 31,4% sem IPsec para 36,4% com AES-128-GCM saturando o N3.

    `/proc/stat` é global do hospedeiro, não por netns. Isso é aceitável
    porque o `idle` vai junto no evento, o que permite checar depois se a
    premissa de "o resto da máquina estava quieto" valia naquela
    execução — premissa que, nesta VM, já se mostrou falsa (load 16 em 8
    núcleos com o rádio rodando).
    """

    def __init__(self, interval_seconds: float = 1.0):
        self._interval = interval_seconds
        self._stop = threading.Event()
        self._thread: Optional[threading.Thread] = None

    def _loop(self) -> None:
        from evaluation.phase_a.dataplane import read_softirq_jiffies

        anterior = read_softirq_jiffies()
        while not self._stop.wait(self._interval):
            atual = read_softirq_jiffies()
            delta = {k: atual[k] - anterior[k] for k in anterior}
            total = sum(delta.values())
            anterior = atual
            if total <= 0:
                continue
            # Percentual do intervalo, não jiffies acumulados: é o que se
            # compara entre execuções de duração diferente.
            emit("cpu_softirq_snapshot",
                 **{f"{k}_percent": 100.0 * v / total for k, v in delta.items()},
                 total_jiffies=total)

    def start(self) -> None:
        self._stop.clear()
        self._thread = threading.Thread(target=self._loop, daemon=True)
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()
        if self._thread is not None:
            self._thread.join(timeout=self._interval + 2)


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
