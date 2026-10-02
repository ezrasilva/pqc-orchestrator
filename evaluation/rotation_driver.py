"""Laço de decisão de rotação contínuo — generaliza
`orchestrator/scheduler/live_demo.py` (que fazia isso uma vez só, pra
demonstrar a Fase 5) pra rodar em background durante a janela de coleta
de um cenário inteiro (ver CENARIOS-TESTE-AVALIACAO.md). A cada
`check_interval_seconds`, lê a idade real das três SAs N3, calcula o
risco contra o SLA por fatia, enfileira e drena a fila pelo SmoCore —
usado pelos Cenários 2/3/4 (não pelo 0, sem IPsec; nem pelo 1, que tem
seu próprio laço de intervalo fixo em scenario1_static_pqc.py)."""

from __future__ import annotations

import re
import subprocess
import threading

from evaluation.collectors.resource import find_charon_pid
from kms.models import InterfaceType, SliceType
from scheduler.models import EnqueueTaskRequest
from scheduler.models import InterfaceType as SchedInterfaceType
from scheduler.models import SliceType as SchedSliceType
from scheduler.models import TaskPriority, TaskType

ROTATION_SLA_SECONDS: dict[SliceType, float] = {
    SliceType.URLLC: 300.0,
    SliceType.EMBB: 900.0,
    SliceType.MIOT: 1800.0,
}
ESTIMATED_ROTATION_COST_SECONDS = 2.0

CONN_NAME: dict[SliceType, str] = {
    SliceType.URLLC: "n3-urllc-cu-edge",
    SliceType.EMBB: "n3-embb-cu-edge",
    SliceType.MIOT: "n3-miot-cu-edge",
}

_AGE_RE = re.compile(r"installed (\d+)s ago")


def _read_sa_ages(charon_pid: int) -> dict[SliceType, float]:
    result = subprocess.run(
        ["nsenter", f"--mount=/proc/{charon_pid}/ns/mnt", f"--net=/proc/{charon_pid}/ns/net",
         "swanctl", "--list-sas"],
        capture_output=True, text=True,
    )
    ages = {}
    for slice, conn_name in CONN_NAME.items():
        block_match = re.search(
            rf"^  {re.escape(conn_name)}: .*?INSTALLED.*?(?=^  \S+: #|\Z)",
            result.stdout, re.MULTILINE | re.DOTALL,
        )
        if block_match:
            age_match = _AGE_RE.search(block_match.group(0))
            if age_match:
                ages[slice] = float(age_match.group(1))
    return ages


class RotationDriver:
    def __init__(self, smo, scheduler, netns: str = "cu-ns", check_interval_seconds: float = 10.0):
        self._smo = smo
        self._scheduler = scheduler
        self._netns = netns
        self._interval = check_interval_seconds
        self._stop = threading.Event()
        self._thread: "threading.Thread | None" = None

    def _tick(self) -> None:
        charon_pid = find_charon_pid(self._netns)
        if charon_pid is None:
            return
        ages = _read_sa_ages(charon_pid)
        for slice, age in ages.items():
            sla = ROTATION_SLA_SECONDS[slice]
            self._scheduler.enqueue_task(
                EnqueueTaskRequest(
                    slice=SchedSliceType(slice.value),
                    interface=SchedInterfaceType.N3,
                    task_type=TaskType.ROTATE,
                    priority=TaskPriority.NORMAL,
                    slack_seconds=sla - age,
                    estimated_cost_seconds=ESTIMATED_ROTATION_COST_SECONDS,
                    reason=f"idade atual {age:.0f}s / SLA {sla:.0f}s",
                )
            )
        # Drena a fila inteira neste tick — **achado testando isto**:
        # processar só 1 por tick (a de maior risco) acumulava fila sem
        # limite, porque o próximo tick enfileira mais 3 antes de
        # qualquer uma das anteriores ser consumida (queue_depth_after
        # crescia 2,4,6,8,10... numa execução de 15s). Isso também
        # significava que eMBB/mIoT NUNCA eram processadas de verdade —
        # URLLC sempre vence (slice_bonus domina), mas era só a cabeça
        # da fila que saía. Drenar tudo simula o SMO rodando
        # continuamente até a fila esvaziar — mais fiel ao fluxo
        # principal da arquitetura (seção "Fluxo — rotação de chave").
        while self._scheduler.queue_size() > 0:
            self._smo.process_next_task()

    def _loop(self) -> None:
        while not self._stop.wait(self._interval):
            try:
                self._tick()
            except Exception:
                pass  # não derruba o laço de coleta por uma falha pontual de leitura

    def start(self) -> None:
        self._stop.clear()
        self._thread = threading.Thread(target=self._loop, daemon=True)
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()
        if self._thread is not None:
            self._thread.join(timeout=self._interval + 2)
