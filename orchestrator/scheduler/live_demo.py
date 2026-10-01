"""Fase 5 do protótipo SBRC (ver docs/ARQUITETURA-PROTOTIPO-COMPLETA.md): liga
o SchedulerCore (fórmula de risco) às três SAs N3 reais do laboratório
(construídas nas Fases 3/4) pra decidir qual rotacionar primeiro — em vez
de rotação fixa/manual.

Não é o SMO (isso continua propositalmente não-implementado, ver
../README.md) — é a prova de que a fila de risco, aplicada a estado real
de SA (idade via `swanctl --list-sas`), produz a decisão certa e consegue
de fato disparar uma rotação via `swanctl --initiate`, a mesma chamada que
`load-and-initiate-n3.sh` usa.

Uso: sudo .venv/bin/python3 -m scheduler.live_demo
(precisa de root — fala com o charon isolado via nsenter, igual o resto
do laboratório).
"""

from __future__ import annotations

import re
import subprocess
import sys
from dataclasses import dataclass

from scheduler.models import (
    EnqueueTaskRequest,
    InterfaceType,
    SliceType,
    TaskPriority,
    TaskType,
)
from scheduler.service import SchedulerCore

# SLA de exemplo pra esta demo — não é uma política fixada em nenhum lugar
# da arquitetura, é só o "deve rotacionar a cada X segundos" que dá sentido
# a slack = sla - idade_atual. URLLC mais curto porque é a fatia crítica
# (mesmo raciocínio do slice_bonus em policy.py).
ROTATION_SLA_SECONDS: dict[SliceType, float] = {
    SliceType.URLLC: 300.0,
    SliceType.EMBB: 900.0,
    SliceType.MIOT: 1800.0,
}

# Visto empiricamente nos logs do charon desta VM (IKE_AUTH + CHILD_SA
# completos em bem menos de 1s pras três fatias) — arredondado com folga.
ESTIMATED_ROTATION_COST_SECONDS = 2.0

CONN_NAME: dict[SliceType, str] = {
    SliceType.URLLC: "n3-urllc-cu-edge",
    SliceType.EMBB: "n3-embb-cu-edge",
    SliceType.MIOT: "n3-miot-cu-edge",
}


@dataclass
class SaSnapshot:
    slice: SliceType
    conn_name: str
    age_seconds: float
    spi_out: str


def _find_charon_pid(ns: str) -> str:
    out = subprocess.run(
        ["ip", "netns", "pids", ns], capture_output=True, text=True, check=True
    ).stdout.split()
    for pid in out:
        comm = subprocess.run(
            ["ps", "-p", pid, "-o", "comm="], capture_output=True, text=True
        ).stdout.strip()
        if comm == "charon":
            return pid
    raise RuntimeError(f"charon não encontrado em {ns} — rode start-ipsec-side.sh primeiro")


def _swanctl(charon_pid: str, *args: str) -> str:
    return subprocess.run(
        [
            "nsenter",
            f"--mount=/proc/{charon_pid}/ns/mnt",
            f"--net=/proc/{charon_pid}/ns/net",
            "swanctl",
            *args,
        ],
        capture_output=True,
        text=True,
        check=True,
    ).stdout


_CHILD_SUBBLOCK_RE = re.compile(
    r"^  (\S+): #\d+, reqid \d+, (INSTALLED|DELETED).*?(?=^  \S+: #|\Z)",
    re.MULTILINE | re.DOTALL,
)
_AGE_RE = re.compile(r"installed (\d+)s ago")
_SPI_OUT_RE = re.compile(r"out (\S+)")


def read_sa_snapshots(charon_pid: str) -> list[SaSnapshot]:
    """Faz o parse do `swanctl --list-sas` pra idade e SPI atual de cada
    uma das três SAs N3 — é a entrada real do cálculo de risco (slack =
    SLA - idade). Durante uma transição de rekey existem DOIS blocos de
    child-SA pra mesma conexão (o antigo, DELETED, e o novo, INSTALLED) —
    só o INSTALLED importa aqui."""
    raw = _swanctl(charon_pid, "--list-sas")
    snapshots = []
    for slice_type, conn_name in CONN_NAME.items():
        for match in _CHILD_SUBBLOCK_RE.finditer(raw):
            name, state = match.group(1), match.group(2)
            if name != conn_name or state != "INSTALLED":
                continue
            block = match.group(0)
            age_match = _AGE_RE.search(block)
            spi_match = _SPI_OUT_RE.search(block)
            if not age_match or not spi_match:
                continue
            snapshots.append(
                SaSnapshot(
                    slice=slice_type,
                    conn_name=conn_name,
                    age_seconds=float(age_match.group(1)),
                    spi_out=spi_match.group(1),
                )
            )
            break
    return snapshots


def enqueue_from_snapshots(core: SchedulerCore, snapshots: list[SaSnapshot]) -> None:
    for snap in snapshots:
        sla = ROTATION_SLA_SECONDS[snap.slice]
        slack = sla - snap.age_seconds
        task = core.enqueue_task(
            EnqueueTaskRequest(
                slice=snap.slice,
                interface=InterfaceType.N3,
                task_type=TaskType.ROTATE,
                priority=TaskPriority.NORMAL,
                slack_seconds=slack,
                estimated_cost_seconds=ESTIMATED_ROTATION_COST_SECONDS,
                reason=f"idade atual {snap.age_seconds:.0f}s / SLA {sla:.0f}s",
            )
        )
        print(
            f"  enfileirado: {snap.conn_name:<20} idade={snap.age_seconds:>6.0f}s "
            f"slack={slack:>7.0f}s risk={task.risk_score:.3f}"
        )


def rotate(charon_pid: str, conn_name: str) -> None:
    """`--initiate` falha numa child já ESTABLISHED ("existing duplicate")
    — confirmado testando contra o laboratório real. `--rekey` é o
    comando certo: gera uma CHILD_SA nova (SPI novo) pra mesma conexão,
    sem derrubar o túnel."""
    _swanctl(charon_pid, "--rekey", "--child", conn_name)


def main() -> int:
    cu_pid = _find_charon_pid("cu-ns")

    print("Lendo estado real das três SAs N3 (swanctl --list-sas)...")
    snapshots = read_sa_snapshots(cu_pid)
    if len(snapshots) != 3:
        print(f"esperava 3 SAs N3, achei {len(snapshots)} — laboratório está de pé?", file=sys.stderr)
        return 1

    before_spi = {s.slice: s.spi_out for s in snapshots}

    core = SchedulerCore()
    print("\nCalculando risco (slack = SLA - idade) e enfileirando:")
    enqueue_from_snapshots(core, snapshots)

    next_task = core.get_next_task()
    conn_name = CONN_NAME[next_task.slice]
    print(f"\nMaior risco: {conn_name} (risk={next_task.risk_score:.3f}) — rotacionando de verdade...")
    rotate(cu_pid, conn_name)

    after = {s.slice: s.spi_out for s in read_sa_snapshots(cu_pid)}
    changed = before_spi[next_task.slice] != after[next_task.slice]
    print(
        f"SPI de saída antes={before_spi[next_task.slice]} depois={after[next_task.slice]} "
        f"({'MUDOU — rotação real confirmada' if changed else 'NÃO MUDOU — algo deu errado'})"
    )
    return 0 if changed else 1


if __name__ == "__main__":
    sys.exit(main())
