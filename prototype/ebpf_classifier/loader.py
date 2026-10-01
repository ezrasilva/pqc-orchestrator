"""Carrega e acopla o classificador TC/eBPF (Módulo 3) numa interface, e
dá uma API Python pro resto do sistema (testes, ou futuramente o
Módulo 2) atualizar o BPF map — ver
docs/ARQUITETURA-PROTOTIPO-COMPLETA.md seção 4.

Usa `tc`/`bpftool` via subprocess, como o roteiro recomenda pra começar
("Fase 2... via bpftool map update chamado por subprocess... otimizar só
se a latência disso se mostrar um problema real") — não precisa de
libbpf/pyroute2 nativo pra validar o mecanismo.
"""

from __future__ import annotations

import json
import subprocess
from pathlib import Path
from typing import Optional

OBJ_PATH = Path(__file__).parent / "src" / "classifier.bpf.o"
PROG_SECTION = "classify_gtpu"


def _run(cmd: list[str], **kwargs) -> subprocess.CompletedProcess:
    return subprocess.run(cmd, check=True, capture_output=True, text=True, **kwargs)


class TcClassifier:
    """Representa o classificador acoplado numa interface específica, via
    um qdisc `clsact` + filtro BPF no egress. `netns` é opcional — se
    informado, todos os comandos `tc`/`ip` rodam dentro daquele network
    namespace (via `ip netns exec`), do jeito que o resto do laboratório
    já faz (ver RUNBOOK-OAI.md)."""

    def __init__(self, iface: str, netns: Optional[str] = None, direction: str = "egress"):
        self.iface = iface
        self.netns = netns
        self.direction = direction  # "egress" ou "ingress"

    def _prefix(self) -> list[str]:
        return ["ip", "netns", "exec", self.netns] if self.netns else []

    def attach(self) -> None:
        """Idempotente: remove qualquer qdisc/filtro clsact anterior
        nessa interface antes de recriar, pra poder rodar de novo sem
        acumular filtros duplicados."""
        self.detach()

        _run([*self._prefix(), "tc", "qdisc", "add", "dev", self.iface, "clsact"])
        _run(
            [
                *self._prefix(),
                "tc",
                "filter",
                "add",
                "dev",
                self.iface,
                self.direction,
                "bpf",
                "da",
                "obj",
                str(OBJ_PATH),
                "sec",
                "tc",
            ]
        )

    def detach(self) -> None:
        subprocess.run(
            [*self._prefix(), "tc", "qdisc", "del", "dev", self.iface, "clsact"],
            capture_output=True,
        )

    def _find_map_id(self, map_name: str) -> Optional[str]:
        result = _run([*self._prefix(), "bpftool", "-j", "map", "show"])
        for entry in json.loads(result.stdout):
            if entry.get("name") == map_name:
                return str(entry["id"])
        return None

    def update_teid_mark(self, teid: int, mark: int) -> None:
        """Equivalente ao `update_bpf_map(teid, mark)` que o roteiro do
        Módulo 2 descreve como a interface entre Módulo 2 e Módulo 3."""
        map_id = self._find_map_id("teid_to_mark")
        if map_id is None:
            raise RuntimeError(
                f"teid_to_mark não encontrado em {self.iface} — chamou attach() primeiro?"
            )
        key_hex = " ".join(f"{b:02x}" for b in teid.to_bytes(4, "little"))
        value_hex = " ".join(f"{b:02x}" for b in mark.to_bytes(4, "little"))
        _run(
            [
                *self._prefix(),
                "bpftool",
                "map",
                "update",
                "id",
                map_id,
                "key",
                "hex",
                *key_hex.split(),
                "value",
                "hex",
                *value_hex.split(),
            ]
        )

    def read_stats(self) -> dict[str, int]:
        """STAT_MATCHED / STAT_UNKNOWN_TEID / STAT_NOT_GTPU — ver
        classifier.bpf.c. Útil pros testes confirmarem que o programa
        está vendo tráfego de verdade, não só que o `tc filter` existe."""
        map_id = self._find_map_id("map_stats")
        if map_id is None:
            return {}
        result = _run([*self._prefix(), "bpftool", "-j", "map", "dump", "id", map_id])
        entries = json.loads(result.stdout)
        names = {0: "matched", 1: "unknown_teid", 2: "not_gtpu"}
        stats = {}
        for entry in entries:
            # bpftool já decodifica key/value pra inteiro em "formatted"
            # quando o BTF descreve os tipos (é o nosso caso) — mais
            # simples e robusto que reimplementar o parse dos bytes hex.
            idx = entry["formatted"]["key"]
            value = entry["formatted"]["value"]
            stats[names.get(idx, str(idx))] = value
        return stats
