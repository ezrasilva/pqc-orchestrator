"""Módulo 2→3 de verdade: liga o `pfcp_sniffer` (já testado, só emitia
log) às regras `iptables -t mangle -A OUTPUT` que classificam o GTP-U de
cada fatia (Módulo 3 real desta VM — eBPF/TC não funciona pra tráfego
gerado localmente pela CU, ver `docs/ARQUITETURA-PROTOTIPO-COMPLETA.md`
seção 4.1). Antes disso, `apply-n3-slice-marks.sh` era chamado à mão a
cada restart de RAN, com o TEID capturado manualmente — isto substitui
a parte manual por uma reação automática a cada evento PFCP real.

**Reconstrução completa a cada mudança, não edição incremental.** As 3
fatias cabem inteiras em `_known: dict[str, SliceMapping]` (no máximo 3
entradas). A cada `on_mapping`/`on_removed`, a tabela inteira é
reescrita do zero (`iptables -t mangle -F OUTPUT` seguido de todas as
regras MARK+RETURN conhecidas + o catch-all fail-closed) — iptables não
tem transação, então qualquer estratégia incremental (`-D` de uma regra
específica por `--comment`, depois `-I` de outra) deixa uma janela onde
uma fatia já classificada fica temporariamente sem regra, e cai no
catch-all. Reescrever tudo de uma vez por um único processo (nunca dois
em paralelo — ver `_lock`) é mais simples de raciocinar sobre e rápido o
bastante (poucos `iptables` por segundo, nunca por pacote).

**Por que isto importa de verdade nesta VM, não só estilo**: o `nr-gnb`
do UERANSIM trava o processo inteiro (`terminate()`) na primeira vez que
um `sendto()` leva EPERM do DROP fail-closed (achado documentado na
memória do projeto) — uma fatia sem regra por tempo demais não é só
"tráfego descartado", é "gNB inteira cai". Por isso o `RETURN` depois de
cada `MARK` (bug raiz já corrigido em `apply-n3-slice-marks.sh`) e a
reação rápida a cada PFCP Establishment são as duas pernas da mesma
correção — sem as duas, o fail-closed é mais perigoso que proteger.
"""

from __future__ import annotations

import argparse
import logging
import shlex
import subprocess
import threading
from typing import Optional

from pfcp_sniffer.models import SliceMapping
from pfcp_sniffer.sniffer import PfcpSniffer

logger = logging.getLogger("auto_classifier")

_MARK_RULE = (
    "-A OUTPUT -p udp --dport 2152 -m u32 --u32 32={teid:#x} -j MARK --set-mark {mark:#x}"
)
_RETURN_RULE = "-A OUTPUT -p udp --dport 2152 -m mark --mark {mark:#x} -j RETURN"
_LOG_RULE = (
    '-A OUTPUT -p udp --dport 2152 -m limit --limit 10/min --limit-burst 5 '
    '-j LOG --log-prefix "[n3-teid-nao-classificado] " --log-level 4'
)
_DROP_RULE = "-A OUTPUT -p udp --dport 2152 -j DROP"


class MangleClassifier:
    """Mantém a tabela `mangle OUTPUT` de uma netns sincronizada com o
    que o sniffer PFCP sabe sobre as fatias ativas agora."""

    def __init__(self, netns: str) -> None:
        self.netns = netns
        self._known: dict[str, SliceMapping] = {}
        self._lock = threading.Lock()

    def _run(self, rule_args: str) -> None:
        cmd = ["ip", "netns", "exec", self.netns, "iptables", "-t", "mangle"] + shlex.split(rule_args)
        subprocess.run(cmd, check=True)

    def _rebuild(self) -> None:
        self._run("-F OUTPUT")
        for name, mapping in sorted(self._known.items()):
            if mapping.mark is None:
                logger.warning("fatia %s sem mark definido (SST=%d) — ignorada", name, mapping.sst)
                continue
            self._run(_MARK_RULE.format(teid=mapping.uplink.teid, mark=mapping.mark))
            self._run(_RETURN_RULE.format(mark=mapping.mark))
        self._run(_LOG_RULE)
        self._run(_DROP_RULE)
        logger.info(
            "mangle OUTPUT (%s) reconstruída: %s",
            self.netns,
            {
                n: f"teid={m.uplink.teid:#x} mark={m.mark:#x}" if m.mark is not None else "SEM PERFIL"
                for n, m in self._known.items()
            },
        )

    def on_mapping(self, mapping: SliceMapping) -> None:
        name = mapping.slice_name
        with self._lock:
            old = self._known.get(name)
            if old is not None and old.uplink.teid == mapping.uplink.teid:
                return  # nada mudou, não vale um flush+rebuild
            self._known[name] = mapping
            logger.info(
                "%s: novo TEID uplink %#x (SEID=%#x, DNN=%s)",
                name, mapping.uplink.teid, mapping.seid, mapping.dnn,
            )
            self._rebuild()

    def on_removed(self, seid: int) -> None:
        with self._lock:
            removed = [n for n, m in self._known.items() if m.seid == seid]
            if not removed:
                return
            for name in removed:
                del self._known[name]
                logger.info("%s: sessão removida (SEID=%#x) — sem regra até a próxima Establishment", name, seid)
            self._rebuild()


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--iface", default="br-3665a185754f", help="interface onde o N4/PFCP é visível (bridge da rede 5gc_default)")
    ap.add_argument("--cu-netns", default="cu-ns", help="netns da CU onde a mangle OUTPUT é mantida")
    ap.add_argument("-v", "--verbose", action="store_true")
    args = ap.parse_args()

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s [%(levelname)s] %(message)s",
    )

    classifier = MangleClassifier(args.cu_netns)
    sniffer = PfcpSniffer(
        iface=args.iface,
        on_mapping=classifier.on_mapping,
        on_removed=classifier.on_removed,
    )
    logger.info("Módulo 2→3 automático — escutando PFCP em %s, aplicando mangle em %s", args.iface, args.cu_netns)
    sniffer.run()


if __name__ == "__main__":
    main()
