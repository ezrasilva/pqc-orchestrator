"""Captura passiva de PFCP (udp/8805) e alimenta o SessionTracker — a
casca fina que liga scapy ao resto do Módulo 2. Ver
docs/ROTEIRO-MODULO2-SNIFFER-PFCP.md seção 1: não fica no caminho do
tráfego de dados, só observa.
"""

from __future__ import annotations

import logging
from typing import Callable, Optional

from scapy.all import UDP, sniff

from pfcp_sniffer.models import SliceMapping
from pfcp_sniffer.parser import parse
from pfcp_sniffer.session_tracker import SessionTracker

logger = logging.getLogger(__name__)

PFCP_PORT = 8805

OnMapping = Callable[[SliceMapping], None]
OnRemoved = Callable[[int], None]


def _default_on_mapping(mapping: SliceMapping) -> None:
    logger.info(
        "SEID=%#x %s (SST=%d SD=%#x) DNN=%s uplink=TEID=%#x@%s downlink=TEID=%#x@%s -> mark=%s",
        mapping.seid,
        mapping.slice_name,
        mapping.sst,
        mapping.sd,
        mapping.dnn,
        mapping.uplink.teid,
        mapping.uplink.ipv4,
        mapping.downlink.teid,
        mapping.downlink.ipv4,
        f"{mapping.mark:#x}" if mapping.mark is not None else "SEM PERFIL",
    )


def _default_on_removed(session_seid: int) -> None:
    logger.info("SEID=%#x removido (Session Deletion)", session_seid)


class PfcpSniffer:
    def __init__(
        self,
        iface: str,
        on_mapping: Optional[OnMapping] = None,
        on_removed: Optional[OnRemoved] = None,
    ):
        self.iface = iface
        self.tracker = SessionTracker()
        self.on_mapping = on_mapping or _default_on_mapping
        self.on_removed = on_removed or _default_on_removed

    def _handle_packet(self, pkt) -> None:
        if UDP not in pkt:
            return
        udp = pkt[UDP]
        if udp.sport != PFCP_PORT and udp.dport != PFCP_PORT:
            return
        try:
            parsed = parse(bytes(udp.payload))
        except Exception:
            logger.exception("falha parseando pacote PFCP, ignorando")
            return

        result = self.tracker.process(parsed)
        if result.mapping is not None:
            self.on_mapping(result.mapping)
        if result.removed_seid is not None:
            self.on_removed(result.removed_seid)

    def run(self, count: int = 0, timeout: Optional[float] = None) -> None:
        """count=0 roda pra sempre (até Ctrl-C ou timeout)."""
        sniff(
            iface=self.iface,
            filter=f"udp port {PFCP_PORT}",
            prn=self._handle_packet,
            store=False,
            count=count,
            timeout=timeout,
        )
