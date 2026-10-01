"""Testes do classificador TC/eBPF (Módulo 3) — pacotes GTP-U sintéticos
(via scapy) injetados num veth descartável, não dependem do laboratório
OAI estar de pé. Ver docs/ARQUITETURA-PROTOTIPO-COMPLETA.md seção 4 e
`../README.md` pro achado importante sobre ordem XFRM vs. TC egress que
estes testes NÃO cobrem (precisaria do Módulo 4/IPsec real pra isso —
aqui só validamos que o classificador em si lê o TEID certo e marca
certo, não que o mark influencia a escolha de SA)."""

import struct
import sys
from pathlib import Path

from scapy.all import IP, UDP, Ether, Raw, sendp

sys.path.insert(0, str(Path(__file__).parent.parent))
from loader import TcClassifier  # noqa: E402

from .conftest import requires_root


def _gtpu_packet(teid: int, flags: int = 0x30) -> bytes:
    """G-PDU (msg type 0xff) mínimo, header de 8 bytes + payload
    qualquer. flags=0x30 é próximo do valor real observado em tráfego
    desta VM (version=1, PT=1)."""
    header = struct.pack("!BBHI", flags, 0xFF, 8, teid)
    payload = b"\x00\x00\x00\x00\x10\x11\x12\x13"  # 8 bytes de "dado" qualquer
    return header + payload


def _send_gtpu(iface: str, teid: int, **kwargs) -> None:
    # src= explícito: sem isso o scapy tenta resolver a rota/interface de
    # origem sozinho, usando uma tabela de interfaces que ele cacheou
    # ANTES do fixture trocar de netns (via os.setns) — fica
    # desatualizada e aponta pra interfaces que não existem neste netns.
    pkt = (
        Ether(src="02:00:00:00:00:01", dst="02:00:00:00:00:02")
        / IP(src="10.0.0.1", dst="172.18.0.2")
        / UDP(sport=2152, dport=2152)
        / Raw(load=_gtpu_packet(teid, **kwargs))
    )
    sendp(pkt, iface=iface, verbose=False)


@requires_root
def test_known_teid_gets_matched_and_marked(test_netns):
    _, iface = test_netns
    clf = TcClassifier(iface, direction="egress")
    clf.attach()
    try:
        clf.update_teid_mark(0xDEADBEEF, 0x20)
        _send_gtpu(iface, 0xDEADBEEF)
        stats = clf.read_stats()
        assert stats["matched"] == 1
        assert stats["unknown_teid"] == 0
    finally:
        clf.detach()


@requires_root
def test_unknown_teid_not_matched(test_netns):
    _, iface = test_netns
    clf = TcClassifier(iface, direction="egress")
    clf.attach()
    try:
        clf.update_teid_mark(0x1111, 0x20)  # TEID diferente do que vamos mandar
        _send_gtpu(iface, 0x2222)
        stats = clf.read_stats()
        assert stats["matched"] == 0
        assert stats["unknown_teid"] == 1
    finally:
        clf.detach()


@requires_root
def test_non_gtpu_udp_traffic_ignored(test_netns):
    _, iface = test_netns
    clf = TcClassifier(iface, direction="egress")
    clf.attach()
    try:
        clf.update_teid_mark(0xDEADBEEF, 0x20)
        pkt = Ether(src="02:00:00:00:00:01", dst="02:00:00:00:00:02") / IP(src="10.0.0.1", dst="172.18.0.2") / UDP(sport=12345, dport=53) / Raw(load=b"nao e gtpu")
        sendp(pkt, iface=iface, verbose=False)
        stats = clf.read_stats()
        assert stats["matched"] == 0
        assert stats["not_gtpu"] == 1
    finally:
        clf.detach()


@requires_root
def test_teid_offset_correct_even_with_extension_header_flag(test_netns):
    """Regressão direta do achado documentado em
    docs/ROTEIRO-MODULO2-SNIFFER-PFCP.md: o TEID fica nos bytes 4-7 do
    header GTP-U independente da flag de extensão (E) estar ligada — a
    extensão em si vem DEPOIS do TEID, não desloca o offset. flags=0x34
    (E=1) é o valor real visto em tráfego desta VM."""
    _, iface = test_netns
    clf = TcClassifier(iface, direction="egress")
    clf.attach()
    try:
        clf.update_teid_mark(0x58D7, 0x20)  # TEID real já visto em captura desta VM
        _send_gtpu(iface, 0x58D7, flags=0x34)
        stats = clf.read_stats()
        assert stats["matched"] == 1, "TEID não bateu com a flag de extensão ligada"
    finally:
        clf.detach()


@requires_root
def test_multiple_slices_independently_classified(test_netns):
    """Três TEIDs, três marks — simula as três fatias simultâneas que o
    Módulo 2 já validou (embb/urllc/miot)."""
    _, iface = test_netns
    clf = TcClassifier(iface, direction="egress")
    clf.attach()
    try:
        clf.update_teid_mark(0x1001, 0x20)  # eMBB
        clf.update_teid_mark(0x2002, 0x10)  # URLLC
        clf.update_teid_mark(0x3003, 0x30)  # mIoT
        for teid in (0x1001, 0x2002, 0x3003, 0x1001):  # eMBB duas vezes
            _send_gtpu(iface, teid)
        stats = clf.read_stats()
        assert stats["matched"] == 4
        assert stats["unknown_teid"] == 0
    finally:
        clf.detach()
