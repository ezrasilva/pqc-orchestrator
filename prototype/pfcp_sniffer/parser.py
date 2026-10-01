"""Extração dos campos que o Módulo 2 precisa, usando o dissector PFCP
nativo do scapy (`scapy.contrib.pfcp`) em vez de um parser TLV escrito à
mão — a primeira versão deste módulo (no rascunho do roteiro) tinha um bug
real no cálculo do tamanho do header PFCP quando o SEID está presente (16
bytes, não 12 — a diferença são os 3 bytes do número de sequência + 1 de
spare que ficam entre o SEID e as IEs). Usar o dissector do scapy evita
essa classe de bug inteira e qualquer outra parecida, sem perder nada —
ele decodifica corretamente até IEs que não tem classe dedicada (como
S-NSSAI, ver `_extract_snssai_raw`), só não dá um nome bonito pra eles.

Conferido campo a campo contra uma captura real desta VM antes de
confiar neste módulo — ver docs/ROTEIRO-MODULO2-SNIFFER-PFCP.md seção 2b.
"""

from __future__ import annotations

from typing import Iterator, Optional, Type, TypeVar

from scapy.contrib.pfcp import (
    IE_CreatedPDR,
    IE_DestinationInterface,
    IE_ForwardingParameters,
    IE_FSEID,
    IE_FTEID,
    IE_NetworkInstance,
    IE_OuterHeaderCreation,
    IE_UpdateForwardingParameters,
    PFCP,
)

from pfcp_sniffer.models import FTeid

# S-NSSAI (IE 257) não tem classe dedicada no scapy — cai no wrapper
# genérico "IE not implemented", que ainda expõe `.ietype`/`.data` brutos.
# Formato (TS 29.244 / TS 23.003): 1 byte SST, 3 bytes SD (SD ausente =
# IE de 1 byte só, mas a Open5GS sempre manda os 4).
_SNSSAI_IE_TYPE = 257

T = TypeVar("T")


def _walk(packet, cls: Type[T]) -> Iterator[T]:
    """Percorre a árvore de IEs (incluindo Grouped IEs aninhados, via o
    atributo `IE_list` que o scapy usa pra eles) procurando por instâncias
    de `cls`. Funciona pra qualquer profundidade de aninhamento — não
    assume que S-NSSAI/F-TEID estão num nível fixo, só que estão em
    algum lugar da árvore."""
    if isinstance(packet, cls):
        yield packet
    for ie in getattr(packet, "IE_list", []) or []:
        yield from _walk(ie, cls)


def parse(payload: bytes) -> PFCP:
    return PFCP(payload)


def message_type(pkt: PFCP) -> str:
    return str(pkt.message_type)


def has_seid(pkt: PFCP) -> bool:
    return bool(pkt.S)


def seid(pkt: PFCP) -> int:
    """O SEID do CABEÇALHO — **não** é um ID único de sessão, é o SEID
    "do destinatário": em mensagens Request (CP->UP) é o SEID que o UP
    (UPF) atribuiu a essa sessão; em mensagens Response (UP->CP) é o SEID
    que o CP (SMF) atribuiu. Os dois valores são diferentes pra mesma
    sessão — ver `extract_fseid` e `session_tracker.py` pra como
    correlacionar os dois (conferido byte a byte contra captura real,
    não é suposição — ver docs/ROTEIRO-MODULO2-SNIFFER-PFCP.md)."""
    return int(pkt.seid)


def extract_fseid(pkt: PFCP) -> Optional[int]:
    """SEID carregado explicitamente no IE F-SEID (payload, não
    cabeçalho) — aparece na Establishment Request (ali é o SEID que o CP
    está anunciando pra essa sessão) e na Establishment Response (ali é o
    SEID que o UP acabou de atribuir). É o valor estável que liga as duas
    pontas — ver nota em `seid()`."""
    for f in _walk(pkt, IE_FSEID):
        return int(f.seid)
    return None


def extract_snssai(pkt: PFCP) -> Optional[tuple[int, int]]:
    """(sst, sd) a partir do IE 257, onde quer que esteja na árvore —
    None se a mensagem não carregar esse IE (normal fora da
    Establishment Request)."""
    return _extract_snssai_raw(pkt)


def _extract_snssai_raw(packet) -> Optional[tuple[int, int]]:
    if getattr(packet, "ietype", None) == _SNSSAI_IE_TYPE:
        data = bytes(packet.data)
        if len(data) >= 1:
            sst = data[0]
            sd = int.from_bytes(data[1:4], "big") if len(data) >= 4 else 0xFFFFFF
            return sst, sd
    for ie in getattr(packet, "IE_list", []) or []:
        found = _extract_snssai_raw(ie)
        if found is not None:
            return found
    return None


def extract_dnn(pkt: PFCP) -> Optional[str]:
    """Network Instance (IE 22) — reaproveita o campo pra identificar o
    DNN/APN, igual ao que já confirmamos no `smf.yaml` (embb/urllc/miot)."""
    for ie in _walk(pkt, IE_NetworkInstance):
        instance = ie.instance
        if instance:
            return instance.decode() if isinstance(instance, bytes) else str(instance)
    return None


def extract_uplink_fteid(pkt: PFCP) -> Optional[FTeid]:
    """F-TEID com valor real (não CH/CHOOSE) dentro de um Created PDR —
    só aparece na Session Establishment/Modification **Response**, é a
    UPF dizendo "me manda o uplink nesse TEID". Ignora F-TEID com CH=1
    (a Request também carrega F-TEID, mas só pedindo pra UPF escolher —
    sem valor usável ainda)."""
    for created_pdr in _walk(pkt, IE_CreatedPDR):
        for fteid in _walk(created_pdr, IE_FTEID):
            if not fteid.CH and fteid.ipv4:
                return FTeid(teid=int(fteid.TEID), ipv4=str(fteid.ipv4))
    return None


_DESTINATION_INTERFACE_ACCESS = 0  # ver scapy.contrib.pfcp.SourceInterface


def extract_downlink_fteid(pkt: PFCP) -> Optional[FTeid]:
    """Outer Header Creation dentro de (Update) Forwarding Parameters —
    é o TEID que a CU anunciou pra UPF usar no downlink. Confirmado
    nesta VM que normalmente só chega numa Modification Request
    posterior à Establishment, não na Establishment em si — ver nota no
    roteiro.

    **Cuidado que não é óbvio sem olhar uma captura real**: uma sessão
    tem VÁRIOS "Create FAR"/"Update FAR", um por direção/PDR — inclusive
    um apontando `Destination Interface = CP-function` (a UPF notificando
    a própria SMF via GTP-U, nada a ver com o enlace N3). Pegar o
    primeiro Outer Header Creation da árvore sem checar pra qual
    interface ele aponta pega esse IE errado. Só aceita o que estiver no
    MESMO grupo (Forwarding Parameters) que um Destination Interface =
    Access (0) — isto é, o FAR que entrega de verdade no rádio, não o que
    entrega de volta pro core."""
    for group_cls in (IE_ForwardingParameters, IE_UpdateForwardingParameters):
        for group in _walk(pkt, group_cls):
            destinations = list(_walk(group, IE_DestinationInterface))
            if not any(d.interface == _DESTINATION_INTERFACE_ACCESS for d in destinations):
                continue
            for ohc in _walk(group, IE_OuterHeaderCreation):
                if ohc.ipv4:
                    return FTeid(teid=int(ohc.TEID), ipv4=str(ohc.ipv4))
    return None
