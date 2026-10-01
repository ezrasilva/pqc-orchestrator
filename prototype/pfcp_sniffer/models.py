"""Tipos de domínio do sniffer PFCP (Módulo 2) — ver
docs/ROTEIRO-MODULO2-SNIFFER-PFCP.md e docs/ARQUITETURA-PROTOTIPO-COMPLETA.md.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Optional

# URLLC=SST2, eMBB=SST1, mIoT=SST3 — conferido contra smf.yaml/nssf.yaml
# desta VM (ver docs/ARQUITETURA-ORQUESTRADOR.md, mapeamento já corrigido).
SST_TO_MARK: dict[int, int] = {2: 0x10, 1: 0x20, 3: 0x30}
SST_TO_SLICE_NAME: dict[int, str] = {2: "URLLC", 1: "eMBB", 3: "mIoT"}


@dataclass
class FTeid:
    teid: int
    ipv4: str


@dataclass
class SessionState:
    """Estado acumulado de uma sessão PFCP, chaveada por SEID — o sniffer
    só emite um SliceMapping quando sst/sd e os dois TEIDs (uplink e
    downlink) estiverem presentes. O par de TEIDs chega em mensagens
    diferentes na prática (uplink na Establishment Response, downlink
    numa Modification Request posterior) — ver achado documentado no
    roteiro."""

    seid: int
    sst: Optional[int] = None
    sd: Optional[int] = None
    dnn: Optional[str] = None
    uplink: Optional[FTeid] = None   # TEID da UPF — CU envia pra cá
    downlink: Optional[FTeid] = None  # TEID da CU — UPF envia pra cá
    emitted: bool = False  # já emitimos o mapeamento completo pra esta sessão?

    @property
    def is_complete(self) -> bool:
        return self.sst is not None and self.uplink is not None and self.downlink is not None


@dataclass
class SliceMapping:
    """A saída do Módulo 2 — o que alimenta o Módulo 3 (BPF map) e o
    Módulo 4 (Agente de Segurança / IPsec Agent)."""

    seid: int
    sst: int
    sd: int
    dnn: str
    uplink: FTeid
    downlink: FTeid
    mark: Optional[int]  # None se o SST não tiver perfil definido (ver SST_TO_MARK)

    @property
    def slice_name(self) -> str:
        return SST_TO_SLICE_NAME.get(self.sst, f"SST{self.sst}")
