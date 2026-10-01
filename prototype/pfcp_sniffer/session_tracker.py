"""Acumula estado por sessão até ter informação suficiente pra emitir um
SliceMapping — ver docs/ROTEIRO-MODULO2-SNIFFER-PFCP.md seções 2c/2d.

**Correlação de SEID (achado real, não documentado no roteiro
original)**: o SEID do cabeçalho PFCP não é um ID de sessão único — é o
SEID "do destinatário da mensagem". Numa Request (CP->UP, ex: SMF->UPF),
o cabeçalho carrega o SEID que o **UP** atribuiu à sessão; numa Response
(UP->CP), carrega o SEID que o **CP** atribuiu. Os dois valores são
diferentes pra mesma sessão. A ligação entre eles vem do IE F-SEID
(payload, não cabeçalho): a Establishment Request anuncia o SEID do CP,
e a Establishment Response anuncia o SEID do UP. Por isso este tracker
mantém duas tabelas (`_by_cp_seid`, `_by_up_seid`) apontando pro mesmo
`SessionState` — uma mensagem qualquer é resolvida tentando as duas,
porque não dá pra saber de antemão, só pelo cabeçalho, qual delas bate.

Conferido contra uma captura real com três sessões simultâneas
(embb/urllc/miot) antes de confiar nisso — ver tests/fixtures/ e o
roteiro.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Optional

from pfcp_sniffer.models import SST_TO_MARK, SessionState, SliceMapping
from pfcp_sniffer.parser import (
    extract_dnn,
    extract_downlink_fteid,
    extract_fseid,
    extract_snssai,
    extract_uplink_fteid,
    has_seid,
    message_type,
    seid,
)

# TS 29.244 — tipos de mensagem de sessão que temos handlers específicos
# pra ela; os outros (Report, etc.) caem no caminho genérico de
# "absorve o que tiver, emite se completar".
_SESSION_ESTABLISHMENT_REQUEST = 50
_SESSION_DELETION_REQUEST = 54


@dataclass
class ProcessResult:
    mapping: Optional[SliceMapping] = None
    removed_seid: Optional[int] = None  # SEID do CP (chave estável) da sessão removida


class SessionTracker:
    def __init__(self) -> None:
        self._by_cp_seid: dict[int, SessionState] = {}
        self._by_up_seid: dict[int, SessionState] = {}

    def _resolve(self, header_seid: int) -> Optional[SessionState]:
        return self._by_cp_seid.get(header_seid) or self._by_up_seid.get(header_seid)

    def process(self, pkt) -> ProcessResult:
        if not has_seid(pkt):
            # Heartbeat, Association Setup/Update — sem conceito de SEID,
            # não é uma sessão de UE. Nada a fazer.
            return ProcessResult()

        mt = int(message_type(pkt))
        header_seid = seid(pkt)
        fseid = extract_fseid(pkt)

        if mt == _SESSION_ESTABLISHMENT_REQUEST:
            # header_seid é sempre 0 aqui (UP ainda não existe) — a
            # identidade real da sessão é o F-SEID (SEID do CP).
            cp_seid = fseid if fseid is not None else header_seid
            state = self._by_cp_seid.setdefault(cp_seid, SessionState(seid=cp_seid))
        else:
            state = self._resolve(header_seid)
            if state is None:
                if mt == _SESSION_DELETION_REQUEST:
                    # Sessão que já existia antes do sniffer começar a
                    # escutar — não tem o que limpar porque nunca
                    # emitimos mapeamento pra ela.
                    return ProcessResult()
                # Mensagem de uma sessão que ainda não vimos a
                # Establishment (ex: sniffer iniciado no meio do fluxo)
                # — cria estado novo chaveado pelo próprio header, melhor
                # que descartar a mensagem silenciosamente.
                state = self._by_cp_seid.setdefault(header_seid, SessionState(seid=header_seid))

            # Establishment Response: aprende o SEID que o UP atribuiu,
            # pra mensagens futuras (Modification/Deletion Request, que
            # vêm endereçadas ao UP) resolverem pra essa mesma sessão.
            if fseid is not None and fseid not in self._by_up_seid:
                self._by_up_seid[fseid] = state

        if mt == _SESSION_DELETION_REQUEST:
            self._by_cp_seid.pop(state.seid, None)
            for up_seid, mapped in list(self._by_up_seid.items()):
                if mapped is state:
                    del self._by_up_seid[up_seid]
            return ProcessResult(removed_seid=state.seid)

        if state.sst is None:
            snssai = extract_snssai(pkt)
            if snssai is not None:
                state.sst, state.sd = snssai

        if state.dnn is None:
            dnn = extract_dnn(pkt)
            if dnn is not None:
                state.dnn = dnn

        if state.uplink is None:
            uplink = extract_uplink_fteid(pkt)
            if uplink is not None:
                state.uplink = uplink

        if state.downlink is None:
            downlink = extract_downlink_fteid(pkt)
            if downlink is not None:
                state.downlink = downlink

        if state.is_complete and not state.emitted:
            state.emitted = True
            mapping = SliceMapping(
                seid=state.seid,
                sst=state.sst,
                sd=state.sd,
                dnn=state.dnn or "",
                uplink=state.uplink,
                downlink=state.downlink,
                mark=SST_TO_MARK.get(state.sst),
            )
            return ProcessResult(mapping=mapping)

        return ProcessResult()

    def get(self, cp_seid: int) -> Optional[SessionState]:
        return self._by_cp_seid.get(cp_seid)

    def __len__(self) -> int:
        return len(self._by_cp_seid)
