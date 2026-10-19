#!/usr/bin/env python3
"""Coletor de eventos do kernel IPsec via `ip xfrm monitor`.

**Por que existe, tendo já o `xfrm_state.py`.** O outro coletor faz
AMOSTRAGEM (`ip -s xfrm state` a cada 0,5 s) e serve para contadores de
pacotes/bytes por SPI — a métrica de isolamento. Mas amostragem não
responde *quando* uma SA foi instalada ou removida: um rekey inteiro
acontece entre duas amostras. Isso já custou caro nesta campanha — o gap
de isolamento de 2-3% acabou sendo o poller rodando a 0,5 s contra uma
frequência de rotação maior que isso.

Este coletor é ORIENTADO A EVENTO: o kernel notifica no instante em que
a SA entra ou sai, com resolução de microssegundo. É o que permite medir
a janela em que **nenhuma SA estava instalada** — a interrupção real de
uma rotação — em vez de inferi-la da perda de pacotes.

**O ruído tem de ser filtrado, e é a maior parte.** Medido: numa janela
de 6 s com um rekey, o monitor emitiu ~6000 eventos, dos quais mais de
99% eram `replay update` e `timer expired` — contabilidade interna do
kernel, emitida a cada poucos milissegundos por SPI ativa. Sem filtro, o
registro de uma campanha de horas fica inutilizável e o sinal
desaparece. Os dois tipos são CONTADOS e reportados em agregado, para a
filtragem ser auditável, mas não geram um evento cada.

**Formas de cabeçalho, confirmadas capturando contra o laboratório** (o
`ip` não documenta isso de forma utilizável):

| Cabeçalho | Significado |
| --- | --- |
| `src A dst B` (sem verbo) | SA **adicionada** |
| `Deleted src A dst B` | SA ou política removida |
| `Updated src A/m dst B/m` | política atualizada |
| `Async event (0x…) replay update` | ruído |
| `Async event (0x20) timer expired` | ruído |

SA e política se distinguem pela linha de DETALHE seguinte: a de SA traz
`proto esp spi 0x…`, a de política traz `dir out|in|fwd`.
"""

from __future__ import annotations

import os
import re
import signal
import subprocess
import threading
from typing import Optional

from evaluation.instrumentation import emit

# `ip -ts` prefixa cada bloco com `[AAAA-MM-DDTHH:MM:SS.ffffff]`.
_CABECALHO_RE = re.compile(r"^\[(?P<ts>[\d\-T:.]+)\]\s*(?P<resto>.*)$")
_SPI_RE = re.compile(r"\bspi (?P<spi>0x[0-9a-f]+)")
_REQID_RE = re.compile(r"\breqid (?P<reqid>0x[0-9a-f]+|\d+)")
_DIR_RE = re.compile(r"\bdir (?P<dir>out|in|fwd)\b")
_SRCDST_RE = re.compile(r"src (?P<src>\S+) dst (?P<dst>\S+)")

# Eventos de contabilidade interna do kernel. Ver docstring.
_RUIDO = ("replay update", "timer expired")


class XfrmMonitor:
    """Um monitor por netns. `start()`/`stop()` como os outros coletores."""

    def __init__(self, netns: str, emit_noise_summary: bool = True):
        self._netns = netns
        self._emit_noise_summary = emit_noise_summary
        self._cmd = ["ip", "netns", "exec", netns, "ip", "-ts", "xfrm", "monitor"]
        self._proc: Optional[subprocess.Popen] = None
        self._thread: Optional[threading.Thread] = None
        self._ruido = {k: 0 for k in _RUIDO}
        self._eventos = 0

    def start(self) -> None:
        # `start_new_session` põe o processo num grupo próprio para o
        # `stop()` poder matar o GRUPO INTEIRO.
        #
        # **Por que isso não é detalhe.** `ip netns exec` faz fork+exec,
        # então o `ip ... xfrm monitor` de verdade é um FILHO do processo
        # que o Popen controla. Matar só o pai deixa o filho órfão, ligado
        # ao netns, emitindo eventos para sempre — e esse monitor emite
        # mais de 99% de ruído (`replay update`) sob tráfego.
        #
        # Isto já custou caro: um `ip -ts xfrm monitor` de um teste manual
        # sobreviveu 1 dia e 4 horas e escreveu **10,9 GB** num arquivo que
        # havia sido apagado, segurando o espaço pelo descritor aberto. O
        # `/tmp` desta VM é um tmpfs de 12 GB; ele encheu, e o sintoma não
        # foi "disco cheio" — foi `EDQUOT` em ferramentas sem relação
        # nenhuma com o coletor, com os arquivos grandes INVISÍVEIS ao
        # `find` porque já não tinham nome.
        self._proc = subprocess.Popen(
            self._cmd, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
            text=True, bufsize=1, start_new_session=True,
        )
        self._thread = threading.Thread(target=self._ler, daemon=True)
        self._thread.start()

    def _ler(self) -> None:
        assert self._proc and self._proc.stdout
        ts: Optional[str] = None
        cabecalho: Optional[str] = None
        detalhe: list[str] = []

        def despacha() -> None:
            if ts and cabecalho is not None:
                self._classifica(ts, cabecalho, " ".join(detalhe))

        for linha in self._proc.stdout:
            m = _CABECALHO_RE.match(linha)
            if m:
                # Linha de cabeçalho: fecha o bloco anterior antes de
                # abrir o novo. É isso que mantém cada evento junto do
                # seu detalhe, que é onde SPI e reqid aparecem.
                despacha()
                ts, cabecalho, detalhe = m["ts"], m["resto"].strip(), []
            else:
                detalhe.append(linha.strip())
        despacha()

    def _encerra_grupo(self) -> None:
        """Mata o grupo de processos, não só o pai. Ver `start()`."""
        assert self._proc is not None
        try:
            grupo = os.getpgid(self._proc.pid)
        except OSError:
            return  # já morreu
        for sinal in (signal.SIGTERM, signal.SIGKILL):
            try:
                os.killpg(grupo, sinal)
            except OSError:
                return
            try:
                self._proc.wait(timeout=5)
                return
            except subprocess.TimeoutExpired:
                continue

    def _classifica(self, ts: str, cabecalho: str, detalhe: str) -> None:
        for chave in _RUIDO:
            if chave in cabecalho:
                self._ruido[chave] += 1
                return

        texto = f"{cabecalho} {detalhe}"
        spi = (m := _SPI_RE.search(texto)) and m["spi"]
        direcao = (m := _DIR_RE.search(texto)) and m["dir"]
        # SA traz `spi`; política traz `dir`. Se vier nenhum dos dois é
        # um cabeçalho que ainda não conhecemos — registra como
        # desconhecido em vez de descartar em silêncio, para não perder
        # um tipo de evento novo sem aviso.
        if spi:
            objeto = "sa"
        elif direcao:
            objeto = "policy"
        else:
            objeto = "desconhecido"

        if cabecalho.startswith("Deleted"):
            acao = "deleted"
        elif cabecalho.startswith("Updated"):
            acao = "updated"
        elif cabecalho.startswith("src "):
            acao = "added"
        else:
            acao = "outro"

        endereco = _SRCDST_RE.search(texto)
        reqid = (m := _REQID_RE.search(texto)) and m["reqid"]
        self._eventos += 1
        emit(
            "xfrm_event",
            netns=self._netns,
            # Relógio do KERNEL, não deste processo — é isso que dá a
            # resolução para medir a janela sem SA.
            kernel_ts=ts,
            object=objeto,
            action=acao,
            spi=spi,
            reqid=reqid,
            direction=direcao,
            src=endereco and endereco["src"],
            dst=endereco and endereco["dst"],
            header=cabecalho if objeto == "desconhecido" else None,
        )

    def stop(self) -> None:
        if self._proc:
            self._encerra_grupo()
        if self._thread:
            self._thread.join(timeout=5)
        if self._emit_noise_summary:
            # O ruído entra em agregado para a filtragem ser auditável:
            # dá para conferir depois que não se descartou sinal junto.
            emit("xfrm_monitor_summary", netns=self._netns,
                 events_emitted=self._eventos, noise_filtered=dict(self._ruido))
