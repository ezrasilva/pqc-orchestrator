#!/usr/bin/env python3
"""A.2 — rekey/reauth sob tráfego: perda, pico de RTT e duração da
interrupção.

**Três tipos de evento, e por quê.** O documento da campanha pede a
medição "com make-before-break ligado e desligado". Lendo o strongSwan
6.0.4, `charon.make_before_break` (default `yes`) governa a
**reautenticação IKEv2**, não o rekey da Child SA — este é sempre
make-before-break por imposição da RFC 7296 (as SAs novas são instaladas
antes de as velhas serem apagadas). Então o toggle só existe no caminho
de reauth, e a medição honesta contrasta:

| Evento | Toggle | Por que interessa ao SAPQ-IPsec |
| --- | --- | --- |
| `child_rekey` | n/a (sempre MBB) | é a rotação barata, de material de chave do ESP |
| `ike_reauth` + MBB | `yes` | **é o caminho da renovação de PPK**: o PPK só entra na derivação no IKE_AUTH, logo renovar PPK exige reauth, não rekey |
| `ike_reauth` sem MBB | `no` | cota o custo de errar essa configuração — quebra antes de refazer |

Essa distinção não é um detalhe de implementação: ela determina o custo
real do mecanismo central da proposta. Se renovar PPK exige reauth, o
custo da renovação de PPK é o da linha 2, não o da linha 1.

**Resolução da medição.** Dois geradores, de propósito, com resoluções
complementares:

* **ping a 1 kHz** — a perda é detectada por lacuna no `icmp_seq`, logo
  a duração da interrupção fica **quantizada no intervalo do ping**.

  **Por que 1 kHz e não os 100 Hz que o documento da campanha pede**:
  medido nesta bancada (15/10). A 100 Hz, uma reauth em
  break-before-make (`make_before_break = no`) deu **perda zero** em
  todas as repetições — o que levaria à conclusão errada de que não há
  interrupção. Repetindo a 1 kHz na mesma configuração: **1 pacote
  perdido, corrida máxima de 1, ou seja ~1 ms de interrupção**. A
  interrupção existe, só é curta demais para uma sonda de 10 ms de
  passo enxergar. Os 100 Hz do documento foram dimensionados supondo
  que o break-before-make custaria um handshake inteiro (~30 ms); não é
  o que acontece, porque a política XFRM permanece instalada e só o
  estado é refeito.

  Essa é também a razão de a interrupção ser derivada de sequências
  ausentes e não do intervalo entre chegadas — ver `_gap_stats`.

**Qual instrumento manda, quando os dois discordam: o UDP.** Medido na
campanha de 15/10 (6 perfis x 20 reauths, make-before-break ligado): o
ping reportou 1 pacote perdido em 87 de 114 repetições, enquanto o fluxo
UDP, a nove vezes a taxa, perdeu ZERO em 120 de 120. Se houvesse lacuna
de tráfego, o fluxo mais rápido teria perdido mais, não menos.

O campo `max_interarrival_ms` desambigua, e é por isso que ele existe:

| repetições | `lost` (ping) | `max_interarrival_ms` | `udp_lost` |
| --- | --- | --- | --- |
| 87 de 114 | 1 | **~11,1 ms** | 0 |
| 27 de 114 | 0 | ~1,7–2,3 ms | 0 |

Uma lacuna de 11 ms a 1 kHz deveria deixar ~11 sequências ausentes;
falta **uma**. Ou seja, o processo `ping` ficou ~11 ms sem ser
escalonado e nesse intervalo não enviou — enquanto o fluxo UDP, que é
conduzido pelo kernel, atravessou sem perda nenhuma. Logo o pacote ICMP
é artefato de escalonamento do processo de sonda sob carga, não
interrupção da SA.

Consequência prática: **o `outage_ms` derivado do ping não é confiável na
escala de 1 ms** — a sonda é um processo de userspace e pode parar por
mais tempo que o evento que se quer medir. O `outage_udp_ms` é a
estimativa a reportar; o do ping fica como verificação grosseira e o
`max_interarrival_ms` como sinal de que a sonda travou.

* O `rtt_peak_ms`, lido do próprio `time=` do ping, entra no relatório
  porque tem resolução de µs e mostra o soluço de enfileiramento mesmo
  quando NENHUM pacote se perde — que é o resultado esperado para o
  `child_rekey`.
* **iperf3 UDP a taxa fixa** com `-i 0.1` — dá perda por janela de
  100 ms, atribuível a cada evento, a uma taxa de pacotes muito maior
  que a do ping.

  **A perda é lida do SERVIDOR, não do cliente.** Medido (15/10): o JSON
  do cliente não traz `lost_packets` em `intervals[].sum` — a chave não
  existe ali, só em `end.sum`. É consequência do protocolo: no UDP a
  perda é calculada pelo RECEPTOR, e o cliente só sabe o que enviou. A
  primeira versão deste módulo lia `intervals[].sum.lost_packets` do
  cliente com default 0, então reportava **perda zero em todas as
  janelas, estruturalmente** — a coluna não media nada. O servidor
  rodado com `-J -i 0.1` traz `lost_packets` e `jitter_ms` por
  intervalo, e é dele que a atribuição sai.

  **Taxa de 100 Mbps, não 10.** A 10 Mbps são ~900 pacotes/s, ou um
  pacote a cada 1,1 ms — a mesma resolução do ping de 1 kHz, de modo que
  o UDP não acrescentava sensibilidade nenhuma a uma interrupção de
  ~1 ms. A 100 Mbps são ~9000 pacotes/s, ou ~9 pacotes por milissegundo
  de interrupção. Continua longe de saturar (a A.3 mediu 2466 Mbps de
  teto com AES-128-GCM), então a A.2 segue medindo interrupção e não
  congestionamento.

A conclusão que se espera poder sustentar é "o rekey de Child SA não
perde pacote, a reauth sem MBB perde N" — e para isso a combinação
acima basta. Afirmar duração de interrupção com precisão melhor que
10 ms exigiria outro gerador, e o relatório não afirma isso.
"""

from __future__ import annotations

import json
import re
import subprocess
import threading
import time
from dataclasses import dataclass
from pathlib import Path

from evaluation.collectors.resource import find_charon_pid
from evaluation.instrumentation import emit

# Drop-in em /etc/strongswan.d/: o strongswan.conf principal termina com
# `include strongswan.d/*.conf`, então basta soltar um arquivo ali para
# sobrepor a opção, sem editar o arquivo principal (que é global do host
# e não versionado neste repositório). O prefixo `zz-` garante que vem
# depois dos outros includes.
MBB_DROPIN = Path("/etc/strongswan.d/zz-phase-a-mbb.conf")

_PING_RE = re.compile(
    r"^\[(?P<ts>\d+\.\d+)\]\s+\d+ bytes from \S+:\s+icmp_seq=(?P<seq>\d+)\s+ttl=\d+\s+time=(?P<rtt>[\d.]+)\s*ms"
)

# Uma porta por sentido: os dois fluxos correm ao mesmo tempo.
IPERF_PORT_FWD = 5201   # CU -> borda (initiator -> responder)
IPERF_PORT_REV = 5202   # borda -> CU (responder -> initiator)

# Incerteza da âncora temporal do fluxo UDP, em segundos.
#
# **Por que existe**: os `start`/`end` dos intervalos do iperf3 são
# relativos ao início do teste, e a única âncora absoluta no JSON é
# `start.timestamp.timesecs` — que é um INTEIRO em segundos. Medido:
# âncora 1792076681 contra 1792076681,8 de relógio local, ou 0,84 s de
# defasagem só por truncamento. Com janelas de 100 ms isso é erro
# grande, e foi o que estragou a primeira versão: a janela da linha de
# base, calculada como os 2 s anteriores ao primeiro evento, caía em
# cima do próprio evento e reportava 16 pacotes perdidos num trecho que
# deveria ser silencioso.
#
# A atribuição por evento é alargada por esta margem nos dois lados. Dá
# para fazer isso sem perder o sentido porque o piso de ruído do fluxo
# UDP é ZERO: medido 0 perdidos em 107.605 pacotes a 100 Mbps com a
# sonda de 1 kHz rodando junto e nenhum evento. Então qualquer perda
# dentro da janela alargada é atribuível ao evento, mesmo que a janela
# seja folgada — o que exige apenas que os eventos fiquem mais afastados
# entre si que a margem (ver `spacing_s`).
UDP_ANCHOR_UNCERTAINTY_S = 1.0


@dataclass
class PingSample:
    ts: float          # relógio de parede (ping -D), para casar com os eventos
    seq: int
    rtt_ms: float


def set_make_before_break(enabled: bool | None) -> None:
    """Liga/desliga `charon.make_before_break`; `None` remove o drop-in.

    Exige reinício do charon para valer — quem chama é responsável por
    isso (ver `bench_n3.apply_profile`).
    """
    if enabled is None:
        MBB_DROPIN.unlink(missing_ok=True)
        return
    MBB_DROPIN.write_text(
        "# Escrito pela Fase A (evaluation/phase_a/rekey_traffic.py).\n"
        "# Removível: nada mais depende deste arquivo.\n"
        f"charon {{\n    make_before_break = {'yes' if enabled else 'no'}\n}}\n"
    )


class PingProbe:
    """`ping -D -i <intervalo>` no netns da CU, lido linha a linha.

    **Por que linha a linha numa thread** e não `capture_output` no fim:
    o mesmo motivo do coletor de latência da campanha anterior — fazer
    parse em lote no final funciona para a estatística agregada, mas o
    `ts` de cada amostra é justamente o que permite atribuir a perda ao
    evento de rekey que a causou.
    """

    def __init__(self, netns: str, source: str, target: str, interval_s: float = 0.001):
        self._cmd = ["ip", "netns", "exec", netns, "ping", "-D", "-n",
                     "-i", str(interval_s), "-I", source, target]
        self.interval_s = interval_s
        self.samples: list[PingSample] = []
        self._proc: subprocess.Popen | None = None
        self._thread: threading.Thread | None = None

    def start(self) -> None:
        self._proc = subprocess.Popen(self._cmd, stdout=subprocess.PIPE,
                                      stderr=subprocess.DEVNULL, text=True, bufsize=1)
        self._thread = threading.Thread(target=self._read, daemon=True)
        self._thread.start()

    # O `icmp_seq` do ping é de 16 bits e dá a volta em 65535. A 1 kHz
    # isso acontece a cada 65,5 s, e as execuções da A.2 passam disso
    # (20 eventos x 4 s = 88 s). Sem desenrolar, as sequências deixam de
    # ser monotônicas e a contagem de perda por lacuna vira lixo —
    # medido: uma execução de 88 s reportou perda TOTAL NEGATIVA
    # (-393125), que é o que denunciou o problema. O desenrolamento é
    # feito na coleta, onde as amostras chegam em ordem.
    _SEQ_WRAP = 65536

    def _read(self) -> None:
        assert self._proc and self._proc.stdout
        offset = 0
        anterior = None
        for line in self._proc.stdout:
            if (m := _PING_RE.match(line.strip())):
                bruto = int(m["seq"])
                if anterior is not None and bruto < anterior - self._SEQ_WRAP // 2:
                    # Queda grande = volta do contador, não reordenação.
                    # O limiar de meia volta distingue os dois casos.
                    offset += self._SEQ_WRAP
                anterior = bruto
                self.samples.append(PingSample(float(m["ts"]), bruto + offset,
                                               float(m["rtt"])))

    def stop(self) -> None:
        if self._proc:
            self._proc.terminate()
            try:
                self._proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self._proc.kill()
        if self._thread:
            self._thread.join(timeout=5)


class IperfUdpProbe:
    """Fluxo UDP a taxa fixa atravessando o túnel, num sentido, com
    relatório a cada 100 ms lido do RECEPTOR.

    **O sentido é parâmetro, e isso não é detalhe.** A primeira versão
    media só CU -> borda e reportava interrupção ZERO na reauth com
    make-before-break. Medido com os contadores ICMP do kernel nos dois
    netns (8 reauths, MBB ligado): a borda recebeu 16165 de 16165
    requests — nenhuma perda na ida — e a CU recebeu 16158 de 16165
    replies, ou seja **7 perdidos na volta**. Repetindo com fluxo UDP nos
    dois sentidos, 197275 pacotes cada: 0 perdidos na ida, **64 na
    volta** (8 por reauth, ~0,9 ms a 9000 pps).

    Ou seja: com make-before-break a interrupção existe, só que **apenas
    no sentido responder -> initiator**. A reauth é iniciada pela CU, que
    troca a própria SA de saída de forma atômica; a borda troca a dela ao
    processar a troca, e há um instante em que a SA de saída que ela usa
    não casa com a de entrada instalada na CU.

    Com o sentido certo medido, os dois instrumentos concordam: o ping a
    1 kHz perde 1 pacote (~1 ms) e o fluxo a 9 kHz perde 8 (~0,9 ms). A
    divergência que me fez suspeitar da sonda de ping era artefato de
    medir só o sentido que não quebra.

    Taxa fixa (e não saturando) de propósito: a A.2 quer medir a
    interrupção causada pelo evento, não o teto do enlace. Saturar faria
    a perda por congestionamento se confundir com a do evento — o teto é
    assunto da A.3. Com os dois sentidos ativos são 200 Mbps, ainda bem
    abaixo dos 2405-2649 Mbps medidos na A.3.

    Ver o docstring do módulo para por que a perda vem do receptor e por
    que a taxa é de 100 Mbps.
    """

    def __init__(self, sender_netns: str, sender_addr: str,
                 receiver_netns: str, receiver_addr: str,
                 mbps: float, duration_s: float, port: int,
                 label: str = ""):
        self.mbps, self.duration_s, self.label = mbps, duration_s, label
        # O servidor é SEMPRE o receptor: é ele que computa a perda, e é
        # dele que o JSON sai com `lost_packets` por intervalo. Montar
        # com `-R` para inverter o sentido coloca a perda no relatório do
        # cliente, e ler o campo errado foi exatamente o erro que
        # escondeu a perda na volta.
        self._server_cmd = ["ip", "netns", "exec", receiver_netns, "iperf3", "-s",
                            "-B", receiver_addr, "-p", str(port), "-1", "-J", "-i", "0.1"]
        self._client_cmd = ["ip", "netns", "exec", sender_netns, "iperf3",
                            "-c", receiver_addr, "-B", sender_addr, "-p", str(port),
                            "-u", "-b", f"{mbps}M", "-t", str(int(duration_s)), "-i", "0.1"]
        self._server: subprocess.Popen | None = None
        self._client: subprocess.Popen | None = None
        self.result: dict | None = None
        self.started_at: float | None = None

    def start(self) -> None:
        self._server = subprocess.Popen(self._server_cmd, stdout=subprocess.PIPE,
                                        stderr=subprocess.DEVNULL, text=True)
        time.sleep(0.5)  # deixa o servidor fazer bind antes de o cliente conectar
        self.started_at = time.time()
        self._client = subprocess.Popen(self._client_cmd, stdout=subprocess.DEVNULL,
                                        stderr=subprocess.DEVNULL)

    def stop(self) -> None:
        if self._client:
            try:
                self._client.wait(timeout=self.duration_s + 15)
            except subprocess.TimeoutExpired:
                self._client.kill()
        if self._server:
            try:
                saida, _ = self._server.communicate(timeout=20)
                self.result = json.loads(saida) if saida.strip() else None
            except (subprocess.TimeoutExpired, json.JSONDecodeError):
                self._server.kill()
                self.result = None

    def loss_windows(self) -> list[dict]:
        """Perda por janela de 100 ms, com o instante absoluto de cada
        janela, para casar com os eventos.

        A âncora absoluta vem de `start.timestamp.timesecs` do próprio
        JSON do servidor — e não do `started_at` medido aqui — porque os
        `start`/`end` dos intervalos são relativos ao PRIMEIRO PACOTE
        recebido pelo servidor, não ao instante em que este processo
        lançou o cliente. Usar o relógio local introduziria o atraso de
        arranque do iperf3 como erro sistemático. Mas `timesecs` é
        INTEIRO em segundos, daí a margem de UDP_ANCHOR_UNCERTAINTY_S.
        """
        if not self.result:
            return []
        ancora = (self.result.get("start", {})
                  .get("timestamp", {})
                  .get("timesecs"))
        if ancora is None:
            ancora = self.started_at
        if ancora is None:
            return []
        janelas = []
        for intervalo in self.result.get("intervals", []):
            s = intervalo.get("sum", {})
            janelas.append({
                "t_start": ancora + s.get("start", 0.0),
                "t_end": ancora + s.get("end", 0.0),
                "packets": s.get("packets", 0),
                # None quando o JSON não traz a chave — distingue
                # "nenhuma perda" de "não medido", que foi exatamente a
                # confusão da primeira versão deste módulo.
                "lost": s.get("lost_packets"),
                "jitter_ms": s.get("jitter_ms"),
            })
        return janelas


def _nsenter(charon_pid: int, *args: str) -> list[str]:
    return ["nsenter", f"--mount=/proc/{charon_pid}/ns/mnt",
            f"--net=/proc/{charon_pid}/ns/net", *args]


def trigger_event(charon_pid: int, conn_name: str, kind: str) -> tuple[float, float, bool]:
    """Dispara o evento e devolve (t_antes, t_depois, ok).

    O par de instantes delimita a janela em que a interrupção pode ter
    ocorrido: o `swanctl --rekey` retorna assim que o charon aceita o
    pedido, não quando o rekey conclui, então a atribuição de perda usa
    a janela e não um instante único.
    """
    if kind == "child_rekey":
        cmd = _nsenter(charon_pid, "swanctl", "--rekey", "--child", conn_name)
    elif kind == "ike_reauth":
        cmd = _nsenter(charon_pid, "swanctl", "--rekey", "--ike", conn_name, "--reauth")
    else:
        raise ValueError(f"tipo de evento desconhecido: {kind}")

    t0 = time.time()
    res = subprocess.run(cmd, capture_output=True, text=True)
    return t0, time.time(), res.returncode == 0


def _gap_stats(samples: list[PingSample], t_from: float, t_to: float,
               interval_s: float) -> dict:
    """Perda e pico de RTT numa janela, a partir das amostras do ping.

    A perda é contada por lacuna no `icmp_seq` entre as amostras que
    cercam a janela — o `ping` não imprime nada para pacote perdido, só
    some o número de sequência.
    """
    inside = [s for s in samples if t_from <= s.ts <= t_to]
    if not inside:
        return {"samples": 0, "lost": None, "rtt_peak_ms": None,
                "outage_ms": None, "note": "nenhuma amostra de ping na janela"}

    seqs = [s.seq for s in inside]
    expected = seqs[-1] - seqs[0] + 1
    lost = expected - len(seqs)
    if lost < 0:
        # Impossível com as sequências desenroladas; se acontecer, o
        # desenrolamento falhou e é melhor dizer "não medido" do que
        # publicar um número sem sentido.
        return {"samples": len(inside), "lost": None, "rtt_peak_ms": None,
                "outage_ms": None, "max_consecutive_lost": None,
                "note": f"sequências não monotônicas (lost={lost}): "
                        f"desenrolamento do icmp_seq falhou"}

    # A interrupção é derivada dos números de sequência AUSENTES, não do
    # intervalo entre chegadas.
    #
    # **Por que**: a primeira versão desta função usava a maior lacuna
    # temporal entre amostras consecutivas, e o resultado foi ~2,1 ms
    # tanto nos rekeys quanto na LINHA DE BASE sem evento nenhum. Ou
    # seja, media o jitter de agendamento do próprio `ping -i 0.01`
    # (que ocasionalmente dorme 12 ms em vez de 10), não a interrupção.
    # Contar sequências ausentes não tem esse problema: um pacote que
    # atravessou o túnel não conta como interrupção, por mais tarde que
    # tenha chegado — e o atraso dele aparece no `rtt_peak_ms`.
    maior_corrida = corrida = 0
    for a, b in zip(seqs, seqs[1:]):
        corrida = (b - a - 1) if b > a + 1 else 0
        maior_corrida = max(maior_corrida, corrida)

    # Diagnóstico, não resultado: inclui o jitter do ping. Fica no
    # registro para dar para distinguir "não perdeu pacote" de "o
    # gerador travou".
    maior_lacuna_ms = max((b.ts - a.ts for a, b in zip(inside, inside[1:])), default=0.0) * 1000

    return {
        "samples": len(inside),
        "lost": lost,
        "max_consecutive_lost": maior_corrida,
        "rtt_peak_ms": max(s.rtt_ms for s in inside),
        "rtt_median_ms": sorted(s.rtt_ms for s in inside)[len(inside) // 2],
        # 0 quando nada se perdeu; quantizado no intervalo do ping.
        "outage_ms": maior_corrida * interval_s * 1000,
        "outage_resolution_ms": interval_s * 1000,
        "max_interarrival_ms": maior_lacuna_ms,
    }


def _loss_in_window(windows: list[dict], t_from: float, t_to: float) -> dict:
    """Agrega as janelas de 100 ms do iperf3 que cobrem o evento.

    `udp_lost = None` significa NÃO MEDIDO, não zero — ver o docstring do
    módulo. A primeira versão confundia as duas coisas e reportava perda
    zero estruturalmente.
    """
    # Alarga pela incerteza da âncora (ver UDP_ANCHOR_UNCERTAINTY_S).
    t_from -= UDP_ANCHOR_UNCERTAINTY_S
    t_to += UDP_ANCHOR_UNCERTAINTY_S
    cobertas = [w for w in windows if w["t_end"] >= t_from and w["t_start"] <= t_to]
    perdas = [w["lost"] for w in cobertas if w["lost"] is not None]
    jitters = [w["jitter_ms"] for w in cobertas if w.get("jitter_ms") is not None]
    pacotes = sum(w["packets"] for w in cobertas)
    perdidos = sum(perdas) if (cobertas and len(perdas) == len(cobertas)) else None

    # Interrupção estimada pelo fluxo UDP, em ms.
    #
    # **Por que esta estimativa é MELHOR que a do ping**, apesar de
    # indireta: a do ping é quantizada no passo da sonda (1 ms), e um
    # único pacote caindo na lacuna já satura a contagem. O fluxo UDP
    # roda a ~9000 pacotes/s, então conta a lacuna com resolução de
    # ~0,11 ms. Medido na K2 (15/10): o ping dava 1 ms de interrupção na
    # reauth, o UDP dá ~3,4 ms a partir de 31 pacotes perdidos. O ping
    # subestimava por 3x.
    #
    # Válida porque o piso de ruído do fluxo é zero — medido 0 perdidos
    # em 107.605 pacotes sem evento, e 0 nas linhas de base de todas as
    # repetições. Sem esse piso, converter perda em tempo não teria
    # sentido.
    duracao = max((w["t_end"] for w in cobertas), default=0.0) - \
              min((w["t_start"] for w in cobertas), default=0.0)
    outage_udp_ms = None
    if perdidos is not None and duracao > 0 and pacotes > 0:
        pps = pacotes / duracao
        outage_udp_ms = 1000.0 * perdidos / pps

    return {
        "udp_windows": len(cobertas),
        "udp_packets": pacotes,
        # Só soma se TODAS as janelas cobertas trouxeram a chave;
        # somar um subconjunto subestimaria a perda em silêncio.
        "udp_lost": perdidos,
        "udp_pps": (pacotes / duracao) if duracao > 0 else None,
        "outage_udp_ms": outage_udp_ms,
        "udp_jitter_max_ms": max(jitters) if jitters else None,
    }
