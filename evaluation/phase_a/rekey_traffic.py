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

* O `rtt_peak_ms`, lido do próprio `time=` do ping, entra no relatório
  porque tem resolução de µs e mostra o soluço de enfileiramento mesmo
  quando NENHUM pacote se perde — que é o resultado esperado para o
  `child_rekey`.
* **iperf3 UDP a taxa fixa** com `-i 0.1` — dá perda por janela de
  100 ms, atribuível a cada evento, a uma taxa de pacotes muito maior
  que 100 Hz.

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

IPERF_PORT = 5201


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

    def _read(self) -> None:
        assert self._proc and self._proc.stdout
        for line in self._proc.stdout:
            if (m := _PING_RE.match(line.strip())):
                self.samples.append(PingSample(float(m["ts"]), int(m["seq"]),
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
    """iperf3 UDP a taxa fixa atravessando o túnel, com relatório a cada
    100 ms.

    Taxa fixa (e não saturando) de propósito: a A.2 quer medir a
    interrupção causada pelo rekey, não o teto do enlace. Saturar faria
    a perda por congestionamento se confundir com a perda pelo rekey —
    o teto é assunto da A.3.
    """

    def __init__(self, cu_netns: str, edge_netns: str, source: str, target: str,
                 mbps: float, duration_s: float):
        self.target, self.mbps, self.duration_s = target, mbps, duration_s
        self._server_cmd = ["ip", "netns", "exec", edge_netns, "iperf3", "-s",
                            "-B", target, "-p", str(IPERF_PORT)]
        self._client_cmd = ["ip", "netns", "exec", cu_netns, "iperf3",
                            "-c", target, "-B", source, "-p", str(IPERF_PORT),
                            "-u", "-b", f"{mbps}M", "-t", str(int(duration_s)),
                            "-i", "0.1", "-J"]
        self._server: subprocess.Popen | None = None
        self._client: subprocess.Popen | None = None
        self.result: dict | None = None
        self.started_at: float | None = None

    def start(self) -> None:
        self._server = subprocess.Popen(self._server_cmd, stdout=subprocess.DEVNULL,
                                        stderr=subprocess.DEVNULL)
        time.sleep(0.5)  # deixa o servidor fazer bind antes de o cliente conectar
        self.started_at = time.time()
        self._client = subprocess.Popen(self._client_cmd, stdout=subprocess.PIPE,
                                        stderr=subprocess.DEVNULL, text=True)

    def stop(self) -> None:
        if self._client:
            try:
                out, _ = self._client.communicate(timeout=self.duration_s + 15)
                self.result = json.loads(out) if out.strip() else None
            except (subprocess.TimeoutExpired, json.JSONDecodeError):
                self._client.kill()
                self.result = None
        if self._server:
            self._server.terminate()
            try:
                self._server.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self._server.kill()

    def loss_windows(self) -> list[dict]:
        """Perda por janela de 100 ms, com o instante absoluto de cada
        janela, para casar com os eventos de rekey."""
        if not self.result or self.started_at is None:
            return []
        windows = []
        for interval in self.result.get("intervals", []):
            s = interval.get("sum", {})
            windows.append({
                "t_start": self.started_at + s.get("start", 0.0),
                "t_end": self.started_at + s.get("end", 0.0),
                "packets": s.get("packets", 0),
                "lost": s.get("lost_packets", 0),
            })
        return windows


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
    overlapping = [w for w in windows if w["t_end"] >= t_from and w["t_start"] <= t_to]
    return {
        "udp_windows": len(overlapping),
        "udp_packets": sum(w["packets"] for w in overlapping),
        "udp_lost": sum(w["lost"] for w in overlapping),
    }
