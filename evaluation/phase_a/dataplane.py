#!/usr/bin/env python3
"""A.3 — plano de dados: teto de vazão por cifra do ESP, RTT a vazio e
sob carga, e CPU em softirq.

**Por que esta medição decide algo que as outras não decidem.** A A.1 e
a A.2 medem o plano de CONTROLE (handshake, rekey) — e lá o ML-KEM
desaparece no ruído. O custo do PQC no plano de controle é de bytes, não
de CPU. Já o plano de dados não tem ML-KEM nenhum: todo pacote de
usuário é cifrado pelo ESP, com AES-GCM ou ChaCha20-Poly1305. É aqui
que a decisão em aberto da campanha — **AES-128 contra AES-256 para a
URLLC** — se resolve, porque é aqui que a cifra é exercida milhões de
vezes por segundo em vez de uma vez por rekey.

**Três instrumentos, cada um respondendo uma coisa:**

* `iperf3 -P <n>` TCP até saturar → teto de vazão da cifra;
* `ping` CONCORRENTE ao iperf3 → RTT sob carga, que é o número que
  interessa à URLLC (RTT a vazio já se sabe que é ~0,1 ms nesta
  bancada, e não é o cenário de interesse);
* delta de softirq em `/proc/stat` → onde o custo de cifragem aparece,
  porque o ESP roda em contexto de softirq no kernel, não no processo.

**Linha de base sem IPsec, e por que ela usa outros endereços.** O
tráfego de teste normal vai entre 172.18.0.99 e 172.18.0.90, que só se
alcançam ATRAVÉS do túnel — sem IPsec não há rota entre eles, então
"desligar o IPsec e repetir" não mede nada. A linha de base usa os
endereços EXTERNOS, 10.97.0.11 ↔ 10.97.0.12, que são as duas pontas do
mesmo par veth: mesmo caminho físico, mesma pilha, sem ESP. É o teto do
enlace, e a diferença contra ele é o custo da cifra.
"""

from __future__ import annotations

import json
import re
import subprocess
import threading
import time

from evaluation.instrumentation import emit

# Porta própria, longe das que a A.2 usa (5201 ida, 5202 volta).
#
# **Era 5202, a mesma da sonda de volta da A.2.** Duas execuções da A.3
# lançadas logo depois de uma execução da A.2 falharam inteiras —
# 0,0 Mbps com `retransmits=None`, não número baixo — porque o servidor
# residual da A.2 ainda detinha a porta. O sintoma passou pelo
# consolidador como média de 705,6 Mbps com 300% de variação, em vez de
# erro.
IPERF_PORT = 5210

_PING_STATS_RE = re.compile(r"min/avg/max/mdev = ([\d.]+)/([\d.]+)/([\d.]+)/([\d.]+)")


def read_softirq_jiffies() -> dict[str, int]:
    """Lê os contadores de CPU de `/proc/stat` que importam para o ESP.

    **Por que softirq e não o tempo do processo**: a cifragem do ESP
    acontece no kernel, em contexto de softirq, disparada pela pilha de
    rede — nenhum processo de userspace é creditado por ela. Medir CPU
    do charon ou do iperf3 não veria o custo da cifra.

    `/proc/stat` é global do host, não por netns. Isso é aceitável aqui
    porque a Fase A roda com o laboratório ocioso (sem OCUDU nem srsUE),
    e o registro guarda `idle` junto para dar para checar essa premissa
    depois.
    """
    with open("/proc/stat") as fh:
        for linha in fh:
            if linha.startswith("cpu "):
                campos = [int(v) for v in linha.split()[1:]]
                # user nice system idle iowait irq softirq steal ...
                return {
                    "user": campos[0], "nice": campos[1], "system": campos[2],
                    "idle": campos[3], "iowait": campos[4], "irq": campos[5],
                    "softirq": campos[6],
                }
    return {}


def _cpu_delta(antes: dict[str, int], depois: dict[str, int]) -> dict:
    delta = {k: depois[k] - antes[k] for k in antes}
    total = sum(delta.values())
    if total <= 0:
        return {"cpu_total_jiffies": 0}
    return {
        "cpu_total_jiffies": total,
        **{f"cpu_{k}_pct": 100.0 * v / total for k, v in delta.items()},
    }


class PingLoad:
    """`ping` rodando em paralelo à carga, só para o resumo estatístico.

    Diferente do `PingProbe` da A.2, aqui não interessa o instante de
    cada amostra — interessa a distribuição sob carga. Então usa `-q`
    e lê o resumo do próprio ping, que já dá min/avg/max/mdev, e os
    percentis saem das amostras individuais quando pedidas.
    """

    def __init__(self, netns: str, source: str, target: str,
                 count: int, interval_s: float = 0.01):
        self._cmd = ["ip", "netns", "exec", netns, "ping", "-n",
                     "-c", str(count), "-i", str(interval_s),
                     "-I", source, target]
        self.rtts: list[float] = []
        self._proc: subprocess.Popen | None = None
        self._thread: threading.Thread | None = None

    def start(self) -> None:
        self._proc = subprocess.Popen(self._cmd, stdout=subprocess.PIPE,
                                      stderr=subprocess.DEVNULL, text=True, bufsize=1)
        self._thread = threading.Thread(target=self._read, daemon=True)
        self._thread.start()

    def _read(self) -> None:
        assert self._proc and self._proc.stdout
        for linha in self._proc.stdout:
            if (m := re.search(r"time=([\d.]+)", linha)):
                self.rtts.append(float(m.group(1)))

    def stop(self) -> None:
        if self._proc:
            try:
                self._proc.wait(timeout=10)
            except subprocess.TimeoutExpired:
                self._proc.terminate()
        if self._thread:
            self._thread.join(timeout=5)

    def stats(self) -> dict:
        if not self.rtts:
            return {"rtt_samples": 0}
        ordenados = sorted(self.rtts)
        def p(q: float) -> float:
            return ordenados[min(len(ordenados) - 1, int(round(q * (len(ordenados) - 1))))]
        return {
            "rtt_samples": len(ordenados),
            "rtt_p50_ms": p(0.50), "rtt_p95_ms": p(0.95), "rtt_p99_ms": p(0.99),
            "rtt_min_ms": ordenados[0], "rtt_max_ms": ordenados[-1],
        }


def rtt_idle(netns: str, source: str, target: str, count: int = 200) -> dict:
    sonda = PingLoad(netns, source, target, count)
    sonda.start()
    sonda.stop()
    return {f"idle_{k}": v for k, v in sonda.stats().items()}


def iperf3_tcp(cu_netns: str, edge_netns: str, source: str, target: str,
               duration_s: int, streams: int) -> dict:
    """iperf3 TCP saturando o caminho. Devolve a vazão do RECEPTOR.

    **Por que a do receptor e não a do emissor**: a do emissor conta o
    que entrou no socket, que com TCP inclui o que ainda está em buffer
    quando o teste termina. A do receptor é o que de fato atravessou o
    túnel e foi decifrado — que é o que a medição quer.
    """
    servidor = subprocess.Popen(
        ["ip", "netns", "exec", edge_netns, "iperf3", "-s", "-B", target,
         "-p", str(IPERF_PORT), "-1"],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )
    time.sleep(0.5)
    try:
        cliente = subprocess.run(
            ["ip", "netns", "exec", cu_netns, "iperf3", "-c", target, "-B", source,
             "-p", str(IPERF_PORT), "-t", str(duration_s), "-P", str(streams), "-J"],
            capture_output=True, text=True, timeout=duration_s + 30,
        )
        dados = json.loads(cliente.stdout) if cliente.stdout.strip() else {}
    except (subprocess.TimeoutExpired, json.JSONDecodeError) as exc:
        return {"erro": f"{type(exc).__name__}: {exc}"}
    finally:
        servidor.terminate()
        try:
            servidor.wait(timeout=5)
        except subprocess.TimeoutExpired:
            servidor.kill()

    fim = dados.get("end", {})
    recebido = fim.get("sum_received", {})
    enviado = fim.get("sum_sent", {})
    if not recebido:
        # Sem `end.sum_received` o iperf3 não produziu resultado algum —
        # porta ocupada, servidor fora, conexão recusada. Devolver 0 aqui
        # faria uma FALHA entrar na média como se fosse vazão medida,
        # que é exatamente o que aconteceu com a porta 5202.
        return {"erro": "iperf3 não devolveu end.sum_received",
                "stderr": (cliente.stderr or "").strip()[-300:] or None}
    return {
        "throughput_mbps": recebido.get("bits_per_second", 0) / 1e6,
        "sender_mbps": enviado.get("bits_per_second", 0) / 1e6,
        "retransmits": enviado.get("retransmits"),
        "bytes_received": recebido.get("bytes"),
        "streams": streams,
        "duration_s": duration_s,
    }


def measure_one(label: str, cu_netns: str, edge_netns: str,
                source: str, target: str, duration_s: int, streams: int,
                extra: dict | None = None) -> None:
    """Um ponto da A.3: RTT a vazio, depois vazão com RTT concorrente."""
    vazio = rtt_idle(cu_netns, source, target)

    # O ping sob carga é dimensionado para cobrir toda a janela do
    # iperf3: a 100 Hz, duration_s * 100 amostras.
    sob_carga = PingLoad(cu_netns, source, target, count=duration_s * 100)
    cpu_antes = read_softirq_jiffies()
    sob_carga.start()
    vazao = iperf3_tcp(cu_netns, edge_netns, source, target, duration_s, streams)
    sob_carga.stop()
    cpu_depois = read_softirq_jiffies()

    emit(
        "phase_a_dataplane",
        label=label,
        # Explícito, para o consolidador poder descartar falha em vez de
        # somá-la como medição.
        ok="erro" not in vazao,
        **(extra or {}),
        **vazao,
        **vazio,
        **{f"loaded_{k}": v for k, v in sob_carga.stats().items()},
        **_cpu_delta(cpu_antes, cpu_depois),
    )
    if "erro" in vazao:
        print(f"  [{label}] ERRO: {vazao['erro']}")
    else:
        s = sob_carga.stats()
        print(f"  [{label}] {vazao['throughput_mbps']:>8.1f} Mbps  "
              f"RTT vazio p50 {vazio.get('idle_rtt_p50_ms', float('nan')):.3f} ms  "
              f"carga p50/p95/p99 {s.get('rtt_p50_ms', float('nan')):.3f}/"
              f"{s.get('rtt_p95_ms', float('nan')):.3f}/{s.get('rtt_p99_ms', float('nan')):.3f} ms  "
              f"softirq {_cpu_delta(cpu_antes, cpu_depois).get('cpu_softirq_pct', 0):.1f}%")
