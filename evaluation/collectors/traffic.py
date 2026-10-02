"""Geração de tráfego por fatia — ver CENARIOS-TESTE-AVALIACAO.md seção
3 ("perfil de tráfego por fatia") e seção 4 ("Gerador de Tráfego").

**Desvio deliberado do documento pro perfil de latência fina (URLLC),
documentado aqui**: o documento recomenda `sockperf` ping-pong sobre um
teste de throughput genérico pra latência determinística. `sockperf`
precisa de um processo servidor do lado remoto — aqui o lado remoto é a
UPF, rodando na imagem `gradiant/open5gs:2.8.0` (container Docker), sem
`sockperf` instalado e fora do escopo deste pipeline modificar a imagem
só pra isso. Substituído por `ping -i <intervalo fino> -I <interface>` — mesma
propriedade que o documento pede (pacotes pequenos, periódicos,
determinísticos), validado contra o laboratório real com RTT de
verdade (~20-25ms, 0% perda com a UE registrada e a sessão PDU ativa).
RTT vem do próprio `ping` (`time=X ms` por pacote), não é estimado. Se
o ping não retornar nada (100% perda) antes de rodar um cenário de
verdade, é sinal de UE/sessão PDU desatualizada, não do mecanismo em
si — confirme com `grep "PDU Session Establishment Accept" /tmp/ue*.log`
e reinicie a UE se o IP não bater com a sessão que a interface mostra
(achado desta sessão: um restart de charon/rede no meio de uma sessão
PDU ativa pode deixá-la "presa" sem tráfego respondendo, mesmo com a
interface e o IP ainda visíveis).

Throughput (eMBB/mIoT) usa `iperf3 -J` contra um servidor real rodando
na UPF (`10.45.0.1:5201`) — isso sim já validado como está no documento,
sem substituição (ver Fase 1 do protótipo)."""

from __future__ import annotations

import json
import re
import subprocess

from evaluation.instrumentation import emit

_PING_RTT_RE = re.compile(r"time=(?P<rtt_ms>[\d.]+) ms")


def run_latency_probe(
    netns: str, iface: str, dest: str, count: int = 50, interval_seconds: float = 0.1, label: str = "latency"
) -> list[float]:
    """`ping` dentro de `netns`, saindo pela `iface` da UE (ex:
    `oaitun_ue1`/`oaitun_ue1p2`/`oaitun_ue1p3`), emite um evento
    `latency_sample` por pacote respondido. Retorna a lista de RTTs em
    ms (útil pro chamador reportar perda: `count - len(retorno)`)."""
    # timeout generoso (não só `count * interval`) — `ping` pode demorar
    # além do esperado esperando o timeout de cada pacote perdido, não só
    # o intervalo entre envios.
    timeout_seconds = count * max(interval_seconds, 1.0) + 10
    try:
        result = subprocess.run(
            ["ip", "netns", "exec", netns, "ping", "-i", str(interval_seconds), "-c", str(count), "-I", iface, dest],
            capture_output=True, text=True, timeout=timeout_seconds,
        )
    except subprocess.TimeoutExpired as exc:
        result = exc
    rtts = []
    for match in _PING_RTT_RE.finditer(result.stdout):
        rtt_ms = float(match.group("rtt_ms"))
        rtts.append(rtt_ms)
        emit("latency_sample", label=label, iface=iface, rtt_ms=rtt_ms)
    emit(
        "latency_probe_summary", label=label, iface=iface,
        sent=count, received=len(rtts), loss_percent=100.0 * (count - len(rtts)) / count if count else 0.0,
    )
    return rtts


def run_throughput_probe(
    netns: str, iface_bind_ip: str, dest: str = "10.45.0.1", port: int = 5201,
    duration_seconds: int = 10, udp: bool = False, bitrate: str = "", label: str = "throughput",
) -> dict:
    """`iperf3 -J` contra o servidor real na UPF — precisa de
    `iperf3 -s` já rodando lá (ver RUNBOOK-OAI.md/Fase 1). `--bind`
    garante que o tráfego sai pela sessão PDU certa (uma interface por
    fatia), não pela rota default."""
    cmd = [
        "ip", "netns", "exec", netns, "iperf3", "-c", dest, "-p", str(port),
        "-t", str(duration_seconds), "-J", "--bind", iface_bind_ip,
    ]
    if udp:
        cmd.append("-u")
        if bitrate:
            cmd.extend(["-b", bitrate])

    # timeout generoso além da duração pedida — se o servidor iperf3
    # (dentro do container da UPF) não estiver respondendo, `iperf3 -c`
    # pode ficar pendurado tentando conectar bem além de `-t`, travando
    # a janela inteira do experimento (achado testando isto).
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=duration_seconds + 15)
    except subprocess.TimeoutExpired:
        emit("throughput_probe_failed", label=label, stderr="timeout esperando iperf3 (servidor fora do ar?)")
        return {}
    try:
        data = json.loads(result.stdout)
    except json.JSONDecodeError:
        emit("throughput_probe_failed", label=label, stderr=result.stderr[-500:])
        return {}

    end = data.get("end", {})
    summary = end.get("sum_received") or end.get("sum") or {}
    bits_per_second = summary.get("bits_per_second", 0.0)
    lost_percent = summary.get("lost_percent")  # só existe em UDP

    emit(
        "throughput_probe_summary", label=label, iface_bind_ip=iface_bind_ip,
        mbps=bits_per_second / 1e6, lost_percent=lost_percent, udp=udp,
    )
    return data
