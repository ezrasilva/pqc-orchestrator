#!/usr/bin/env python3
"""Fase A — bancada de caracterização dos perfis criptográficos no N3,
sem rádio (ver `docs/CAMPANHA-SAPQ-IPSEC.md`, "Fase A").

**Por que sem rádio**: medido ao vivo nesta VM — RTT pelo túnel N3
direto (`cu-ns` ↔ `5gc-edge-ns`) é ~0,1 ms, contra ~57 ms quando o
mesmo tráfego passa pelo rádio simulado via ZMQ. Uma interrupção de
rekey da ordem de 1-20 ms é perfeitamente visível na primeira e fica
afogada no ruído da segunda. A Fase A existe pra medir o custo do
PERFIL CRIPTOGRÁFICO; o rádio só mascararia a diferença.

**Topologia**: uma única conexão (`phasea`), sem `mark_in`/`mark_out`
(marcas por fatia são assunto da Fase B), entre os endereços que já
existem permanentemente nos dois netns:

    cu-ns 10.97.0.11  <--IKE/ESP-->  10.97.0.12 5gc-edge-ns
      TS 172.18.0.99/32  <-tráfego->  172.18.0.90/32

O tráfego de teste é gerado direto entre esses dois endereços, que são
locais de cada netns — nenhum processo de RAN envolvido.

Uso:
    sudo .venv/bin/python3 -m evaluation.phase_a.bench_n3 \
        --measurement handshake --profiles K0,K1,K2,K3,K4 --repetitions 30
"""

from __future__ import annotations

import argparse
import os
import random
import re
import secrets as pysecrets
import subprocess
import sys
import time
import uuid
from pathlib import Path

from evaluation import instrumentation, lab_control
from evaluation.collectors.resource import (RADIO_PROCESS_NAMES, find_charon_pid,
                                            find_pids_by_name)
from evaluation.instrumentation import emit
from evaluation.phase_a import dataplane, netem, rekey_traffic, scale
from evaluation.phase_a.profiles import ALL_PROFILES, Profile, by_name

CONN_NAME = "phasea"
CU_NETNS = "cu-ns"
EDGE_NETNS = "5gc-edge-ns"
CU_ADDR, EDGE_ADDR = "10.97.0.11", "10.97.0.12"
CU_TS, EDGE_TS = "172.18.0.99/32", "172.18.0.90/32"
PPK_ID = "ppk-phasea"

RESULTS_DIR = Path(__file__).resolve().parent.parent / "results_phase_a"

_SENT_RE = re.compile(r"sending packet:.*?\((\d+) bytes\)")
_RECV_RE = re.compile(r"received packet:.*?\((\d+) bytes\)")
_EXCHANGE_RE = re.compile(r"generating (IKE_SA_INIT|IKE_INTERMEDIATE|IKE_AUTH) request")
_PROPOSAL_RE = re.compile(r"selected proposal: (IKE|ESP):(\S+)")
_ESTABLISHED_RE = re.compile(r"CHILD_SA .* established with SPIs")
_FRAGMENT_RE = re.compile(r"EF\(\d+/\d+\)")


def registra_carga(momento: str, **extra) -> dict:
    """Registra a carga do hospedeiro junto de cada medição.

    **Por que isto existe.** A Fase A é especificada para rodar "sem
    OCUDU nem srsUE" (ver docs/CAMPANHA-SAPQ-IPSEC.md), e a primeira
    execução dela, em 15/10, foi tomada com o rádio RODANDO — gNB mais
    três srsUE consumindo ~5 dos 8 núcleos. Isso passou sem ser notado
    porque nada registrava a carga.

    O efeito medido ao comparar as duas condições é de 2 a 3×:

    | Medição | sem registro de carga (15/10) | com load ~18 |
    | --- | --- | --- |
    | ML-KEM-768 keygen | 21,9 µs | 63,4 µs |
    | handshake K2 (p50) | 29,8 ms | 64,2 ms |

    E a 18 de load o ML-KEM-1024 mede mais RÁPIDO que o 768, o que é
    fisicamente impossível — ruído de escalonamento dominando o sinal.

    Registrar não corrige a medição; corrige a possibilidade de
    confiar nela depois. Qualquer execução da Fase A agora carrega a
    condição em que foi tomada.
    """
    try:
        load1, load5, load15 = os.getloadavg()
    except OSError:
        load1 = load5 = load15 = float("nan")
    radio = find_pids_by_name(RADIO_PROCESS_NAMES)
    dados = dict(
        moment=momento,
        load_1min=load1, load_5min=load5, load_15min=load15,
        cpu_count=os.cpu_count(),
        # A premissa da Fase A é que estes não estejam rodando. Guardar
        # a lista, e não só um booleano, permite saber DEPOIS o que
        # estava de pé numa execução já colhida.
        radio_processes=sorted(radio),
        radio_running=bool(radio),
        **extra,
    )
    emit("phase_a_host_load", **dados)
    return dados


def _conn_conf(profile: Profile, local_addr: str, remote_addr: str,
               local_ts: str, remote_ts: str, start_action: str) -> str:
    ppk_lines = ""
    if profile.needs_ppk:
        # RFC 8784: o PPK entra na derivação junto do material do IKE.
        ppk_lines = f"        ppk_id = {PPK_ID}\n        ppk_required = yes\n"
    return f"""connections {{
    {CONN_NAME} {{
        local_addrs = {local_addr}
        remote_addrs = {remote_addr}
        proposals = {profile.ike_proposal}
        local {{ auth = psk }}
        remote {{ auth = psk }}
{ppk_lines}        children {{
            {CONN_NAME} {{
                local_ts = {local_ts}
                remote_ts = {remote_ts}
                esp_proposals = {profile.esp_proposal}
                mode = tunnel
                start_action = {start_action}
            }}
        }}
        version = 2
    }}
}}
"""


def _secrets_conf(psk: str, ppk_hex: str | None) -> str:
    ppk_block = ""
    if ppk_hex:
        ppk_block = f"""    ppk-{CONN_NAME} {{
        id = {PPK_ID}
        secret = 0x{ppk_hex}
    }}
"""
    return f"""secrets {{
    ike-{CONN_NAME} {{
        id-1 = {CU_ADDR}
        id-2 = {EDGE_ADDR}
        secret = "{psk}"
    }}
{ppk_block}}}
"""


def apply_profile(profile: Profile) -> None:
    """Escreve a config dos dois lados pro perfil e reinicia o charon.

    Só o lado CU tem `start_action = start`→ aqui usamos `none` nos dois
    e iniciamos explicitamente a cada medição; a borda fica responder
    passivo. (Os dois lados com `start` causam corrida de iniciação —
    achado real da campanha anterior, ver `scenario1_static_pqc.py`.)
    """
    psk = pysecrets.token_urlsafe(32)
    ppk_hex = pysecrets.token_bytes(32).hex() if profile.needs_ppk else None

    base = lab_control.LIVE_LAB_IPSEC_DIR
    (base / "swanctl-cu" / "conf.d" / "connections.conf").write_text(
        _conn_conf(profile, CU_ADDR, EDGE_ADDR, CU_TS, EDGE_TS, "none")
    )
    (base / "swanctl-edge" / "conf.d" / "connections.conf").write_text(
        _conn_conf(profile, EDGE_ADDR, CU_ADDR, EDGE_TS, CU_TS, "none")
    )
    for side in ("swanctl-cu", "swanctl-edge"):
        path = base / side / "conf.d" / "secrets.conf"
        path.write_text(_secrets_conf(psk, ppk_hex))
        path.chmod(0o600)

    lab_control.restart_ipsec_lab((CU_NETNS, EDGE_NETNS))
    for netns in (EDGE_NETNS, CU_NETNS):  # borda primeiro: tem que estar pronta pra responder
        pid = find_charon_pid(netns)
        if pid is None:
            raise RuntimeError(f"charon não subiu em {netns} depois de aplicar o perfil {profile.name}")
        subprocess.run(_nsenter(pid, "swanctl", "--load-all"), capture_output=True, check=True)


def _nsenter(charon_pid: int, *args: str) -> list[str]:
    return [
        "nsenter", f"--mount=/proc/{charon_pid}/ns/mnt", f"--net=/proc/{charon_pid}/ns/net", *args
    ]


_CONF_FILES = (
    ("swanctl-cu", "connections.conf"),
    ("swanctl-cu", "secrets.conf"),
    ("swanctl-edge", "connections.conf"),
    ("swanctl-edge", "secrets.conf"),
)


def backup_lab_config() -> dict[tuple[str, str], str]:
    """Guarda a config por-fatia (usada pela Fase B) antes de a Fase A
    sobrescrevê-la.

    **Por que isto existe**: o `secrets.conf` NÃO é versionado (tem PSK
    e o PPK), então sobrescrevê-lo sem backup é irreversível — o
    `connections.conf` dá pra recuperar com `git checkout` em
    `~/oai-lab-conf`, o `secrets.conf` não. Perder esse arquivo custou
    duas regenerações de PSK no meio da campanha anterior."""
    base = lab_control.LIVE_LAB_IPSEC_DIR
    backup = {key: (base / key[0] / "conf.d" / key[1]).read_text() for key in _CONF_FILES}

    # GUARDA: se o que está vivo já é a config DESTA bancada, então uma
    # execução anterior da Fase A rodou com `--no-restore` e a config
    # por-fatia da Fase B não está mais aqui. "Restaurar" este backup no
    # fim devolveria a config da Fase A e o `load_and_initiate_n3`
    # falharia com "CHILD_SA config 'n3-urllc-cu-edge' not found" —
    # exatamente o que aconteceu ao encadear duas execuções, a primeira
    # com `--no-restore`.
    #
    # Falhar aqui, ANTES de medir, é melhor que descobrir no fim: a
    # recuperação é `git -C ~/oai-lab-conf checkout swanctl-cu
    # swanctl-edge` mais `lab/ipsec/regen-secrets.py`, e não custa nada
    # fazer antes.
    if any(f"{CONN_NAME} {{" in texto for texto in backup.values()):
        raise RuntimeError(
            f"a config viva em {base} já é a da Fase A (conexão {CONN_NAME!r}), "
            f"não a por-fatia da Fase B — provavelmente de uma execução anterior "
            f"com --no-restore. Restaurar este backup no fim não devolveria a "
            f"Fase B. Recupere antes com:\n"
            f"  git -C {base} checkout swanctl-cu swanctl-edge\n"
            f"  sudo lab/ipsec/regen-secrets.py\n"
            f"Ou rode esta execução com --no-restore, se o encadeamento for "
            f"intencional e a restauração vier depois."
        )
    return backup


def restore_lab_config(backup: dict[tuple[str, str], str]) -> None:
    """Devolve a config por-fatia e reinicia o IPsec, deixando o
    laboratório pronto pra Fase B (ou pra qualquer uso normal)."""
    base = lab_control.LIVE_LAB_IPSEC_DIR
    for key, content in backup.items():
        path = base / key[0] / "conf.d" / key[1]
        path.write_text(content)
        if key[1] == "secrets.conf":
            path.chmod(0o600)
    lab_control.restart_ipsec_lab((CU_NETNS, EDGE_NETNS))
    lab_control.load_and_initiate_n3()


def _terminate(charon_pid: int) -> None:
    subprocess.run(_nsenter(charon_pid, "swanctl", "--terminate", "--ike", CONN_NAME),
                   capture_output=True)


def measure_handshake(profile: Profile, repetitions: int) -> None:
    """Métrica A.1 — tempo total e por troca, bytes no fio, nº de
    mensagens e fragmentos.

    **Como o tempo por troca é obtido sem mexer no logging do charon**:
    `swanctl --initiate` imprime o progresso do handshake na saída
    padrão conforme ele acontece; lendo essa saída LINHA A LINHA (não
    em lote no final) dá pra carimbar cada troca com o instante em que
    ela ocorreu. Mesma técnica validada no coletor de latência
    (`collectors/traffic.py`) — lá, fazer parse em lote no fim tornava
    o `ts` de cada amostra inútil pra correlação temporal.
    """
    charon_pid = find_charon_pid(CU_NETNS)
    if charon_pid is None:
        raise RuntimeError(f"charon não encontrado em {CU_NETNS}")

    for rep in range(1, repetitions + 1):
        _terminate(charon_pid)
        time.sleep(0.3)  # deixa a terminação assentar antes de medir a subida

        bytes_sent = bytes_received = 0
        messages_sent = messages_received = 0
        fragments = 0
        exchanges: dict[str, float] = {}
        negotiated: dict[str, str] = {}
        established = False

        start = time.monotonic()
        proc = subprocess.Popen(
            _nsenter(charon_pid, "swanctl", "--initiate", "--child", CONN_NAME),
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, bufsize=1,
        )
        for line in proc.stdout:
            now = time.monotonic() - start
            if (m := _EXCHANGE_RE.search(line)):
                exchanges.setdefault(m.group(1), now)
            if (m := _SENT_RE.search(line)):
                bytes_sent += int(m.group(1))
                messages_sent += 1
            if (m := _RECV_RE.search(line)):
                bytes_received += int(m.group(1))
                messages_received += 1
            if _FRAGMENT_RE.search(line):
                fragments += 1
            if (m := _PROPOSAL_RE.search(line)):
                negotiated[m.group(1)] = m.group(2)
            if _ESTABLISHED_RE.search(line):
                established = True
        proc.wait()
        total = time.monotonic() - start

        emit(
            "phase_a_handshake",
            profile=profile.name,
            repetition=rep,
            ok=established and proc.returncode == 0,
            duration_seconds=total,
            exchanges_offset_seconds=exchanges,
            n_exchanges=len(exchanges),
            bytes_sent=bytes_sent,
            bytes_received=bytes_received,
            messages_sent=messages_sent,
            messages_received=messages_received,
            fragments=fragments,
            negotiated_ike=negotiated.get("IKE"),
            negotiated_esp=negotiated.get("ESP"),
            ike_proposal_requested=profile.ike_proposal,
            esp_proposal_requested=profile.esp_proposal,
        )
        if not established:
            print(f"  [{profile.name}] rep {rep}: NÃO estabeleceu (returncode={proc.returncode})")


def _is_established(charon_pid: int) -> bool:
    res = subprocess.run(_nsenter(charon_pid, "swanctl", "--list-sas", "--ike", CONN_NAME),
                         capture_output=True, text=True)
    return "INSTALLED" in res.stdout


def _ensure_established(charon_pid: int, timeout_s: float = 30.0) -> None:
    """Garante uma Child SA de pé, sem falhar se já havia uma."""
    if _is_established(charon_pid):
        return
    res = subprocess.run(_nsenter(charon_pid, "swanctl", "--initiate", "--child", CONN_NAME),
                         capture_output=True, text=True)
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        if _is_established(charon_pid):
            return
        time.sleep(0.5)
    raise RuntimeError(
        f"Child SA {CONN_NAME} não estabeleceu em {timeout_s}s "
        f"(returncode={res.returncode}): {res.stdout.strip()[-400:]}"
    )


def measure_rekey(profile: Profile, repetitions: int, event_kind: str,
                  make_before_break: bool | None, udp_mbps: float = 100.0,
                  ping_interval_s: float = 0.001, spacing_s: float = 4.0) -> None:
    """Métrica A.2 — perda, pico de RTT e interrupção por evento de
    rekey/reauth, sob tráfego.

    Ver `phase_a/rekey_traffic.py` para por que há três combinações de
    evento × make-before-break e qual a resolução de cada gerador.
    """
    charon_pid = find_charon_pid(CU_NETNS)
    if charon_pid is None:
        raise RuntimeError(f"charon não encontrado em {CU_NETNS}")

    # O túnel tem de estar de pé ANTES de o tráfego começar: medir um
    # rekey exige uma SA existente para renovar. Idempotente de
    # propósito — medições consecutivas no mesmo perfil (child_rekey e
    # depois ike_reauth) reaproveitam a SA, e `--initiate` sobre uma
    # Child SA já estabelecida retorna erro.
    _ensure_established(charon_pid)

    cu_ip, edge_ip = CU_TS.split("/")[0], EDGE_TS.split("/")[0]
    # Folga nos dois extremos para o tráfego já estar em regime no
    # primeiro evento e ainda correr depois do último.
    duration_s = spacing_s * (repetitions + 2)

    ping = rekey_traffic.PingProbe(CU_NETNS, cu_ip, edge_ip, ping_interval_s)
    # DOIS fluxos, um por sentido. A primeira versão media só
    # CU -> borda e por isso reportava interrupção zero na reauth com
    # make-before-break: com MBB a interrupção existe apenas no sentido
    # responder -> initiator (ver `phase_a/rekey_traffic.py`). Medir um
    # sentido só foi o que fez os dois instrumentos parecerem discordar.
    iperf_fwd = rekey_traffic.IperfUdpProbe(
        CU_NETNS, cu_ip, EDGE_NETNS, edge_ip, udp_mbps, duration_s,
        rekey_traffic.IPERF_PORT_FWD, label="fwd")
    iperf_rev = rekey_traffic.IperfUdpProbe(
        EDGE_NETNS, edge_ip, CU_NETNS, cu_ip, udp_mbps, duration_s,
        rekey_traffic.IPERF_PORT_REV, label="rev")
    ping.start()
    iperf_fwd.start()
    iperf_rev.start()
    time.sleep(spacing_s)  # regime antes do primeiro evento

    events: list[tuple[int, float, float, bool]] = []
    for rep in range(1, repetitions + 1):
        t0, t1, ok = rekey_traffic.trigger_event(charon_pid, CONN_NAME, event_kind)
        events.append((rep, t0, t1, ok))
        if not ok:
            print(f"  [{profile.name}/{event_kind}] rep {rep}: swanctl falhou")
        time.sleep(spacing_s)

    ping.stop()
    iperf_fwd.stop()
    iperf_rev.stop()
    janelas_fwd = iperf_fwd.loss_windows()
    janelas_rev = iperf_rev.loss_windows()

    # A janela de atribuição vai do pedido até `spacing_s` depois: o
    # `swanctl --rekey` retorna quando o charon ACEITA o pedido, não
    # quando o rekey conclui, então a interrupção cai depois do retorno.
    for rep, t0, t1, ok in events:
        t_to = t1 + spacing_s
        emit(
            "phase_a_rekey",
            profile=profile.name,
            repetition=rep,
            event_kind=event_kind,
            make_before_break=make_before_break,
            ok=ok,
            trigger_seconds=t1 - t0,
            udp_offered_mbps=udp_mbps,
            **rekey_traffic._gap_stats(ping.samples, t0, t_to, ping_interval_s),
            **{f"fwd_{k}": v for k, v in
               rekey_traffic._loss_in_window(janelas_fwd, t0, t_to).items()},
            **{f"rev_{k}": v for k, v in
               rekey_traffic._loss_in_window(janelas_rev, t0, t_to).items()},
        )

    # Linha de base no mesmo tráfego, sem nenhum evento: sem ela não há
    # como dizer se o pico de RTT de um rekey é do rekey ou do ruído da
    # bancada. Pega a folga inicial, anterior ao primeiro evento.
    #
    # A GUARDA de `UDP_ANCHOR_UNCERTAINTY_S` existe porque a atribuição
    # do fluxo UDP alarga a janela por essa margem nos dois lados (a
    # âncora do iperf3 tem granularidade de 1 s). Sem a guarda, a janela
    # alargada da linha de base invadiria o primeiro evento e reportaria
    # como ruído de fundo a perda causada por ele — foi exatamente o que
    # aconteceu na primeira versão, que creditou 16 pacotes perdidos a um
    # trecho que deveria ser silencioso.
    if events:
        guarda = rekey_traffic.UDP_ANCHOR_UNCERTAINTY_S
        baseline_to = events[0][1] - 2 * guarda
        baseline_from = baseline_to - spacing_s / 2
        emit(
            "phase_a_rekey_baseline",
            profile=profile.name,
            event_kind=event_kind,
            make_before_break=make_before_break,
            udp_offered_mbps=udp_mbps,
            **rekey_traffic._gap_stats(ping.samples, baseline_from, baseline_to,
                                       ping_interval_s),
            **{f"fwd_{k}": v for k, v in
               rekey_traffic._loss_in_window(janelas_fwd, baseline_from, baseline_to).items()},
            **{f"rev_{k}": v for k, v in
               rekey_traffic._loss_in_window(janelas_rev, baseline_from, baseline_to).items()},
        )


def measure_dataplane(profile: Profile, duration_s: int, streams: int) -> None:
    """Métrica A.3 — teto de vazão, RTT a vazio e sob carga, e softirq,
    para a cifra de ESP do perfil.

    Ver `phase_a/dataplane.py` para por que o softirq é o contador certo
    e por que a linha de base sem IPsec usa os endereços externos.
    """
    charon_pid = find_charon_pid(CU_NETNS)
    if charon_pid is None:
        raise RuntimeError(f"charon não encontrado em {CU_NETNS}")
    _ensure_established(charon_pid)

    dataplane.measure_one(
        f"{profile.name}", CU_NETNS, EDGE_NETNS,
        CU_TS.split("/")[0], EDGE_TS.split("/")[0], duration_s, streams,
        extra={"profile": profile.name, "esp_proposal": profile.esp_proposal,
               "ike_proposal": profile.ike_proposal, "ipsec": True},
    )


def measure_dataplane_baseline(duration_s: int, streams: int) -> None:
    """Linha de base da A.3: o mesmo caminho físico SEM ESP.

    Usa os endereços externos (10.97.0.11 ↔ 10.97.0.12) porque os
    internos só se alcançam através do túnel — ver docstring de
    `phase_a/dataplane.py`. Sem esta linha, os números de vazão por
    cifra não têm contra o que ser comparados: não daria para dizer se
    um teto de X Mbps é limite da cifra ou do enlace.
    """
    dataplane.measure_one(
        "SEM-IPSEC", CU_NETNS, EDGE_NETNS, CU_ADDR, EDGE_ADDR,
        duration_s, streams,
        extra={"profile": None, "esp_proposal": None, "ipsec": False,
               "note": "endereços externos: mesmo par veth, sem ESP"},
    )


def _conn_conf_scale(profile: Profile, n: int, local_addr: str, remote_addr: str,
                     mirror: bool) -> str:
    """Config com N Child SAs sob uma única IKE_SA (ver `phase_a/scale.py`
    para por que uma só)."""
    ppk_lines = ""
    if profile.needs_ppk:
        ppk_lines = f"        ppk_id = {PPK_ID}\n        ppk_required = yes\n"
    filhos = scale.children_block(n, CONN_NAME, profile.esp_proposal, mirror)
    return f"""connections {{
    {CONN_NAME} {{
        local_addrs = {local_addr}
        remote_addrs = {remote_addr}
        proposals = {profile.ike_proposal}
        local {{ auth = psk }}
        remote {{ auth = psk }}
{ppk_lines}        children {{
{filhos}
        }}
        version = 2
    }}
}}
"""


def apply_profile_scale(profile: Profile, n: int) -> None:
    """Como `apply_profile`, mas com N Child SAs. Mantém o mesmo PSK/PPK
    novo por aplicação e o mesmo `start_action = none` nos dois lados."""
    psk = pysecrets.token_urlsafe(32)
    ppk_hex = pysecrets.token_bytes(32).hex() if profile.needs_ppk else None

    base = lab_control.LIVE_LAB_IPSEC_DIR
    (base / "swanctl-cu" / "conf.d" / "connections.conf").write_text(
        _conn_conf_scale(profile, n, CU_ADDR, EDGE_ADDR, mirror=False))
    (base / "swanctl-edge" / "conf.d" / "connections.conf").write_text(
        _conn_conf_scale(profile, n, EDGE_ADDR, CU_ADDR, mirror=True))
    for side in ("swanctl-cu", "swanctl-edge"):
        path = base / side / "conf.d" / "secrets.conf"
        path.write_text(_secrets_conf(psk, ppk_hex))
        path.chmod(0o600)

    lab_control.restart_ipsec_lab((CU_NETNS, EDGE_NETNS))
    for netns in (EDGE_NETNS, CU_NETNS):
        pid = find_charon_pid(netns)
        if pid is None:
            raise RuntimeError(f"charon não subiu em {netns} (A.4, n={n})")
        subprocess.run(_nsenter(pid, "swanctl", "--load-all"), capture_output=True, check=True)


def measure_scale(profile: Profile, n: int, repetitions: int) -> None:
    """Métrica A.4 — N Child SAs fazendo rekey ao mesmo tempo."""
    scale.setup_addresses(n, CU_NETNS, EDGE_NETNS)
    try:
        apply_profile_scale(profile, n)
        charon_pid = find_charon_pid(CU_NETNS)
        if charon_pid is None:
            raise RuntimeError(f"charon não encontrado em {CU_NETNS}")
        cmd = _nsenter(charon_pid)

        # Sobe as N Child SAs. Sequencial de propósito: a A.4 mede o
        # custo do REKEY simultâneo, não o da subida inicial — e subir
        # N de uma vez só adicionaria uma variável.
        subidas = 0
        for i in range(1, n + 1):
            res = subprocess.run([*cmd, "swanctl", "--initiate", "--child", f"{CONN_NAME}-{i}"],
                                 capture_output=True, text=True)
            subidas += res.returncode == 0
        emit("phase_a_scale_setup", profile=profile.name, n_children=n,
             n_established=subidas)
        if subidas < n:
            print(f"  [{profile.name}] n={n}: só {subidas}/{n} Child SAs subiram — "
                  f"o rekey mede menos do que se pediu")

        for rep in range(1, repetitions + 1):
            resultados = scale.rekey_all_concurrently(cmd, CONN_NAME, n)
            scale.emit_scale_result(profile.name, n, rep, resultados)
            duracoes = sorted(r["seconds"] for r in resultados)
            ok = sum(1 for r in resultados if r["ok"])
            print(f"  [{profile.name}] n={n:>2} rep {rep:>2}: {ok}/{n} ok  "
                  f"parede {resultados[0]['wall_total_seconds']*1000:>7.1f} ms  "
                  f"por-filho p50 {duracoes[len(duracoes)//2]*1000:>7.1f} ms  "
                  f"max {duracoes[-1]*1000:>7.1f} ms")
            time.sleep(1.0)  # deixa o charon assentar entre rodadas
    finally:
        scale.teardown_addresses(n, CU_NETNS, EDGE_NETNS)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--measurement", default="handshake",
                        choices=["handshake", "rekey", "dataplane", "scale"],
                        help="handshake = A.1, rekey = A.2 (sob tráfego), "
                             "dataplane = A.3 (vazão/RTT/softirq por cifra do ESP), "
                             "scale = A.4 (N Child SAs em rekey simultâneo)")
    parser.add_argument("--profiles", default="K0,K1,K2,K3,K4",
                        help="lista separada por vírgula (ver phase_a/profiles.py)")
    parser.add_argument("--repetitions", type=int, default=30)
    parser.add_argument("--rtt-ms", default="0",
                        help="A.6 — eixo de RTT: atraso netem POR SENTIDO, em ms, "
                             "separado por vírgula (ex. 0,5,20). O RTT resultante é o "
                             "dobro de cada valor")
    parser.add_argument("--event-kind", default="child_rekey",
                        help="A.2 — child_rekey e/ou ike_reauth, separados por vírgula. "
                             "A renovação de PPK exige ike_reauth: o PPK só entra na "
                             "derivação no IKE_AUTH")
    parser.add_argument("--make-before-break", default="yes",
                        help="A.2 — yes, no, ou 'both' para medir os dois. Só afeta "
                             "ike_reauth: o rekey de Child SA é sempre make-before-break "
                             "por imposição da RFC 7296")
    parser.add_argument("--udp-mbps", type=float, default=100.0,
                        help="A.2 — taxa fixa do iperf3 UDP sob o rekey")
    parser.add_argument("--children", default="3,10,30",
                        help="A.4 — quantidades de Child SAs simultâneas a medir")
    parser.add_argument("--duration", type=int, default=30,
                        help="A.3 — duração de cada ponto de iperf3, em segundos")
    parser.add_argument("--streams", type=int, default=4,
                        help="A.3 — fluxos TCP paralelos do iperf3. Mais de um porque "
                             "um fluxo só pode ficar limitado pela janela TCP em vez "
                             "da cifra, que é o que se quer medir")
    parser.add_argument("--no-shuffle", dest="shuffle", action="store_false",
                        help="roda os perfis na ordem dada em vez de sortear")
    parser.add_argument("--no-restore", dest="restore", action="store_false",
                        help="não devolve a config por-fatia no fim (útil pra encadear execuções "
                             "da Fase A sem pagar o restart do IPsec entre elas)")
    args = parser.parse_args()

    try:
        profiles = [by_name(n.strip()) for n in args.profiles.split(",")]
    except KeyError as exc:
        parser.error(str(exc))

    RESULTS_DIR.mkdir(parents=True, exist_ok=True)
    run_id = f"phaseA-{args.measurement}-{uuid.uuid4().hex[:8]}"
    instrumentation.configure(RESULTS_DIR / f"{run_id}.jsonl", run_id)
    print(f"run_id={run_id}")

    # Ordem sorteada entre perfis (exigência de rigor do documento da
    # campanha). As repetições DENTRO de um perfil ficam consecutivas de
    # propósito: intercalar perfil a perfil exigiria reiniciar o IPsec a
    # cada repetição (~8s), o que domina o custo de uma medição de
    # handshake de ~30ms. Cada repetição já termina e refaz a IKE_SA do
    # zero, então não há estado herdado entre elas dentro do perfil.
    if args.shuffle:
        random.shuffle(profiles)
        print(f"ordem sorteada: {[p.name for p in profiles]}")

    rtts = [float(v) for v in args.rtt_ms.split(",")]
    event_kinds = [k.strip() for k in args.event_kind.split(",")]
    # O make-before-break só tem sentido na A.2, e só no caminho de
    # reauth; na A.1 ele não participa, então não gera combinações.
    if args.measurement != "rekey":
        mbb_values: list[bool | None] = [None]
    elif args.make_before_break == "both":
        mbb_values = [True, False]
    else:
        mbb_values = [args.make_before_break == "yes"]

    carga = registra_carga("inicio")
    if carga["radio_running"]:
        print(f"AVISO: o rádio está rodando ({', '.join(carga['radio_processes'])}) e a "
              f"Fase A é especificada SEM ele. Load {carga['load_1min']:.1f} em "
              f"{carga['cpu_count']} núcleos. As medições absolutas ficarão infladas "
              f"em 2-3× — pare o rádio antes de colher resultados.")

    # A A.2 precisa VARIAR o make_before_break, e o drop-in da Fase B o
    # fixa em `yes`. Sem suspendê-lo, as execuções com `no` medem `yes` —
    # e o modo de falha é silencioso: as duas configurações dão
    # resultados idênticos. Ver `rekey_traffic.suspende_dropins_conflitantes`.
    dropins_suspensos: list = []
    if args.measurement == "rekey":
        dropins_suspensos = rekey_traffic.suspende_dropins_conflitantes()
        if dropins_suspensos:
            print(f"drop-ins suspensos durante a medição: "
                  f"{[p.name for p in dropins_suspensos]}")

    backup = backup_lab_config()
    try:
        for rtt in rtts:
            # Ordem importa: o netem é aplicado ANTES de medir, e o RTT
            # efetivo é medido depois de aplicar, para o relatório não
            # depender de fé no `tc`.
            netem.apply(rtt)
            measured = netem.measured_rtt_ms()
            print(f"\n### RTT: netem {rtt} ms/sentido -> medido {measured} ms de RTT")
            emit("phase_a_rtt_axis", netem_delay_ms=rtt, measured_rtt_ms=measured)
            registra_carga("ponto_de_rtt", netem_delay_ms=rtt)

            if args.measurement == "dataplane":
                # Antes dos perfis, e dentro do mesmo ponto de RTT: a
                # linha de base tem de pagar o mesmo netem que eles.
                measure_dataplane_baseline(args.duration, args.streams)

            for mbb in mbb_values:
                # Muda a opção ANTES de aplicar o perfil: é o restart do
                # charon feito pelo apply_profile que a faz valer.
                rekey_traffic.set_make_before_break(mbb)
                if mbb is not None:
                    print(f"--- make_before_break = {'yes' if mbb else 'no'}")

                for profile in profiles:
                    print(f"=== perfil {profile.name} "
                          f"({profile.ike_proposal} / ESP {profile.esp_proposal}) ===")
                    apply_profile(profile)
                    if args.measurement == "handshake":
                        measure_handshake(profile, args.repetitions)
                    elif args.measurement == "dataplane":
                        measure_dataplane(profile, args.duration, args.streams)
                    elif args.measurement == "scale":
                        for n in [int(v) for v in args.children.split(",")]:
                            measure_scale(profile, n, args.repetitions)
                    else:
                        for kind in event_kinds:
                            print(f"  evento: {kind}")
                            measure_rekey(profile, args.repetitions, kind, mbb,
                                          udp_mbps=args.udp_mbps)
    finally:
        instrumentation.reset()
        netem.clear()
        rekey_traffic.set_make_before_break(None)
        rekey_traffic.restaura_dropins(dropins_suspensos)
        if args.restore:
            print("restaurando a config por-fatia da Fase B...")
            restore_lab_config(backup)

    print(f"\nResultados em {RESULTS_DIR / (run_id + '.jsonl')}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
