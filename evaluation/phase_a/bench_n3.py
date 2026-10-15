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
import random
import re
import secrets as pysecrets
import subprocess
import sys
import time
import uuid
from pathlib import Path

from evaluation import instrumentation, lab_control
from evaluation.collectors.resource import find_charon_pid
from evaluation.instrumentation import emit
from evaluation.phase_a import netem, rekey_traffic
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
    return {key: (base / key[0] / "conf.d" / key[1]).read_text() for key in _CONF_FILES}


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
                  make_before_break: bool | None, udp_mbps: float = 10.0,
                  ping_interval_s: float = 0.001, spacing_s: float = 2.0) -> None:
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
    iperf = rekey_traffic.IperfUdpProbe(CU_NETNS, EDGE_NETNS, cu_ip, edge_ip,
                                        udp_mbps, duration_s)
    ping.start()
    iperf.start()
    time.sleep(spacing_s)  # regime antes do primeiro evento

    events: list[tuple[int, float, float, bool]] = []
    for rep in range(1, repetitions + 1):
        t0, t1, ok = rekey_traffic.trigger_event(charon_pid, CONN_NAME, event_kind)
        events.append((rep, t0, t1, ok))
        if not ok:
            print(f"  [{profile.name}/{event_kind}] rep {rep}: swanctl falhou")
        time.sleep(spacing_s)

    ping.stop()
    iperf.stop()
    windows = iperf.loss_windows()

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
            **rekey_traffic._loss_in_window(windows, t0, t_to),
        )

    # Linha de base no mesmo tráfego, sem nenhum evento: sem ela não há
    # como dizer se o pico de RTT de um rekey é do rekey ou do ruído da
    # bancada. Pega a folga inicial, anterior ao primeiro evento.
    if events:
        baseline_to = events[0][1]
        baseline_from = baseline_to - spacing_s
        emit(
            "phase_a_rekey_baseline",
            profile=profile.name,
            event_kind=event_kind,
            make_before_break=make_before_break,
            udp_offered_mbps=udp_mbps,
            **rekey_traffic._gap_stats(ping.samples, baseline_from, baseline_to,
                                       ping_interval_s),
            **rekey_traffic._loss_in_window(windows, baseline_from, baseline_to),
        )


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--measurement", default="handshake",
                        choices=["handshake", "rekey"],
                        help="handshake = A.1, rekey = A.2 (sob tráfego)")
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
    parser.add_argument("--udp-mbps", type=float, default=10.0,
                        help="A.2 — taxa fixa do iperf3 UDP sob o rekey")
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
                    else:
                        for kind in event_kinds:
                            print(f"  evento: {kind}")
                            measure_rekey(profile, args.repetitions, kind, mbb,
                                          udp_mbps=args.udp_mbps)
    finally:
        instrumentation.reset()
        netem.clear()
        rekey_traffic.set_make_before_break(None)
        if args.restore:
            print("restaurando a config por-fatia da Fase B...")
            restore_lab_config(backup)

    print(f"\nResultados em {RESULTS_DIR / (run_id + '.jsonl')}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
