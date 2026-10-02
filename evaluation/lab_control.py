"""Operações de controle do laboratório reaproveitadas pelos cenários —
fininas em cima dos scripts já existentes e validados em `lab/ipsec/`
(Fases 3/4/5), não uma reimplementação. Ver `docs/RUNBOOK-OAI.md` seção
4 pro procedimento manual equivalente.
"""

from __future__ import annotations

import os
import pwd
import subprocess
import time
from pathlib import Path
from typing import Optional

from evaluation.collectors.resource import find_charon_pid


def _real_home() -> Path:
    """`Path.home()` sob `sudo` resolve pra `/root` (o `$HOME` do
    processo, não do usuário original) — achado rodando isto pela
    primeira vez: o `start-ipsec-side.sh` "sumia" com erro 127 porque o
    caminho montado apontava pra `/root/oai-lab-conf`, inexistente,
    silenciado por `stderr=DEVNULL`. Usa `SUDO_USER` quando existir."""
    sudo_user = os.environ.get("SUDO_USER")
    if sudo_user:
        return Path(pwd.getpwnam(sudo_user).pw_dir)
    return Path.home()


REPO_ROOT = Path(__file__).resolve().parent.parent
LAB_IPSEC_DIR = REPO_ROOT / "lab" / "ipsec"
# Script real de produção fica em ~/oai-lab-conf (gerado a partir do
# template versionado) — ver docs/RUNBOOK-OAI.md. Os cenários operam
# contra ele, não contra o template do repositório.
LIVE_LAB_IPSEC_DIR = _real_home() / "oai-lab-conf"


def _run(cmd: list[str], **kwargs) -> subprocess.CompletedProcess:
    return subprocess.run(cmd, capture_output=True, text=True, **kwargs)


def kill_ipsec_instance(netns: str) -> None:
    pids = subprocess.run(["ip", "netns", "pids", netns], capture_output=True, text=True).stdout.split()
    targets = []
    for pid in pids:
        comm = subprocess.run(["ps", "-p", pid, "-o", "comm="], capture_output=True, text=True).stdout.strip()
        if comm in ("charon", "starter"):
            targets.append(pid)
    if targets:
        subprocess.run(["kill", "-9", *targets])


def flush_xfrm(netns: str) -> None:
    _run(["ip", "netns", "exec", netns, "ip", "xfrm", "policy", "flush"])
    _run(["ip", "netns", "exec", netns, "ip", "xfrm", "state", "flush"])


def start_ipsec_instance(netns: str, timeout_seconds: float = 10.0, retries: int = 2) -> int:
    """`start-ipsec-side.sh` já bind-monta ipsec.conf/swanctl conforme o
    netns (ver lab/ipsec/start-ipsec-side.sh) — roda em background e
    espera o charon aparecer.

    **Achado rodando esta avaliação**: ocasionalmente o charon não sobe
    na primeira tentativa dentro do timeout, mesmo com o mesmo comando
    funcionando isoladamente logo em seguida — não isolamos a causa raiz
    (suspeita: uma janela de corrida entre o `kill -9` da instância
    anterior e o bind-mount novo de `/run`), mas uma segunda tentativa
    (matando qualquer resquício e tentando de novo) sempre resolveu nos
    testes. Documentado como instabilidade conhecida, não escondida."""
    script = LIVE_LAB_IPSEC_DIR / "start-ipsec-side.sh"
    for attempt in range(retries + 1):
        subprocess.Popen(["bash", str(script), netns], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        deadline = time.monotonic() + timeout_seconds
        while time.monotonic() < deadline:
            pid = find_charon_pid(netns)
            if pid is not None:
                return pid
            time.sleep(0.3)
        kill_ipsec_instance(netns)
        time.sleep(1)
    raise RuntimeError(f"charon não apareceu em {netns} depois de {retries + 1} tentativas")


def restart_ipsec_lab(netnses: tuple[str, ...] = ("cu-ns", "5gc-edge-ns")) -> dict[str, int]:
    """Reinício limpo (kill + flush + start) — necessário entre cenários
    que mudam a config IPsec, porque matar o charon não limpa o xfrm
    state/policy do kernel (achado da Fase 3, ver
    docs/RUNBOOK-OAI.md troubleshooting)."""
    for ns in netnses:
        kill_ipsec_instance(ns)
    time.sleep(1)
    for ns in netnses:
        flush_xfrm(ns)
    pids = {}
    for ns in netnses:
        pids[ns] = start_ipsec_instance(ns)
        time.sleep(1)
    return pids


def load_and_initiate_n3() -> None:
    """As três SAs N3 (vici) não sobem sozinhas — `start_action = none`
    (ver ARQUITETURA-PROTOTIPO-COMPLETA.md seção 5.4)."""
    script = LIVE_LAB_IPSEC_DIR / "load-and-initiate-n3.sh"
    result = subprocess.run(["bash", str(script)], capture_output=True, text=True)
    if result.returncode != 0:
        raise RuntimeError(f"load-and-initiate-n3.sh falhou: {result.stderr}")


def apply_slice_marks(netns: str, teid_urllc: str, teid_embb: str, teid_miot: str) -> None:
    script = LIVE_LAB_IPSEC_DIR / "apply-n3-slice-marks.sh"
    subprocess.run(["bash", str(script), netns, teid_urllc, teid_embb, teid_miot], check=True)


# interface da UE -> fatia, pela sub-rede (ver docs/RUNBOOK-OAI.md e
# prototype/README.md) — não muda entre sessões, só o TEID muda.
_SLICE_IFACE = {"urllc": "oaitun_ue1p2", "embb": "oaitun_ue1", "miot": "oaitun_ue1p3"}


def _capture_uplink_teid(ue_netns: str, cu_netns: str, cu_iface: str, ue_iface: str, dest: str = "10.45.0.1") -> str:
    """Captura o TEID de uplink real de uma sessão PDU **já estabelecida**
    — diferente do Módulo 2 (`pfcp_sniffer`), que só vê o TEID na
    sinalização PFCP durante o *estabelecimento* da sessão (não serve
    pra sessões que já estavam de pé antes do sniffer começar a
    escutar). Sniffa `udp/2152` em `cu_iface` enquanto gera uma rajada de
    ping por `ue_iface`, e lê os bytes 4-7 do payload GTP-U (TEID) do
    pacote de saída (`172.18.0.99 -> ...`) — mesmo offset confirmado
    manualmente contra este laboratório (byte 32 a partir do início do
    IP, igual ao usado nas regras `mangle -m u32`)."""
    capture = subprocess.Popen(
        ["ip", "netns", "exec", cu_netns, "tcpdump", "-i", cu_iface, "-n", "-xx",
         "-c", "4", f"udp port 2152 and src 172.18.0.99"],
        stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True,
    )
    time.sleep(0.3)
    subprocess.run(
        ["ip", "netns", "exec", ue_netns, "ping", "-c", "4", "-i", "0.1", "-I", ue_iface, dest],
        capture_output=True,
    )
    out, _ = capture.communicate(timeout=5)

    # cada pacote vira um bloco de linhas "0xNNNN: ...." — concatena os
    # bytes hex de todas as linhas do bloco, então pega os bytes 42-45
    # (14 Ethernet + 20 IP + 8 UDP) = TEID.
    teids = []
    current_bytes: list[str] = []
    for line in out.splitlines():
        line = line.strip()
        if line.startswith("0x"):
            hex_part = line.split(":", 1)[1].strip()
            current_bytes.extend(hex_part.replace(" ", ""))
        elif current_bytes:
            frame_hex = "".join(current_bytes)
            if len(frame_hex) >= 100:
                teids.append(frame_hex[92:100])  # bytes 46-49 (TEID) em nibbles
            current_bytes = []
    if current_bytes:
        frame_hex = "".join(current_bytes)
        if len(frame_hex) >= 100:
            teids.append(frame_hex[92:100])

    if not teids:
        raise RuntimeError(f"nenhum pacote GTP-U capturado em {cu_iface} pra {ue_iface} — sessão ativa?")
    # TEID estável durante a rajada — pega o mais frequente.
    from collections import Counter

    return "0x" + Counter(teids).most_common(1)[0][0]


UE_BUILD_DIR = _real_home() / "openairinterface5g" / "cmake_targets" / "ran_build" / "build"
UE_CONF = LIVE_LAB_IPSEC_DIR / "ue.conf"
UE_RF_ARGS = ["-C", "3450720000", "-r", "106", "--numerology", "1", "--band", "78", "--ssb", "516"]


def restart_ue(ue_netns: str = "du-ns", settle_seconds: float = 20.0) -> None:
    """**Achado real, recorrente nesta avaliação**: reiniciar o IPsec
    (`restart_ipsec_lab`) enquanto a UE já tem uma sessão PDU ativa deixa
    essa sessão "presa" — N2/SCTP continua `ESTABLISHED`, as interfaces
    `oaitun_ue1*` continuam com IP, mas nenhum pacote de dados novo flui
    (ping trava sem nem imprimir o cabeçalho, nunca retorna). Reiniciar a
    UE (ela reconecta e reestabelece as 3 sessões PDU do zero) resolve —
    não encontramos a causa raiz exata (plano de controle sobrevive, só o
    plano de dados "esquece" o caminho), documentado aqui como
    comportamento conhecido do laboratório, não um bug deste pipeline."""
    subprocess.run(["pkill", "-9", "-f", "nr-uesoftmodem"], capture_output=True)
    time.sleep(2)
    subprocess.Popen(
        ["ip", "netns", "exec", ue_netns, str(UE_BUILD_DIR / "nr-uesoftmodem"),
         "-O", str(UE_CONF), "--rfsim", *UE_RF_ARGS],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )
    time.sleep(settle_seconds)


def ue_data_plane_healthy(ue_netns: str = "du-ns", iface: str = "oaitun_ue1", dest: str = "10.45.0.1") -> bool:
    result = subprocess.run(
        ["ip", "netns", "exec", ue_netns, "timeout", "4", "ping", "-c", "2", "-I", iface, dest],
        capture_output=True, text=True,
    )
    return "bytes from" in result.stdout


def all_slices_data_plane_healthy(ue_netns: str = "du-ns") -> bool:
    """As três sessões PDU (uma por fatia) podem terminar de se
    reestabelecer em instantes diferentes depois de um restart de UE —
    checar só `oaitun_ue1` (eMBB) não garante que `oaitun_ue1p2`/`p3`
    (URLLC/mIoT) já estejam prontas também (achado rodando esta
    avaliação: `_capture_uplink_teid` falhava na URLLC mesmo com a eMBB
    já respondendo ping)."""
    return all(ue_data_plane_healthy(ue_netns, iface) for iface in _SLICE_IFACE.values())


def ensure_ue_data_plane(ue_netns: str = "du-ns", retries: int = 3) -> None:
    """Chamado pelos cenários depois de mexer no IPsec — só reinicia a UE
    se o plano de dados realmente estiver travado (idempotente/barato
    quando já está saudável). Confere as TRÊS fatias, com algumas
    tentativas de espera extra antes de desistir (reestabelecer as 3
    sessões PDU depois de um restart pode levar mais que os
    `settle_seconds` de uma única chamada)."""
    for attempt in range(retries):
        if all_slices_data_plane_healthy(ue_netns):
            return
        if attempt == 0:
            restart_ue(ue_netns)
        else:
            time.sleep(5)
    if not all_slices_data_plane_healthy(ue_netns):
        raise RuntimeError(
            "plano de dados da UE continua indisponível (em pelo menos uma fatia) mesmo "
            "depois do restart — verifique CU/DU/5GC manualmente (ver docs/RUNBOOK-OAI.md)"
        )


def capture_and_apply_slice_marks(cu_netns: str = "cu-ns", ue_netns: str = "du-ns", cu_iface: str = "veth-cu-n2") -> dict[str, str]:
    """Recaptura os TEIDs reais das três sessões PDU **já ativas** e
    reaplica as regras `mangle OUTPUT` — necessário sempre que a UE for
    reiniciada (TEIDs mudam a cada nova sessão PDU), senão o tráfego de
    teste sai sem mark e as métricas de isolamento (B.3) dão falso
    negativo (achado rodando esta avaliação pela primeira vez: os
    contadores de `ip -s xfrm state` nunca incrementavam nas SAs
    marcadas porque as regras `mangle` ainda tinham os TEIDs de uma
    sessão anterior). Garante o plano de dados da UE antes de tentar —
    ver `ensure_ue_data_plane` (reinicia a UE se o restart do IPsec
    anterior tiver deixado a sessão PDU travada)."""
    ensure_ue_data_plane(ue_netns)
    teids = {
        slice: _capture_uplink_teid(ue_netns, cu_netns, cu_iface, iface)
        for slice, iface in _SLICE_IFACE.items()
    }
    apply_slice_marks(cu_netns, teids["urllc"], teids["embb"], teids["miot"])
    return teids


def wait_for_sa_established(netns: str, conn_name: str, timeout_seconds: float = 30.0) -> bool:
    charon_pid = find_charon_pid(netns)
    if charon_pid is None:
        return False
    deadline = time.monotonic() + timeout_seconds
    while time.monotonic() < deadline:
        result = subprocess.run(
            ["nsenter", f"--mount=/proc/{charon_pid}/ns/mnt", f"--net=/proc/{charon_pid}/ns/net",
             "swanctl", "--list-sas"],
            capture_output=True, text=True,
        )
        if f"{conn_name}: " in result.stdout and "ESTABLISHED" in result.stdout:
            return True
        time.sleep(0.5)
    return False
