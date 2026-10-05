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


def _pids_by_comm(netns: str, comms: tuple[str, ...]) -> list[str]:
    pids = subprocess.run(["ip", "netns", "pids", netns], capture_output=True, text=True).stdout.split()
    return [
        pid for pid in pids
        if subprocess.run(["ps", "-p", pid, "-o", "comm="], capture_output=True, text=True).stdout.strip() in comms
    ]


def _kill_and_verify(targets: list[str], label: str, timeout_seconds: float = 15.0, retries: int = 2) -> None:
    """Manda `kill -9`, espera o `/proc/<pid>` sumir, e reenvia o sinal
    se algum sobreviver — levanta erro alto só se persistir depois de
    todas as tentativas.

    **Achado rodando a campanha de validação do fix original (só kill +
    verificação de uma tentativa só)**: a causa real de quase toda
    execução falhar não era um zumbi de verdade nem falta de tempo de
    espera — era `teardown()` de uma iteração reiniciando charon/UE pro
    próximo cenário, e segundos depois `setup()` da iteração SEGUINTE já
    mandando matar de novo, pegando o processo no meio da própria
    inicialização (carregando config, criando threads) — nesse estado
    transitório ele demora mais pra morrer, não porque esteja travado,
    só porque está ocupado. Reenviar `kill -9` e dar mais uma chance de
    espera resolve; só um timeout maior numa tentativa só não resolvia
    (testado: 24 de 25 execuções falsearam com 15s numa tentativa só)."""
    survivors = list(targets)
    for attempt in range(retries + 1):
        subprocess.run(["kill", "-9", *survivors])
        deadline = time.monotonic() + timeout_seconds
        while time.monotonic() < deadline:
            survivors = [pid for pid in survivors if Path(f"/proc/{pid}").exists()]
            if not survivors:
                return
            time.sleep(0.2)
        survivors = [pid for pid in survivors if Path(f"/proc/{pid}").exists()]
        if not survivors:
            return
    raise RuntimeError(
        f"kill -9 não matou {label} (PIDs sobreviventes: {survivors}) depois de "
        f"{retries + 1} tentativas — não prossiga sem resolver isso manualmente "
        "(ver docs/RUNBOOK-OAI.md)"
    )


def kill_ipsec_instance(netns: str, timeout_seconds: float = 15.0) -> None:
    """**Achado real debugando esta avaliação**: um `charon` de uma
    instância ANTERIOR (dias atrás) sobreviveu a múltiplos `kill -9`
    chamados ao longo de uma campanha inteira sem que ninguém percebesse
    — a função matava e seguia em frente sem checar se o processo
    realmente morreu, então um PID zumbi continuou competindo com as SAs
    novas silenciosamente. Agora verifica e reenvia o sinal se precisar
    (ver `_kill_and_verify`) em vez de deixar passar ou desistir cedo
    demais."""
    targets = _pids_by_comm(netns, ("charon", "starter"))
    if not targets:
        return
    _kill_and_verify(targets, f"charon/starter em {netns}", timeout_seconds)


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
                # **Achado real**: mais de um charon no mesmo netns (um
                # zumbi de uma instância anterior + o recém-criado) é
                # exatamente o bug que passou despercebido numa campanha
                # inteira — `find_charon_pid` pega só o primeiro que
                # achar, então sem essa checagem o segundo fica invisível
                # competindo por SAs. Falha alto em vez de seguir feliz.
                survivors = _pids_by_comm(netns, ("charon",))
                if len(survivors) > 1:
                    raise RuntimeError(
                        f"mais de um charon rodando em {netns} (PIDs {survivors}) — "
                        "provável zumbi de uma instância anterior que `kill_ipsec_instance` "
                        "não devia ter deixado passar; não prossiga sem matar manualmente"
                    )
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


# testbed OCUDU+srsUE (ver ~/ocudu-lab/): cada fatia é um processo
# srsue SEPARADO (nao 3 sessoes PDU multiplexadas por uma UE OAI so),
# cada um com seu proprio netns (`netns = ue-<fatia>` no .conf) — so a
# interface tun_srsue fica nesse netns, o processo srsue em si roda
# dentro de cu-ns (ver watchdog_start.sh).
_SLICE_NETNS_IFACE = {
    "urllc": ("ue-urllc", "tun_srsue"),
    "embb": ("ue-embb", "tun_srsue"),
    "miot": ("ue-miot", "tun_srsue"),
}
# Gateway/dest por fatia (N6 da UPF) — mantido aqui só como referência
# pros `traffic_plan()` dos cenários (não usado mais internamente neste
# módulo: a captura de TEID agora lê o log do gNB, não precisa mais de
# ping/reply nenhum). ACHADO REAL: o UPF (Open5GS) só tem UM endereço de
# verdade na `ogstun` (10.45.0.1/16, cobre o /16 inteiro) — pingar
# 10.45.0.1 só responde quando a sessão é da própria sub-rede dela
# (eMBB); URLLC/mIoT (sub-redes .1.x/.2.x) não recebem resposta, mesmo
# com o tráfego de uplink fluindo normalmente (confirmado via contador
# de bytes da SA) — parece assimetria real de roteamento de retorno no
# UPF entre sessões PDU de sub-rede diferente, não investigada a fundo.
# Isso afeta a métrica de latência real da URLLC (profile "latency" no
# traffic_plan) até ser corrigido — throughput (iperf3, embb/miot) não
# depende de ping e não é afetado.
_SLICE_DEST = {"urllc": "10.45.1.1", "embb": "10.45.0.1", "miot": "10.45.2.1"}


def assert_no_stray_processes() -> None:
    """**Checagem adicionada depois de uma campanha inteira (50 execuções)
    ter rodado contaminada por um DU, uma CU e um `charon` zumbis de DOIS
    DIAS atrás** — nenhum morreu com os `pkill`/`kill -9` chamados ao
    longo do dia (ver achados em `kill_ipsec_instance`/`restart_ue`), e
    nada no pipeline verificava isso antes de seguir. Roda uma vez no
    início de `run_experiment.py main()`, antes de qualquer cenário.

    **Não conta PIDs** (OAI faz fork interno — um DU "lógico" já aparece
    como 2-3 PIDs distintos com o mesmo `comm`, então "número de PIDs >
    N" dá falso positivo). Em vez disso, olha o **tempo de vida**
    (`etimes`) de cada grupo: um DU/CU/UE/charon iniciado agora não deve
    ter processo nenhum rodando há muito mais tempo que os outros do
    mesmo grupo — se tiver, é a assinatura exata do zumbi encontrado
    nesta campanha (DU/CU de 2 dias atrás convivendo com tudo que foi
    iniciado hoje).

    **Achado rodando a campanha de validação deste próprio fix**: uma
    checagem de instante único pode pegar um processo filho tardio do
    OAI bem no meio de morrer (visto na prática: um PID aparecia com
    idade 0s junto dos originais, e já tinha sumido sozinho segundos
    depois) — falso positivo. Agora faz duas passadas com alguns segundos
    de intervalo e só aborta se o MESMO problema persistir nas duas."""

    def _scan() -> list[str]:
        stale_threshold_seconds = 600  # qualquer spread > 10min dentro do mesmo grupo é suspeito

        def _etimes(pids: list[str]) -> list[int]:
            if not pids:
                return []
            out = subprocess.run(["ps", "-p", ",".join(pids), "-o", "etimes="], capture_output=True, text=True).stdout
            return [int(line) for line in out.split()]

        found = []
        for pattern in ("apps/gnb/gnb", "srsue ue_", "multi_ue_scenario.py"):
            pids = subprocess.run(["pgrep", "-f", pattern], capture_output=True, text=True).stdout.split()
            times = _etimes(pids)
            if times and max(times) - min(times) > stale_threshold_seconds:
                found.append(
                    f"'{pattern}': PIDs {pids} com idades muito diferentes entre si "
                    f"(min {min(times)}s, max {max(times)}s) — parece zumbi de uma execução anterior"
                )
        for netns in ("cu-ns", "5gc-edge-ns"):
            charons = _pids_by_comm(netns, ("charon",))
            times = _etimes(charons)
            if len(charons) > 1 and times and max(times) - min(times) > stale_threshold_seconds:
                found.append(
                    f"charon em {netns}: PIDs {charons} com idades muito diferentes entre si "
                    f"(min {min(times)}s, max {max(times)}s) — parece zumbi de uma execução anterior"
                )
            elif len(charons) > 1:
                # mais de um charon no mesmo netns, mesmo com idade
                # parecida, ainda é inesperado (deveria ser só 1 por
                # netns) — avisa.
                found.append(f"{len(charons)} charon rodando em {netns} (esperado no máx 1): PIDs {charons}")
        return found

    first_pass = _scan()
    if not first_pass:
        return
    time.sleep(5)
    second_pass = _scan()
    if second_pass:
        raise RuntimeError(
            "processos suspeitos de zumbi detectados antes de começar a campanha, confirmados em "
            "duas passadas com 5s de intervalo (ver docs/RUNBOOK-OAI.md e a seção 'pkill às vezes "
            "não mata'):\n  " + "\n  ".join(second_pass)
        )


GNB_COMBINED_LOG = Path("/tmp/gnb_combined.log")

# ordem de lancamento do watchdog (urllc, embb, miot) == indice interno
# `ue=N` do gNB (confirmado por correlacao de timestamp com os logs do
# SMF: `docker logs 5gc-smf-1 | grep "UE SUPI"` bate exatamente com a
# ordem desta lista, em duas rodadas distintas desta sessao — ver
# observability/README.md).
_SLICE_UE_INDEX = {"urllc": 0, "embb": 1, "miot": 2}


def _capture_uplink_teid_from_gnb_log(slice: str) -> str:
    """**Substitui a técnica antiga de sniff+ping+offset de byte** (que
    dependia de capturar GTP-U em texto puro em `veth-cu-n2`) — acho real
    migrando pro OCUDU: assim que as SAs N3 sobem (que é exatamente o
    estado em que todo cenário 1-4 chama isto), aquele link só carrega
    ESP cifrado; o GTP-U original nunca aparece na fiação depois que o
    túnel está ativo, então a captura sempre dava timeout sem nenhum
    pacote. O gNB já loga o TEID real de cada sessão (`GTPU PSUP TX
    configured... peer_teid=0x...`) no próprio `/tmp/gnb_combined.log`,
    texto puro, independente do estado do IPsec — mais simples e mais
    robusto que farejar a rede. Pega a ocorrência MAIS RECENTE pro índice
    `ue=N` daquela fatia (o log acumula entre restarts)."""
    import re

    if not GNB_COMBINED_LOG.exists():
        raise RuntimeError(f"{GNB_COMBINED_LOG} não existe — gNB rodou pelo menos uma vez?")
    ue_index = _SLICE_UE_INDEX[slice]
    pattern = re.compile(rf"ue={ue_index} UL teid=(0x[0-9a-f]+): GTPU PSUP TX configured")
    last_teid = None
    with GNB_COMBINED_LOG.open(errors="replace") as f:
        for line in f:
            m = pattern.search(line)
            if m:
                last_teid = m.group(1)
    if last_teid is None:
        raise RuntimeError(
            f"nenhum TEID encontrado pra fatia {slice!r} (ue={ue_index}) em {GNB_COMBINED_LOG} — "
            "sessão PDU ativa? watchdog_start.sh rodou de verdade?"
        )
    return last_teid


GNB_BIN = _real_home() / "ocudu" / "build" / "apps" / "gnb" / "gnb"
GNB_CONF = _real_home() / "ocudu-lab" / "gnb.yml"
WATCHDOG_SCRIPT = _real_home() / "ocudu-lab" / "watchdog_start.sh"


def restart_ran_stack(timeout_seconds: float = 400.0) -> None:
    """**Diferença estrutural real em relação ao lab antigo**: lá, uma UE
    OAI travada podia ser reiniciada sozinha (`restart_ue`), sem mexer no
    resto. Aqui não — o gNB combinado (CU+DU), o broker GNU Radio e as 3
    instâncias srsUE sincronizam juntos via handshake ZMQ a frio (5
    processos REQ/REP), que é instável o bastante pra precisar de um
    watchdog com retry (ver `~/ocudu-lab/watchdog_start.sh` e a memória
    do projeto) — não existe "reiniciar só a UE da fatia X" nesse
    topologia, é tudo ou nada. Em vez de reimplementar essa dança em
    Python (já validada, já lida com `pkill` não confiável nesta VM e
    com permissão de arquivo de log), só invoca o script direto —
    consistente com o resto deste módulo (fininas em cima do que já
    existe, não reimplementação)."""
    result = subprocess.run(
        ["sudo", "bash", str(WATCHDOG_SCRIPT)],
        capture_output=True, text=True, timeout=timeout_seconds,
    )
    if result.returncode != 0:
        raise RuntimeError(
            f"watchdog_start.sh falhou (rc={result.returncode}) — stack RAN não sincronizou:\n"
            f"{result.stdout[-2000:]}\n{result.stderr[-500:]}"
        )


def ue_data_plane_healthy(slice: str) -> bool:
    """**Achado real portando pro testbed OCUDU+srsUE**: diferente do lab
    antigo, nem todo gateway responde ping aqui — o UPF (Open5GS) só tem
    UM endereço real configurado na `ogstun` (`10.45.0.1/16`, cobrindo o
    `/16` inteiro); `10.45.1.1`/`10.45.2.1` nunca foram endereços de
    verdade, só caem dentro da mesma rota. Testado: `10.45.0.1` responde
    quando a sessão PDU é da própria sub-rede dela (eMBB, `10.45.0.x`),
    mas NÃO responde pra sessões de sub-rede diferente (URLLC/mIoT,
    `10.45.1.x`/`10.45.2.x`) — parece assimetria real de roteamento de
    retorno no UPF entre sessões PDU, não investigada a fundo ainda (ver
    `observability/README.md` ou pergunte sobre "achado: ping URLLC/mIoT"
    antes de confiar na métrica de latência dessas duas fatias). Por
    isso o health-check usa um sinal 100% local (interface com IP
    atribuído) em vez de depender de uma resposta ICMP que nem sempre
    existe."""
    ue_netns, iface = _SLICE_NETNS_IFACE[slice]
    result = subprocess.run(
        ["ip", "netns", "exec", ue_netns, "ip", "-4", "-o", "addr", "show", iface],
        capture_output=True, text=True,
    )
    return "inet " in result.stdout


def all_slices_data_plane_healthy() -> bool:
    """As três sessões PDU (uma por fatia, cada uma seu próprio processo
    srsUE) podem terminar de se reestabelecer em instantes diferentes
    depois de um restart — checar só uma fatia não garante que as outras
    duas já estejam prontas também (mesmo achado do lab antigo, ver
    `docs/RUNBOOK-OAI.md` original; só muda o mecanismo por baixo)."""
    return all(ue_data_plane_healthy(slice) for slice in _SLICE_NETNS_IFACE)


def ensure_ue_data_plane(retries: int = 2) -> None:
    """Chamado pelos cenários depois de mexer no IPsec — só reinicia a
    pilha RAN inteira se o plano de dados realmente estiver travado
    (idempotente/barato quando já está saudável). Diferente do lab
    antigo, não há "reiniciar só a UE" aqui — qualquer recuperação passa
    por `restart_ran_stack()` (ver docstring lá), que já inclui seu
    próprio retry interno; `retries` aqui é só pro caso raro do restart
    completo "pegar" mas alguma fatia específica ainda não responder
    ping a tempo."""
    for attempt in range(retries):
        if all_slices_data_plane_healthy():
            return
        restart_ran_stack()
    if not all_slices_data_plane_healthy():
        raise RuntimeError(
            "plano de dados da UE continua indisponível (em pelo menos uma fatia) mesmo "
            "depois do restart da pilha RAN — verifique gNB/broker/srsUE manualmente "
            "(ver ~/ocudu-lab/watchdog_start.sh e /tmp/gnb_combined.log)"
        )


def capture_and_apply_slice_marks(cu_netns: str = "cu-ns") -> dict[str, str]:
    """Recaptura os TEIDs reais das três sessões PDU **já ativas** e
    reaplica as regras `mangle OUTPUT` — necessário sempre que a pilha
    RAN for reiniciada (TEIDs mudam a cada nova sessão PDU), senão o
    tráfego de teste sai sem mark e as métricas de isolamento (B.3) dão
    falso negativo (mesmo achado do lab antigo, ver histórico). Garante
    o plano de dados antes de tentar — ver `ensure_ue_data_plane`."""
    ensure_ue_data_plane()
    teids = {slice: _capture_uplink_teid_from_gnb_log(slice) for slice in _SLICE_NETNS_IFACE}
    apply_slice_marks(cu_netns, teids["urllc"], teids["embb"], teids["miot"])
    return teids


def wait_for_sa_established(netns: str, conn_name: str, timeout_seconds: float = 30.0) -> bool:
    """**Achado real rodando a primeira campanha longa**: a versão
    anterior checava `conn_name in stdout` e `"ESTABLISHED" in stdout`
    como duas condições SEPARADAS — como outras conexões (F1, N2) já
    costumam estar `ESTABLISHED` na mesma saída do `swanctl --list-sas`,
    isso dava falso positivo pra uma conexão que na verdade ainda estava
    presa em `CONNECTING` (o Cenário 1 "passou" no setup com a SA nunca
    tendo subido de verdade). Corrigido: exige que a palavra
    `ESTABLISHED` apareça especificamente na linha de cabeçalho daquela
    conexão (`"<conn_name>: #N, ESTABLISHED, ..."`), não em qualquer
    lugar do output."""
    import re

    pattern = re.compile(rf"^{re.escape(conn_name)}: #\d+, ESTABLISHED,", re.MULTILINE)
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
        if pattern.search(result.stdout):
            return True
        time.sleep(0.5)
    return False
