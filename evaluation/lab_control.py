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


def flush_slice_marks(netns: str = "cu-ns") -> None:
    """Só limpa a tabela `mangle OUTPUT` (sem capturar TEID nem aplicar
    marks novas) — usado pelos cenários 0/1, que não têm SA por fatia
    pra comparar contra (B.3 já retorna N/A pros dois, ver
    `analyze.py`). Sem isso, `classification_snapshot` continuaria
    reportando contagens baseadas em TEIDs órfãos do cenário anterior
    (silenciosamente errados, não zero) — pior que simplesmente não ter
    dado nenhum. Evita a parte frágil (`capture_and_apply_slice_marks`
    depende de `ensure_ue_data_plane` + sniff de TEID real) nos dois
    únicos cenários onde ela não contribui pra nenhuma métrica real."""
    subprocess.run(["ip", "netns", "exec", netns, "iptables", "-t", "mangle", "-F", "OUTPUT"], check=True)


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
# ping/reply nenhum).
#
# ACHADO REAL + CORRIGIDO: apesar de `smf.yaml` definir um gateway
# PRÓPRIO por DNN/fatia (10.45.0.1 embb, 10.45.1.1 urllc, 10.45.2.1
# miot — ver `session:` em `~/pqc-oran-local-lab/5gc/config/smf.yaml`),
# o UPF (Open5GS) só vincula o PRIMEIRO como endereço local de verdade
# na `ogstun`. Pings pros outros dois viravam ICMP REDIRECT, não echo
# reply (confirmado com tcpdump em `tun_srsue`: `10.45.0.1 > 10.45.1.9:
# ICMP redirect 10.45.1.1 to host 10.45.1.1`) — o kernel tenta
# "encaminhar" em vez de responder, já que o endereço não é dele.
# `ping` conta isso como 100% de perda mesmo com o plano de usuário
# funcionando normalmente. Corrigido rodando
# `~/pqc-oran-local-lab/5gc/fix-upf-gateways.sh` (`ip addr add` dos 2
# gateways que faltam, no MESMO escopo /16 do que já existe — testado:
# /24 sobrepondo o /16 quebra o roteamento de TODAS as fatias, não só
# da que foi adicionada). Efêmero — precisa rodar de novo depois de
# qualquer recreate do container `5gc-upf-1`.
#
# Achado relacionado: cada UE só tem rota local pra PRÓPRIA sub-rede
# /24 (não o /16 inteiro) — `iperf3 -c 10.45.0.1` dá "Network is
# unreachable" quando rodado de dentro de `ue-urllc`/`ue-miot`. Por
# isso throughput TAMBÉM precisa do dest específico de cada fatia
# aqui, não um endereço único pra todas (diferente do lab antigo).
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
_UE_LOGS = (Path("/tmp/ue_urllc.log"), Path("/tmp/ue_embb.log"), Path("/tmp/ue_miot.log"))
_GROWING_LOGS = (GNB_COMBINED_LOG,) + _UE_LOGS


def ensure_disk_headroom(threshold_percent: float = 60.0) -> None:
    """**Achado real investigando a degradação permanente/inexplicável do
    cenário 1 numa campanha longa**: `/tmp` nesta VM é `tmpfs` (12GB, em
    RAM) — os logs do gNB (`gnb_combined.log`) e das 3 UEs (`ue_*.log`)
    crescem sem limite (sem rotação real configurada) durante uma
    sessão de dias, e em algum momento ENCHEM o `/tmp` por completo.
    Confirmado ao vivo: somados, os 4 arquivos bateram exatamente nos
    12GB do tmpfs. Depois disso, qualquer escrita em `/tmp` (do próprio
    gNB, do charon, de qualquer coisa) pode falhar silenciosamente — e
    como reiniciar processos não libera espaço em disco, o problema
    NUNCA se resolvia sozinho, só piorava (explicando por que o ponto
    exato de quebra variava entre campanhas: dependia de quanto log já
    tinha acumulado de sessões anteriores, não de contagem de
    iteração). Hipóteses de causa testadas antes desta (esgotamento de
    fd/conntrack, ARP obsoleto, reqid de conexão reusado) foram só
    sintomas corrigidos no caminho, não a causa raiz real.

    **Por que precisa reiniciar a RAN, não só truncar os arquivos**: os
    processos gNB/UE mantêm o descritor aberto com a posição de escrita
    onde estava — truncar o arquivo por fora enquanto o processo ainda
    escreve não libera espaço de verdade, ele continua escrevendo a
    partir do offset antigo (vira um arquivo esparso, o problema volta
    na prática imediatamente). Só funciona truncar ANTES de reiniciar
    os processos (quem nasce depois já abre no offset zero).

    **Achado real rodando a campanha de validação deste fix**: a
    primeira versão truncava DEPOIS do `watchdog_start.sh` (raciocínio
    "só libera espaço de verdade com processo novo" — verdade, mas na
    ordem errada). Isso apagava, junto com o lixo acumulado, as linhas
    de TEID que o PRÓPRIO restart tinha acabado de escrever durante o
    attach das 3 UEs (`gnb_combined.log`) — exatamente o que
    `capture_and_apply_slice_marks()` (cenários 2/3/4) precisa ler
    depois pra achar o TEID de cada fatia. Resultado: 90/90 execuções
    desses três cenários falharam com "nenhum TEID encontrado", 100%
    reprodutível, numa campanha inteira. Corrigido invertendo a ordem:
    trunca ANTES de reiniciar — o attach da próxima inicialização
    escreve as linhas de TEID num arquivo que ninguém mais apaga depois.

    Chamada no início de `main()` e entre cenários — barata quando não
    precisa agir (só um `shutil.disk_usage`), e o restart via
    `watchdog_start.sh` já é o mesmo procedimento usado manualmente
    (RUNBOOK-OAI.md) pra um RAN saudável do zero."""
    import shutil

    usage = shutil.disk_usage("/tmp")
    percent_used = 100.0 * usage.used / usage.total
    if percent_used < threshold_percent:
        return

    print(
        f"[ensure_disk_headroom] /tmp em {percent_used:.0f}% "
        f"(limite {threshold_percent:.0f}%) — truncando logs e reiniciando RAN antes de continuar"
    )
    for log_path in _GROWING_LOGS:
        subprocess.run(["sudo", "truncate", "-s", "0", str(log_path)], capture_output=True)
    watchdog = _real_home() / "ocudu-lab" / "watchdog_start.sh"
    result = subprocess.run(["sudo", "bash", str(watchdog)], capture_output=True, text=True, timeout=300)
    if "SUCESSO" not in result.stdout:
        raise RuntimeError(
            f"ensure_disk_headroom: watchdog_start.sh não confirmou sucesso — "
            f"saída:\n{result.stdout[-2000:]}\n{result.stderr[-1000:]}"
        )
    print("[ensure_disk_headroom] RAN reiniciada com logs truncados, espaço liberado.")

# IMSI (fixo em cada ue_<fatia>.conf) -> fatia, pelo prefixo -011/-012/-013
# (ver ~/ocudu-lab/ue_*.conf). Único jeito confiável de identificar a
# fatia: o índice `ue=N` do gNB NÃO é estável entre restarts.
_IMSI_SLICE = {"001010000000011": "urllc", "001010000000012": "embb", "001010000000013": "miot"}


def _resolve_slice_ue_index() -> dict[str, int]:
    """**Achado real, crítico, corrigindo um bug do port**: a primeira
    versão deste módulo assumia um `_SLICE_UE_INDEX` FIXO
    (`{"urllc": 0, "embb": 1, "miot": 2}`), por analogia com a ordem de
    lançamento do `watchdog_start.sh`. Errado — o índice interno `ue=N`
    do gNB reflete a ordem em que cada srsUE *vence a corrida de Random
    Access no rádio*, não a ordem do script. Confirmado ao vivo: numa
    sincronização a URLLC ganhou `rnti=0x4601` (`ue=0`); numa sincronização
    anterior na mesma sessão, foi a eMBB quem ganhou esse mesmo RNTI. Usar
    um índice fixo aplicaria o TEID errado pra fatia errada de forma
    silenciosa e imprevisível entre execuções.

    A correlação que REALMENTE vale é por **ordem relativa**: a criação de
    cada sessão no SMF (`UE SUPI[imsi-...] DNN[...]`) e a configuração do
    GTP-U correspondente no gNB (`ue=N UL teid=...`) são dois passos
    SEQUENCIAIS do mesmo procedimento de estabelecimento de sessão PDU,
    por UE — então a 1ª sessão criada no SMF sempre corresponde a `ue=0`,
    a 2ª a `ue=1`, a 3ª a `ue=2`, **mesmo que qual UE física "ganhou"
    cada posição mude entre execuções** (confirmado comparando as duas
    ordens lado a lado, timestamps a poucos ms de distância, consistente
    nas duas sincronizações observadas nesta sessão)."""
    # `docker logs` manda pro stderr, não stdout (achado real debugando
    # este fix) — combina os dois.
    result = subprocess.run(
        ["docker", "logs", "--tail", "500", "5gc-smf-1"], capture_output=True, text=True
    )
    raw = result.stdout + result.stderr
    import re

    imsis_in_order = [
        m.group(1) for m in re.finditer(r"UE SUPI\[imsi-(\d+)\] DNN\[", raw)
    ][-3:]
    if len(imsis_in_order) < 3:
        raise RuntimeError(
            f"só achei {len(imsis_in_order)} sessão(ões) recente(s) no log do SMF (esperava 3) — "
            "a pilha RAN sincronizou de verdade? ver /tmp/gnb_combined.log"
        )
    slice_ue_index = {}
    for ue_index, imsi in enumerate(imsis_in_order):
        slice_name = _IMSI_SLICE.get(imsi)
        if slice_name is None:
            raise RuntimeError(f"IMSI {imsi} não reconhecido em _IMSI_SLICE — config da UE mudou?")
        slice_ue_index[slice_name] = ue_index
    return slice_ue_index


def _capture_uplink_teid_from_gnb_log(slice: str, ue_index: int) -> str:
    """**Substitui a técnica antiga de sniff+ping+offset de byte** (que
    dependia de capturar GTP-U em texto puro em `veth-cu-n2`) — acho real
    migrando pro OCUDU: assim que as SAs N3 sobem (que é exatamente o
    estado em que todo cenário 1-4 chama isto), aquele link só carrega
    ESP cifrado; o GTP-U original nunca aparece na fiação depois que o
    túnel está ativo, então a captura sempre dava timeout sem nenhum
    pacote. O gNB já loga o TEID real de cada sessão (`GTPU PSUP TX
    configured... peer_teid=0x...`) no próprio `/tmp/gnb_combined.log`,
    texto puro, independente do estado do IPsec — mais simples e mais
    robusto que farejar a rede. `ue_index` vem de
    `_resolve_slice_ue_index()` — NÃO é um índice fixo por fatia (ver lá
    o porquê). Pega a ocorrência MAIS RECENTE pro índice `ue=N` (o log
    acumula entre restarts)."""
    import re

    if not GNB_COMBINED_LOG.exists():
        raise RuntimeError(f"{GNB_COMBINED_LOG} não existe — gNB rodou pelo menos uma vez?")
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
    """Ping de verdade, não só "a interface tem IP" — achado real
    rodando a campanha: a interface continua com IP mesmo quando o
    plano de dados fica "preso" depois de mexer no IPsec (mesmo bug já
    documentado no lab antigo, causa raiz nunca encontrada — reinstalar
    a SA ou rotacionar a chave às vezes deixa a sessão PDU sem fluir
    dado novo, plano de controle intacto). Um check puramente local
    nunca detectaria isso, e sem detectar, `ensure_ue_data_plane` nunca
    aciona o `restart_ran_stack()` que de fato resolve.

    Só passou a ser seguro usar ping aqui depois de corrigir o bug real
    do UPF (ver `_SLICE_DEST`/`fix-upf-gateways.sh`): antes do fix,
    ping pros gateways de URLLC/mIoT SEMPRE dava falso-negativo
    (virava ICMP redirect, não reply), mesmo com o plano de dados
    saudável — daí a versão anterior desta função ter trocado pra
    checagem local. Com o UPF corrigido, ping volta a ser o sinal
    correto (e mais forte) de saúde real."""
    ue_netns, iface = _SLICE_NETNS_IFACE[slice]
    dest = _SLICE_DEST[slice]
    result = subprocess.run(
        ["ip", "netns", "exec", ue_netns, "timeout", "4", "ping", "-c", "2", "-I", iface, dest],
        capture_output=True, text=True,
    )
    return "bytes from" in result.stdout


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
    slice_ue_index = _resolve_slice_ue_index()
    teids = {
        slice: _capture_uplink_teid_from_gnb_log(slice, slice_ue_index[slice])
        for slice in _SLICE_NETNS_IFACE
    }
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
