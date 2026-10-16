#!/usr/bin/env python3
"""Orquestrador principal do pipeline de coleta — ver
CENARIOS-TESTE-AVALIACAO.md. Roda um ou mais cenários (0-4), N vezes
cada (`--iterations`, default 10 — seção 3 do documento, "Rigor
Experimental"), coletando os quatro fluxos da seção 4 (tráfego, kernel,
decisão do scheduler, CPU/memória) num JSONL por execução, com um
`run_id` único por execução pra correlacionar tudo sem ambiguidade.

Uso:
    sudo .venv/bin/python3 run_experiment.py --scenario 3 --iterations 10 --duration 300
    sudo .venv/bin/python3 run_experiment.py --scenario all --iterations 3 --duration 30  # smoke test

Precisa de root (fala com os netns do laboratório) e do laboratório já
montado (ver docs/RUNBOOK-OCUDU.md passos 0-3 — RAN/5GC/rede de pé; este
script cuida só da camada IPsec de cada cenário)."""

from __future__ import annotations

import argparse
import importlib
import random
import re
import subprocess
import sys
import threading
import time
import uuid
from pathlib import Path

from evaluation import instrumentation, lab_control
from evaluation.collectors.classification_stats import ClassificationStatsPoller
from evaluation.collectors.resource import ResourcePoller, find_charon_pid
from evaluation.collectors.traffic import run_latency_probe, run_throughput_probe
from evaluation.collectors.xfrm_state import XfrmStatePoller
from evaluation.instrumentation import emit
from evaluation.rotation_driver import RotationDriver
from ipsec_agent.agent import IpsecAgentCore
from kms.models import SliceType
from kms.qkd import PpkProvider, Qkd014Client
from kms.service import KeyManagementCore
from kms.store import KeyStore
from scheduler.service import SchedulerCore
from smo.service import SmoCore

RESULTS_DIR = Path(__file__).resolve().parent / "results"

SCENARIOS = {
    "0": "evaluation.scenarios.scenario0_baseline_native",
    "1": "evaluation.scenarios.scenario1_static_pqc",
    "2": "evaluation.scenarios.scenario2_diff_no_risk",
    "3": "evaluation.scenarios.scenario3_risk_aware",
    "4": "evaluation.scenarios.scenario4_contention",
}

def _resolve_bind_ip(iface: str, netns: str, retries: int = 5, retry_delay_seconds: float = 0.3) -> str:
    """**Achado real rodando a campanha de 30 iterações**: em ~34-43%
    das execuções, a fatia eMBB (e só ela, nunca urllc/miot) perdia o
    `throughput_probe_summary` inteiro porque este `ip netns exec`
    falhava com exit 1 ("device does not exist") num instante
    específico. Investigado a fundo: não é RLF nem churn de sessão PDU
    (zero ocorrências nos logs do srsue_embb), e não reproduz isolado
    (iperf3 real + polling repetido da interface, 150 tentativas, 0
    falhas) — só acontece sob a carga COMBINADA da campanha inteira (3
    sondas simultâneas + pollers de kernel a cada 0.5-1s + rotation
    driver), sugerindo contenção de recursos (fork/exec) no pico de
    carga, não um problema de RF real. Como a condição é confirmada
    transitória (nunca persiste — a mesma interface sempre resolve
    normalmente segundos depois), a correção correta é absorver a
    transitoriedade com retry, não impedir a perda de dado tratando o
    sintoma no coletor.

    **Segunda rodada de investigação (sugestões externas)**: o
    `capture_output=True` anterior descartava o `stderr` real do `ip`
    no momento da falha — a mensagem textual real nunca foi vista, só
    o exit code. Agora loga via `emit()` pra próxima falha real deixar
    rastro (`stderr` pode ser "Cannot allocate memory"/EAGAIN no
    socket Netlink sob CPU estrangulado, não necessariamente "device
    not found" — ainda não confirmado, é só o que o exit code 1 permite
    descartar/confirmar da próxima vez)."""
    last_error: Exception | None = None
    for attempt in range(retries):
        try:
            out = subprocess.run(
                ["ip", "netns", "exec", netns, "ip", "-4", "-o", "addr", "show", iface],
                capture_output=True, text=True, check=True,
            ).stdout
            match = re.search(r"inet (\d+\.\d+\.\d+\.\d+)", out)
            if not match:
                raise RuntimeError(f"não achei endereço IPv4 em {iface} dentro de {netns}")
            return match.group(1)
        except subprocess.CalledProcessError as exc:
            last_error = exc
            emit(
                "resolve_bind_ip_retry", iface=iface, netns=netns, attempt=attempt,
                returncode=exc.returncode, stderr=(exc.stderr or "").strip()[:500],
            )
            if attempt < retries - 1:
                time.sleep(retry_delay_seconds)
    raise RuntimeError(f"não resolvi IPv4 em {iface} dentro de {netns} após {retries} tentativas") from last_error


def _run_one_probe(probe: dict, duration_seconds: int) -> None:
    # `netns`/`dest` por sonda (não um UE_NETNS global) desde a migração
    # pro testbed OCUDU+srsUE: cada fatia é um processo UE separado, em
    # seu próprio netns, com seu próprio gateway/subnet — ver
    # `lab_control._SLICE_NETNS_IFACE`/`_SLICE_DEST`.
    label, netns, iface, dest, profile = probe["label"], probe["netns"], probe["iface"], probe["dest"], probe["profile"]
    # jitter antes de resolver o IP — as 3 threads (uma por fatia) chamam
    # `_resolve_bind_ip` no mesmo instante exato (todas disparadas juntas
    # em `_run_traffic_plan`); se a falha intermitente da eMBB (ver achado
    # em `_resolve_bind_ip`) for uma colisão de timing com os pollers de
    # kernel (XfrmStatePoller/ClassificationStatsPoller, tick de 0.5s) em
    # vez de pura falta de recurso, espalhar esse instante deve bastar
    # pra reduzir a taxa — ainda não confirmado, é um teste.
    time.sleep(random.uniform(0.01, 0.05))
    bind_ip = _resolve_bind_ip(iface, netns)
    if profile == "latency":
        count = max(1, int(duration_seconds / 0.1))
        run_latency_probe(netns, iface, dest, count=count, interval_seconds=0.1, label=label)
    elif profile == "throughput_tcp":
        run_throughput_probe(
            netns, bind_ip, dest=dest, port=probe.get("port", 5201),
            duration_seconds=duration_seconds, udp=False, label=label,
        )
    elif profile == "throughput_udp_sparse":
        run_throughput_probe(
            netns, bind_ip, dest=dest, port=probe.get("port", 5201),
            duration_seconds=duration_seconds, udp=True, bitrate="10K", label=label,
        )
    else:
        raise ValueError(f"profile desconhecido: {profile}")


def _run_traffic_plan(plan: list[dict], duration_seconds: int) -> None:
    """As três fatias rodam **em paralelo** (threads), não uma depois da
    outra — achado rodando esta avaliação pela primeira vez: a versão
    sequencial fazia `--duration` real da janela virar
    `3 * duration_seconds` (uma sonda de 20s por fatia, uma após a
    outra, em vez de três sondas simultâneas de 20s cada), o que também
    é mais fiel ao cenário real (as três fatias têm tráfego ao mesmo
    tempo, não em rodízio)."""
    threads = [
        threading.Thread(target=_run_one_probe, args=(probe, duration_seconds))
        for probe in plan
    ]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=duration_seconds + 30)


# QKDN do QuDitto (ver lab/qkd/). O nó A é onde roda o controller e o
# RabbitMQ; o B é a outra ponta do enlace simulado de 20 km.
QKDN_MASTER_URL = "http://172.20.0.11:8000"
QKDN_SLAVE_SAE_ID = "B"
# Profundidade do poço por fatia. Três é o suficiente para absorver uma
# rajada de rotações sem que o reauth espere: medido, cada chave custa
# ~15,4 s de simulação e a QKDN SERIALIZA a geração (três threads em
# paralelo renderam ~1 chave por 15 s, não três), então encher mais
# fundo não acelera — só aumenta o tempo de aquecimento.
PPK_POOL_DEPTH = 3


def _build_smo() -> tuple[SmoCore, SchedulerCore, KeyStore, PpkProvider]:
    store = KeyStore(RESULTS_DIR / ".kms-experiment.sqlite3")
    kms = KeyManagementCore(store)
    scheduler = SchedulerCore()
    # O poço começa a gastar QKD ao `start()`, então ele sobe aqui e é
    # devolvido para quem chama poder pará-lo no fim do experimento.
    provider = PpkProvider(
        Qkd014Client(QKDN_MASTER_URL), QKDN_SLAVE_SAE_ID,
        tuple(SliceType), depth=PPK_POOL_DEPTH,
    )
    provider.start()
    smo = SmoCore(kms, scheduler, IpsecAgentCore(), provider)
    return smo, scheduler, store, provider


def run_once(scenario_key: str, iteration: int, duration_seconds: int, warmup_seconds: int) -> str:
    """**Achado real rodando a primeira campanha longa**: `module.setup()`
    rodava FORA do `try/finally` — uma falha de setup (ex: a conexão
    estática do Cenário 1 não estabelecer) pulava o `teardown()` (lab
    fica com configuração parcial pro próximo cenário) E, sem nenhum
    try/except no laço principal (`main()`), matava o processo inteiro —
    uma campanha de 5 cenários × 10 iterações × 5min foi interrompida na
    primeira falha de UM cenário, perdendo todo o resto já enfileirado.
    Agora: setup/teardown sempre pareados, e `main()` captura falhas por
    execução e segue pra próxima em vez de abortar a campanha toda."""
    module = importlib.import_module(SCENARIOS[scenario_key])
    run_id = f"{module.NAME}-{iteration:03d}-{uuid.uuid4().hex[:8]}"
    log_path = RESULTS_DIR / f"{run_id}.jsonl"
    instrumentation.configure(log_path, run_id)

    smo = scheduler = store = ppk_provider = None
    rotation_driver = None
    xfrm_poller = classification_poller = resource_poller = None

    try:
        print(f"[{run_id}] setup...")
        module.setup()

        policy = getattr(module, "scheduling_policy", None)
        if policy is not None:
            smo, scheduler, store, ppk_provider = _build_smo()
            scheduler.set_policy(policy)
            rotation_driver = RotationDriver(smo, scheduler, check_interval_seconds=10.0)

        charon_pid = find_charon_pid("cu-ns")
        pids = {"experiment": __import__("os").getpid()}
        if charon_pid is not None:
            pids["charon"] = charon_pid

        # **Achado real investigando o gap de isolamento (B.3)**: testei
        # tcpdump real (contagem na rede) contra o `iptables` e a SA
        # numa execução sem rotação — os três bateram exatamente (300
        # pacotes), provando que não há perda real nem contador de
        # kernel desatualizado. O gap de ~2-3% só aparece em cenários
        # COM rotação periódica (2/3/4, ~18 rotações numa janela de
        # 60s): cada rotação cria uma SA nova e remove a antiga, e o
        # poller de 0.5s podia não pegar o valor final verdadeiro da SA
        # antiga bem no instante em que ela desaparecia. Confirmado
        # isolando a variável: só acelerar este poller pra 0.1s (sem
        # mudar mais nada) fez o gap cair de ~2-3% pra ~0.3-0.5% nas
        # fatias de maior volume. A classificação (iptables) não tem
        # esse problema — a regra nunca é removida, só o contador
        # cresce — por isso fica em 0.5s.
        xfrm_poller = XfrmStatePoller("cu-ns", interval_seconds=0.1)
        classification_poller = ClassificationStatsPoller("cu-ns", interval_seconds=0.5)
        resource_poller = ResourcePoller(pids, interval_seconds=1)

        print(f"[{run_id}] warm-up ({warmup_seconds}s, descartado da análise)...")
        time.sleep(warmup_seconds)

        xfrm_poller.start()
        classification_poller.start()
        resource_poller.start()
        if rotation_driver is not None:
            rotation_driver.start()

        emit("run_window_start", scenario=module.NAME, duration_seconds=duration_seconds)

        if scenario_key == "4" and smo is not None:
            half = duration_seconds / 2
            time.sleep(half)
            print(f"[{run_id}] disparando contenção...")
            module.trigger_contention(smo, scheduler)
            _run_traffic_plan(module.traffic_plan(), int(duration_seconds - half))
        else:
            _run_traffic_plan(module.traffic_plan(), duration_seconds)

        emit("run_window_end", scenario=module.NAME)
        # **Achado real investigando o gap de isolamento (B.3)**: testei
        # manualmente (iperf3 isolado + concorrente nas 3 fatias,
        # contagem limpa antes/depois) e o gap classificação-vs-SA
        # fica em ~0.1% nesses testes, bem abaixo do ~2-3% da campanha
        # automática — a diferença não é concorrência entre fatias, é
        # que aqui `stop()` roda imediatamente após o tráfego acabar
        # (sem a folga natural que um teste manual tem), capturando
        # pacotes ainda "em trânsito" no kernel entre o mangle (marca
        # ANTES de cifrar) e a SA (conta DEPOIS de cifrar). Uma folga
        # curta aqui deixa esses pacotes residuais escoarem antes da
        # leitura final.
        time.sleep(0.2)
    finally:
        if xfrm_poller is not None:
            xfrm_poller.stop()
        if classification_poller is not None:
            classification_poller.stop()
        if resource_poller is not None:
            resource_poller.stop()
        if rotation_driver is not None:
            rotation_driver.stop()
        if ppk_provider is not None:
            # Antes do store: as threads de reposição não devem continuar
            # gastando QKD depois do fim da iteração.
            ppk_provider.stop()
        if store is not None:
            store.close()
        print(f"[{run_id}] teardown...")
        try:
            module.teardown()
        except Exception:
            print(f"[{run_id}] teardown também falhou — lab pode estar em estado parcial, confira manualmente")
            raise
        instrumentation.reset()

    return str(log_path)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument(
        "--scenario", default="3",
        help="um cenário (ex: 3), 'all' (todos), ou uma lista separada por vírgula (ex: 1,2,3,4)",
    )
    parser.add_argument("--iterations", type=int, default=10, help="repetições por cenário (default: 10)")
    parser.add_argument("--duration", type=int, default=300, help="segundos de coleta por execução (default: 300)")
    parser.add_argument("--warmup", type=int, default=10, help="segundos descartados no início de cada execução")
    args = parser.parse_args()

    # Achado real: uma campanha inteira (50 execuções) rodou contaminada
    # por um DU/CU/charon zumbis de dois dias atrás, sem que nada
    # avisasse — falha alto aqui, antes do primeiro cenário, em vez de
    # descobrir só depois de coletar tudo (ver lab_control.py).
    print("checando se há processos zumbis antes de começar...")
    lab_control.assert_no_stray_processes()
    print("ok, nenhum processo a mais detectado.")

    RESULTS_DIR.mkdir(parents=True, exist_ok=True)

    if args.scenario == "all":
        scenario_keys = list(SCENARIOS.keys())
    else:
        scenario_keys = [s.strip() for s in args.scenario.split(",")]
        for key in scenario_keys:
            if key not in SCENARIOS:
                parser.error(f"cenário desconhecido: {key!r} (válidos: {', '.join(SCENARIOS)}, ou 'all')")
    # garante espaço livre em /tmp (tmpfs) ANTES de qualquer cenário —
    # ver docstring de ensure_disk_headroom. Uma campanha longa (horas)
    # acumula log de gNB/UE o bastante pra encher os 12GB sozinha.
    lab_control.ensure_disk_headroom()

    log_paths = []
    failures = []
    for key in scenario_keys:
        for i in range(1, args.iterations + 1):
            print(f"=== cenário {key}, iteração {i}/{args.iterations} ===")
            # checagem barata entre execuções — numa campanha de horas,
            # o /tmp pode passar do limite no meio, não só no começo.
            lab_control.ensure_disk_headroom()
            try:
                log_paths.append(run_once(key, i, args.duration, args.warmup))
            except Exception as exc:
                # uma falha numa execução não pode derrubar a campanha
                # inteira (achado real: já aconteceu, ver docstring de
                # run_once) — loga e segue pra próxima.
                print(f"=== FALHOU: cenário {key}, iteração {i}: {exc!r} — seguindo pra próxima ===")
                failures.append((key, i, repr(exc)))

    print("\nArquivos gerados:")
    for path in log_paths:
        print(f"  {path}")

    if failures:
        print(f"\n{len(failures)} execução(ões) falharam (seguiu pras próximas mesmo assim):")
        for key, i, err in failures:
            print(f"  cenário {key}, iteração {i}: {err}")
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
