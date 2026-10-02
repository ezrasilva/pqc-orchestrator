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
montado (ver docs/RUNBOOK-OAI.md passos 0-3 — RAN/5GC/rede de pé; este
script cuida só da camada IPsec de cada cenário)."""

from __future__ import annotations

import argparse
import importlib
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

UE_NETNS = "du-ns"


def _resolve_bind_ip(iface: str, netns: str = UE_NETNS) -> str:
    out = subprocess.run(
        ["ip", "netns", "exec", netns, "ip", "-4", "-o", "addr", "show", iface],
        capture_output=True, text=True, check=True,
    ).stdout
    match = re.search(r"inet (\d+\.\d+\.\d+\.\d+)", out)
    if not match:
        raise RuntimeError(f"não achei endereço IPv4 em {iface} dentro de {netns}")
    return match.group(1)


def _run_one_probe(probe: dict, duration_seconds: int) -> None:
    label, iface, profile = probe["label"], probe["iface"], probe["profile"]
    bind_ip = _resolve_bind_ip(iface)
    if profile == "latency":
        count = max(1, int(duration_seconds / 0.1))
        run_latency_probe(UE_NETNS, iface, "10.45.0.1", count=count, interval_seconds=0.1, label=label)
    elif profile == "throughput_tcp":
        run_throughput_probe(UE_NETNS, bind_ip, duration_seconds=duration_seconds, udp=False, label=label)
    elif profile == "throughput_udp_sparse":
        run_throughput_probe(
            UE_NETNS, bind_ip, duration_seconds=duration_seconds, udp=True, bitrate="10K", label=label
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


def _build_smo() -> tuple[SmoCore, SchedulerCore, KeyStore]:
    store = KeyStore(RESULTS_DIR / ".kms-experiment.sqlite3")
    kms = KeyManagementCore(store)
    scheduler = SchedulerCore()
    smo = SmoCore(kms, scheduler, IpsecAgentCore())
    return smo, scheduler, store


def run_once(scenario_key: str, iteration: int, duration_seconds: int, warmup_seconds: int) -> str:
    module = importlib.import_module(SCENARIOS[scenario_key])
    run_id = f"{module.NAME}-{iteration:03d}-{uuid.uuid4().hex[:8]}"
    log_path = RESULTS_DIR / f"{run_id}.jsonl"
    instrumentation.configure(log_path, run_id)

    print(f"[{run_id}] setup...")
    module.setup()

    smo = scheduler = store = None
    rotation_driver = None
    policy = getattr(module, "scheduling_policy", None)
    if policy is not None:
        smo, scheduler, store = _build_smo()
        scheduler.set_policy(policy)
        rotation_driver = RotationDriver(smo, scheduler, check_interval_seconds=10.0)

    charon_pid = find_charon_pid("cu-ns")
    pids = {"experiment": __import__("os").getpid()}
    if charon_pid is not None:
        pids["charon"] = charon_pid

    xfrm_poller = XfrmStatePoller("cu-ns", interval_seconds=0.5)
    classification_poller = ClassificationStatsPoller("cu-ns", interval_seconds=0.5)
    resource_poller = ResourcePoller(pids, interval_seconds=1)

    try:
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
    finally:
        xfrm_poller.stop()
        classification_poller.stop()
        resource_poller.stop()
        if rotation_driver is not None:
            rotation_driver.stop()
        if store is not None:
            store.close()
        print(f"[{run_id}] teardown...")
        module.teardown()
        instrumentation.reset()

    return str(log_path)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--scenario", choices=[*SCENARIOS.keys(), "all"], default="3")
    parser.add_argument("--iterations", type=int, default=10, help="repetições por cenário (default: 10)")
    parser.add_argument("--duration", type=int, default=300, help="segundos de coleta por execução (default: 300)")
    parser.add_argument("--warmup", type=int, default=10, help="segundos descartados no início de cada execução")
    args = parser.parse_args()

    RESULTS_DIR.mkdir(parents=True, exist_ok=True)

    scenario_keys = list(SCENARIOS.keys()) if args.scenario == "all" else [args.scenario]
    log_paths = []
    for key in scenario_keys:
        for i in range(1, args.iterations + 1):
            print(f"=== cenário {key}, iteração {i}/{args.iterations} ===")
            log_paths.append(run_once(key, i, args.duration, args.warmup))

    print("\nArquivos gerados:")
    for path in log_paths:
        print(f"  {path}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
