#!/usr/bin/env python3
"""Processamento dos resultados — ver CENARIOS-TESTE-AVALIACAO.md seção
4 ("Processador Python: pandas + matplotlib (CDF, P95/P99, tabelas)").

Lê todos os `.jsonl` de `--input-dir` (um por execução, gerados por
`run_experiment.py`), agrega por cenário (extraído do prefixo do
`run_id`) e produz:

- `rekey_timing.csv`/`.png`: tempo de rekeying decomposto (geração de
  chave PQC + confirmação de SPI), P50/P95/P99 por cenário (métrica B.1).
- `latency.csv` + CDF em `.png`: RTT da fatia URLLC, P50/P95/P99 por
  cenário (métrica A.1).
- `throughput.csv`: vazão útil por fatia/cenário (métrica A.3).
- `isolation.csv`: contadores de classificação (`iptables mangle`) vs.
  contadores de SA (`ip xfrm state`) por mark — confirma 100% de
  isolamento entre fatias ou aponta o desvio (métrica B.3).
- `resources.csv`: CPU/memória por processo/cenário (métrica C).

Uso:
    .venv/bin/python3 analyze.py --input-dir results/ --output-dir report/
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path

import matplotlib

matplotlib.use("Agg")  # sem display — gera PNG direto, ambiente de servidor/VM
import matplotlib.pyplot as plt
import pandas as pd


def _scenario_from_run_id(run_id: str) -> str:
    # run_id = "<NAME>-<iteration>-<hex>" — NAME pode ter "_" no meio
    # (ex: "cenario3_risk_aware"), então corta pelos dois últimos "-".
    parts = run_id.rsplit("-", 2)
    return parts[0] if len(parts) == 3 else run_id


def load_events(input_dir: Path) -> pd.DataFrame:
    records = []
    for path in sorted(input_dir.glob("*.jsonl")):
        with open(path) as f:
            for line in f:
                line = line.strip()
                if line:
                    records.append(json.loads(line))
    if not records:
        raise SystemExit(f"nenhum evento encontrado em {input_dir} (rode run_experiment.py primeiro)")
    df = pd.json_normalize(records)
    df["scenario"] = df["run_id"].apply(_scenario_from_run_id)
    return df


def _subset(df: pd.DataFrame, event: str, columns: list[str]) -> pd.DataFrame:
    """Filtra por tipo de evento e seleciona colunas de forma defensiva —
    **achado rodando isto pela primeira vez**: quando uma sonda não
    produz nenhuma amostra (ex: latência com 100% de perda, nenhum
    `latency_sample` emitido), a coluna correspondente (`rtt_ms`) nem
    aparece no DataFrame depois do `json_normalize`, e um `df[cols]`
    direto levanta `KeyError` em vez de só devolver vazio. Preenche
    colunas ausentes com `NaN` em vez de falhar — o resto do pipeline já
    trata DataFrames vazios/com `NaN` corretamente."""
    events = df[df["event"] == event]
    for col in columns:
        if col not in events.columns:
            events = events.assign(**{col: pd.NA})
    return events[columns]


def _percentiles(series: pd.Series) -> dict:
    return {
        "n": len(series),
        "mean": series.mean(),
        "p50": series.quantile(0.50),
        "p95": series.quantile(0.95),
        "p99": series.quantile(0.99),
        "max": series.max(),
    }


def analyze_rekey_timing(df: pd.DataFrame, output_dir: Path) -> None:
    keygen = _subset(df, "keygen_pqc_end", ["scenario", "duration_seconds", "slice"]).copy()
    keygen["stage"] = "keygen_pqc"
    spi = _subset(df, "spi_confirmation_end", ["scenario", "duration_seconds"]).copy()
    spi["stage"] = "spi_confirmation"
    combined = pd.concat([keygen, spi], ignore_index=True).dropna(subset=["duration_seconds"])
    if combined.empty:
        print("(nenhuma rotação ocorreu durante esta coleta)")
        return

    rows = []
    for (scenario, stage), group in combined.groupby(["scenario", "stage"]):
        rows.append({"scenario": scenario, "stage": stage, **_percentiles(group["duration_seconds"] * 1000)})
    table = pd.DataFrame(rows).sort_values(["scenario", "stage"])
    table.to_csv(output_dir / "rekey_timing.csv", index=False)
    print(table.to_string(index=False))

    fig, ax = plt.subplots(figsize=(8, 5))
    combined["duration_ms"] = combined["duration_seconds"] * 1000
    combined.boxplot(column="duration_ms", by=["scenario", "stage"], ax=ax, rot=45)
    ax.set_ylabel("duração (ms)")
    ax.set_title("Tempo de rekeying decomposto por sub-etapa")
    plt.suptitle("")
    fig.tight_layout()
    fig.savefig(output_dir / "rekey_timing.png", dpi=150)
    plt.close(fig)


def analyze_latency(df: pd.DataFrame, output_dir: Path) -> None:
    samples = _subset(df, "latency_sample", ["scenario", "label", "rtt_ms"]).dropna()
    if samples.empty:
        print("(nenhuma amostra de latência — todos os pacotes de sonda foram perdidos nesta coleta)")
        return

    rows = []
    for (scenario, label), group in samples.groupby(["scenario", "label"]):
        rows.append({"scenario": scenario, "label": label, **_percentiles(group["rtt_ms"])})
    table = pd.DataFrame(rows).sort_values(["scenario", "label"])
    table.to_csv(output_dir / "latency.csv", index=False)
    print(table.to_string(index=False))

    fig, ax = plt.subplots(figsize=(8, 5))
    for (scenario, label), group in samples.groupby(["scenario", "label"]):
        sorted_rtt = group["rtt_ms"].sort_values().reset_index(drop=True)
        cdf = (sorted_rtt.index + 1) / len(sorted_rtt)
        ax.plot(sorted_rtt, cdf, label=f"{scenario}/{label}")
    ax.set_xlabel("RTT (ms)")
    ax.set_ylabel("CDF")
    ax.set_title("Latência (URLLC) — CDF por cenário")
    ax.legend(fontsize=7)
    fig.tight_layout()
    fig.savefig(output_dir / "latency_cdf.png", dpi=150)
    plt.close(fig)


def analyze_throughput(df: pd.DataFrame, output_dir: Path) -> None:
    samples = _subset(df, "throughput_probe_summary", ["scenario", "label", "mbps", "lost_percent"]).dropna(subset=["mbps"])
    if samples.empty:
        print("(nenhuma amostra de throughput)")
        return
    table = samples.groupby(["scenario", "label"]).agg(["mean", "std", "count"])
    table.to_csv(output_dir / "throughput.csv")
    print(table.to_string())


def analyze_isolation(df: pd.DataFrame, output_dir: Path) -> None:
    """Confirma zero-leakage: o total de pacotes marcados por
    `iptables mangle` (classification_snapshot, contador cumulativo
    desde o início da regra) deve corresponder ao total que as SAs
    daquele mark efetivamente carregaram (xfrm_snapshot) — métrica B.3.

    **Achado corrigindo isto**: uma rotação de chave cria uma SA NOVA
    (contador zerado) pro mesmo mark — pegar só o `max` de "packets"
    agrupado por mark comparava o contador cumulativo do iptables contra
    o pico de UMA SA só, nunca batendo quando havia rotação no meio da
    janela (óbvio em retrospecto, mas só ficou claro rodando contra
    tráfego real com rotação acontecendo). Corrigido: soma o `max` de
    cada SPI individual (cada SA só cresce durante sua própria vida) e
    só então agrupa por mark."""
    classification = _subset(df, "classification_snapshot", ["scenario", "mark", "packets"]).dropna(subset=["mark"])
    xfrm = _subset(df, "xfrm_snapshot", ["scenario", "mark", "spi", "packets"]).dropna(subset=["mark"])
    if classification.empty or xfrm.empty:
        print("(sem amostras suficientes de classificação/xfrm pra checar isolamento)")
        return

    cls_last = classification.groupby(["scenario", "mark"])["packets"].max().rename("classified_packets")
    per_spi_peak = xfrm.groupby(["scenario", "mark", "spi"])["packets"].max()
    xfrm_total = per_spi_peak.groupby(["scenario", "mark"]).sum().rename("sa_packets_total")
    joined = pd.concat([cls_last, xfrm_total], axis=1).reset_index()
    joined["match"] = joined["classified_packets"] == joined["sa_packets_total"]
    joined.to_csv(output_dir / "isolation.csv", index=False)
    print(joined.to_string(index=False))


def analyze_resources(df: pd.DataFrame, output_dir: Path) -> None:
    samples = _subset(df, "resource_snapshot", ["scenario", "process", "cpu_percent", "rss_kb"]).dropna(subset=["cpu_percent"])
    if samples.empty:
        print("(nenhuma amostra de CPU/memória)")
        return
    table = samples.groupby(["scenario", "process"]).agg(
        cpu_mean=("cpu_percent", "mean"), cpu_max=("cpu_percent", "max"),
        rss_mean_kb=("rss_kb", "mean"), rss_max_kb=("rss_kb", "max"),
    )
    table.to_csv(output_dir / "resources.csv")
    print(table.to_string())


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--input-dir", type=Path, default=Path(__file__).parent / "results")
    parser.add_argument("--output-dir", type=Path, default=Path(__file__).parent / "report")
    args = parser.parse_args()

    args.output_dir.mkdir(parents=True, exist_ok=True)
    df = load_events(args.input_dir)

    print(f"\n{len(df)} eventos carregados, cenários: {sorted(df['scenario'].unique())}\n")

    print("=== B.1 — tempo de rekeying decomposto (ms) ===")
    analyze_rekey_timing(df, args.output_dir)
    print("\n=== A.1 — latência URLLC (ms) ===")
    analyze_latency(df, args.output_dir)
    print("\n=== A.3 — throughput (Mbps) ===")
    analyze_throughput(df, args.output_dir)
    print("\n=== B.3 — isolamento (classificação vs. SA real) ===")
    analyze_isolation(df, args.output_dir)
    print("\n=== C — CPU/memória ===")
    analyze_resources(df, args.output_dir)

    print(f"\nRelatórios em: {args.output_dir}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
