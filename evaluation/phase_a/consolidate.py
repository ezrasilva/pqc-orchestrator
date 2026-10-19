#!/usr/bin/env python3
"""Consolida os resultados da Fase A nas tabelas do artigo.

**Por que isto existe e não é só um notebook.** A Fase A foi colhida em
execuções separadas, algumas delas **sob condição inválida**: ela é
especificada para rodar sem OCUDU nem srsUE, e as primeiras execuções
foram tomadas com o rádio ligado, consumindo ~5 dos 8 núcleos. O efeito
medido foi de 0% na A.5, ~17% (deslocamento constante) na A.1 e o
bastante na A.3 para **inverter a decisão da cifra**.

Então consolidar à mão é arriscado: basta somar um arquivo contaminado
para a tabela do artigo carregar um artefato. Este script usa o evento
`phase_a_host_load` — gravado por `bench_n3.py` e `kem_bench.py` — para
**separar automaticamente** o que é válido do que não é, e marca como
descartado todo arquivo em que o rádio estava de pé ou que não traz o
registro (os anteriores à instrumentação).

Uso:
    .venv/bin/python3 -m evaluation.phase_a.consolidate            # só válidos
    .venv/bin/python3 -m evaluation.phase_a.consolidate --todos    # inclui e marca
"""

from __future__ import annotations

import argparse
import json
import statistics as st
import sys
from collections import defaultdict
from pathlib import Path

RESULTS_DIR = Path(__file__).resolve().parent.parent / "results_phase_a"


def percentil(valores: list[float], q: float) -> float:
    if not valores:
        return float("nan")
    v = sorted(valores)
    return v[min(len(v) - 1, int(round(q * (len(v) - 1))))]


def carrega(caminho: Path) -> dict:
    """Lê um arquivo de resultado e classifica a condição em que foi
    colhido."""
    eventos = []
    for linha in caminho.open():
        linha = linha.strip()
        if not linha:
            continue
        try:
            eventos.append(json.loads(linha))
        except json.JSONDecodeError:
            # Linha truncada: acontece quando uma execução é interrompida
            # no meio da escrita. Descartar a linha é melhor que abortar o
            # arquivo todo.
            continue

    cargas = [e for e in eventos if e.get("event") == "phase_a_host_load"]
    tem_rekey = any(e.get("event") == "phase_a_rekey" for e in eventos)
    # A A.2 varia `make_before_break`, e um drop-in da Fase B fixava a
    # opção, anulando o toggle em silêncio. O evento
    # `phase_a_dropins_suspensos` só existe na versão corrigida do
    # harness, então a ausência dele num arquivo de rekey significa
    # "toggle não verificado" — e somar esse arquivo mistura repetições
    # em que `no` mediu `yes` com repetições corretas, o que já
    # aconteceu: dobrou o `n` sem ninguém notar.
    toggle_verificado = any(
        e.get("event") == "phase_a_dropins_suspensos" for e in eventos)

    if not cargas:
        condicao = "sem_registro"
    elif any(c.get("radio_running") for c in cargas):
        condicao = "radio_ligado"
    elif tem_rekey and not toggle_verificado:
        condicao = "toggle_nao_verificado"
    else:
        condicao = "valido"
    return {
        "arquivo": caminho.name,
        "eventos": eventos,
        "condicao": condicao,
        "load_max": max((c.get("load_1min", 0.0) for c in cargas), default=None),
        "radio": sorted({p for c in cargas for p in c.get("radio_processes", [])}),
    }


def tabela_a1(arquivos: list[dict]) -> str:
    """A.1/A.6 — handshake por perfil e por ponto de RTT."""
    por_rtt: dict[float, dict[str, list[float]]] = defaultdict(lambda: defaultdict(list))
    extras: dict[str, dict] = {}
    rtt_medido: dict[float, float] = {}
    for arq in arquivos:
        rtt = None
        for e in arq["eventos"]:
            if e.get("event") == "phase_a_rtt_axis":
                rtt = e["netem_delay_ms"]
                rtt_medido[rtt] = e["measured_rtt_ms"]
            elif e.get("event") == "phase_a_handshake" and rtt is not None:
                por_rtt[rtt][e["profile"]].append(e["duration_seconds"] * 1000)
                extras.setdefault(e["profile"], e)
    if not por_rtt:
        return ""

    perfis = sorted(extras, key=lambda p: p)
    linhas = ["### A.1 + A.6 — handshake por perfil e RTT", ""]
    cab = "| Perfil | Trocas | Frag. | Bytes env. | " + " | ".join(
        f"p50 @ {rtt_medido[r]:.2f} ms" for r in sorted(por_rtt)) + " | Δ/RTT |"
    linhas += [cab, "|" + " --- |" * (4 + len(por_rtt) + 1)]
    for perfil in perfis:
        ex = extras[perfil]
        p50s = [percentil(por_rtt[r][perfil], 0.50) for r in sorted(por_rtt)]
        rtts = sorted(por_rtt)
        # Inclinação entre o primeiro e o último ponto, em múltiplos de
        # RTT. É a grandeza estruturalmente robusta: sendo diferença,
        # cancela qualquer deslocamento constante de carga.
        if len(rtts) >= 2 and rtt_medido[rtts[-1]] > rtt_medido[rtts[0]]:
            delta_rtt = rtt_medido[rtts[-1]] - rtt_medido[rtts[0]]
            inclinacao = f"{(p50s[-1] - p50s[0]) / delta_rtt:.2f}"
        else:
            inclinacao = "—"
        linhas.append(
            f"| {perfil} | {ex['n_exchanges']} | {ex['fragments']} | {ex['bytes_sent']} | "
            + " | ".join(f"{v:.1f} ms" for v in p50s) + f" | **{inclinacao}** |")
    linhas += ["", "A coluna Δ/RTT é a inclinação entre o primeiro e o último ponto, "
               "em múltiplos de RTT: ela vale o número de trocas de cada perfil, e por "
               "ser uma diferença é imune a deslocamento constante de carga.", ""]
    return "\n".join(linhas)


def tabela_a2(arquivos: list[dict]) -> str:
    """A.2 — interrupção por evento, sentido e RTT."""
    chave = lambda rtt, kind, mbb, sentido: (rtt, kind, mbb, sentido)
    dados: dict[tuple, list[float]] = defaultdict(list)
    perdas: dict[tuple, list[int]] = defaultdict(list)
    base: dict[tuple, list[int]] = defaultdict(list)
    for arq in arquivos:
        rtt = None
        for e in arq["eventos"]:
            if e.get("event") == "phase_a_rtt_axis":
                rtt = round(e["measured_rtt_ms"], 1)
            elif e.get("event") in ("phase_a_rekey", "phase_a_rekey_baseline") and rtt is not None:
                alvo = base if e["event"].endswith("baseline") else perdas
                for sentido, pref in (("ida", "fwd"), ("volta", "rev")):
                    k = chave(rtt, e["event_kind"], e["make_before_break"], sentido)
                    ms = e.get(f"{pref}_outage_udp_ms")
                    perdidos = e.get(f"{pref}_udp_lost")
                    if alvo is perdas and ms is not None:
                        dados[k].append(ms)
                    if perdidos is not None:
                        alvo[k].append(perdidos)
    if not dados:
        return ""

    linhas = ["### A.2 + A.6 — interrupção por evento, sentido e RTT", "",
              "| Evento | `make_before_break` | Sentido | RTT | n | p50 | p95 | máx | reps c/ perda | base |",
              "| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |"]
    for k in sorted(dados, key=lambda x: (x[1], str(x[2]), x[3], x[0])):
        rtt, kind, mbb, sentido = k
        v = dados[k]
        pl = perdas.get(k, [])
        bl = sum(base.get(k, [])) if k in base else "—"
        linhas.append(
            f"| {kind} | {'yes' if mbb else 'no'} | {sentido} | {rtt} ms | {len(v)} | "
            f"{percentil(v, .50):.2f} ms | {percentil(v, .95):.2f} ms | {max(v):.2f} ms | "
            f"{sum(1 for x in pl if x > 0)}/{len(pl)} | {bl} |")
    linhas += ["", "A coluna `base` soma os pacotes perdidos nas janelas de linha de base "
               "(mesmo tráfego, nenhum evento): zero é o que torna a perda atribuível ao "
               "evento e não ao ruído.", ""]
    return "\n".join(linhas)


def tabela_a3(arquivos: list[dict]) -> str:
    por_perfil: dict[str, list[dict]] = defaultdict(list)
    for arq in arquivos:
        for e in arq["eventos"]:
            if e.get("event") != "phase_a_dataplane":
                continue
            # Descarta medição que falhou. `ok` só existe nas execuções
            # posteriores à correção; nas anteriores, vazão zero com
            # `retransmits` ausente é a assinatura da falha.
            if e.get("ok") is False:
                continue
            if not e.get("throughput_mbps") and e.get("retransmits") is None:
                continue
            por_perfil[e["label"]].append(e)
    if not por_perfil:
        return ""
    linhas = ["### A.3 — plano de dados por cifra do ESP", "",
              "| Perfil | n | Vazão média | Variação | RTT carga p50/p95/p99 | softirq |",
              "| --- | --- | --- | --- | --- | --- |"]
    for k in sorted(por_perfil, key=lambda x: -st.fmean(e["throughput_mbps"] for e in por_perfil[x])):
        v = [e["throughput_mbps"] for e in por_perfil[k]]
        m = st.fmean(v)
        var = 100 * (max(v) - min(v)) / m if m else 0
        amostra = por_perfil[k][0]
        linhas.append(
            f"| {k} | {len(v)} | {m:.1f} Mbps | {var:.1f}% | "
            f"{amostra.get('loaded_rtt_p50_ms', 0):.3f} / {amostra.get('loaded_rtt_p95_ms', 0):.3f} / "
            f"{amostra.get('loaded_rtt_p99_ms', 0):.3f} ms | {amostra.get('cpu_softirq_pct', 0):.1f}% |")
    return "\n".join(linhas) + "\n"


def tabela_a4(arquivos: list[dict]) -> str:
    por_n: dict[int, list[dict]] = defaultdict(list)
    for arq in arquivos:
        for e in arq["eventos"]:
            if e.get("event") == "phase_a_scale":
                por_n[e["n_children"]].append(e)
    if not por_n:
        return ""
    linhas = ["### A.4 — rekey simultâneo de N Child SAs", "",
              "| Child SAs | n | Todas ok | Parede p50 | Por filho p50 | Por filho máx | ms/filho |",
              "| --- | --- | --- | --- | --- | --- | --- |"]
    for n in sorted(por_n):
        r = por_n[n]
        parede = percentil([x["wall_total_seconds"] * 1000 for x in r], .50)
        linhas.append(
            f"| {n} | {len(r)} | {sum(1 for x in r if x['n_ok'] == n)}/{len(r)} | {parede:.1f} ms | "
            f"{percentil([x['per_child_p50_seconds'] * 1000 for x in r], .50):.1f} ms | "
            f"{percentil([x['per_child_max_seconds'] * 1000 for x in r], .50):.1f} ms | "
            f"{parede / n:.2f} |")
    linhas += ["", "Se o custo fosse linear, `ms/filho` seria constante.", ""]
    return "\n".join(linhas)


def tabela_a5(arquivos: list[dict]) -> str:
    kems: dict[str, dict] = {}
    for arq in arquivos:
        for e in arq["eventos"]:
            if e.get("event") == "phase_a_kem" and "erro" not in e:
                kems[e["kem"]] = e
    if not kems:
        return ""
    destaque = ["ML-KEM-512", "ML-KEM-768", "ML-KEM-1024", "HQC-1", "HQC-3", "HQC-5",
                "FrodoKEM-640-AES", "FrodoKEM-976-AES", "FrodoKEM-1344-AES",
                "BIKE-L1", "BIKE-L3", "BIKE-L5", "sntrup761", "Classic-McEliece-348864"]
    linhas = [f"### A.5 — microbenchmark de KEM ({len(kems)} medidos via liboqs)", "",
              "| KEM | NIST | keygen | encaps | decaps | total | pk | ct | strongSwan |",
              "| --- | --- | --- | --- | --- | --- | --- | --- | --- |"]
    for k in destaque:
        e = kems.get(k)
        if not e:
            continue
        tot = e["keygen"]["p50_us"] + e["encaps"]["p50_us"] + e["decaps"]["p50_us"]
        linhas.append(
            f"| {k} | {e['nist_level']} | {e['keygen']['p50_us']:.1f} | "
            f"{e['encaps']['p50_us']:.1f} | {e['decaps']['p50_us']:.1f} | {tot:.0f} µs | "
            f"{e['public_key_bytes']} B | {e['ciphertext_bytes']} B | "
            f"{'sim' if e['strongswan_proposal'] else '—'} |")
    return "\n".join(linhas) + "\n"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--todos", action="store_true",
                        help="inclui execuções inválidas, marcando-as (por padrão só as válidas)")
    parser.add_argument("--saida", type=Path, default=None,
                        help="escreve o markdown neste arquivo em vez da saída padrão")
    args = parser.parse_args()

    arquivos = [carrega(p) for p in sorted(RESULTS_DIR.glob("phaseA-*.jsonl"))]
    if not arquivos:
        print(f"nenhum resultado em {RESULTS_DIR}", file=sys.stderr)
        return 1

    por_condicao: dict[str, list[dict]] = defaultdict(list)
    for a in arquivos:
        por_condicao[a["condicao"]].append(a)

    cabecalho = ["# Fase A — dados consolidados", "",
                 "## Procedência das execuções", "",
                 "| Condição | Arquivos | O que significa |",
                 "| --- | --- | --- |"]
    sentidos = {
        "valido": "rádio parado e carga registrada — **condição que a Fase A especifica**",
        "radio_ligado": "rádio de pé durante a medição: premissa violada, descartado",
        "toggle_nao_verificado": "A.2 anterior à correção do conflito de drop-in: o "
                                 "toggle de `make_before_break` podia estar anulado, descartado",
        "sem_registro": "anterior à instrumentação de carga: condição desconhecida, descartado",
    }
    for cond in ("valido", "radio_ligado", "toggle_nao_verificado", "sem_registro"):
        if cond in por_condicao:
            cabecalho.append(f"| `{cond}` | {len(por_condicao[cond])} | {sentidos[cond]} |")
    cabecalho.append("")

    usados = arquivos if args.todos else por_condicao.get("valido", [])
    if not usados:
        print("nenhuma execução válida — rode a Fase A com o rádio parado", file=sys.stderr)
        return 1
    cargas = [a["load_max"] for a in usados if a["load_max"] is not None]
    if cargas:
        cabecalho.append(f"`load_1min` máximo entre as execuções usadas: **{max(cargas):.2f}**")
        cabecalho.append("")

    partes = [t for t in (tabela_a1(usados), tabela_a2(usados), tabela_a3(usados),
                          tabela_a4(usados), tabela_a5(usados)) if t]
    texto = "\n".join(cabecalho) + "\n" + "\n".join(partes)

    if args.saida:
        args.saida.write_text(texto)
        print(f"escrito em {args.saida}")
    else:
        print(texto)
    return 0


if __name__ == "__main__":
    sys.exit(main())
