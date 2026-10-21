#!/usr/bin/env python3
"""Consolida a Fase B nas tabelas do artigo, com procedência declarada.

Mesmo princípio do `phase_a/consolidate.py`: gerar do dado em vez de
transcrever à mão, e **rejeitar automaticamente** execução colhida em
condição inválida. Na Fase A isso pegou duas contaminações antes de os
números serem usados; os filtros abaixo existem por defeitos igualmente
reais desta campanha.

| Filtro | O defeito que previne |
| --- | --- |
| `incompleta` | sem `run_window_end`: execução interrompida no meio |
| `tick_falhou` | `rotation_tick_failed`: o laço de rotação morreu num tick. Causa medida: o `stop()` do driver esperava 4 s pela thread, o banco do KMS fechava antes dela terminar, e o tick morria com `Cannot operate on a closed database` |
| `thread_vazou` | `rotation_driver_stop_timeout`: a thread não encerrou, e como o destino da instrumentação é global do módulo ela escreve no `.jsonl` da execução SEGUINTE |
| `contaminada` | evento de rotação em C0 ou C1, que não têm driver. É contaminação da execução anterior — foi assim que o vazamento de thread foi descoberto, porque o evento era impossível por construção |
| `radio_degradado` | o rádio ZMQ travou durante a janela. Assinatura medida em 3 de 174 execuções: vazão eMBB pela metade (0,25 contra 0,54 Mbps), latência URLLC 15× maior (859 contra 56,7 ms) e CPU do gNB MENOR (181% contra 218%, porque está parado). O N3 fica normal nas três, o que confirma rádio e não cripto |

**Por que o filtro de rádio não é circular.** Ele usa a vazão da eMBB
para descartar execução cuja métrica de interesse é a latência da URLLC
— são métricas diferentes, de fatias diferentes e de sondas diferentes.
São afetadas pela mesma causa (o rádio), e é exatamente isso que o torna
um indicador útil: a degradação aparece em tudo ao mesmo tempo, e o
limiar é escolhido num vale largo (0,25 contra 0,54) e não num corte
apertado.
"""

from __future__ import annotations

import argparse
import json
import statistics as st
import sys
from collections import Counter, defaultdict
from pathlib import Path

RESULTS_DIR = Path(__file__).resolve().parent / "results"

# Vazão da eMBB abaixo disto indica rádio travado. O vale medido é
# largo: execuções saudáveis ficam em ~0,54 Mbps e degradadas em ~0,25.
EMBB_MBPS_MINIMO = 0.40

CENARIOS = [
    ("C0 sem IPsec", "cenario0_baseline_nativo"),
    ("C1 túnel único", "cenario1_pqc_estatico"),
    ("C2 proteção máxima", "cenario2_protecao_maxima"),
    ("C3 proposta", "cenario3_risk_aware"),
    ("C4a escassez de QKD", "cenario4a_escassez_qkd"),
    ("C4b contenção", "cenario4_contencao"),
]
SEM_ORQUESTRADOR = {"cenario0_baseline_nativo", "cenario1_pqc_estatico"}


def pct(valores, q):
    if not valores:
        return float("nan")
    v = sorted(valores)
    return v[min(len(v) - 1, int(round(q * (len(v) - 1))))]


def carrega(caminho: Path, prefixo: str) -> dict:
    eventos = []
    for linha in caminho.open():
        linha = linha.strip()
        if not linha:
            continue
        try:
            eventos.append(json.loads(linha))
        except json.JSONDecodeError:
            continue  # linha truncada por interrupção; descartar a linha, não o arquivo
    c = Counter(e.get("event") for e in eventos)

    latencias = [e["rtt_ms"] for e in eventos
                 if e.get("event") == "latency_sample" and e.get("rtt_ms") is not None]
    embb = [e["mbps"] for e in eventos
            if e.get("event") == "throughput_probe_summary" and e.get("label") == "embb"]

    if not c.get("run_window_end"):
        cond = "incompleta"
    elif c.get("rotation_tick_failed"):
        cond = "tick_falhou"
    elif c.get("rotation_driver_stop_timeout"):
        cond = "thread_vazou"
    elif prefixo in SEM_ORQUESTRADOR and any(
            k and k.startswith(("rotation_", "ppk_", "reauth", "child_rekey")) for k in c):
        cond = "contaminada"
    elif not latencias:
        cond = "sem_trafego"
    elif len([e for e in eventos
              if e.get("event") == "throughput_probe_summary"]) < 2:
        # O plano de tráfego tem três sondas: latência na URLLC e vazão
        # na eMBB e na mIoT. Menos de dois resumos de vazão significa que
        # uma sonda não terminou, e a execução está incompleta mesmo que
        # a janela tenha fechado.
        #
        # **Por que isto é um filtro próprio.** O `radio_degradado`
        # compara a vazão da eMBB com um limiar, e não dispara quando o
        # resumo SIMPLESMENTE NÃO EXISTE. Medido: duas execuções do C0
        # tinham um resumo só, e uma delas era a de latência mediana de
        # 800 ms — passava pelo filtro de rádio por falta do dado em que
        # ele se baseia. Ausência de dado não pode ser tratada como
        # ausência de problema.
        cond = "sonda_incompleta"
    elif embb and embb[0] < EMBB_MBPS_MINIMO:
        cond = "radio_degradado"
    else:
        cond = "valida"

    # A política vem do próprio dado (`scenario_config`, emitido pelo
    # runner), não de janelas de tempo que eu teria de acertar à mão —
    # delimitar blocos por epoch já me fez consolidar 119 arquivos
    # quando eram 181.
    cfg = [e for e in eventos if e.get("event") == "scenario_config"]
    politica = cfg[0].get("policy") if cfg else None

    return {"arquivo": caminho.name, "eventos": eventos, "contadores": c,
            "condicao": cond, "latencias": latencias, "embb": embb,
            "politica": politica}


def tabela_desempenho(por_cenario: dict) -> str:
    linhas = ["### Desempenho por cenário", "",
              "Mediana entre execuções válidas. `N3` é a sonda de alta resolução no "
              "túnel (0,1 ms de piso); o fim a fim atravessa o rádio ZMQ, cujo piso é "
              "~54 ms e cuja cauda domina qualquer p99.", "",
              "| Cenário | n | N3 p50 | N3 p99 | URLLC fim a fim p50 | URLLC p95 | eMBB | mIoT perda |",
              "| --- | --- | --- | --- | --- | --- | --- | --- |"]
    for nome, pref in CENARIOS:
        runs = por_cenario.get(pref, [])
        if not runs:
            continue
        n3p50, n3p99, up50, up95, embb, miot = [], [], [], [], [], []
        for r in runs:
            s = [e for e in r["eventos"] if e.get("event") == "n3_latency_summary"]
            if s:
                n3p50.append(s[0]["rtt_p50_ms"]); n3p99.append(s[0]["rtt_p99_ms"])
            if r["latencias"]:
                up50.append(st.median(r["latencias"])); up95.append(pct(r["latencias"], .95))
            if r["embb"]:
                embb.append(r["embb"][0])
            m = [e["lost_percent"] for e in r["eventos"]
                 if e.get("event") == "throughput_probe_summary"
                 and e.get("label") == "miot" and e.get("lost_percent") is not None]
            if m:
                miot.append(m[0])
        med = lambda v: st.median(v) if v else float("nan")
        linhas.append(
            f"| {nome} | {len(runs)} | {med(n3p50):.3f} ms | {med(n3p99):.3f} ms | "
            f"{med(up50):.1f} ms | {med(up95):.1f} ms | {med(embb):.2f} Mbps | "
            f"{med(miot):.2f}% |")
    return "\n".join(linhas) + "\n"


def tabela_politicas(por_cenario: dict) -> str:
    """Compara risk-aware com EDF nos cenários que têm disputa.

    Só C4a e C4b rodam nas duas políticas, e isso é deliberado: sem
    disputa a fila tem no máximo uma tarefa e as duas políticas chegam à
    mesma ordem, então comparar nos outros cenários não mediria nada.
    """
    por_pol: dict[tuple, list] = defaultdict(list)
    for pref, runs in por_cenario.items():
        for r in runs:
            if r["politica"]:
                por_pol[(pref, r["politica"])].append(r)
    alvos = [(n, p) for n, p in CENARIOS
             if len({k[1] for k in por_pol if k[0] == p}) > 1]
    if not alvos:
        return ""

    linhas = ["### Risk-aware contra EDF, sob disputa", "",
              "Média entre execuções ± IC95. A política ordena TAREFAS; ela não "
              "muda quanta entropia se consome, e é por isso que o efeito aparece "
              "na latência da URLLC e não na contagem de PPK.", "",
              "| Cenário | Política | n | URLLC p50 | URLLC p95 | rebaixamentos | PPK obtido |",
              "| --- | --- | --- | --- | --- | --- | --- |"]
    for nome, pref in alvos:
        for pol in sorted({k[1] for k in por_pol if k[0] == pref}):
            runs = por_pol[(pref, pol)]
            p50 = [st.median(r["latencias"]) for r in runs]
            p95 = [pct(r["latencias"], .95) for r in runs]
            reb = [r["contadores"].get("rotation_downgraded", 0) for r in runs]
            ppk = [r["contadores"].get("ppk_fetched", 0) for r in runs]
            ic = lambda v: 1.96 * st.stdev(v) / len(v) ** 0.5 if len(v) > 1 else 0.0
            linhas.append(
                f"| {nome} | {pol} | {len(runs)} | {st.fmean(p50):.2f} ± {ic(p50):.2f} ms | "
                f"{st.fmean(p95):.1f} ± {ic(p95):.1f} ms | {st.median(reb):.0f} | "
                f"{st.median(ppk):.0f} |")
    return "\n".join(linhas) + "\n"


def tabela_rotacao(por_cenario: dict) -> str:
    linhas = ["### Economia de rotação e de entropia", "",
              "Mediana por execução de 300 s. `rebaixada` é a fatia que perdeu o PPK "
              "novo e renovou só o ML-KEM do ESP por falta de entropia.", "",
              "| Cenário | n | rekey de Child SA | reauth c/ PPK | PPK obtido | poço vazio | rebaixamentos |",
              "| --- | --- | --- | --- | --- | --- | --- |"]
    for nome, pref in CENARIOS:
        runs = por_cenario.get(pref, [])
        if not runs or pref in SEM_ORQUESTRADOR:
            continue
        g = lambda k: st.median([r["contadores"].get(k, 0) for r in runs])
        linhas.append(f"| {nome} | {len(runs)} | {g('child_rekey_end'):.0f} | "
                      f"{g('reauth_end'):.0f} | {g('ppk_fetched'):.0f} | "
                      f"{g('ppk_pool_empty'):.0f} | {g('rotation_downgraded'):.0f} |")
    return "\n".join(linhas) + "\n"


def tabela_entropia_por_fatia(por_cenario: dict) -> str:
    linhas = ["### Quem fica com o PPK sob escassez", "",
              "Soma sobre as execuções válidas. É a tabela que testa a tese: pela "
              "ordem de criticidade I > H > D a URLLC deveria manter o PPK e as "
              "outras fatias renovar só o ML-KEM.", "",
              "| Cenário | Fatia | PPK obtido | rebaixada | poço vazio |",
              "| --- | --- | --- | --- | --- |"]
    for nome, pref in CENARIOS:
        runs = por_cenario.get(pref, [])
        if not runs or pref in SEM_ORQUESTRADOR:
            continue
        obt, reb, vaz = Counter(), Counter(), Counter()
        for r in runs:
            for e in r["eventos"]:
                ev, fatia = e.get("event"), e.get("slice")
                if ev == "ppk_fetched":
                    obt[fatia] += 1
                elif ev == "rotation_downgraded":
                    reb[fatia] += 1
                elif ev == "ppk_pool_empty":
                    vaz[fatia] += 1
        for s in ("URLLC", "EMBB", "MIOT"):
            linhas.append(f"| {nome if s == 'URLLC' else ''} | {s} | {obt[s]} | "
                          f"{reb[s]} | {vaz[s]} |")
    return "\n".join(linhas) + "\n"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--desde", type=float, default=None,
                        help="só arquivos modificados depois deste epoch (delimita o bloco)")
    parser.add_argument("--ate", type=float, default=None)
    parser.add_argument("--saida", type=Path, default=None)
    args = parser.parse_args()

    por_cenario: dict[str, list] = defaultdict(list)
    procedencia: Counter = Counter()
    detalhe: dict[str, Counter] = defaultdict(Counter)

    for nome, pref in CENARIOS:
        for caminho in sorted(RESULTS_DIR.glob(f"{pref}-*.jsonl")):
            t = caminho.stat().st_mtime
            if args.desde and t < args.desde:
                continue
            if args.ate and t > args.ate:
                continue
            r = carrega(caminho, pref)
            procedencia[r["condicao"]] += 1
            detalhe[pref][r["condicao"]] += 1
            if r["condicao"] == "valida":
                por_cenario[pref].append(r)

    if not por_cenario:
        print("nenhuma execução válida no intervalo", file=sys.stderr)
        return 1

    cab = ["# Fase B — dados consolidados", "", "## Procedência das execuções", "",
           "| Cenário | válidas | descartadas | motivos |", "| --- | --- | --- | --- |"]
    for nome, pref in CENARIOS:
        d = detalhe[pref]
        if not d:
            continue
        desc = {k: v for k, v in d.items() if k != "valida"}
        cab.append(f"| {nome} | {d['valida']} | {sum(desc.values())} | "
                   f"{', '.join(f'{k}={v}' for k, v in sorted(desc.items())) or '—'} |")
    cab += ["", f"Total: **{procedencia['valida']} válidas** de "
            f"{sum(procedencia.values())}.", ""]

    texto = "\n".join(cab) + "\n" + "\n".join([
        tabela_desempenho(por_cenario),
        tabela_rotacao(por_cenario),
        tabela_entropia_por_fatia(por_cenario),
        tabela_politicas(por_cenario),
    ])
    if args.saida:
        args.saida.write_text(texto)
        print(f"escrito em {args.saida}")
    else:
        print(texto)
    return 0


if __name__ == "__main__":
    sys.exit(main())
