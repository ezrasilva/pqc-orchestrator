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
    """Lê um arquivo UMA VEZ, agrega o que as tabelas precisam e DESCARTA
    os eventos.

    **Por que não guardar os eventos.** A primeira versão retinha a lista
    completa de cada execução e cada tabela fazia a própria passagem. Com
    223 execuções de ~26 mil eventos são ~5,8 milhões de dicts vivos ao
    mesmo tempo, vários GB, e a tabela de isolamento sozinha fazia 18
    passagens (6 cenários × 3 marks) sobre tudo isso. Medido: a
    consolidação passou de 8 minutos para **quase 3 horas** e foi morta
    sem terminar.

    Agregar na leitura resolve as duas coisas de uma vez — memória
    constante por arquivo e uma passagem só.

    As latências ficam retidas (3 mil por execução) porque percentis
    exigem a amostra; o resto vira contador.
    """
    contadores: Counter = Counter()
    latencias: list[float] = []
    # Duracao de cada estagio de rotacao. Retidas porque percentil exige a
    # amostra, e sao poucas (~270 por execucao contra 3 mil latencias).
    duracoes: dict[str, list[float]] = defaultdict(list)
    embb: list[float] = []
    miot: list[float] = []
    n3: dict[str, float] = {}
    politica = None
    por_fatia: dict[str, Counter] = defaultdict(Counter)
    resumos_vazao = 0
    # Isolamento: último valor por mark (contador monotônico) e pico por
    # SPI. Somar o pico de CADA SPI e não o máximo entre eles — a rotação
    # cria dezenas de SPIs numa janela de 300 s.
    classificados: dict[str, int] = {}
    picos_spi: dict[str, dict[str, int]] = defaultdict(dict)
    marks_por_spi: dict[str, set] = defaultdict(set)

    for linha in caminho.open():
        linha = linha.strip()
        if not linha:
            continue
        try:
            e = json.loads(linha)
        except json.JSONDecodeError:
            continue  # linha truncada por interrupção; descarta a linha
        ev = e.get("event")
        contadores[ev] += 1

        if ev == "latency_sample":
            if e.get("rtt_ms") is not None:
                latencias.append(e["rtt_ms"])
        elif ev in ("child_rekey_end", "reauth_end", "ppk_fetch_end",
                    "ppk_install_end"):
            if e.get("duration_seconds") is not None:
                duracoes[ev[:-4]].append(e["duration_seconds"] * 1000.0)
        elif ev == "throughput_probe_summary":
            resumos_vazao += 1
            if e.get("label") == "embb":
                embb.append(e.get("mbps", 0.0))
            elif e.get("label") == "miot" and e.get("lost_percent") is not None:
                miot.append(e["lost_percent"])
        elif ev == "n3_latency_summary":
            n3 = {"p50": e.get("rtt_p50_ms"), "p99": e.get("rtt_p99_ms")}
        elif ev == "scenario_config":
            politica = e.get("policy")
        elif ev in ("ppk_fetched", "rotation_downgraded", "ppk_pool_empty"):
            por_fatia[e.get("slice")][ev] += 1
        elif ev == "classification_snapshot":
            m = e.get("mark")
            if m:
                classificados[m] = e.get("packets", 0)
        elif ev == "xfrm_snapshot":
            spi, m = e.get("spi"), e.get("mark")
            if spi and m:  # sem mark = SA de entrada deste lado
                marks_por_spi[spi].add(m)
                atual = picos_spi[m].get(spi, 0)
                picos_spi[m][spi] = max(atual, e.get("packets", 0))

    if not contadores.get("run_window_end"):
        cond = "incompleta"
    elif contadores.get("rotation_tick_failed"):
        cond = "tick_falhou"
    elif contadores.get("rotation_driver_stop_timeout") or contadores.get(
            "ppk_provider_stop_timeout"):
        cond = "thread_vazou"
    elif prefixo in SEM_ORQUESTRADOR and any(
            k and k.startswith(("rotation_", "ppk_", "reauth", "child_rekey"))
            for k in contadores):
        cond = "contaminada"
    elif not latencias:
        cond = "sem_trafego"
    elif resumos_vazao < 2:
        cond = "sonda_incompleta"
    elif embb and embb[0] < EMBB_MBPS_MINIMO:
        cond = "radio_degradado"
    else:
        cond = "valida"

    return {
        "arquivo": caminho.name, "contadores": contadores, "condicao": cond,
        "latencias": latencias, "duracoes": duracoes,
        "embb": embb, "miot": miot, "n3": n3,
        "politica": politica, "por_fatia": por_fatia,
        "classificados": classificados,
        "cifrados": {m: sum(d.values()) for m, d in picos_spi.items()},
        "spis": {m: len(d) for m, d in picos_spi.items()},
        "conflitos": sum(1 for ms in marks_por_spi.values() if len(ms) > 1),
    }


def _med(valores):
    return st.median(valores) if valores else float("nan")


def _ic(valores):
    return 1.96 * st.stdev(valores) / len(valores) ** 0.5 if len(valores) > 1 else 0.0


def tabela_desempenho(por_cenario: dict) -> str:
    linhas = ["### Desempenho por cenário", "",
              "Mediana entre execuções válidas. `N3` é a sonda de alta resolução no "
              "túnel (0,05 ms de piso); o fim a fim atravessa o rádio ZMQ, cujo piso é "
              "~55 ms e cuja cauda domina qualquer p99.", "",
              "| Cenário | n | N3 p50 | N3 p99 | URLLC p50 | URLLC p95 | eMBB | mIoT perda |",
              "| --- | --- | --- | --- | --- | --- | --- | --- |"]
    for nome, pref in CENARIOS:
        runs = por_cenario.get(pref, [])
        if not runs:
            continue
        linhas.append(
            f"| {nome} | {len(runs)} | "
            f"{_med([r['n3'].get('p50') for r in runs if r['n3']]):.3f} ms | "
            f"{_med([r['n3'].get('p99') for r in runs if r['n3']]):.3f} ms | "
            f"{_med([st.median(r['latencias']) for r in runs]):.1f} ms | "
            f"{_med([pct(r['latencias'], .95) for r in runs]):.1f} ms | "
            f"{_med([r['embb'][0] for r in runs if r['embb']]):.2f} Mbps | "
            f"{_med([r['miot'][0] for r in runs if r['miot']]):.2f}% |")
    return "\n".join(linhas) + "\n"


def tabela_rotacao(por_cenario: dict) -> str:
    linhas = ["### Economia de rotação e de entropia", "",
              "Mediana por execução de 300 s. `rebaixamentos` conta a fatia que perdeu "
              "o PPK novo e renovou só o ML-KEM do ESP por falta de entropia.", "",
              "| Cenário | n | rekey de Child SA | reauth c/ PPK | PPK obtido | poço vazio | rebaixamentos |",
              "| --- | --- | --- | --- | --- | --- | --- |"]
    for nome, pref in CENARIOS:
        runs = por_cenario.get(pref, [])
        if not runs or pref in SEM_ORQUESTRADOR:
            continue
        g = lambda k: _med([r["contadores"].get(k, 0) for r in runs])
        linhas.append(f"| {nome} | {len(runs)} | {g('child_rekey_end'):.0f} | "
                      f"{g('reauth_end'):.0f} | {g('ppk_fetched'):.0f} | "
                      f"{g('ppk_pool_empty'):.0f} | {g('rotation_downgraded'):.0f} |")
    return "\n".join(linhas) + "\n"


def tabela_entropia_por_fatia(por_cenario: dict) -> str:
    linhas = ["### Quem fica com o PPK sob escassez", "",
              "Soma sobre as execuções válidas. É a tabela que testa a tese: pela "
              "ordem de criticidade I > H > D a URLLC deveria manter o PPK e as "
              "outras fatias renovar só o ML-KEM.", "",
              "A contagem crua de `PPK obtido` **não** mede a alocação: uma "
              "fatia faminta re-tenta a cada tick (2,5 s) porque a reauth "
              "falhada não zera a idade da IKE_SA, então ela acumula "
              "tentativas e, por acumulá-las, acaba obtendo mais chaves que a "
              "URLLC — que tenta só a cada 30 s e acerta sempre. A métrica que "
              "testa a tese é a **taxa de sucesso**, que é independente do "
              "número de tentativas.", "",
              "| Cenário | Fatia | tentativas | PPK obtido | taxa | rebaixada | poço vazio |",
              "| --- | --- | --- | --- | --- | --- | --- |"]
    for nome, pref in CENARIOS:
        runs = por_cenario.get(pref, [])
        if not runs or pref in SEM_ORQUESTRADOR:
            continue
        for i, fatia in enumerate(("URLLC", "EMBB", "MIOT")):
            soma = lambda k: sum(r["por_fatia"].get(fatia, Counter()).get(k, 0)
                                 for r in runs)
            obtido, vazio = soma("ppk_fetched"), soma("ppk_pool_empty")
            tentativas = obtido + vazio
            taxa = f"{obtido / tentativas * 100:.1f}%" if tentativas else "—"
            linhas.append(f"| {nome if i == 0 else ''} | {fatia} | {tentativas} | "
                          f"{obtido} | {taxa} | {soma('rotation_downgraded')} | "
                          f"{vazio} |")
    return "\n".join(linhas) + "\n"


def tabela_politicas(por_cenario: dict) -> str:
    """Compara risk-aware com EDF nos cenários que têm disputa.

    Só C4a e C4b rodam nas duas políticas, e isso é deliberado: sem
    disputa a fila tem no máximo uma tarefa e as duas chegam à mesma
    ordem, então comparar nos outros cenários não mediria nada.
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
              "Média entre execuções ± IC95. A política ordena TAREFAS; ela não muda "
              "quanta entropia se consome, e é por isso que o efeito aparece na "
              "latência da URLLC e não na contagem de PPK.", "",
              "| Cenário | Política | n | URLLC p50 | URLLC p95 | rebaixamentos | PPK obtido |",
              "| --- | --- | --- | --- | --- | --- | --- |"]
    for nome, pref in alvos:
        for pol in sorted({k[1] for k in por_pol if k[0] == pref}):
            runs = por_pol[(pref, pol)]
            p50 = [st.median(r["latencias"]) for r in runs]
            p95 = [pct(r["latencias"], .95) for r in runs]
            linhas.append(
                f"| {nome} | {pol} | {len(runs)} | {st.fmean(p50):.2f} ± {_ic(p50):.2f} ms | "
                f"{st.fmean(p95):.1f} ± {_ic(p95):.1f} ms | "
                f"{_med([r['contadores'].get('rotation_downgraded', 0) for r in runs]):.0f} | "
                f"{_med([r['contadores'].get('ppk_fetched', 0) for r in runs]):.0f} |")
    return "\n".join(linhas) + "\n"


# Marks do `mangle` por fatia (ver lab/ipsec/apply-n3-slice-marks.sh).
MARK_POR_FATIA = {"0x10": "URLLC", "0x20": "EMBB", "0x30": "MIOT"}


def tabela_isolamento(por_cenario: dict) -> str:
    """Métrica B.3 — cada fatia só sai pela SA dela.

    O `classification_snapshot` conta pacotes no `mangle`, ANTES de
    cifrar, por mark de fatia; o `xfrm_snapshot` conta por SPI, DEPOIS de
    cifrar, e cada SA carrega o mark da fatia dela. Isolamento perfeito
    significa que os pacotes marcados para uma fatia aparecem só nas SAs
    com aquele mark, e em igual número.

    **A folga esperada não é zero.** A classificação conta antes de
    cifrar e a SA depois, então pacotes em trânsito no kernel no instante
    da leitura final aparecem num contador e não no outro. Investigar
    uma folga de 2-3% nesta campanha é o que revelou o poller a 0,5 s ser
    lento demais para a frequência de rotação; hoje roda a 0,1 s.

    O teste NEGATIVO da mesma propriedade é
    `evaluation/negative_teid_test.py`: esta tabela mostra que cada fatia
    sai pela SA dela, e o outro mostra que nada mais sai.
    """
    linhas = ["### Isolamento: cada fatia sai pela SA dela (B.3)", "",
              "`classificados` conta no `mangle` antes de cifrar; `cifrados` soma o "
              "pico de cada SPI com o mark da fatia, depois de cifrar. A folga vem de "
              "pacotes em trânsito entre os dois pontos de contagem.", "",
              "| Cenário | Fatia | classificados | cifrados | folga | SPIs | SPI com 2 marks |",
              "| --- | --- | --- | --- | --- | --- | --- |"]
    for nome, pref in CENARIOS:
        runs = por_cenario.get(pref, [])
        if not runs:
            continue
        for i, (mark, fatia) in enumerate(sorted(MARK_POR_FATIA.items())):
            cls = sum(r["classificados"].get(mark, 0) for r in runs)
            cif = sum(r["cifrados"].get(mark, 0) for r in runs)
            spis = sum(r["spis"].get(mark, 0) for r in runs)
            conf = sum(r["conflitos"] for r in runs)
            if not cls and not cif:
                continue
            folga = 100.0 * (cls - cif) / cls if cls else 0.0
            linhas.append(f"| {nome if i == 0 else ''} | {fatia} | {cls} | {cif} | "
                          f"{folga:+.2f}% | {spis} | {conf} |")
    linhas += ["", "`SPI com 2 marks` deve ser **zero**: um SPI que carregasse duas "
               "fatias seria vazamento de isolamento, não imprecisão de contagem.", ""]
    return "\n".join(linhas)


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
    janela = []
    if args.desde:
        janela.append(f"--desde {args.desde:.0f}")
    if args.ate:
        janela.append(f"--ate {args.ate:.0f}")
    cab += ["", f"Total: **{procedencia['valida']} válidas** de "
            f"{sum(procedencia.values())}.", ""]
    # Registrar a janela: sem isto o documento gerado não diz qual bloco
    # da campanha produziu os números, e `results/` acumula blocos.
    if janela:
        cab += [f"Janela: `{' '.join(janela)}`.", ""]

    texto = "\n".join(cab) + "\n" + "\n".join([
        tabela_desempenho(por_cenario),
        tabela_rotacao(por_cenario),
        tabela_entropia_por_fatia(por_cenario),
        tabela_politicas(por_cenario),
        tabela_isolamento(por_cenario),
    ])
    if args.saida:
        args.saida.write_text(texto)
        print(f"escrito em {args.saida}")
    else:
        print(texto)
    return 0


if __name__ == "__main__":
    sys.exit(main())
