#!/usr/bin/env python3
"""A.5 — microbenchmark de KEM via liboqs.

**Por que esta medição existe separada da A.1.** A A.1 mostrou que o
tempo de handshake quase não varia entre perfis (p50 de 29 a 32 ms para
x25519, ML-KEM-512/768/1024 e híbrido): o custo de CPU do KEM desaparece
no ruído de agendamento do charon. Isso é um resultado — mas é um
resultado que não dá para *reportar como custo do KEM*, porque a medição
não separa as duas coisas. A A.5 mede o KEM isolado, em userspace, sem
charon no meio:

* dá o custo de CPU limpo, para mostrar quantitativamente **por que** ele
  desaparece na A.1 (dezenas de µs contra dezenas de ms);
* cobre os KEMs do catálogo que **o strongSwan não suporta** (HQC,
  FrodoKEM, BIKE…), que não dão para medir pela A.1 de jeito nenhum;
* dá os tamanhos de chave pública e de ciphertext, que são a variável
  que de fato explica a A.1 — lá os bytes no fio variaram 4×.

**O que NÃO se pode concluir daqui**: que um KEM mais rápido em liboqs
produz handshake mais rápido. A A.1 já mostrou que não produz nesta
bancada. As duas medições são complementares, e a tabela final precisa
das duas colunas (µs de CPU, bytes no fio) porque é a segunda que manda.
"""

from __future__ import annotations

import argparse
import statistics as st
import sys
import time
import uuid
from pathlib import Path

from evaluation import instrumentation
from evaluation.instrumentation import emit
from evaluation.phase_a.bench_n3 import registra_carga

RESULTS_DIR = Path(__file__).resolve().parent.parent / "results_phase_a"

# KEMs que o strongSwan 6.0.4 desta VM negocia como `ke`/`ke1_`,
# confirmado com `swanctl --list-algs`. Serve para marcar, na tabela
# final, quais linhas são mediáveis também pela A.1 (fim a fim) e quais
# só existem aqui.
STRONGSWAN_KEMS = {
    "ML-KEM-512": "mlkem512",
    "ML-KEM-768": "mlkem768",
    "ML-KEM-1024": "mlkem1024",
}


def _percentis(valores: list[float]) -> dict:
    ordenados = sorted(valores)
    def p(q: float) -> float:
        return ordenados[min(len(ordenados) - 1, int(round(q * (len(ordenados) - 1))))]
    return {
        "p50_us": p(0.50), "p95_us": p(0.95), "p99_us": p(0.99),
        "min_us": ordenados[0], "max_us": ordenados[-1],
        "mean_us": st.fmean(ordenados),
        "stdev_us": st.stdev(ordenados) if len(ordenados) > 1 else 0.0,
    }


def bench_kem(nome: str, repeticoes: int, warmup: int) -> dict | None:
    """Mede keygen, encaps e decaps de um KEM.

    Cada operação é medida **em iterações separadas**, não num pipeline
    único: medir o trio junto esconderia qual das três domina, e para a
    negociação IKE importa saber — o initiator paga keygen+decaps e o
    responder paga encaps, então um KEM assimétrico pesa diferente nas
    duas pontas.
    """
    import oqs

    try:
        with oqs.KeyEncapsulation(nome) as kem:
            detalhes = kem.details
            # Warm-up descartado: a primeira chamada paga alocação de
            # buffers e aquecimento de cache, e entraria como outlier no
            # p99 sem representar o regime.
            for _ in range(warmup):
                pk = kem.generate_keypair()
                ct, _ = kem.encap_secret(pk)
                kem.decap_secret(ct)

            t_keygen, t_encaps, t_decaps = [], [], []
            for _ in range(repeticoes):
                t0 = time.perf_counter_ns()
                pk = kem.generate_keypair()
                t1 = time.perf_counter_ns()
                t_keygen.append((t1 - t0) / 1000)

                t0 = time.perf_counter_ns()
                ct, ss_a = kem.encap_secret(pk)
                t1 = time.perf_counter_ns()
                t_encaps.append((t1 - t0) / 1000)

                t0 = time.perf_counter_ns()
                ss_b = kem.decap_secret(ct)
                t1 = time.perf_counter_ns()
                t_decaps.append((t1 - t0) / 1000)

                # Correção: um KEM que devolve segredos diferentes nas
                # duas pontas estaria quebrado, e o tempo dele não
                # significaria nada. Verificar é barato.
                if ss_a != ss_b:
                    return {"kem": nome, "erro": "segredo compartilhado divergente"}
    except Exception as exc:  # KEM habilitado na build mas indisponível
        return {"kem": nome, "erro": f"{type(exc).__name__}: {exc}"}

    return {
        "kem": nome,
        "nist_level": detalhes.get("claimed_nist_level"),
        "ind_cca": detalhes.get("is_ind_cca"),
        "public_key_bytes": detalhes.get("length_public_key"),
        "secret_key_bytes": detalhes.get("length_secret_key"),
        "ciphertext_bytes": detalhes.get("length_ciphertext"),
        "shared_secret_bytes": detalhes.get("length_shared_secret"),
        "strongswan_proposal": STRONGSWAN_KEMS.get(nome),
        "keygen": _percentis(t_keygen),
        "encaps": _percentis(t_encaps),
        "decaps": _percentis(t_decaps),
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--repetitions", type=int, default=100)
    parser.add_argument("--warmup", type=int, default=5)
    parser.add_argument("--kems", default="all",
                        help="'all' para todos os habilitados na liboqs, ou lista "
                             "separada por vírgula com os nomes exatos")
    args = parser.parse_args()

    import oqs

    disponiveis = oqs.get_enabled_kem_mechanisms()
    if args.kems == "all":
        alvos = list(disponiveis)
    else:
        alvos = [k.strip() for k in args.kems.split(",")]
        if faltando := [k for k in alvos if k not in disponiveis]:
            parser.error(f"KEM não habilitado na liboqs: {faltando}")

    RESULTS_DIR.mkdir(parents=True, exist_ok=True)
    run_id = f"phaseA-kem-{uuid.uuid4().hex[:8]}"
    instrumentation.configure(RESULTS_DIR / f"{run_id}.jsonl", run_id)
    print(f"run_id={run_id}  liboqs={oqs.oqs_version()}  KEMs={len(alvos)}")

    emit("phase_a_kem_env", liboqs_version=oqs.oqs_version(),
         repetitions=args.repetitions, warmup=args.warmup, n_kems=len(alvos))
    # Mesma razão do `bench_n3.py`: sem registrar a carga não há como
    # confiar na medição depois. Medido, este microbenchmark infla 3× sob
    # `load` 18 e chega a dar ML-KEM-1024 mais rápido que o 768 —
    # fisicamente impossível, e um bom detector de condição inutilizável.
    registra_carga("inicio")

    try:
        for nome in alvos:
            res = bench_kem(nome, args.repetitions, args.warmup)
            if res is None:
                continue
            emit("phase_a_kem", **res)
            if "erro" in res:
                print(f"  {nome:<28} ERRO: {res['erro']}")
            else:
                print(f"  {nome:<28} keygen {res['keygen']['p50_us']:>9.1f} µs  "
                      f"encaps {res['encaps']['p50_us']:>9.1f} µs  "
                      f"decaps {res['decaps']['p50_us']:>9.1f} µs  "
                      f"pk {res['public_key_bytes']:>6} B  ct {res['ciphertext_bytes']:>6} B")
    finally:
        instrumentation.reset()

    print(f"\nResultados em {RESULTS_DIR / (run_id + '.jsonl')}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
