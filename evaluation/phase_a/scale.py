#!/usr/bin/env python3
"""A.4 — escala: 3, 10 e 30 Child SAs fazendo rekey ao mesmo tempo.

**A pergunta que esta medição responde.** A Fase B rotaciona três fatias
(URLLC, eMBB, mIoT) com prazos diferentes, e o `rotation_driver` pode
enfileirar as três na mesma janela. Se o custo de rekey crescer
superlinearmente com o número de Child SAs simultâneas, a URLLC — que
tem o prazo mais curto — paga a fila das outras duas. Daí medir 3, 10 e
30: 3 é a Fase B como ela é, 10 e 30 mostram para onde a curva vai se a
proposta escalar para mais fatias ou mais nós.

**Por que as Child SAs ficam sob UMA IKE_SA.** É assim que a Fase B
funciona (uma associação por par de nós, uma Child SA por fatia) e é o
caso em que a contenção importa: as N Child SAs disputam o mesmo
task manager e a mesma janela de mensagens do charon. N IKE_SAs
separadas não teriam essa contenção e mediriam outra coisa.

**Endereços.** Cada Child SA precisa de um par de traffic selectors
distinto, senão o kernel colapsa as políticas (achado da campanha
anterior: TS sobreposto faz o narrowing reduzir tudo a dois hosts). Por
isso o módulo ADICIONA endereços /32 temporários aos dois netns —
172.19.1.<i> na CU e 172.19.2.<i> na borda — e os remove no fim. A faixa
172.19.0.0/16 foi escolhida por estar livre nesta VM (o 5GC usa
172.18.0.0/16, a bridge do Docker 172.17.0.0/16, a QKDN 172.20.0.0/16 e
a core-net 10.98.0.0/24).
"""

from __future__ import annotations

import subprocess
import threading
import time

from evaluation.instrumentation import emit

CU_IF, EDGE_IF = "veth-cu-n2", "veth-edge-cu"
CU_PREFIX, EDGE_PREFIX = "172.19.1", "172.19.2"


def cu_addr(i: int) -> str:
    return f"{CU_PREFIX}.{i}"


def edge_addr(i: int) -> str:
    return f"{EDGE_PREFIX}.{i}"


def _ip(netns: str, *args: str, check: bool = True) -> subprocess.CompletedProcess:
    return subprocess.run(["ip", "netns", "exec", netns, "ip", *args],
                          capture_output=True, text=True, check=check)


def setup_addresses(n: int, cu_netns: str, edge_netns: str) -> None:
    """Adiciona os /32 de teste. Idempotente — `check=False` porque
    readicionar um endereço existente é erro no `ip`, e repetir a
    execução da A.4 é o caso normal."""
    for i in range(1, n + 1):
        _ip(cu_netns, "addr", "add", f"{cu_addr(i)}/32", "dev", CU_IF, check=False)
        _ip(edge_netns, "addr", "add", f"{edge_addr(i)}/32", "dev", EDGE_IF, check=False)


def teardown_addresses(n: int, cu_netns: str, edge_netns: str) -> None:
    for i in range(1, n + 1):
        _ip(cu_netns, "addr", "del", f"{cu_addr(i)}/32", "dev", CU_IF, check=False)
        _ip(edge_netns, "addr", "del", f"{edge_addr(i)}/32", "dev", EDGE_IF, check=False)


def children_block(n: int, conn_name: str, esp_proposal: str,
                   mirror: bool) -> str:
    """Bloco `children` com N Child SAs, cada uma com seu par de TS.

    `mirror` troca local/remote para o lado da borda — mesmo cuidado que
    custou 30 iterações vazias na campanha anterior, quando o espelho
    trocava os endereços mas NÃO os traffic selectors.
    """
    partes = []
    for i in range(1, n + 1):
        local, remoto = cu_addr(i), edge_addr(i)
        if mirror:
            local, remoto = remoto, local
        partes.append(f"""            {conn_name}-{i} {{
                local_ts = {local}/32
                remote_ts = {remoto}/32
                esp_proposals = {esp_proposal}
                mode = tunnel
                start_action = none
            }}""")
    return "\n".join(partes)


def _rekey_one(nsenter_cmd: list[str], nome: str, resultados: list, trava: threading.Lock) -> None:
    t0 = time.monotonic()
    res = subprocess.run([*nsenter_cmd, "swanctl", "--rekey", "--child", nome],
                         capture_output=True, text=True)
    dur = time.monotonic() - t0
    with trava:
        resultados.append({"child": nome, "seconds": dur, "ok": res.returncode == 0,
                           "stderr": res.stderr.strip()[-200:] or None})


def rekey_all_concurrently(nsenter_cmd: list[str], conn_name: str, n: int) -> list[dict]:
    """Dispara o rekey das N Child SAs em paralelo.

    **Por que threads e não um laço sequencial**: um laço mediria N
    rekeys isolados somados, que é justamente o que a A.4 quer contrastar
    com o caso simultâneo. A contenção só aparece se os pedidos chegarem
    ao charon ao mesmo tempo — por isso uma barreira antes do disparo.
    """
    resultados: list[dict] = []
    trava = threading.Lock()
    barreira = threading.Barrier(n)

    def alvo(i: int) -> None:
        barreira.wait()  # todos largam juntos
        _rekey_one(nsenter_cmd, f"{conn_name}-{i}", resultados, trava)

    threads = [threading.Thread(target=alvo, args=(i,)) for i in range(1, n + 1)]
    t0 = time.monotonic()
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=180)
    total = time.monotonic() - t0

    for r in resultados:
        r["wall_total_seconds"] = total
    return resultados


def emit_scale_result(profile_name: str, n: int, repeticao: int,
                      resultados: list[dict]) -> None:
    duracoes = sorted(r["seconds"] for r in resultados)
    def p(q: float) -> float:
        if not duracoes:
            return float("nan")
        return duracoes[min(len(duracoes) - 1, int(round(q * (len(duracoes) - 1))))]
    emit(
        "phase_a_scale",
        profile=profile_name,
        n_children=n,
        repetition=repeticao,
        n_ok=sum(1 for r in resultados if r["ok"]),
        wall_total_seconds=resultados[0]["wall_total_seconds"] if resultados else None,
        per_child_p50_seconds=p(0.50),
        per_child_p95_seconds=p(0.95),
        per_child_max_seconds=duracoes[-1] if duracoes else None,
        per_child_min_seconds=duracoes[0] if duracoes else None,
        falhas=[r["child"] for r in resultados if not r["ok"]] or None,
    )
