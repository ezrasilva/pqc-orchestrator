"""Fórmula de risco e as três políticas de escalonamento (ver
../docs/ARQUITETURA-ORQUESTRADOR.md seção 2):

    risk(i) = -slack(i)/estimated_cost(i) + slice_bonus(i) + interface_bonus(i) + aging(i)

`slack(i)` é `deadline - now` em segundos (negativo = já atrasada — nesse
caso `-slack(i)` fica positivo e aumenta o risco, o que é o comportamento
certo). Tarefas sem deadline usam `slack=0` por convenção do chamador (ver
EnqueueTaskRequest) — isso faz a urgência vir inteiramente de
`slice_bonus`/`interface_bonus`/`aging`, não da parcela de slack.

`slice_bonus`/`interface_bonus` são constantes de desempate, não
recalculadas — os valores abaixo são a decisão de design desta
implementação (a arquitetura só diz "favorece URLLC"/"diferencia F1 de
N2/N3 se a política pedir", sem fixar magnitude):

- slice_bonus: a ORDEM vem do vetor de criticidade (`criticality.py`),
  pelo desempate lexicográfico I > H > D que o documento da campanha
  declara — hoje **URLLC > mIoT > eMBB**. As magnitudes seguem sendo
  constantes de desempate desta implementação, que é o que a
  arquitetura deixa aberto; o que deixou de ser escolhido à mão é a
  ordem.

  **Era URLLC > eMBB > mIoT**, herdado da seção 5.1 do
  ARQUITETURA-PROTOTIPO-COMPLETA.md, anterior ao vetor de criticidade. A
  divergência apareceu nos dados da Fase B: no C3 a eMBB levou 464
  chaves de QKD contra 336 da mIoT, o inverso do que o modelo prevê.
  eMBB e mIoT empatam em I (média) e o desempate é H, onde a mIoT é alta
  (telemetria com horizonte longo, mais exposta a harvest-now-decrypt-
  later) contra baixa da eMBB.
- interface_bonus: N3 > N2 > F1 — N3 é a única interface realmente
  diferenciada por fatia (carrega o dado de usuário até o núcleo); N2 é
  controle, compartilhado entre todas as fatias, sem componente PQC
  diferenciado; F1 é midhaul intra-gNB, superfície de exposição menor
  ainda.

`aging` cresce linearmente com o tempo na fila (`aging_rate` por segundo)
— evita starvation de tarefas de baixo risco (ver comentário no
scheduler.proto).
"""

from __future__ import annotations

from typing import Callable

from criticality import ordem_de_prioridade
from scheduler.models import InterfaceType, SchedulingPolicy, SliceType, Task, utcnow

def _slice_bonus() -> dict[SliceType, float]:
    """Deriva o bônus da ordem de prioridade do vetor de criticidade.

    Escrever o dicionário à mão era o que permitiu a divergência: se os
    níveis H/I/D de uma fatia mudarem no documento, uma tabela fixa fica
    errada em silêncio. Derivando, o escalonador acompanha o modelo.

    As magnitudes (2,0 / 1,0 / 0,0) são espaçamento de desempate, não
    pesos entre as dimensões de criticidade — essas já foram resolvidas
    lexicograficamente antes de chegar aqui.
    """
    ordem = ordem_de_prioridade()
    por_nome = {s.value: s for s in SliceType}
    return {por_nome[nome]: float(len(ordem) - 1 - i)
            for i, nome in enumerate(ordem) if nome in por_nome}


SLICE_BONUS: dict[SliceType, float] = _slice_bonus()

INTERFACE_BONUS: dict[InterfaceType, float] = {
    InterfaceType.N3: 0.5,
    InterfaceType.N2: 0.2,
    InterfaceType.F1: 0.0,
    InterfaceType.FRONTHAUL: 0.0,  # reservado, ver kms/models.py
}

AGING_RATE_PER_SECOND = 0.01  # +1.0 de risco a cada ~100s esperando na fila


def compute_risk(task: Task, *, now=None) -> float:
    now = now or utcnow()
    seconds_in_queue = max(0.0, (now - task.enqueued_at).total_seconds())
    aging = AGING_RATE_PER_SECOND * seconds_in_queue

    cost = task.estimated_cost_seconds
    urgency = -task.slack_seconds / cost if cost > 0 else 0.0

    return (
        urgency
        + SLICE_BONUS.get(task.slice, 0.0)
        + INTERFACE_BONUS.get(task.interface, 0.0)
        + aging
    )


def _effective_deadline_key(task: Task):
    """Pra weighted-EDF: tarefas com deadline vêm primeiro, ordenadas pela
    mais próxima; tarefas sem deadline vêm depois, ordenadas por FIFO
    entre si (ver docstring do módulo)."""
    if task.deadline is not None:
        return (0, task.deadline)
    return (1, task.enqueued_at)


# Cada política retorna a chave de ordenação (menor primeiro = mais
# prioritária) pra usar dentro de uma classe de prioridade já fixada
# (EMERGENCY > CRITICAL > NORMAL continua valendo sempre, ver
# queue.py). `risk_score` já deve estar atualizado antes de chamar isto
# (SchedulerCore faz isso no enqueue e a cada leitura da fila).
_POLICY_SORT_KEYS: dict[SchedulingPolicy, Callable[[Task], object]] = {
    SchedulingPolicy.RISK_AWARE: lambda t: -t.risk_score,
    SchedulingPolicy.WEIGHTED_EDF: _effective_deadline_key,
    SchedulingPolicy.FIFO: lambda t: t.enqueued_at,
}


def sort_key(policy: SchedulingPolicy, task: Task):
    return _POLICY_SORT_KEYS[policy](task)
