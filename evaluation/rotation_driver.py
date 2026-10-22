"""Laço de decisão de rotação contínuo — generaliza
`orchestrator/scheduler/live_demo.py` (que fazia isso uma vez só, pra
demonstrar a Fase 5) pra rodar em background durante a janela de coleta
de um cenário inteiro (ver CENARIOS-TESTE-AVALIACAO.md). A cada
`check_interval_seconds`, lê a idade real das SAs N3, decide o que
venceu e enfileira — usado pelos Cenários 2/3/4 (não pelo 0, sem IPsec;
nem pelo 1, que tem seu próprio laço em scenario1_static_pqc.py).

**Dois níveis de rotação, não um.** A arquitetura SAPQ-IPsec separa:

| Tarefa | Prazo | O que renova | Custo medido na Fase A |
| --- | --- | --- | --- |
| `REKEY_CHILD` | `Tr_child` | chaves do ESP, com ML-KEM novo | **zero** perda de pacote |
| `REAUTH_PPK` | `Tr_ppk` | PPK vindo da QKD (exige reauth) | ~1,8 ms a 163 ms |

A versão anterior deste módulo tinha um único `TaskType.ROTATE` e
enfileirava as três fatias **a cada tick de 10 s, incondicionalmente** —
a idade entrava só como `slack_seconds` no cálculo de risco. Isso
produzia duas distorções graves na medição:

1. **rotacionava muito mais que o Tr de qualquer fatia.** Com tick de
   10 s, a URLLC era rotacionada a cada 10 s quando seu `Tr_child` é
   12 s e o `Tr_ppk` é 30 s; a mIoT, cujo `Tr_ppk` é 180 s, também era
   rotacionada a cada 10 s. O consumo de QKD medido não tinha relação
   com o modelo `Σ k / Tr_ppk,i ≤ R_qkd` que a campanha quer avaliar;
2. **pagava sempre o caminho caro.** Toda rotação era um reauth, mesmo
   quando só o material do ESP havia vencido — justamente a confusão que
   a Fase A mostrou custar três ordens de grandeza.

Agora o enfileiramento é **condicionado à idade**: uma fatia só entra na
fila quando a idade da SA correspondente passa do seu prazo. A idade da
Child SA governa o `REKEY_CHILD`, a da IKE_SA governa o `REAUTH_PPK` —
são duas idades distintas, lidas de linhas diferentes do `swanctl`.

**A idade sozinha não basta, e isso foi medido.** O portão de idade
pressupõe que a tentativa zere a idade que ele lê — o que só vale quando
ela dá certo. Uma reauth que falha por escassez de QKD não reautentica
nada, logo não mexe em `established Ns ago`, e o portão continua aberto
no tick seguinte, e no próximo, até o fim da execução. Medido na
campanha v2 (intervalos entre `ppk_fetch_start` num C3 de 300 s):

| Fatia | tentativas | intervalo | o que o intervalo é |
| --- | --- | --- | --- |
| URLLC | 10 | 29,9 s | o próprio `Tr_ppk` — acerta e zera a idade |
| eMBB | 104 | 2,5 s | o intervalo do tick |
| mIoT | 72 | 2,5 s | o intervalo do tick |

Duas consequências. A de comportamento: uma fatia sem entropia bate no
KMS 40× mais que o projetado, o que nenhuma arquitetura descreve. A de
medição, pior: por acumular tentativas, a mIoT obtinha **mais** chaves
que a URLLC em números absolutos (589 contra 260), o que inverte a
leitura da tese sem que nada no mecanismo esteja priorizando a mIoT.

Daí o segundo portão, por **tempo desde a última tentativa**: ver
`_pode_tentar_ppk`.
"""

from __future__ import annotations

import re
import subprocess
import threading
import time
import traceback
from typing import NamedTuple

from evaluation.collectors.resource import find_charon_pid
from evaluation.instrumentation import emit
from kms.models import InterfaceType, SliceType
from scheduler.models import EnqueueTaskRequest
from scheduler.models import InterfaceType as SchedInterfaceType
from scheduler.models import SliceType as SchedSliceType
from scheduler.models import TaskPriority, TaskType

# Prazos de rotação por fatia, em segundos. Valores fixados em 14/10
# (ver docs/CAMPANHA-SAPQ-IPSEC.md, "Valores fixados").
#
# **Escala de teste, fator 1/10.** Os prazos reais (Tr_child de 120/300/
# 600 s e Tr_ppk de 300/900/1800 s) não cabem numa janela de coleta de
# 300 s: a mIoT não rotacionaria nenhuma vez. Os testes usam 1/10
# mantendo as RAZÕES entre fatias, que é o que o modelo de contenção
# depende. O artigo tem de declarar essa escala.
TR_CHILD_SECONDS: dict[SliceType, float] = {
    SliceType.URLLC: 12.0,
    SliceType.EMBB: 30.0,
    SliceType.MIOT: 60.0,
}
TR_PPK_SECONDS: dict[SliceType, float] = {
    SliceType.URLLC: 30.0,
    SliceType.EMBB: 90.0,
    SliceType.MIOT: 180.0,
}
# Os reais, só para registro e para o fator de escala ser auditável.
TR_CHILD_REAL_SECONDS: dict[SliceType, float] = {
    SliceType.URLLC: 120.0, SliceType.EMBB: 300.0, SliceType.MIOT: 600.0,
}
TR_PPK_REAL_SECONDS: dict[SliceType, float] = {
    SliceType.URLLC: 300.0, SliceType.EMBB: 900.0, SliceType.MIOT: 1800.0,
}

# Custo estimado que o scheduler usa no cálculo de risco. O reauth é
# mais caro que o rekey de Child SA — medido na Fase A: ~10 ms de
# caminho crítico (busca do PPK no poço + instalação + reauth) contra
# ~2,4-3,2 ms do rekey de Child SA.
ESTIMATED_REKEY_CHILD_COST_SECONDS = 0.005
ESTIMATED_REAUTH_PPK_COST_SECONDS = 0.015

CONN_NAME: dict[SliceType, str] = {
    SliceType.URLLC: "n3-urllc-cu-edge",
    SliceType.EMBB: "n3-embb-cu-edge",
    SliceType.MIOT: "n3-miot-cu-edge",
}

_IDADE_CHILD_RE = re.compile(r"installed (\d+)s ago")
_IDADE_IKE_RE = re.compile(r"established (\d+)s ago")


class IdadesSa(NamedTuple):
    """Duas idades, porque os dois prazos olham para SAs diferentes: o
    `Tr_child` para a Child SA (material do ESP) e o `Tr_ppk` para a
    IKE_SA (onde o PPK entra, no IKE_AUTH)."""
    ike_seconds: float
    child_seconds: float | None


def _read_sa_ages(charon_pid: int) -> dict[SliceType, IdadesSa]:
    """Lê as duas idades por fatia do `swanctl --list-sas`.

    O formato distingue os dois níveis pela INDENTAÇÃO: a IKE_SA começa
    na coluna 0 e traz `established Ns ago`; a Child SA vem indentada em
    2 espaços dentro dela e traz `installed Ns ago`. A versão anterior
    desta função lia só `installed` e por isso não tinha como separar os
    dois prazos.
    """
    result = subprocess.run(
        ["nsenter", f"--mount=/proc/{charon_pid}/ns/mnt", f"--net=/proc/{charon_pid}/ns/net",
         "swanctl", "--list-sas"],
        capture_output=True, text=True,
    )
    idades: dict[SliceType, IdadesSa] = {}
    for slice, conn_name in CONN_NAME.items():
        # Bloco da IKE_SA: da linha sem indentação que abre esta conexão
        # até a próxima linha sem indentação (ou o fim).
        bloco = re.search(
            rf"^{re.escape(conn_name)}: #.*?(?=^\S|\Z)",
            result.stdout, re.MULTILINE | re.DOTALL,
        )
        if not bloco:
            continue
        texto = bloco.group(0)
        m_ike = _IDADE_IKE_RE.search(texto)
        if not m_ike:
            continue
        m_child = _IDADE_CHILD_RE.search(texto)
        idades[slice] = IdadesSa(
            ike_seconds=float(m_ike.group(1)),
            child_seconds=float(m_child.group(1)) if m_child else None,
        )
    return idades


class RotationDriver:
    def __init__(self, smo, scheduler, netns: str = "cu-ns",
                 check_interval_seconds: float = 2.0,
                 tr_child: dict[SliceType, float] | None = None,
                 tr_ppk: dict[SliceType, float] | None = None):
        """O intervalo cai de 10 s para 2 s porque o enfileiramento agora
        é condicionado à idade: o tick é só uma AMOSTRAGEM dos prazos, e
        um tick de 10 s contra um `Tr_child` de 12 s daria um erro de
        quantização de até 83%. Com 2 s o erro cai para ~17%, e ticks
        que não vencem nada custam apenas uma leitura do `swanctl`.

        Os prazos são injetáveis para o C4a poder apertá-los sem mexer
        no módulo."""
        self._smo = smo
        self._scheduler = scheduler
        self._netns = netns
        self._interval = check_interval_seconds
        self._tr_child = tr_child or TR_CHILD_SECONDS
        self._tr_ppk = tr_ppk or TR_PPK_SECONDS
        self._stop = threading.Event()
        self._thread: "threading.Thread | None" = None
        # Relógio do recuo: quando cada fatia tentou renovar PPK pela
        # última vez, com ou sem sucesso. `monotonic` porque é intervalo,
        # não instante — não pode andar para trás com ajuste de relógio.
        self._ultima_tentativa_ppk: dict[SliceType, float] = {}
        # Fatias que já anunciaram que estão recuando. Serve só para não
        # emitir um evento por tick: o anúncio é por janela de recuo.
        self._recuo_anunciado: set[SliceType] = set()

    def _enfileira(self, slice: SliceType, tipo: TaskType, prazo: float,
                   idade: float, custo: float) -> None:
        # `slack` negativo = atrasado. Mantém a semântica que o scheduler
        # já usava (prazo - idade), então quanto mais atrasada a fatia,
        # maior o risco calculado.
        folga = prazo - idade
        self._scheduler.enqueue_task(
            EnqueueTaskRequest(
                slice=SchedSliceType(slice.value),
                interface=SchedInterfaceType.N3,
                task_type=tipo,
                priority=TaskPriority.NORMAL,
                slack_seconds=folga,
                estimated_cost_seconds=custo,
                reason=f"{tipo.value}: idade {idade:.0f}s / prazo {prazo:.0f}s",
            )
        )
        emit("rotation_enqueued", slice=slice.value, task_type=tipo.value,
             age_seconds=idade, deadline_seconds=prazo, slack_seconds=folga)

    def _pode_tentar_ppk(self, slice: SliceType, tr_ppk: float) -> bool:
        """Segundo portão: só tenta renovar PPK se já passou `Tr_ppk`
        desde a ÚLTIMA TENTATIVA, não desde o último sucesso.

        **Por que o período e não um recuo exponencial.** O que a
        arquitetura especifica é "a fatia renova o PPK a cada `Tr_ppk`";
        se a entropia não estiver lá, ela passa aquele período renovando
        só o ML-KEM do ESP e tenta de novo no período seguinte. Um recuo
        exponencial faria a fatia tentar MENOS que o projetado depois de
        uma sequência de falhas, inclusive depois de a entropia voltar —
        atrasaria a recuperação, que é o oposto do que se quer. O período
        é o teto natural, e é o único valor que não precisa de
        justificativa separada no artigo.

        **Por que isto não é redundante com o portão de idade.** Os dois
        concordam quando a tentativa dá certo (o sucesso zera a idade da
        IKE_SA, e `Tr_ppk` se passou desde a tentativa). Eles divergem
        exatamente no caso que importa: a tentativa que falha deixa a
        idade intacta, e só este portão a segura.
        """
        ultima = self._ultima_tentativa_ppk.get(slice)
        if ultima is None:
            return True  # primeira tentativa da execução
        desde = time.monotonic() - ultima
        if desde >= tr_ppk:
            return True
        if slice not in self._recuo_anunciado:
            # Uma vez por janela, não uma vez por tick: anunciar a cada
            # tick repetiria o próprio volume que este portão corta.
            self._recuo_anunciado.add(slice)
            emit("ppk_retry_deferred", slice=slice.value,
                 seconds_since_attempt=round(desde, 2), tr_ppk_seconds=tr_ppk,
                 reason="tentativa anterior não renovou o PPK; aguarda o período")
        return False

    def _tick(self) -> None:
        charon_pid = find_charon_pid(self._netns)
        if charon_pid is None:
            return
        for slice, idades in _read_sa_ages(charon_pid).items():
            # Reauth primeiro, de propósito: ele recria a Child SA, então
            # enfileirar os dois no mesmo tick faria o rekey de Child SA
            # rodar sobre uma SA que a reauth acabou de substituir —
            # trabalho duplicado e, pior, um evento de rotação que a
            # análise contaria como se tivesse vencido por idade.
            tr_ppk = self._tr_ppk[slice]
            if idades.ike_seconds >= tr_ppk and self._pode_tentar_ppk(slice, tr_ppk):
                self._ultima_tentativa_ppk[slice] = time.monotonic()
                self._recuo_anunciado.discard(slice)
                self._enfileira(slice, TaskType.REAUTH_PPK, tr_ppk,
                                idades.ike_seconds,
                                ESTIMATED_REAUTH_PPK_COST_SECONDS)
                # O `continue` aqui é o que evita o trabalho duplicado —
                # mas quando a reauth FALHA por escassez de QKD ele
                # deixaria a fatia sem rotação nenhuma. Esse caso é
                # tratado no dreno, não aqui: ver `_drena`.
                continue

            # Sem `continue` quando o recuo segura a tentativa, **de
            # propósito**: durante a janela de recuo não há tentativa,
            # logo não há falha, logo `_drena` não rebaixa — e sem esta
            # queda a fatia ficaria sem rotação NENHUMA pela janela
            # inteira, que é o defeito que o rebaixamento existe para
            # evitar. Aqui ela simplesmente rotaciona o ESP pela idade,
            # que é o nível barato ao qual seria rebaixada de todo jeito.

            tr_child = self._tr_child[slice]
            if idades.child_seconds is not None and idades.child_seconds >= tr_child:
                self._enfileira(slice, TaskType.REKEY_CHILD, tr_child,
                                idades.child_seconds,
                                ESTIMATED_REKEY_CHILD_COST_SECONDS)

        self._drena(_read_sa_ages(charon_pid))

    def _drena(self, idades: dict[SliceType, IdadesSa]) -> None:
        """Processa a fila e, quando uma reauth falha por escassez de
        QKD, cai para o nível barato na MESMA passagem.

        **Por que o rebaixamento existe.** Medido ao vivo (17/10): com o
        poço de PPK vazio, eMBB e mIoT re-enfileiravam reauth a cada
        tick e, por causa do `continue` do `_tick`, **nunca chegavam ao
        rekey de Child SA** — uma fatia sem QKD parava de rotacionar
        também o material do ESP. É o oposto do propósito de ter dois
        níveis, e deixaria o ESP com a mesma chave por toda a janela de
        coleta justamente na fatia que a campanha quer mostrar
        degradando com elegância.

        É também o comportamento que o documento da campanha já
        especifica para o C4a: sob escassez, "a URLLC fica com o PPK e
        eMBB e mIoT passam a renovar só o ML-KEM".
        """
        # Drena a fila inteira neste tick — **achado testando isto**:
        # processar só 1 por tick (a de maior risco) acumulava fila sem
        # limite, porque o próximo tick enfileirava mais antes de
        # qualquer uma das anteriores ser consumida, e eMBB/mIoT nunca
        # eram processadas de verdade (a URLLC sempre vence o desempate).
        # Drenar simula o SMO rodando continuamente até a fila esvaziar,
        # que é o fluxo principal da arquitetura.
        #
        # Com o enfileiramento condicionado à idade a fila é curta por
        # construção (no máximo uma tarefa por fatia por tick), então
        # drenar não tem mais como crescer sem limite.
        rebaixadas: set[SliceType] = set()
        while self._scheduler.queue_size() > 0:
            resultado = self._smo.process_next_task()
            if resultado is None or resultado.success:
                continue
            # Só rebaixa por ESCASSEZ DE QKD. Qualquer outra falha
            # (charon fora, SA não subiu) não é caso de rotacionar
            # outra coisa — é caso de aparecer no registro como falha.
            if "escassez de QKD" not in (resultado.error_message or ""):
                continue
            fatia = SliceType(resultado.slice.value)
            if fatia in rebaixadas:
                continue  # uma vez por tick, não um laço
            rebaixadas.add(fatia)
            tr_child = self._tr_child[fatia]
            idade_child = idades.get(fatia, IdadesSa(0.0, None)).child_seconds
            if idade_child is None or idade_child < tr_child:
                continue  # o ESP ainda não venceu; nada a rebaixar
            emit("rotation_downgraded", slice=fatia.value,
                 reason="poço de PPK vazio — renovando só o ML-KEM do ESP",
                 child_age_seconds=idade_child, tr_child_seconds=tr_child)
            self._enfileira(fatia, TaskType.REKEY_CHILD, tr_child, idade_child,
                            ESTIMATED_REKEY_CHILD_COST_SECONDS)

    def _loop(self) -> None:
        while not self._stop.wait(self._interval):
            try:
                self._tick()
            except Exception as exc:
                # **Não engolir em silêncio.** A versão anterior fazia
                # `pass` aqui, com o comentário "não derruba o laço por
                # uma falha pontual de leitura" — a intenção é correta,
                # mas sem registrar nada o efeito foi esconder um defeito
                # por uma campanha inteira: as tarefas de REAUTH_PPK eram
                # enfileiradas, a exceção morria aqui, e o `.jsonl`
                # mostrava `rotation_enqueued` sem nenhum evento de PPK
                # depois — como se o orquestrador tivesse decidido não
                # rotacionar.
                #
                # Seguir em frente continua certo (um tick perdido não
                # deve derrubar a coleta), mas agora o tick perdido
                # APARECE, com tipo e mensagem.
                emit("rotation_tick_failed",
                     error=f"{type(exc).__name__}: {exc}",
                     traceback=traceback.format_exc()[-1200:])

    def start(self) -> None:
        self._stop.clear()
        self._ultima_tentativa_ppk.clear()
        self._recuo_anunciado.clear()
        self._thread = threading.Thread(target=self._loop, daemon=True)
        self._thread.start()

    # Tempo máximo de espera pela thread no `stop()`. Generoso de
    # propósito: um tick pode estar no meio de um reauth, e o agente
    # espera até `_APPLY_TIMEOUT_SECONDS` (60 s) pela SA nova.
    #
    # **Era `interval + 2` = 4 s, e isso produzia dois defeitos.** Com o
    # join estourando, o `stop()` retornava com o tick ainda vivo; o
    # `finally` do runner fechava o banco do KMS em seguida e o tick
    # morria com `ProgrammingError: Cannot operate on a closed
    # database` (7 ocorrências na campanha). Pior: como o destino da
    # instrumentação é global do módulo, a thread sobrevivente escrevia
    # no `.jsonl` da execução SEGUINTE — medido, 2 arquivos de C1
    # ganharam um `reauth_end` que não era deles. C1 não tem driver de
    # rotação, então o evento era impossível por construção, e foi isso
    # que denunciou.
    STOP_TIMEOUT_SECONDS = 75.0

    def stop(self) -> None:
        self._stop.set()
        if self._thread is None:
            return
        self._thread.join(timeout=self.STOP_TIMEOUT_SECONDS)
        if self._thread.is_alive():
            # Não dá para matar uma thread em Python. Registrar é o que
            # resta — e é melhor que o silêncio: quem analisar sabe que
            # aquela execução pode ter eventos de uma thread que
            # sobreviveu, e o consolidador pode descartá-la.
            emit("rotation_driver_stop_timeout",
                 timeout_seconds=self.STOP_TIMEOUT_SECONDS,
                 note="thread do driver não encerrou; eventos posteriores podem "
                      "vazar para a próxima execução")
