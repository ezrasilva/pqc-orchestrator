"""Vetor de criticidade por fatia, e a ordem de prioridade que ele produz.

**Fonte única de verdade** para "quem vem primeiro" em todo o sistema.
Existe porque o escalonador e o poço de entropia divergiram: o
escalonador usava pesos com a ordem URLLC > eMBB > mIoT, herdada de um
documento anterior ao vetor de criticidade, enquanto o modelo declarado
na campanha produz URLLC > mIoT > eMBB. A divergência apareceu nos
dados — no C3 a eMBB levou 464 chaves de QKD contra 336 da mIoT, o
contrário do que o modelo prevê — e só foi notada ao conferir o código
contra o documento.

**O modelo** (ver `docs/CAMPANHA-SAPQ-IPSEC.md`): a criticidade é um
vetor de três dimensões, cada uma em nível alto/médio/baixo, derivado
dos atributos do descritor de fatia (GST/NEST):

* **H** — horizonte de confidencialidade (o *x* de Mosca): por quanto
  tempo o dado precisa seguir secreto. Escolhe o nível do ML-KEM, a
  cifra e o uso de PPK.
* **I** — impacto do comprometimento: define a prioridade e **a partilha
  de QKD**.
* **D** — tolerância a interrupção: define o `Tr_child` mínimo e o uso de
  make-before-break.

Na disputa por rekey ou por entropia o desempate é **lexicográfico
I > H > D, sem pesos**.

**A ordem resultante não é a intuitiva, e isso é um resultado.**
URLLC vem primeiro por I alta. eMBB e mIoT empatam em I (média), e o
desempate é H: a mIoT tem H **alta** (telemetria precisa seguir secreta
por anos, logo é mais exposta a *harvest now, decrypt later*) contra H
baixa da eMBB (mídia, cujo valor decai em dias). Então a mIoT recebe
material de QKD antes da eMBB, apesar de ter o `Tr` mais longo.

É o tipo de conclusão que justifica derivar a ordem do vetor em vez de
escolhê-la: ninguém ordenaria mIoT acima de eMBB por intuição.
"""

from __future__ import annotations

import enum
from typing import NamedTuple


class Nivel(enum.IntEnum):
    """Ordenável de propósito: `IntEnum` permite comparar níveis
    diretamente, que é o que o desempate lexicográfico precisa."""
    BAIXA = 0
    MEDIA = 1
    ALTA = 2


class Criticidade(NamedTuple):
    h: Nivel  # horizonte de confidencialidade
    i: Nivel  # impacto do comprometimento
    d: Nivel  # tolerância a interrupção


# Valores aceitos em 14/10 (ver "Valores fixados" no documento da
# campanha). Chaveado pelo NOME da fatia, e não por um enum, porque há
# dois `SliceType` no sistema (kms.models e scheduler.models) e os dois
# precisam consultar a mesma tabela.
CRITICIDADE: dict[str, Criticidade] = {
    "URLLC": Criticidade(h=Nivel.MEDIA, i=Nivel.ALTA, d=Nivel.BAIXA),
    "EMBB": Criticidade(h=Nivel.BAIXA, i=Nivel.MEDIA, d=Nivel.MEDIA),
    "MIOT": Criticidade(h=Nivel.ALTA, i=Nivel.MEDIA, d=Nivel.ALTA),
}


def chave_lexicografica(fatia: str) -> tuple[int, int, int]:
    """Chave de ordenação DECRESCENTE por criticidade: a mais crítica
    primeiro. Os sinais negativos fazem `sorted()` crescente entregar a
    ordem de prioridade, sem `reverse=True` espalhado pelo código."""
    c = CRITICIDADE.get(fatia)
    if c is None:
        # Fatia desconhecida vai para o fim, em vez de levantar: uma
        # fatia nova não deve derrubar uma rotação em curso.
        return (1, 1, 1)
    return (-c.i, -c.h, -c.d)


def ordem_de_prioridade() -> list[str]:
    """A ordem DERIVADA do vetor, não escrita à mão.

    Fixar a lista seria mais simples e mais frágil: se os níveis de uma
    fatia mudarem no documento, a lista ficaria errada em silêncio.
    Derivar faz o código acompanhar o modelo.
    """
    return sorted(CRITICIDADE, key=chave_lexicografica)


def posicao(fatia: str) -> int:
    """Posição na ordem de prioridade, 0 = mais crítica."""
    ordem = ordem_de_prioridade()
    return ordem.index(fatia) if fatia in ordem else len(ordem)
