"""Material de chave que o KMS entrega ao IPsec Agent.

**O que mudou e por quê.** A primeira versão gerava, a cada rotação, um
PSK derivado por HKDF de um segredo ML-KEM executado localmente, mais um
"componente quântico" que era `secrets.token_bytes()` rotulado como
simulado. Os dois saíram:

* **O ML-KEM local saiu** porque era redundante e enganoso. O IKE já
  negocia ML-KEM a cada rekey e a cada reauth — medido ao vivo: o rekey
  de Child SA de cada fatia faz uma troca ML-KEM nova (768/768/1024, ver
  `lab/ipsec/.../connections.conf`). Um segundo ML-KEM dentro do KMS não
  acrescentava segurança, e pior: ele rodava os dois lados do KEM no
  mesmo processo, o que não é acordo de chave nenhum — era uma fonte de
  entropia com nome de KEM.
* **O PSK saiu da rotação.** Na arquitetura adotada o PSK é FIXO e serve
  só para autenticação; quem rotaciona é o PPK (RFC 8784), que entra na
  derivação de chaves no IKE_AUTH. Rotacionar o PSK obrigava um reauth a
  cada rotação, inclusive quando só o material do ESP precisava ser
  renovado — e a Fase A mediu três ordens de grandeza entre as duas
  operações (rekey de Child SA sem perda de pacote, contra reauth de
  ~1,8 ms a 163 ms de interrupção).

O que o KMS entrega agora é **a chave de QKD, vinda da QKDN pela API
ETSI GS QKD 014**, para ser carregada como PPK. Ver `kms/qkd.py` para o
cliente e para por que a busca é pré-fetch e não sob demanda.

O PSK continua existindo na configuração do laboratório (gerado por
`lab/ipsec/regen-secrets.py`), só não passa mais por aqui.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Optional

from kms.models import SliceType
from kms.qkd import PpkProvider, QkdKey
from evaluation.instrumentation import emit, timed

logger = logging.getLogger(__name__)

# Mantido porque o `secrets.conf` do laboratório usa 32 bytes e o
# `regen-secrets.py` gera nesse tamanho; serve de referência única.
PSK_LENGTH_BYTES = 32


@dataclass(frozen=True)
class PpkMaterial:
    """Material de uma rotação de PPK.

    O `key_id` é o que viaja para a outra ponta: é com ele que o KMS
    remoto chama `dec_keys` e obtém a MESMA chave, sem que a chave em si
    seja transmitida. Ver `kms/qkd.QkdKey`.
    """
    key_id: str
    ppk: bytes
    slice: SliceType
    source: str


def fetch_ppk(slice: SliceType, provider: PpkProvider,
              timeout_seconds: float = 0.0) -> Optional[PpkMaterial]:
    """Tira do poço a próxima chave de QKD da fatia.

    Devolve `None` quando o poço está vazio — e isso **não é erro**. Poço
    vazio significa escassez de QKD, que é um dos fenômenos que a
    campanha existe para medir (o modelo é `Σ k / Tr_ppk,i ≤ R_qkd`, e
    violá-lo tem de produzir um efeito observável, não uma exceção). O
    evento fica registrado para a análise, e quem chama decide entre
    adiar a rotação ou seguir com o PPK anterior.

    **O `timeout` é 0 por padrão, de propósito.** Esperar aqui colocaria
    a latência da QKD de volta no caminho crítico do reauth, que é
    exatamente o que o poço existe para evitar: a busca no master custa
    ~15,4 s medidos, contra ~1,8 ms de interrupção do reauth.
    """
    with timed("ppk_fetch", slice=slice.value):
        chave: Optional[QkdKey] = provider.get(slice, timeout=timeout_seconds)

    if chave is None:
        emit("ppk_pool_empty", slice=slice.value,
             pool_depth=provider.depth(slice))
        logger.warning("poço de PPK vazio para %s — rotação adiada", slice.value)
        return None

    emit("ppk_fetched", slice=slice.value, key_id=chave.key_id,
         bits=len(chave.key) * 8, pool_depth=provider.depth(slice))
    return PpkMaterial(key_id=chave.key_id, ppk=chave.key,
                       slice=slice, source=chave.source)
