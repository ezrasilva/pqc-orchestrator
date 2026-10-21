"""Cliente ETSI GS QKD 014 contra a QKDN do QuDitto, com pré-busca.

**O que substitui.** A primeira versão do KMS gerava o componente
"quântico" com `secrets.token_bytes()` e rotulava como simulado. Agora a
chave vem de uma QKDN de verdade — gêmeo digital, mas com protocolo
quântico simulado de ponta a ponta (BB84 + Cascade sobre SeQUeNCe) e
entregue pela API padronizada. Ver `lab/qkd/`.

**Por que a pré-busca não é otimização, é requisito.** Medido contra a
QKDN (15/10):

| Operação | Tempo de parede |
| --- | --- |
| `enc_keys` (master; dispara a simulação) | **~15,4 s** |
| `dec_keys` (slave; chave já distribuída) | **~1,1 s** |

O `Tr_ppk` da URLLC em escala de teste é 30 s. Buscar a chave dentro do
caminho crítico do reauth somaria 15 s a uma operação que a Fase A mediu
em ~1,8 ms de interrupção — três ordens de grandeza de distorção, e o
resultado mediria a simulação da QKD, não o SAPQ-IPsec. Daí o
`PpkProvider`, que mantém um poço de chaves por fatia preenchido em
segundo plano: o reauth consome uma chave já pronta.

**O formato de resposta do QuDitto não é o da norma.** O `http_receptor.py`
devolve `{result}` onde `result` é o `str()` de um dict Python, e o
FastAPI serializa esse set como array JSON. Na prática:

    '["{\\'key_ID\\': \\'44c6...\\', \\'key\\': \\'aq6SRibq...=\\'}"]'

ou seja: JSON válido, contendo UMA string, que por dentro é repr de dict
Python com aspas simples — não JSON. Por isso o parse é em duas etapas,
`json.loads` e depois `ast.literal_eval`, e não `json.loads` aninhado.
A norma pediria `{"keys":[{"key_ID":...,"key":...}]}`; o parser aceita as
duas formas para não quebrar se o QuDitto for corrigido.
"""

from __future__ import annotations

import ast
import base64
import json
import logging
import threading
import time
import urllib.error
import urllib.request
from dataclasses import dataclass
from queue import Empty, Full, Queue
from typing import Optional

from criticality import ordem_de_prioridade
from evaluation.instrumentation import emit

from kms.models import SliceType

logger = logging.getLogger(__name__)

# Tamanho do PPK, em bits. 256 é o que a campanha usa e o que foi
# validado na QKDN (chave idêntica nas duas pontas).
PPK_BITS = 256

# Generoso porque a chamada ao master dispara a simulação inteira do
# BB84 + Cascade (~15,4 s medidos); um timeout curto aqui transformaria
# funcionamento normal em erro.
_DEFAULT_TIMEOUT_SECONDS = 120.0


@dataclass(frozen=True)
class QkdKey:
    """Chave de QKD com o ID pelo qual a outra ponta a recupera.

    O `key_id` é o que viaja para a outra ponta (fora de banda, pelo
    orquestrador): é com ele que o KMS remoto chama `dec_keys` e obtém a
    MESMA chave. É o mecanismo da ETSI 014 e é o que permite as duas
    pontas carregarem o mesmo PPK sem nunca transmitirem a chave.
    """
    key_id: str
    key: bytes
    source: str  # qual nó da QKDN entregou, para rastrear no log


def _parse_resposta(corpo: bytes) -> list[dict]:
    """Normaliza as duas formas de resposta possíveis (ver docstring do
    módulo) numa lista de dicts com `key_ID` e `key`."""
    texto = corpo.decode().strip()
    dados = json.loads(texto)

    if isinstance(dados, dict) and "keys" in dados:
        return list(dados["keys"])  # forma da norma

    itens = []
    for item in dados if isinstance(dados, list) else [dados]:
        if isinstance(item, str):
            # repr de dict Python: aspas simples, não JSON. O
            # literal_eval aceita só literais, então não executa código.
            itens.append(ast.literal_eval(item))
        elif isinstance(item, dict):
            itens.append(item)
    return itens


class Qkd014Client:
    """Uma instância por nó da QKDN (cada nó expõe sua própria API)."""

    def __init__(self, base_url: str, timeout: float = _DEFAULT_TIMEOUT_SECONDS):
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout

    def _get(self, caminho: str) -> list[dict]:
        url = f"{self.base_url}{caminho}"
        try:
            with urllib.request.urlopen(url, timeout=self.timeout) as resp:
                return _parse_resposta(resp.read())
        except urllib.error.URLError as exc:
            raise RuntimeError(f"QKDN inacessível em {url}: {exc}") from exc

    def enc_keys(self, slave_sae_id: str, bits: int = PPK_BITS) -> QkdKey:
        """Lado master: pede uma chave nova. Dispara a simulação."""
        itens = self._get(
            f"/api/v1/keys/{slave_sae_id}/enc_keys?size={bits}")
        if not itens:
            raise RuntimeError(f"QKDN não devolveu chave para {slave_sae_id}")
        item = itens[0]
        return QkdKey(key_id=str(item["key_ID"]),
                      key=base64.b64decode(item["key"]),
                      source=self.base_url)

    def dec_keys(self, master_sae_id: str, key_id: str) -> bytes:
        """Lado slave: recupera, pelo ID, a chave que o master gerou."""
        itens = self._get(
            f"/api/v1/keys/{master_sae_id}/dec_keys?key_ID={key_id}")
        if not itens:
            raise RuntimeError(
                f"QKDN não devolveu a chave {key_id} em {self.base_url}")
        return base64.b64decode(itens[0]["key"])


class PpkProvider:
    """Poço de chaves de QKD por fatia, preenchido em segundo plano.

    **Por que um poço e não busca sob demanda**: ver o docstring do
    módulo — a busca no master custa ~15,4 s e o reauth que consome a
    chave custa ~1,8 ms de interrupção. Sem o poço, a medição da Fase B
    mediria a simulação da QKD.

    **Por que uma fila por fatia e não uma só**: o `Tr_ppk` é por fatia
    (30 s na URLLC em escala de teste, mais longo nas outras), e o modelo
    de consumo da campanha é `Σ k / Tr_ppk,i ≤ R_qkd`. Uma fila única
    deixaria a fatia de prazo curto disputando com as de prazo longo,
    exatamente o efeito que a campanha quer medir e não sofrer por
    acidente de implementação.

    Thread de reposição por fatia, daemon: o processo não deve ficar
    pendurado por causa delas no encerramento.
    """

    def __init__(self, client: Qkd014Client, slave_sae_id: str,
                 slices: tuple[SliceType, ...], depth: int = 3,
                 r_qkd_bits_per_second: float | None = None,
                 key_bits: int = PPK_BITS):
        # Chaveado por `SliceType`, não por string: a primeira versão
        # usava string e o chamador criava o poço com "urllc" enquanto
        # `SliceType.URLLC.value` é "URLLC" — KeyError em tempo de
        # execução, no meio de uma rotação. Tipar a interface elimina a
        # classe do problema em vez de corrigir um caso dele.
        self._client = client
        self._slave = slave_sae_id
        self._depth = depth
        self._pools: dict[SliceType, Queue[QkdKey]] = {
            s: Queue(maxsize=depth) for s in slices}
        self._threads: dict[SliceType, threading.Thread] = {}
        self._stop = threading.Event()

        # Limitador de taxa AGREGADO, modelando uma fonte de QKD única
        # com taxa `R_qkd` compartilhada entre as fatias.
        #
        # **Por que declarar R_qkd em vez de herdá-lo da simulação.**
        # Medido: o tempo por chave depende da carga do hospedeiro
        # (15,2 s com o rádio parado contra 38-39 s com ele rodando) e do
        # backend de reconciliação (~6,2 s com o Cascade modelado). Com
        # R_qkd herdado, a razão demanda/oferta — que é o que decide
        # quais fatias são rebaixadas — vira variável não controlada, e
        # duas execuções do mesmo cenário medem coisas diferentes. O
        # desenho do C4a já pedia um valor controlado (~8,5 bit/s);
        # declarar aqui é o que torna isso reproduzível.
        #
        # **Por que agregado e não por fatia.** O modelo da campanha é
        # `Σ k / Tr_ppk,i ≤ R_qkd`: uma fonte, várias fatias disputando.
        # Um limitador por thread daria três vezes a taxa e eliminaria
        # justamente a disputa que o C4a quer medir.
        self._key_bits = key_bits
        self._intervalo_minimo = (
            key_bits / r_qkd_bits_per_second if r_qkd_bits_per_second else 0.0)
        self._pacer_lock = threading.Lock()
        self._proxima_liberacao = 0.0

    def start(self) -> None:
        # UMA thread de reposição, não uma por fatia.
        #
        # **Por que mudou.** A versão anterior tinha uma thread por fatia
        # e o limitador agregado as atendia em ROUND-ROBIN, sem
        # prioridade. O escalonador ordena TAREFAS por criticidade, mas
        # se o poço da fatia crítica está vazio quando a tarefa dela
        # roda, ela rebaixa igual — e sob escassez severa todas passam
        # fome por igual. Medido no C4a da Fase B: a URLLC levou 786
        # rebaixamentos, contra 19 no C3. Em escassez moderada funcionava
        # por acidente, porque o `Tr_ppk` da URLLC é o mais curto e ela
        # colhia mais do round-robin.
        #
        # A arquitetura prevê o contrário: I define "a prioridade **e a
        # partilha de QKD**". Com uma thread só, cada vez que o
        # limitador libera uma vaga a chave vai para a fatia mais crítica
        # que ainda tem espaço no poço — ver `_proxima_fatia`.
        self._stop.clear()
        t = threading.Thread(target=self._repor_em_prioridade,
                             name="ppk-repositor", daemon=True)
        t.start()
        self._threads["repositor"] = t

    def stop(self) -> None:
        self._stop.set()

    def _aguarda_vez(self) -> None:
        """Espaça os pedidos conforme `R_qkd`.

        A espera acontece FORA do lock: segurá-lo durante o sleep faria
        a ordem de liberação depender do escalonador de threads em vez
        da taxa declarada. Com uma thread só de reposição o lock é
        redundante hoje, mas fica porque o `_proxima_liberacao` é estado
        compartilhado e o custo é nulo.
        """
        if self._intervalo_minimo <= 0:
            return
        with self._pacer_lock:
            agora = time.monotonic()
            inicio = max(agora, self._proxima_liberacao)
            self._proxima_liberacao = inicio + self._intervalo_minimo
        espera = inicio - time.monotonic()
        if espera > 0:
            # `self._stop.wait` e não `time.sleep`: um `stop()` durante a
            # espera tem de interromper, senão o encerramento fica preso
            # por até um intervalo inteiro (30 s a 8,5 bit/s).
            self._stop.wait(espera)

    def _proxima_fatia(self) -> Optional[SliceType]:
        """A fatia mais crítica cujo poço ainda tem espaço.

        Prioridade ESTRITA, não proporcional, porque o desempate
        declarado é lexicográfico e sem pesos. Não causa inanição das
        menos críticas porque a demanda de cada fatia é LIMITADA pela
        profundidade do poço: satisfeita a URLLC, a vaga seguinte desce
        para a próxima da ordem. O excedente escorre, a escassez sobe.
        """
        for nome in ordem_de_prioridade():
            for fatia, fila in self._pools.items():
                if fatia.value == nome and not fila.full():
                    return fatia
        return None

    def _repor_em_prioridade(self) -> None:
        while not self._stop.is_set():
            self._aguarda_vez()
            if self._stop.is_set():
                return
            fatia = self._proxima_fatia()
            if fatia is None:
                # Todos os poços cheios: espera sem gastar vaga do
                # limitador, senão a taxa declarada seria consumida sem
                # produzir chave.
                self._stop.wait(1.0)
                continue
            try:
                chave = self._client.enc_keys(self._slave, self._key_bits)
            except Exception:  # noqa: BLE001 — repor é best-effort; o get() reporta a falta
                logger.exception("falha buscando PPK para %s", fatia.value)
                self._stop.wait(5.0)
                continue
            try:
                self._pools[fatia].put(chave, timeout=1.0)
                emit("ppk_pool_filled", slice=fatia.value,
                     pool_depth=self._pools[fatia].qsize())
            except Full:
                # Encheu entre a escolha e a entrega: a chave não se
                # perde silenciosamente, vai para a próxima com espaço.
                alternativa = self._proxima_fatia()
                if alternativa is not None:
                    try:
                        self._pools[alternativa].put(chave, timeout=1.0)
                        emit("ppk_pool_filled", slice=alternativa.value,
                             pool_depth=self._pools[alternativa].qsize(),
                             note=f"redirecionada de {fatia.value}")
                    except Full:
                        emit("ppk_descartada", slice=fatia.value,
                             note="todos os poços cheios na entrega")

    def get(self, fatia: SliceType, timeout: float = 0.0) -> Optional[QkdKey]:
        """Tira uma chave do poço da fatia. `None` se o poço estiver
        vazio dentro do timeout — o chamador decide se adia a rotação ou
        falha, e a Fase B registra o evento: poço vazio é escassez de
        QKD, que é um dos fenômenos que a campanha quer medir, não um
        erro a esconder."""
        try:
            return self._pools[fatia].get(timeout=timeout) if timeout else \
                self._pools[fatia].get_nowait()
        except Empty:
            return None

    def depth(self, fatia: SliceType) -> int:
        return self._pools[fatia].qsize()
