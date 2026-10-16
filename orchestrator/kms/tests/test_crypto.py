"""Testes do material de chave do KMS, depois da troca do ML-KEM local
pela chave de QKD (ver docstring de `kms/crypto.py`).

Usa um cliente falso em vez da QKDN real: cada chamada ao `enc_keys`
verdadeiro custa ~15,4 s de simulação BB84+Cascade, o que tornaria a
suíte inviável. O caminho contra a QKDN de verdade é exercitado à parte,
no laboratório.
"""

import base64
import json
import time

import pytest

from kms.crypto import PpkMaterial, fetch_ppk
from kms.models import SliceType
from kms.qkd import PPK_BITS, PpkProvider, QkdKey, _parse_resposta


class FakeQkdClient:
    """Imita o `Qkd014Client` sem rede. Conta as chamadas para dar pra
    verificar que a pré-busca acontece fora do caminho crítico."""

    def __init__(self):
        self.chamadas = 0

    def enc_keys(self, slave_sae_id: str, bits: int = PPK_BITS) -> QkdKey:
        self.chamadas += 1
        return QkdKey(
            key_id=f"fake-{self.chamadas}",
            key=bytes([self.chamadas]) * (bits // 8),
            source="fake",
        )


def _provider_pronto(slices, depth=2, espera=2.0):
    """Sobe o provider e espera o poço de cada fatia ter pelo menos uma
    chave, para o teste não depender do agendamento das threads."""
    prov = PpkProvider(FakeQkdClient(), "B", slices, depth=depth)
    prov.start()
    limite = time.monotonic() + espera
    while time.monotonic() < limite:
        if all(prov.depth(s) > 0 for s in slices):
            break
        time.sleep(0.01)
    return prov


@pytest.mark.parametrize("slice", list(SliceType))
def test_fetch_entrega_chave_de_qkd_com_key_id(slice):
    prov = _provider_pronto((slice,))
    try:
        m = fetch_ppk(slice, prov)
        assert isinstance(m, PpkMaterial)
        assert m.slice is slice
        assert len(m.ppk) * 8 == PPK_BITS
        # O key_id é o que a outra ponta usa no `dec_keys` para obter a
        # MESMA chave — sem ele o PPK não é compartilhável.
        assert m.key_id
    finally:
        prov.stop()


def test_poco_vazio_devolve_none_em_vez_de_levantar():
    """Poço vazio é escassez de QKD, que a campanha mede — não é erro.
    Ver `fetch_ppk`."""
    prov = PpkProvider(FakeQkdClient(), "B", (SliceType.URLLC,), depth=1)
    # Sem `start()`: nenhuma thread de reposição, poço garantidamente vazio.
    assert fetch_ppk(SliceType.URLLC, prov) is None


def test_duas_buscas_nao_repetem_chave():
    prov = _provider_pronto((SliceType.URLLC,), depth=2)
    try:
        a = fetch_ppk(SliceType.URLLC, prov)
        for _ in range(200):
            if prov.depth(SliceType.URLLC) > 0:
                break
            time.sleep(0.01)
        b = fetch_ppk(SliceType.URLLC, prov)
        assert a is not None and b is not None
        assert a.ppk != b.ppk
        assert a.key_id != b.key_id
    finally:
        prov.stop()


def test_poco_e_por_fatia():
    """Uma fila por fatia, não uma só: o Tr_ppk é por fatia e o modelo de
    consumo soma sobre elas. Uma fila única faria a fatia de prazo curto
    disputar com as de prazo longo por acidente de implementação."""
    prov = _provider_pronto(tuple(SliceType))
    try:
        esvaziada = SliceType.URLLC
        while prov.depth(esvaziada):
            prov.get(esvaziada)
        assert all(prov.depth(s) > 0 for s in SliceType if s is not esvaziada)
    finally:
        prov.stop()


def test_provider_tipado_por_slicetype_nao_por_string():
    """A primeira versão chaveava por string e o chamador criava o poço
    com "urllc" enquanto `SliceType.URLLC.value` é "URLLC" — KeyError no
    meio de uma rotação."""
    prov = PpkProvider(FakeQkdClient(), "B", (SliceType.URLLC,))
    with pytest.raises(KeyError):
        prov.get("urllc")


# --- parser do formato de resposta --------------------------------------
# O `http_receptor.py` do QuDitto devolve `{result}` onde result é o
# `str()` de um dict Python, e o FastAPI serializa esse set como array
# JSON: JSON válido contendo UMA string que por dentro é repr de dict
# Python, com aspas simples. O parser aceita também a forma da norma,
# para não quebrar se o QuDitto for corrigido.

def test_parser_aceita_o_formato_do_quditto():
    chave = base64.b64encode(b"x" * 32).decode()
    corpo = json.dumps([f"{{'key_ID': 'abc-123', 'key': '{chave}'}}"]).encode()
    itens = _parse_resposta(corpo)
    assert itens == [{"key_ID": "abc-123", "key": chave}]


def test_parser_aceita_o_formato_da_norma():
    chave = base64.b64encode(b"y" * 32).decode()
    corpo = json.dumps({"keys": [{"key_ID": "def-456", "key": chave}]}).encode()
    itens = _parse_resposta(corpo)
    assert itens == [{"key_ID": "def-456", "key": chave}]
