"""Testa a lógica de reconstrução da mangle OUTPUT sem tocar em
iptables de verdade — `MangleClassifier._run` é substituído por um
coletor de chamadas. O que importa verificar, dado o achado de que o
nr-gnb do UERANSIM trava com EPERM se uma fatia ativa ficar sem regra:
toda fatia conhecida sempre tem MARK+RETURN, e o catch-all (LOG+DROP)
sempre vem depois de todas elas, nunca entre.
"""

from __future__ import annotations

from pfcp_sniffer.models import FTeid, SliceMapping

from auto_classifier import MangleClassifier


def _mapping(sst: int, sd: int, seid: int, teid: int, mark: int) -> SliceMapping:
    return SliceMapping(
        seid=seid, sst=sst, sd=sd, dnn="x",
        uplink=FTeid(teid=teid, ipv4="172.18.0.3"),
        downlink=FTeid(teid=teid + 1, ipv4="172.18.0.99"),
        mark=mark,
    )


def _classifier() -> tuple[MangleClassifier, list[str]]:
    """Intercepta `_run` desde a criação — nenhuma chamada real a
    iptables acontece, inclusive nas chamadas de preparação de cada
    teste."""
    c = MangleClassifier("cu-ns")
    calls: list[str] = []
    c._run = calls.append  # type: ignore[method-assign]
    return c, calls


def test_uma_fatia_gera_mark_return_e_catchall_nessa_ordem():
    c, calls = _classifier()
    c.on_mapping(_mapping(sst=2, sd=0xFFFFFF, seid=1, teid=0x49B7, mark=0x10))

    assert calls[0] == "-F OUTPUT"
    assert "u32 32=0x49b7" in calls[1] and "MARK --set-mark 0x10" in calls[1]
    assert "mark --mark 0x10" in calls[2] and "RETURN" in calls[2]
    assert calls[-2].startswith("-A OUTPUT -p udp --dport 2152") and "LOG" in calls[-2]
    assert calls[-1] == "-A OUTPUT -p udp --dport 2152 -j DROP"


def test_catchall_sempre_depois_de_todas_as_fatias_conhecidas():
    c, calls = _classifier()
    c.on_mapping(_mapping(sst=2, sd=0xFFFFFF, seid=1, teid=0x49B7, mark=0x10))
    c.on_mapping(_mapping(sst=1, sd=0xFFFFFF, seid=2, teid=0xC3DF, mark=0x20))
    c.on_mapping(_mapping(sst=3, sd=0xFFFFFF, seid=3, teid=0xE8D3, mark=0x30))

    # só a última reconstrução (depois do último "-F OUTPUT") importa —
    # as duas primeiras tinham só 1 e 2 fatias conhecidas até então.
    last_flush = len(calls) - 1 - calls[::-1].index("-F OUTPUT")
    tail = calls[last_flush:]
    drop_idx = tail.index("-A OUTPUT -p udp --dport 2152 -j DROP")
    for mark in (0x10, 0x20, 0x30):
        mark_idx = next(i for i, c_ in enumerate(tail) if f"MARK --set-mark {mark:#x}" in c_)
        return_idx = next(i for i, c_ in enumerate(tail) if f"mark --mark {mark:#x}" in c_ and "RETURN" in c_)
        assert mark_idx < return_idx < drop_idx


def test_mesmo_teid_nao_reconstroi():
    c, calls = _classifier()
    c.on_mapping(_mapping(sst=2, sd=0xFFFFFF, seid=1, teid=0x49B7, mark=0x10))
    calls.clear()
    c.on_mapping(_mapping(sst=2, sd=0xFFFFFF, seid=1, teid=0x49B7, mark=0x10))
    assert calls == []


def test_teid_novo_na_mesma_fatia_reconstroi_so_com_o_novo():
    c, calls = _classifier()
    c.on_mapping(_mapping(sst=2, sd=0xFFFFFF, seid=1, teid=0x49B7, mark=0x10))
    calls.clear()
    c.on_mapping(_mapping(sst=2, sd=0xFFFFFF, seid=2, teid=0xAAAA, mark=0x10))
    joined = " ".join(calls)
    assert "0x49b7" not in joined
    assert "0xaaaa" in joined


def test_remocao_tira_a_fatia_e_reconstroi_sem_ela():
    c, calls = _classifier()
    c.on_mapping(_mapping(sst=2, sd=0xFFFFFF, seid=1, teid=0x49B7, mark=0x10))
    c.on_mapping(_mapping(sst=1, sd=0xFFFFFF, seid=2, teid=0xC3DF, mark=0x20))
    calls.clear()
    c.on_removed(seid=1)
    joined = " ".join(calls)
    assert "0x49b7" not in joined
    assert "0xc3df" in joined


def test_remocao_de_seid_desconhecido_nao_faz_nada():
    c, calls = _classifier()
    c.on_mapping(_mapping(sst=2, sd=0xFFFFFF, seid=1, teid=0x49B7, mark=0x10))
    calls.clear()
    c.on_removed(seid=999)
    assert calls == []


def test_fatia_sem_mark_e_ignorada_mas_nao_quebra():
    c, calls = _classifier()
    c.on_mapping(_mapping(sst=9, sd=0, seid=1, teid=0x1234, mark=None))  # SST sem perfil
    assert calls == ["-F OUTPUT",
                      '-A OUTPUT -p udp --dport 2152 -m limit --limit 10/min --limit-burst 5 '
                      '-j LOG --log-prefix "[n3-teid-nao-classificado] " --log-level 4',
                      "-A OUTPUT -p udp --dport 2152 -j DROP"]
