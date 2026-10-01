"""Testes de regressão contra uma captura PFCP real (não sintética) desta
VM — ver docs/ROTEIRO-MODULO2-SNIFFER-PFCP.md seção 2b. A fixture tem as
três sessões PDU de uma UE registrando nas três fatias ao mesmo tempo
(embb/urllc/miot), capturadas na bridge do Docker durante um teste real."""

from pathlib import Path

from scapy.all import UDP, rdpcap

from pfcp_sniffer.models import FTeid
from pfcp_sniffer.parser import parse
from pfcp_sniffer.session_tracker import SessionTracker

FIXTURE = Path(__file__).parent / "fixtures" / "sample_session.pcap"

# Valores conferidos contra a captura real (ver seção 2b do roteiro) —
# não são sintéticos. uplink = TEID que a UPF escolheu (CU manda pra cá);
# downlink = TEID que a CU anunciou (UPF manda pra cá, só aparece numa
# Modification Request, não na Establishment).
EXPECTED = {
    "eMBB": dict(
        seid=0xBBF,
        sst=1,
        sd=0xFFFFFF,
        dnn="embb",
        mark=0x20,
        uplink=FTeid(teid=56502, ipv4="172.18.0.2"),
        downlink=FTeid(teid=1098808716, ipv4="172.18.0.99"),
    ),
    "URLLC": dict(
        seid=0x49A,
        sst=2,
        sd=0xFFFFFF,
        dnn="urllc",
        mark=0x10,
        uplink=FTeid(teid=46265, ipv4="172.18.0.2"),
        downlink=FTeid(teid=1172466075, ipv4="172.18.0.99"),
    ),
    "mIoT": dict(
        seid=0xCE0,
        sst=3,
        sd=0xFFFFFF,
        dnn="miot",
        mark=0x30,
        uplink=FTeid(teid=65044, ipv4="172.18.0.2"),
        downlink=FTeid(teid=2035978683, ipv4="172.18.0.99"),
    ),
}


def _replay_all():
    """Processa todos os pacotes PFCP da fixture, em ordem, e devolve
    (tracker, lista de ProcessResult) — mesma sequência que o sniffer real
    veria ao vivo."""
    tracker = SessionTracker()
    results = []
    for pkt in rdpcap(str(FIXTURE)):
        if UDP not in pkt:
            continue
        udp = pkt[UDP]
        if udp.sport != 8805 and udp.dport != 8805:
            continue
        parsed = parse(bytes(udp.payload))
        results.append(tracker.process(parsed))
    return tracker, results


def test_fixture_file_exists():
    assert FIXTURE.exists(), "captura de referência não encontrada"


def test_emits_exactly_three_complete_mappings():
    _, results = _replay_all()
    mappings = [r.mapping for r in results if r.mapping is not None]
    assert len(mappings) == 3, "a fixture tem três sessões simultâneas (embb/urllc/miot)"


def test_mapping_fields_match_real_capture_for_each_slice():
    _, results = _replay_all()
    mappings = {m.slice_name: m for m in (r.mapping for r in results if r.mapping is not None)}

    assert set(mappings) == {"eMBB", "URLLC", "mIoT"}

    for slice_name, expected in EXPECTED.items():
        m = mappings[slice_name]
        assert m.seid == expected["seid"], slice_name
        assert m.sst == expected["sst"], slice_name
        assert m.sd == expected["sd"], slice_name
        assert m.dnn == expected["dnn"], slice_name
        assert m.mark == expected["mark"], slice_name
        assert m.uplink == expected["uplink"], slice_name
        # downlink só é conhecido depois da Modification Request — é
        # exatamente esse achado que este teste tranca contra regressão.
        assert m.downlink == expected["downlink"], slice_name


def test_downlink_points_to_cu_not_to_smf_or_upf():
    """Regressão direta do bug real que encontramos: o primeiro Outer
    Header Creation da árvore pertence a um FAR que aponta pra
    CP-function (a UPF notificando a SMF), não pro enlace N3 — pegar o
    primeiro sem checar Destination Interface=Access extrai o TEID/IP
    errado (o da SMF, 172.18.0.13, não o da CU, 172.18.0.99)."""
    _, results = _replay_all()
    mappings = [r.mapping for r in results if r.mapping is not None]
    assert len(mappings) == 3
    for m in mappings:
        assert m.downlink.ipv4 == "172.18.0.99", (
            f"downlink de {m.slice_name} apontou pra {m.downlink.ipv4}, "
            "esperava o alias N3 da CU (172.18.0.99) — ver extract_downlink_fteid"
        )


def test_deletion_of_unknown_seid_does_not_crash():
    """A fixture começa com Deletion Requests de sessões anteriores (já
    não rastreadas, de antes do sniffer ter começado a escutar) — não
    deveria derrubar o tracker nem gerar nenhum mapeamento espúrio."""
    tracker, results = _replay_all()
    # não é garantido que existam (depende só do que estava na captura),
    # mas processar sem exceção é o que importa — se chegou até aqui sem
    # levantar, já passou.
    assert isinstance(len(tracker), int)


def test_no_mapping_emitted_twice_for_same_session():
    """Depois da Modification Request completar o mapeamento, mensagens
    seguintes (Modification Response, Heartbeats) não deveriam reemitir
    o mesmo mapeamento de novo."""
    _, results = _replay_all()
    mappings = [r.mapping for r in results if r.mapping is not None]
    seids = [m.seid for m in mappings]
    assert len(seids) == len(set(seids)), "mesma sessão emitida mais de uma vez"
