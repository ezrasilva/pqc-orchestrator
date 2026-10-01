"""Registro estático das conexões que o IPsec Agent conhece nesta fase.

**Lacuna de arquitetura que este módulo contorna, documentada aqui de
propósito**: PSK é segredo *compartilhado* — os dois lados de uma conexão
precisam do mesmo material pra reautenticação funcionar. O
`ARQUITETURA-ORQUESTRADOR.md` descreve só **um** IPsec Agent, nativo no
`cu-ns` (o lado initiator), sem mencionar quem aplica o material no lado
responder (`du-ns` pro F1, `5gc-edge-ns` pro N2/N3).

Nesta fase (VM única, todos os três netns na mesma máquina), o Agent
contorna isso tendo acesso direto aos sockets VICI dos dois lados de cada
conexão — por isso `ConnectionConfig` carrega `initiator_socket` **e**
`responder_socket`. `ApplyKeyMaterial` carrega o segredo nos dois antes de
disparar o reauth do lado initiator.

**Isso não se sustenta numa implantação distribuída de verdade** (DU e a
borda do 5GC em máquinas físicas separadas, como a topologia real da RNP
vai ter) — lá, o Agent do `cu-ns` não vai ter acesso de filesystem ao
socket VICI de uma máquina remota. Duas saídas possíveis quando chegar
nesse ponto, nenhuma implementada ainda:

1. Um componente espelho, mais simples que o IPsec Agent completo, rodando
   no lado responder (`du-ns` real, a borda do 5GC real), só carregando o
   material que o Agent do `cu-ns` manda por uma chamada de rede — não
   precisa saber nada de política/rotação, só "aplica esse PSK quando
   pedirem".
2. Um backend de segredos compartilhado (ex: Vault, ou mais simples um
   arquivo sincronizado) que os dois lados leem — mais simples de montar,
   mas perde a auditoria centralizada que o VICI dá "de graça" hoje.

Tratar essa decisão antes de migrar esse código pra fora de uma VM única.
"""

from __future__ import annotations

from dataclasses import dataclass

from ipsec_agent.models import ConnectionName


@dataclass(frozen=True)
class ConnectionConfig:
    conn_name: str           # nome real da conexão no ipsec.conf/swanctl
    initiator_socket: str    # socket VICI do lado que inicia (cu-ns)
    responder_socket: str    # socket VICI do lado que só responde
    local_id: str            # identidade do initiator (ver ipsec.conf)
    remote_id: str           # identidade do responder
    ppk_id: str | None = None  # só n3-urllc-cu-edge — ver kms/crypto.py


# As três conexões N3 ganharam endereço externo próprio na Fase 4 do
# protótipo (10.97.0.11/.12, .21/.22, .31/.32) — não compartilham mais
# 10.97.0.1/10.97.0.2 com a N2, de propósito: conexões que compartilham
# endereço externo sofrem downgrade silencioso de proposta (achado
# confirmado nesta VM, ver ARQUITETURA-PROTOTIPO-COMPLETA.md seção 5.4).
CONNECTIONS: dict[ConnectionName, ConnectionConfig] = {
    ConnectionName.F1_CU_DU: ConnectionConfig(
        conn_name="f1-cu-du",
        initiator_socket="/run/ipsec-cu-ns/charon.vici",
        responder_socket="/run/ipsec-du-ns/charon.vici",
        local_id="10.99.0.1",
        remote_id="10.99.0.2",
    ),
    ConnectionName.N2_CU_EDGE: ConnectionConfig(
        conn_name="n2-cu-edge",
        initiator_socket="/run/ipsec-cu-ns/charon.vici",
        responder_socket="/run/ipsec-5gc-edge-ns/charon.vici",
        local_id="10.97.0.1",
        remote_id="10.97.0.2",
    ),
    ConnectionName.N3_URLLC_CU_EDGE: ConnectionConfig(
        conn_name="n3-urllc-cu-edge",
        initiator_socket="/run/ipsec-cu-ns/charon.vici",
        responder_socket="/run/ipsec-5gc-edge-ns/charon.vici",
        local_id="10.97.0.11",
        remote_id="10.97.0.12",
        ppk_id="ppk-urllc-qkd",
    ),
    ConnectionName.N3_EMBB_CU_EDGE: ConnectionConfig(
        conn_name="n3-embb-cu-edge",
        initiator_socket="/run/ipsec-cu-ns/charon.vici",
        responder_socket="/run/ipsec-5gc-edge-ns/charon.vici",
        local_id="10.97.0.21",
        remote_id="10.97.0.22",
    ),
    ConnectionName.N3_MIOT_CU_EDGE: ConnectionConfig(
        conn_name="n3-miot-cu-edge",
        initiator_socket="/run/ipsec-cu-ns/charon.vici",
        responder_socket="/run/ipsec-5gc-edge-ns/charon.vici",
        local_id="10.97.0.31",
        remote_id="10.97.0.32",
    ),
}
