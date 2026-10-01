# prototype

Protótipo de 4 módulos pra diferenciação PQC+QKD por fatia descrito em
[`../docs/ARQUITETURA-PROTOTIPO-COMPLETA.md`](../docs/ARQUITETURA-PROTOTIPO-COMPLETA.md)
(leia esse documento primeiro). Mira SBRC 2027 — é uma versão de nó único
do que [`../docs/ARQUITETURA-ORQUESTRADOR.md`](../docs/ARQUITETURA-ORQUESTRADOR.md)
desenha de forma distribuída.

## Estado atual: Módulo 2 (sniffer PFCP) e Módulo 3 (classificador eBPF/TC) implementados e validados; achado crítico aberto na integração com o Módulo 4

`pfcp_sniffer/` escuta udp/8805 (passivo, não entra no caminho do
tráfego), casa S-NSSAI (Establishment Request) com os TEIDs de
uplink/downlink (que chegam em mensagens diferentes — ver achado abaixo)
pelo par de SEID CP/UP, e emite um `SliceMapping` por sessão completa.

Testado de duas formas:
- **Replay determinístico** contra uma captura real salva
  (`pfcp_sniffer/tests/fixtures/sample_session.pcap`, três sessões
  simultâneas embb/urllc/miot) — `pytest`, sem precisar de root nem do
  laboratório de pé.
- **Captura ao vivo** contra a bridge Docker real durante um restart de
  UE de verdade — confirma o `scapy.sniff()` funcionando ponta a ponta,
  não só o parser isolado.

```bash
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
pytest                              # replay da captura salva

# captura ao vivo (precisa de root e do laboratório de pé — ver RUNBOOK-OAI.md)
sudo .venv/bin/python3 -c "
from pfcp_sniffer.sniffer import PfcpSniffer
PfcpSniffer('br-<id-da-bridge-core-net-ou-default>').run()
"
```

Estrutura:
```
pfcp_sniffer/
  models.py          # SliceMapping, FTeid, SST_TO_MARK
  parser.py           # extração via dissector PFCP nativo do scapy
  session_tracker.py   # correlação CP-SEID/UP-SEID, emite quando a sessão completa
  sniffer.py           # scapy.sniff() na porta 8805, liga tudo
  tests/
    fixtures/sample_session.pcap   # captura real, não sintética
    test_session_tracker.py
```

`ebpf_classifier/` (Módulo 3) lê o TEID do GTP-U e marca o pacote — ver
seção 4 do documento de arquitetura e
[`ebpf_classifier/README.md`](ebpf_classifier/README.md) pro estado
completo, incluindo 5 testes determinísticos e validação contra tráfego
real. **Achado crítico ainda em aberto**: confirmado contra o
laboratório real que marcar via TC egress na interface do N3 não
influencia a seleção de SA do XFRM pra tráfego gerado localmente pela
CU — precisa de correção de topologia antes do Módulo 4 poder consumir
o mark como descrito na arquitetura original (detalhes no README do
módulo). O Módulo 4 (Agente de Segurança) reaproveita
`../orchestrator/ipsec_agent/` quase sem mudança, não precisa de código
novo — mas depende desse achado ser resolvido primeiro.

## Dois bugs reais encontrados e corrigidos aqui (não no rascunho do roteiro)

1. **Header PFCP com SEID tem 16 bytes, não 12.** O pseudocódigo original
   do roteiro (`docs/ROTEIRO-MODULO2-SNIFFER-PFCP.md`) nunca tinha sido
   rodado contra tráfego real — usar o dissector nativo do scapy em vez
   de um parser TLV escrito à mão evita essa classe inteira de bug.
2. **SEID do cabeçalho não é um ID de sessão único** — é o SEID "de quem
   vai receber a mensagem" (CP ou UP), os dois lados têm valores
   diferentes pra mesma sessão. A correlação certa usa o IE F-SEID
   (payload) — ver docstring de `session_tracker.py`. Sem isso, o
   tracker nunca casava a Modification Request com a sessão certa.
3. **(Bônus, achado no mesmo processo)**: uma sessão tem vários FAR, um
   deles aponta `Destination Interface = CP-function` (a UPF notificando
   a própria SMF via GTP-U) — pegar o primeiro "Outer Header Creation" da
   árvore sem checar pra qual interface ele serve extrai o TEID/IP
   errado. `extract_downlink_fteid` só aceita o que estiver no mesmo
   grupo que `Destination Interface = Access`.

Todos os três têm teste de regressão dedicado em
`pfcp_sniffer/tests/test_session_tracker.py`.
