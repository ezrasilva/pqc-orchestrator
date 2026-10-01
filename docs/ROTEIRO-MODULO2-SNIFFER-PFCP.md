# Roteiro de implementação — Módulo 2 (Sniffer PFCP) e integração com Módulos 3/4

Opção escolhida: sniffer passivo de PFCP (não mexe na Open5GS), confirmado
viável via leitura direta do código-fonte da Open5GS — o S-NSSAI é o IE 257
do PFCP (`OGS_PFCP_S_NSSAI_TYPE`, `lib/pfcp/message.h`) e a SMF o envia na
Session Establishment Request pra toda sessão 5G (`src/smf/n4-build.c`,
`smf_n4_build_session_establishment_request`, condição `if (!sess->epc)`).

**Validado ao vivo** (não só por leitura de código) — ver nota no final da
seção 2b.

## 0. Correção de um detalhe antes de começar

~~No seu esboço anterior, o mapeamento SST estava certo (SST 2 = URLLC,
SST 1 = eMBB, conforme TS 23.501) — mas o ARQUITETURA-ORQUESTRADOR.md que
fizemos antes tinha isso invertido.~~ **Já corrigido** — o
`ARQUITETURA-ORQUESTRADOR.md` já está com SST 2 = URLLC / SST 1 = eMBB
desde a sessão anterior (ver seção 3 daquele documento). Nenhuma ação
pendente aqui, só manter os dois documentos consistentes daqui pra frente.

## 1. Onde o Módulo 2 se encaixa

```
[SMF] <--- N4/PFCP (udp/8805) ---> [UPF]
   ^                                  ^
   |                                  |
   +---------- Módulo 2 ------------- +
   (sniffer passivo na interface N4,
    ou no loopback se SMF/UPF rodam
    na mesma VM)
        |
        v
   (TEID, S-NSSAI, SEID) -----> Módulo 3 (BPF map: TEID -> mark)
                          \
                           -----> Módulo 4 (garante que a SA com
                                   aquele mark existe, dispara
                                   negociação IKEv2 se não existir)
```

O Módulo 2 não fica no caminho do tráfego de dados (não é inline) — só
observa o N4 e alimenta as tabelas dos módulos 3 e 4. Isso é importante:
se o sniffer cair ou atrasar, o pior caso é uma sessão nova demorar a
ganhar seu mark/SA — o tráfego de sessões já classificadas continua
normalmente, porque a classificação já está no kernel (BPF map + XFRM).

**Nota sobre a VM de laboratório atual**: SMF e UPF são containers Docker
na mesma rede (`5gc_default`, bridge `br-b4c4c468ea0f`) — o tráfego N4
nunca sai pro host "de verdade", mas passa pela bridge Linux, então dá
pra capturar com `tshark -i br-<id-da-bridge>` sem precisar entrar em
nenhum container. Confirmado funcionando (ver seção 2b).

## 2. Sequência de implementação do sniffer

### 2a. Confirmar visualmente antes de escrever parser algum

```bash
sudo tshark -i lo -f "udp port 8805" -Y "pfcp" -V
```

(troque `lo` pela interface real se SMF/UPF não estiverem no mesmo host).
Dispare uma sessão PDU pelo UE do OAI e confirme, na saída do tshark, que
a Session Establishment Request carrega o IE **S-NSSAI** com o SST
esperado, e que a Response (ou a própria Request, dependendo de como a
UPF aloca) carrega o **F-TEID**. Isso valida a hipótese com tráfego real
antes de investir tempo no parser — não pule essa etapa.

### 2b. Parser mínimo, escrito à mão (não usar uma lib pesada de PFCP)

PFCP IEs são TLV simples: 2 bytes tipo, 2 bytes tamanho, valor. Você só
precisa de dois tipos de IE:

- **S-NSSAI** (tipo 257): 4 bytes — 1 byte SST + 3 bytes SD.
- **F-TEID** (tipo 21): flags (1 byte) + TEID (4 bytes) + endereço IPv4/v6
  conforme as flags.

Estrutura sugerida do script (`pfcp_sniffer.py`, usando `scapy` só pra
captura bruta de pacotes, sem depender de dissector de PFCP pronto):

```python
from scapy.all import sniff, UDP, IP
import struct

# SEID -> {"s_nssai": (sst, sd) | None, "teid": int | None}
sessions = {}

def parse_ies(payload):
    ies = {}
    i = 0
    while i + 4 <= len(payload):
        ie_type, ie_len = struct.unpack("!HH", payload[i:i+4])
        value = payload[i+4:i+4+ie_len]
        ies[ie_type] = value
        i += 4 + ie_len
    return ies

def handle_pfcp(pkt):
    payload = bytes(pkt[UDP].payload)
    if len(payload) < 8:
        return
    msg_type = payload[1]
    # cabeçalho PFCP com SEID presente (S flag) tem 12 bytes antes das IEs
    has_seid = payload[0] & 0x01
    header_len = 12 if has_seid else 8
    seid = struct.unpack("!Q", payload[4:12])[0] if has_seid else None
    ies = parse_ies(payload[header_len:])

    entry = sessions.setdefault(seid, {"s_nssai": None, "teid": None})

    if 257 in ies:  # S-NSSAI
        sst, sd = ies[257][0], int.from_bytes(ies[257][1:4], "big")
        entry["s_nssai"] = (sst, sd)

    if 21 in ies:  # F-TEID (dentro de um Created PDR, ver nota abaixo)
        flags = ies[21][0]
        teid = struct.unpack("!I", ies[21][1:5])[0]
        entry["teid"] = teid

    if entry["s_nssai"] and entry["teid"]:
        emit_mapping(seid, entry["teid"], entry["s_nssai"])

SST_TO_MARK = {2: 0x10, 1: 0x20, 3: 0x30}  # URLLC, eMBB, mIoT

def emit_mapping(seid, teid, s_nssai):
    sst, sd = s_nssai
    mark = SST_TO_MARK.get(sst)
    if mark is None:
        print(f"SEID={seid:#x} TEID={teid:#x} SST={sst} sem perfil definido — ignorando")
        return
    print(f"SEID={seid:#x} TEID={teid:#x} SST={sst} SD={sd:#x} -> mark={mark:#x}")
    # próximo passo: escrever no BPF map (Módulo 3) e garantir SA (Módulo 4)

sniff(filter="udp port 8805", prn=handle_pfcp, store=False)
```

**Nota importante de implementação**: o F-TEID nem sempre vem solto no
nível superior da mensagem — ele normalmente está **dentro** de um
Grouped IE (`Created PDR`, tipo 19, na Response, ou `Create PDR`, tipo 1,
na Request). Um Grouped IE é só mais IEs TLV aninhados dentro do `value`
de um IE externo — então `parse_ies` precisa ser chamado recursivamente
quando encontrar tipo 19 ou tipo 1. Ajuste o parser pra isso na primeira
rodada de testes (é o tipo de detalhe que só aparece quando você compara
a saída do seu parser com o `tshark -V` lado a lado).

**Validado ao vivo nesta VM** (captura real com `tshark` na bridge do
Docker durante uma sessão PDU de verdade do OAI, não só leitura de
código):
- Session Establishment Request: IE 257 presente, `SST: 01, SD: ffffff`
  (sessão de teste na fatia eMBB).
- F-TEID na Request vem só com a flag `CH` (CHOOSE) ligada — a UPF ainda
  vai escolher o TEID, o valor real não está aqui ainda.
- F-TEID definitivo (`TEID: 0x000058d7`) aparece na **Response**, dentro
  de `Created PDR` (confirma o Grouped IE).
- O TEID capturado na PFCP bate, byte a byte, com o TEID visto depois no
  tráfego GTP-U real na interface N3 (conferido com `tcpdump -xx`) —
  inclusive com a flag de extensão (E=1) ligada no header GTP-U, e o TEID
  continuando nos bytes 4-7 mesmo assim.

### 2c. Casar Request e Response pelo SEID, não assumir uma mensagem só

O S-NSSAI vem na Request (SMF→UPF); o F-TEID definitivo normalmente vem
confirmado na Response (UPF→SMF), correlacionado pelo mesmo SEID. Por
isso o dicionário `sessions` acumula os dois lados antes de emitir o
mapeamento — não tente extrair tudo de um pacote único.

### 2d. Tratar modificação e remoção de sessão (não só criação)

Duas situações que vão aparecer no seu ambiente de teste e que o roteiro
acima ainda não cobre:

- **PFCP Session Modification Request** (handover, atualização de QoS)
  pode alterar ou adicionar PDRs — se seu script só escuta Establishment,
  vai perder essas atualizações. **Confirmado ao vivo**: nesta VM, o
  F-TEID de **downlink** (o TEID que o CU usa pra receber tráfego vindo
  da UPF) só aparece numa Session Modification Request logo depois da
  Establishment — não vem na troca inicial, porque a UPF só aprende o
  F-TEID do lado RAN depois que o N2 Setup termina e a SMF repassa isso
  via PFCP. Um sniffer que só escuta Establishment perde essa metade do
  par de TEIDs (uplink vem na Establishment, downlink vem na
  Modification).
- **PFCP Session Deletion Request** — quando a UE desconecta, o TEID pode
  ser **reaproveitado** por outra sessão depois. Se o Módulo 3 não limpar
  a entrada correspondente no BPF map na deleção, um TEID reciclado pode
  herdar o mark de uma fatia errada. Trate a Deletion Request como
  gatilho pra remover a entrada do BPF map, não só ignorá-la.

## 3. Interface entre Módulo 2 e Módulo 3 (BPF map)

Pra não acoplar o sniffer Python ao eBPF diretamente, defina um contrato
simples: o `emit_mapping()` acima chama uma função `update_bpf_map(teid,
mark)` que, na Fase 2, pode ser só um `subprocess.run(["bpftool", "map",
"update", ...])`, e mais tarde (Fase 4) evolui pra uma chamada direta via
`libbpf`/`pyroute2` se a latência de atualização via `bpftool` CLI se
mostrar alta demais. Comece simples — `bpftool` via subprocess é
suficiente pra validar o mecanismo inteiro antes de otimizar.

## 4. Interface entre Módulo 2 e Módulo 4 (garantir a SA)

Quando `emit_mapping()` vê uma fatia nova pela primeira vez, ele deve
confirmar que a Security Association com aquele mark já existe (via
`swanctl --list-sas` ou uma consulta VICI) — se não existir, dispara a
negociação (`swanctl --initiate --child <nome-da-fatia>`). Nas Fases 2–3
isso pode ser manual (você mesmo sobe as duas SAs antes do teste); só na
Fase 4 esse gatilho automático entra.

## 5. Checklist de validação (antes de avançar de fase)

- [x] `tshark -Y pfcp -V` confirma S-NSSAI e F-TEID presentes no tráfego
      real do seu OAI+Open5GS. **Feito** — ver nota na seção 2b.
- [ ] `pfcp_sniffer.py` roda em paralelo com uma sessão URLLC e uma eMBB
      simultâneas, e imprime dois mapeamentos TEID→mark diferentes e
      corretos (cheque o SST impresso contra o que você configurou na UE).
- [ ] Desconectar e reconectar uma UE não deixa uma entrada "fantasma" no
      dicionário `sessions` nem no BPF map (testar o caminho de deleção).
- [ ] Só depois disso, conectar `update_bpf_map()` de verdade e confirmar
      com `bpftool map dump` que o mark aparece batendo com o que o
      script decidiu.

## 6. Onde isso entra no roteiro geral

Isso é o detalhamento da "Fase 2" do plano de 4 fases que você já tinha
(Baseline → Classificação eBPF → Cifragem granular manual → Hibridização
PQC+QKD). O sniffer PFCP é o gatilho que alimenta o BPF map da Fase 2 —
sem ele funcionando primeiro (com mapeamento manual/hardcoded, se
necessário, pra não bloquear o teste do eBPF em si), não faz sentido
avançar pra Fase 3.
