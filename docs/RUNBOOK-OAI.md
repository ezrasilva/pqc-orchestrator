# Runbook — subir o laboratório OAI do zero

Este documento é o "como ligar tudo de novo" depois de um reboot da VM ou de
parar os processos manualmente. Ele assume que o ambiente já foi montado uma
vez seguindo o `PLANO-IMPLEMENTACAO-OAI.md` (OAI já clonado e compilado em
`~/openairinterface5g`, configs prontos em `~/oai-lab-conf/`).

## 0. O que já é automático

- **Rede virtual** (netns `cu-ns`/`du-ns`, veths, rotas, NAT, regras de
  firewall): recriada sozinha no boot pelo serviço systemd
  `pqc-lab-network.service` (`systemctl status pqc-lab-network.service` pra
  conferir). Só precisa rodar na mão se desconfiar que algo não subiu:
  ```bash
  sudo bash ~/pqc-oran-vm-fixpack/scripts/setup-network.sh
  ```
  (idempotente — pode rodar quantas vezes quiser). Esse é o mesmo script
  instalado em `/usr/local/bin/pqc-lab-network.sh`; se editar um, copia pro
  outro (`sudo cp ~/pqc-oran-vm-fixpack/scripts/setup-network.sh
  /usr/local/bin/pqc-lab-network.sh`), senão a versão antiga volta a valer no
  próximo boot.
- **Open5GS** não sobe sozinho no boot (containers Docker sem `restart:
  always` global garantido após reboot da VM) — confirme/suba manualmente no
  passo 1 abaixo.
- **Importante sobre ordem no boot:** a parte do `setup-network.sh` que monta
  o `5gc-edge-ns` (usado pelo N2/N3, seção 4) precisa que a rede docker
  `5gc_default` já exista, e essa rede só existe depois que o Open5GS sobe
  (passo 1). No boot, o systemd roda o script ANTES disso e pula essa parte
  de propósito (com um aviso no log). **Depois de rodar `docker compose up
  -d` no passo 1, rode `setup-network.sh` de novo** pra completar o resto —
  senão os aliases de N2/N3 da CU (`10.98.0.98`/`172.18.0.99`) não ficam de
  pé e a CU não vai achar a AMF/UPF.

## 1. Subir o Open5GS (5GC)

```bash
cd ~/pqc-oran-local-lab/5gc
docker compose up -d
docker compose ps          # os 11 serviços (nrf, amf, smf, upf, ausf, udm,
                            # udr, pcf, nssf, bsf, mongo, webui) devem estar "Up"
```

WebUI (assinantes) em `http://localhost:9999` via túnel SSH, como já era feito
antes.

**Confira a rede virtual antes de seguir:**
```bash
sudo ip netns list                          # cu-ns e du-ns devem aparecer
docker exec 5gc-amf-1 ip -br addr           # eth1 deve ter 10.98.0.2/24 (core-net)
sudo ip netns exec cu-ns ping -c1 10.98.0.2 # tem que responder (AMF via core-net)
```

Se o ping falhar, rode o `setup-network.sh` do passo 0 — ele recria as rotas
e as exceções de firewall que esse teste depende.

## 2. Subir o RAN (OAI): DU → CU → UE, nessa ordem

**Não pule a ordem** — a UE só sincroniza depois que a DU está com a célula
ativa, e a DU só ativa o rádio depois do F1 Setup com a CU.

### 2.1 DU (dentro de `du-ns`, ela "liga o rádio simulado")

```bash
sudo ip netns exec du-ns \
  ~/openairinterface5g/cmake_targets/ran_build/build/nr-softmodem \
  -O ~/oai-lab-conf/du.conf --rfsim > /tmp/du.log 2>&1 &
```

Espere aparecer no log algo como `[F1AP] Starting F1AP at DU` e as linhas de
`Frame.Slot` — é normal ver "Connect failed: Connection refused" repetido
até a CU subir.

### 2.2 CU (dentro de `cu-ns`, conecta na DU via F1 e na AMF via N2)

```bash
sudo ip netns exec cu-ns \
  ~/openairinterface5g/cmake_targets/ran_build/build/nr-softmodem \
  -O ~/oai-lab-conf/cu.conf > /tmp/cu.log 2>&1 &
```

Confirme no log **antes de seguir pra UE**:
```bash
grep -E "NGSetupResponse|F1 Setup Response" /tmp/cu.log
```
Precisa aparecer as duas linhas:
- `[NGAP] Received NGSetupResponse from AMF` (N2 com a AMF ok)
- `[NR_RRC] DU ... (du-rfsim): sending F1 Setup Response` (F1 com a DU ok)

Se só uma aparecer (ou nenhuma), veja a seção de Troubleshooting abaixo antes
de subir a UE — não adianta, ela nunca vai achar célula.

### 2.3 UE (dentro de `du-ns`, pra alcançar o rfsimulator da DU)

A DU imprime no log dela os parâmetros exatos de frequência/banda que a UE
precisa (variam se você mudar o `.conf`). Pegue com:
```bash
grep "Command line parameters for OAI UE" /tmp/du.log | tail -1
```
Vai ser algo como `-C 3450720000 -r 106 --numerology 1 --band 78 --ssb 516`.
Use exatamente esses valores:

```bash
sudo ip netns exec du-ns \
  ~/openairinterface5g/cmake_targets/ran_build/build/nr-uesoftmodem \
  -O ~/oai-lab-conf/ue.conf --rfsim \
  -C 3450720000 -r 106 --numerology 1 --band 78 --ssb 516 \
  > /tmp/ue.log 2>&1 &
```

## 3. Confirmar que está tudo de pé

```bash
grep "PDU Session Establishment Accept" /tmp/ue.log
# esperado: "... UE IPv4: 10.45.0.2" (ou outro IP da subnet 10.45.0.0/24 = fatia "embb")

sudo ip netns exec du-ns ping -c3 -I oaitun_ue1 10.45.0.1
# esperado: 3 pacotes recebidos, RTT ~15-20ms — confirma plano de controle E de dados
```

Se a UE registrou (ganhou IP) mas o ping de dados falha, confira a seção 4
(IPsec) abaixo — o caminho de N2/N3 depende do `5gc-edge-ns` estar de pé.

## 4. IPsec — enlaces F1 e N2/N3 criptografados

Os dois enlaces do laboratório (F1 CU↔DU, e N2/N3 CU↔borda-do-5GC) rodam
sobre túneis IPsec (strongSwan), conforme `pqc-oran-local-lab/security/README-integration.md`.
Isso é uma camada OPCIONAL por cima do RAN — o RAN funciona sem ela (passos
1-3 acima não dependem disso), mas pra medir rotação de chave via IPsec
(o objetivo do laboratório) ela precisa estar de pé.

**Pré-requisito de PQC (opcional, só pro protótipo SBRC):** o strongSwan
desta VM foi recompilado a partir do pacote-fonte do Ubuntu (mesma versão
6.0.4, patches de segurança mantidos) com `--enable-ml`, e os pacotes
ficaram em `apt-mark hold` pra não serem revertidos por um `apt upgrade`.
Isso **não é necessário** pro RAN nem pro IPsec "normal" (F1/N2N3 com PSK)
descritos nesta seção — só importa se for configurar as conexões PQC do
`ARQUITETURA-PROTOTIPO-COMPLETA.md`. Achado no processo: o plugin
`openssl` já embutido ganha ML-KEM sozinho com a libssl desta VM (3.5.5),
então o compile nem era estritamente obrigatório — ficou como provedor
nativo redundante. Confirme com `swanctl --list-algs | grep -A1 '^ke:'`
(procure `ML_KEM_768` na lista) antes de assumir que falta alguma coisa.

**Pré-requisito de rede:** o `setup-network.sh` do passo 0 já monta o
`5gc-edge-ns` — um netns extra que atua como "borda do 5GC": entra como
membro real das redes Docker `core-net` e `default` (sem NAT), e expõe pra
CU dois aliases via proxy-ARP: `10.98.0.98` (N2, rota até a AMF) e
`172.18.0.99` (N3, rota até o UPF). O túnel IPsec termina *nesse* netns, não
dentro dos containers do Open5GS (ver decisão de arquitetura — não fazia
sentido instalar strongSwan nas imagens `gradiant/open5gs`).

```bash
sudo bash ~/oai-lab-conf/start-all-ipsec.sh
```

Isso sobe **três** instâncias isoladas do strongSwan (uma dentro de cada
netns — `cu-ns`, `du-ns`, `5gc-edge-ns` —, cada uma com seu próprio mount
namespace pra não brigar por `/run`/porta 500 com as outras). O script já
imprime o `ipsec status` visto do lado da CU ao final; espera-se:

```
Security Associations (2 up, 0 connecting):
  n2-cu-edge[...]: ESTABLISHED ..., 10.97.0.1[10.97.0.1]...10.97.0.2[10.97.0.2]
  n2-cu-edge{...}:  INSTALLED, TUNNEL, ... 10.98.0.98/32 === 10.98.0.0/24
    f1-cu-du[...]: ESTABLISHED ..., 10.99.0.1[10.99.0.1]...10.99.0.2[10.99.0.2]
    f1-cu-du{...}:  INSTALLED, TRANSPORT, ...
```

Desde a Fase 3 do protótipo SBRC (ver `ARQUITETURA-PROTOTIPO-COMPLETA.md`
seção 5), o enlace N3 (GTP-U, dado de usuário) não sobe mais junto com o
N2 — foi dividido em três conexões `n3-<fatia>-cu-edge` (`auto=add`,
porque o gatilho de subir cada uma é a fatia aparecer, não o boot do
sistema). Pra subir as três manualmente:
```bash
CU_CHARON_PID=$(sudo ip netns pids cu-ns | while read -r p; do [ "$(ps -p "$p" -o comm=)" = charon ] && echo "$p" && break; done)
sudo nsenter --mount="/proc/${CU_CHARON_PID}/ns/mnt" ipsec up n3-urllc-cu-edge
sudo nsenter --mount="/proc/${CU_CHARON_PID}/ns/mnt" ipsec up n3-embb-cu-edge
sudo nsenter --mount="/proc/${CU_CHARON_PID}/ns/mnt" ipsec up n3-miot-cu-edge
```

**Ordem importa:** suba o IPsec **depois** da rede (passo 0) e **antes** ou
**depois** da CU/DU/UE tanto faz para o F1 (a CU renegocia sozinha), mas se
você reiniciar o IPsec com a CU já registrada na AMF, a associação SCTP do
N2 pode cair por alguns segundos — confira com
`sudo ip netns exec cu-ns cat /proc/net/sctp/assocs` (coluna `ST` deve virar
`3` = ESTABLISHED de novo sozinha; se ficar em `1` = COOKIE_WAIT por mais de
uns 30s, reinicie a CU).

Pra reiniciar do zero (ex: depois de editar `ipsec.conf`):
```bash
sudo bash ~/oai-lab-conf/stop-all-ipsec.sh
sudo bash ~/oai-lab-conf/start-all-ipsec.sh
```

**Importante**: `stop-all-ipsec.sh` mata o processo `charon` com `kill
-9`, mas isso **não limpa** o `xfrm state`/`xfrm policy` que o kernel já
tinha instalado — SAs antigas continuam roteando tráfego de verdade
mesmo com o charon morto, e competem com as políticas que a instância
nova for instalar (encontrado na prática: reconfigurar `n2n3-cu-edge`
pras três conexões `n3-<fatia>-cu-edge` da Fase 3 deixou um SPI antigo
sem mark ainda roteando tráfego real do N3 depois do restart). Se for
mudar a topologia das conexões (não só girar PSK), limpe explicitamente
antes de subir de novo:
```bash
sudo ip netns exec cu-ns ip xfrm policy flush
sudo ip netns exec cu-ns ip xfrm state flush
sudo ip netns exec 5gc-edge-ns ip xfrm policy flush
sudo ip netns exec 5gc-edge-ns ip xfrm state flush
```

Confirmar que o tráfego realmente está criptografado (não só que a SA subiu):
```bash
sudo timeout 5 ip netns exec cu-ns tcpdump -i veth-cu -n      # F1: só ESP, nunca SCTP/GTP puro
sudo timeout 5 ip netns exec cu-ns tcpdump -i veth-cu-n2 -n   # N2/N3: só ESP, nunca SCTP/GTP puro
```

## 5. Parar tudo (fim do experimento ou pra reiniciar limpo)

```bash
sudo bash ~/oai-lab-conf/stop-all-ipsec.sh   # se o IPsec estiver de pé
sudo pkill -f nr-uesoftmodem
sudo pkill -f nr-softmodem
cd ~/pqc-oran-local-lab/5gc && docker compose down   # só se quiser derrubar o 5GC também
```

Não precisa desmontar a rede virtual (netns/veth/iptables) — ela é
idempotente e o systemd cuida dela no próximo boot.

## Arquivos relevantes

| O quê | Onde |
|---|---|
| Binários compilados | `~/openairinterface5g/cmake_targets/ran_build/build/{nr-softmodem,nr-uesoftmodem}` |
| Configs DU/CU/UE (editáveis) | `~/oai-lab-conf/{du,cu,ue}.conf` |
| Script de rede (fonte) | `~/pqc-oran-vm-fixpack/scripts/setup-network.sh` |
| Script de rede (instalado, rodado no boot) | `/usr/local/bin/pqc-lab-network.sh` |
| Unit systemd da rede | `/etc/systemd/system/pqc-lab-network.service` |
| Docker compose do 5GC | `~/pqc-oran-local-lab/5gc/docker-compose.yaml` |
| Config da AMF (N2) | `~/pqc-oran-local-lab/5gc/config/amf.yaml` |
| Config do UPF (N3) | `~/pqc-oran-local-lab/5gc/config/upf.yaml` |
| Assinante de teste da UE | IMSI `001010000000004`, as três fatias (embb/urllc/miot, sst=1/2/3, sd=ffffff, todas com `default_indicator: true`) — cadastrado no Mongo do Open5GS, credenciais em `~/oai-lab-conf/ue.conf` |
| Configs IPsec, um por lado (cu-ns = initiator, du-ns/edge-ns = responders passivos) | `~/oai-lab-conf/{ipsec-cu,ipsec-du,ipsec-edge}/{ipsec.conf,ipsec.secrets}` |
| Scripts de subida/parada do IPsec | `~/oai-lab-conf/{start-all-ipsec.sh,stop-all-ipsec.sh,start-ipsec-side.sh}` |
| Templates originais de IPsec (referência) | `~/pqc-oran-local-lab/security/{ipsec-f1.conf.example,ipsec-n2n3.conf.example,README-integration.md}` |

### Endereços da CU no enlace N2/N3 (via `5gc-edge-ns`)

| Endereço | Papel | Onde vive |
|---|---|---|
| `10.97.0.1` / `10.97.0.2` | Link direto cu-ns ↔ 5gc-edge-ns ("WAN" simulada), endpoint do túnel IPsec tunnel-mode | `veth-cu-n2` / `veth-edge-cu` |
| `10.98.0.98` | Alias da CU pro N2 (NGAP/SCTP com a AMF), roteado por proxy-ARP através do 5gc-edge-ns | alias `/32` em `veth-cu-n2` |
| `172.18.0.99` | Alias da CU pro N3 (GTP-U com o UPF), roteado por proxy-ARP através do 5gc-edge-ns | alias `/32` em `veth-cu-n2` |
| `10.98.0.99` / `172.18.0.90` | Endereços do próprio `5gc-edge-ns` nas redes docker `core-net`/`default` | `veth-edge-core` / `veth-edge-def` |

## Troubleshooting — problemas já vistos e a causa raiz

**NGAP não conecta (`SCTP Connect failed: Connection refused`) mesmo com o
ping cu-ns → AMF funcionando:**
A AMF só aceita a conexão NGAP na interface que está configurada em
`amf.yaml` → `ngap.server.dev`. Isso **já está corrigido** pra apontar pra
`eth1` (a interface do container na rede `core-net`, IP `10.98.0.2`) — se
algum dia voltar a dar esse erro, confira se esse arquivo não foi sobrescrito
de volta pra `eth0`.

**Ping cu-ns → AMF (ou → UPF) não passa mesmo com rota e MASQUERADE
configurados:**
Docker 27+/29+ adiciona por padrão uma regra na tabela `raw`/`PREROUTING`
que dropa qualquer pacote destinado a um IP de container que não entre pela
própria bridge Docker (proteção anti-spoofing). Isso quebra esse laboratório
porque o CU chega no container via um veth externo (`veth-host-cu`), não pela
bridge. O `setup-network.sh` já injeta uma exceção pontual pra essa interface
em `iptables -t raw`, tanto pra `core-net` (N2/AMF) quanto pra rede `default`
do Docker (N3/UPF). Se o Docker for atualizado de novo e voltar a bloquear,
comece a depuração checando os contadores dessa tabela:
```bash
sudo iptables -t raw -L PREROUTING -n -v --line-numbers | grep DROP
```

**UE registra (ganha IP) mas não passa tráfego de dados:**
O UPF fica só na rede `default` do Docker (não na `core-net` — colocá-lo lá
faz o Open5GS anunciar `127.0.0.1` no PFCP e o SMF rejeita, isso é
proposital, ver comentário em `docker-compose.yaml`). O F-TEID de N3 que o
UPF anuncia pro gNB é o IP dele nessa rede `default` (`172.18.0.x`), então o
`cu-ns` precisa da mesma rota/NAT/exceção de firewall que tem pro `core-net`,
só que apontando pra `172.18.0.0/16`. Já está no `setup-network.sh`.

**UE não sincroniza / trava em `Assertion (0) failed! ... Undefined
Frequency Range for frequency 0 Hz`:**
Faltou passar os parâmetros de RF na linha de comando da UE (`-C`, `-r`,
`--numerology`, `--band`, `--ssb`). Eles não vêm do `.conf` — pegue os
valores exatos no log da DU (seção 2.3 acima).

**N2 nunca estabelece SCTP com IPsec ligado (fica preso em `COOKIE_WAIT`,
`SctpChecksumErrors` sobe em `/proc/net/sctp/snmp` dentro de `cu-ns`), mesmo
com `ipsec status` mostrando o túnel `ESTABLISHED`:**
Esse foi o bug mais chato de achar. Interfaces `veth` fazem *checksum
offload* pro SCTP (CRC32c) assumindo que o pacote nunca sai de verdade da
máquina — quando ele atravessa decrypt/roteamento entre namespaces (o
caminho do N2/N3 via `5gc-edge-ns`), o checksum "prometido" nunca é
calculado de verdade e o kernel do lado que recebe descarta o pacote como
corrompido, silenciosamente (o `tcpdump` não valida esse checksum, então o
pacote *parece* normal na captura, o que engana bastante). O `setup-network.sh`
já desliga `tx-checksum-sctp` (via `ethtool -K ... tx off`) em todas as
interfaces do caminho N2/N3 (`veth-cu-n2`, `veth-edge-cu`, `veth-edge-core`,
`veth-edge-def`, `veth-core-edge`, `veth-def-edge`). Se isso voltar a
acontecer (por exemplo depois de recriar alguma dessas interfaces na mão),
o diagnóstico é `cat /proc/net/sctp/snmp` dentro do netns e olhar
`SctpChecksumErrors` — se estiver subindo, é isso.

**F1 e N2/N3 tentavam usar MASQUERADE (NAT) através do host antes da versão
atual — por que mudou pro `5gc-edge-ns`:**
A primeira versão do N2/N3 roteava `cu-ns` pro Docker via NAT no host
(mesma lógica do F1). Funcionava pra ICMP e até pro GTP-U (UDP tolera
melhor), mas quebrava o SCTP do N2 de duas formas: (1) o F-TEID de N3 que o
UPF anuncia é o IP dele mesmo, que o `cu-ns` NÃO alcançava sem alias
roteado — resolvido com proxy-ARP; (2) o próprio NAT, combinado com o
checksum offload acima, corrompia o SCTP do N2 de forma consistente. A
solução final (`5gc-edge-ns` como membro real das redes Docker, sem NAT,
com proxy-ARP pros aliases da CU) resolve as duas coisas de uma vez. Se você
encontrar essa versão antiga do `setup-network.sh` (rotas via `10.100.0.1`
com MASQUERADE pro N2/N3) num backup antigo, não reaproveita — use a atual.

**Reiniciei o strongSwan (`stop-all-ipsec.sh` + `start-all-ipsec.sh`) e a
UE não registra mais / CU não recebe mais `Initial UE Message`:**
A AMF detecta a queda momentânea da associação N2 durante o restart do
IPsec e derruba o contexto do gNB (log da AMF: `gNB-N2[...] connection
refused!!! [Removed] Number of gNBs is now 0`). A CU não percebe sozinha
que a AMF esqueceu dela. Reinicie a CU (`sudo pkill -9 -f "nr-softmodem -O
.../cu.conf"` e suba de novo) pra forçar um NG Setup do zero — depois disso
o registro da UE volta a funcionar normalmente.

**Processo antigo de DU/CU/UE não morre com `pkill -f` (o padrão de
comando bate, mas o processo continua rodando):** já aconteceu várias
vezes nesta VM — `pkill -9 -f "<padrão>"` às vezes simplesmente não mata o
processo mesmo com o padrão correto (não é erro de digitação, é algo do
ambiente/shell). Sempre confirme com `ps aux | grep <config>.conf` depois
de um `pkill` antes de subir uma instância nova — se o processo antigo
ainda estiver lá, mata por PID explícito (`sudo kill -9 <pid>`). Subir uma
instância nova sem matar a antiga causa erro de porta/socket já em uso
(ex: `Assertion (gtpInst > 0) failed!` na DU) ou, pior, duas instâncias
competindo pelo mesmo rádio simulado.

**UE pede PDU session de uma fatia além da `embb` e recebe "mismatch for
allowed NSSAI" (fatia nunca chega a ser requisitada de verdade):**
A UE do OAI (`nr-uesoftmodem`) **não implementa `Requested NSSAI`** no
Registration Request (IE opcional do 5G NAS) — sem isso, o AMF só libera
(`Allowed NSSAI`) as fatias marcadas como `default_indicator: true` na
assinatura do Mongo, não todas as fatias que o assinante tem. Pra UE pedir
sessão PDU em mais de uma fatia na mesma UE (ver `ue.conf`, campo
`pdu_sessions` com múltiplas entradas), marque **todas** as fatias
relevantes do assinante como default:
```bash
docker exec 5gc-mongo-1 mongosh open5gs --quiet --eval '
db.subscribers.updateOne(
  { imsi: "001010000000004" },
  { $set: { "slice.1.default_indicator": true, "slice.2.default_indicator": true } }
);'
```
(índices do array `slice` — ajuste conforme a ordem real no documento).
Também confirme que `snssaiList` no `cu.conf`/`du.conf` anuncia todas as
fatias (`{ sst = 1; sd = 0xffffff; }, { sst = 2; ... }, { sst = 3; ... }`),
senão a célula nem propaga suporte às fatias extras pro NGAP.

**UE registra em múltiplas fatias, mas só a `embb` passa tráfego de dados
— as outras (`urllc`, `miot`) dão timeout de ping:**
Quase certamente não é bug de rede — é o alvo do ping errado. A UPF usa
**uma única interface TUN** (`ogstun`, endereço `10.45.0.1/16`) pras três
sub-redes de fatia, não uma interface por fatia. Os "gateways" que o
`smf.yaml` declara por DNN (`10.45.1.1` pra `urllc`, `10.45.2.1` pra
`miot`) são só contabilidade interna da SMF pra alocação de IP — não são
endereços reais bindados em nenhuma interface da UPF, então pingar esses
IPs sempre vai dar timeout (ou um ICMP Redirect estranho vindo de
`10.45.0.1`, que é o sintoma real se você capturar com tcpdump). Pingue
`10.45.0.1` (o endereço de verdade) a partir de qualquer fatia — funciona
normalmente, confirmado com as três fatias simultâneas.
