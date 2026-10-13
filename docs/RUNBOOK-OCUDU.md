# Runbook — subir o laboratório OCUDU do zero

> Este documento substitui o antigo `RUNBOOK-OAI.md`, que descrevia o
> procedimento do protótipo SBRC (Fases 1-5, rodou em OAI de verdade —
> ver `PLANO-IMPLEMENTACAO-OAI.md`/`ARQUITETURA-PROTOTIPO-COMPLETA.md`).
> O **pipeline de avaliação experimental** (`evaluation/`, cenários 0-4 —
> o que este runbook descreve) foi portado de OAI pra **OCUDU**
> (gNB combinado CU+DU) **+ srsRAN_4G** (`srsue`, 3 processos de UE)
> depois disso (commit `4ed5048`). Este runbook descreve o procedimento
> real de hoje, confirmado contra o laboratório ao vivo.

Este documento é o "como ligar tudo de novo" depois de um reboot da VM ou de
parar os processos manualmente.

## 0. Topologia real (netns)

| netns | O que roda lá |
|---|---|
| `cu-ns` | gNB combinado CU+DU (`ocudu/build/apps/gnb/gnb`), o broker ZMQ (`multi_ue_scenario.py`, multiplexa o rádio simulado entre as 3 UEs), os 3 processos `srsue` (camada rádio/PHY — compartilham o namespace pra o ZMQ broker conseguir falar com todos), e o `charon`/strongSwan do lado CU (N2/N3) |
| `ue-urllc` / `ue-embb` / `ue-miot` | Só a interface `tun_srsue` (plano de dados) de cada UE — cada `srsue` cria sua própria TUN dentro de `cu-ns` e a **move** pra esse netns dedicado via a opção nativa `netns = ue-<fatia>` no respectivo `ue_<fatia>.conf` (ver `~/ocudu-lab/ue_urllc.conf` etc). O processo `srsue` em si continua rodando em `cu-ns`; só a TUN é isolada por fatia. |
| `5gc-edge-ns` | "Borda do 5GC" — membro real das redes Docker do Open5GS (sem NAT, via proxy-ARP), onde o túnel IPsec de N2/N3 termina do lado do core. `charon`/strongSwan do lado borda roda aqui. |
| `du-ns` | Existe (criado pelo script de rede), mas **sem uso hoje** — vestígio do design anterior (CU/DU separados) ou reservado pra um split F1 futuro. OCUDU neste laboratório roda CU+DU como processo único dentro de `cu-ns`. |

**Rede virtual** (os netns acima, veths, rotas, NAT, firewall): recriada
sozinha no boot pelo serviço systemd `pqc-lab-network.service`
(`systemctl status pqc-lab-network.service` pra conferir). Rodar na mão só
se desconfiar que algo não subiu:
```bash
sudo bash ~/pqc-oran-vm-fixpack/scripts/setup-network.sh
```
(idempotente). Mesmo script instalado em `/usr/local/bin/pqc-lab-network.sh`
— se editar um, copia pro outro, senão a versão antiga volta a valer no
próximo boot.

**Importante sobre ordem no boot:** a parte do `setup-network.sh` que monta
o `5gc-edge-ns` precisa que a rede docker `5gc_default` já exista, e essa
rede só existe depois que o Open5GS sobe (passo 1 abaixo). No boot, o
systemd roda o script ANTES disso e pula essa parte de propósito. **Depois
de rodar `docker compose up -d` no passo 1, rode `setup-network.sh` de
novo** pra completar o resto.

## 1. Subir o Open5GS (5GC)

```bash
cd ~/pqc-oran-local-lab/5gc
docker compose up -d
docker compose ps          # os 11 serviços (nrf, amf, smf, upf, ausf, udm,
                            # udr, pcf, nssf, bsf, mongo, webui) devem estar "Up"
```

WebUI (assinantes) em `http://localhost:9999` via túnel SSH.

**Confira a rede virtual antes de seguir:**
```bash
sudo ip netns list                          # cu-ns, 5gc-edge-ns, du-ns (sem uso), ue-urllc/embb/miot
docker exec 5gc-amf-1 ip -br addr           # eth1 deve ter 10.98.0.2/24 (core-net)
sudo ip netns exec cu-ns ping -c1 10.98.0.2 # tem que responder (AMF via core-net)
```
Se o ping falhar, rode o `setup-network.sh` do passo 0.

## 2. Subir o RAN (OCUDU) — gNB + broker + 3 UEs, tudo de uma vez

Diferente do fluxo manual do OAI (DU → CU → UE em sequência, cada um
inspecionado na mão), o OCUDU sobe como um **processo único** (CU+DU
combinados) e a sincronização ZMQ fria entre ele e as 3 UEs é instável o
bastante pra justificar um watchdog com retry automático em vez de caçar
a causa exata a cada vez:

```bash
sudo bash ~/ocudu-lab/watchdog_start.sh
```

O script: mata qualquer resquício (gNB/broker/UEs — **acabou sendo
necessário matar todas as peças, não só uma**, quando a sincronização
falha), sobe o gNB, espera a AMF confirmar `gNB-N2 accepted` (até 36s),
sobe o broker ZMQ e as 3 UEs, e espera 3 sessões PFCP na UPF (até 40s) —
sinal objetivo de que as 3 UEs completaram registro + sessão PDU. Se não
sincronizar, mata tudo e tenta de novo (até 8 tentativas). Imprime
`=== SUCESSO na tentativa N (Xs) ===` no fim.

Binários/configs:

| O quê | Onde |
|---|---|
| Binário do gNB | `~/ocudu/build/apps/gnb/gnb` |
| Config do gNB | `~/ocudu-lab/gnb.yml` |
| Binário das UEs | `~/srsRAN_4G/build/srsue/src/srsue` |
| Configs das UEs | `~/ocudu-lab/ue_{urllc,embb,miot}.conf` |
| Broker ZMQ (multiplexa o rádio simulado entre as 3 UEs) | `~/ocudu-lab/multi_ue_scenario.py` |
| Logs | `/tmp/gnb_combined.log`, `/tmp/ue_{urllc,embb,miot}.log`, `/tmp/broker.log` |

## 3. Confirmar que está tudo de pé

```bash
sudo ip netns exec ue-urllc ping -c3 -I tun_srsue 10.45.1.1
sudo ip netns exec ue-embb  ping -c3 -I tun_srsue 10.45.0.1
sudo ip netns exec ue-miot  ping -c3 -I tun_srsue 10.45.2.1
# esperado: 0% de perda nas 3, RTT ~40-70ms (ZMQ é CPU-bound, não um link real)
```

Se alguma falhar mas as outras passarem, não é obrigatoriamente bug — ver
seção de Troubleshooting (achado real: sob carga de CPU alta, a eMBB
especificamente tem uma falha transitória de resolução de interface,
mitigada com retry no lado do coletor).

## 4. IPsec — enlace N2/N3 criptografado

O enlace N2/N3 (CU ↔ borda-do-5GC) roda sobre túneis IPsec (strongSwan).
F1 **não é protegido** nesta topologia (CU+DU combinados no mesmo
processo, sem enlace de rede real entre eles).

> **Nota sobre nomenclatura**: os scripts e diretórios abaixo vivem em
> `~/oai-lab-conf/` — nome herdado de quando o IPsec de N2/N3 foi montado
> originalmente, no protótipo em OAI (ver `PLANO-IMPLEMENTACAO-OAI.md`).
> O conteúdo é genérico (fala com qualquer CU via `cu-ns`/`5gc-edge-ns`,
> não é específico de OAI nem de OCUDU) e continua sendo o que o
> pipeline de avaliação usa de verdade hoje — não renomeado pra não quebrar caminhos
> hard-coded em `evaluation/lab_control.py` (`LIVE_LAB_IPSEC_DIR`) e em
> todos os scripts `.sh` que o referenciam pelo nome atual.

**Pré-requisito de PQC**: strongSwan 6.0.4 desta VM, plugin `openssl`
embutido já ganha ML-KEM com a libssl 3.5.5. Confirme com
`swanctl --list-algs | grep -A1 '^ke:'` (procure `ML_KEM_768`/`ML_KEM_512`).

Subir as duas instâncias de charon (uma por netns, mount namespace
isolado — não existe mais enlace F1 pra proteger, o gNB combinado roda
CU+DU num processo só):
```bash
sudo bash ~/oai-lab-conf/start-all-ipsec.sh
```
(chama `start-ipsec-side.sh cu-ns` e `start-ipsec-side.sh 5gc-edge-ns`
por baixo — dá pra rodar cada lado separado também, se precisar.)

Carregar e iniciar as três conexões N3 (urllc/embb/miot, PQC/PPK reais):
```bash
sudo bash ~/oai-lab-conf/load-and-initiate-n3.sh
```
Espera-se ver os três perfis PQC, incluindo `/PPK` na linha da URLLC:
```
n3-miot-cu-edge:  ... AES_GCM_16-128/PRF_HMAC_SHA2_256/ML_KEM_512
n3-embb-cu-edge:  ... AES_GCM_16-256/PRF_HMAC_SHA2_256/ML_KEM_512
n3-urllc-cu-edge: ... AES_GCM_16-128/PRF_HMAC_SHA2_256/ML_KEM_768/PPK
```

Reaplicar as marcas de classificação por fatia (iptables mangle) — o jeito
prático é via o helper Python, que já lê o TEID real de cada fatia no log
do gNB e monta os argumentos:
```bash
cd ~/Desktop/pqc-orchestrator/evaluation
sudo .venv/bin/python3 -c "
import sys; sys.path.insert(0,'.'); sys.path.insert(0,'../orchestrator'); sys.path.insert(0,'..')
from evaluation import lab_control
print(lab_control.capture_and_apply_slice_marks())
"
```
(o script de baixo nível, `~/oai-lab-conf/apply-n3-slice-marks.sh
<netns-da-cu> <teid_urllc> <teid_embb> <teid_miot>`, precisa dos TEIDs em
hex como argumento — normalmente não vale a pena rodar à mão.)

**Reiniciar do zero** (ex: depois de editar `connections.conf`):
```bash
sudo bash ~/oai-lab-conf/stop-all-ipsec.sh
sudo bash ~/oai-lab-conf/start-all-ipsec.sh
sudo bash ~/oai-lab-conf/load-and-initiate-n3.sh
```

**Importante**: matar o `charon` (`kill -9`) **não limpa** o `xfrm
state`/`xfrm policy` que o kernel já tinha instalado — SAs antigas
continuam roteando tráfego real mesmo com o charon morto. Se for mudar a
topologia das conexões (não só girar PSK/rotacionar), limpe explicitamente:
```bash
sudo ip netns exec cu-ns ip xfrm policy flush
sudo ip netns exec cu-ns ip xfrm state flush
sudo ip netns exec 5gc-edge-ns ip xfrm policy flush
sudo ip netns exec 5gc-edge-ns ip xfrm state flush
```

Confirmar que o tráfego N3 está mesmo criptografado:
```bash
sudo timeout 5 ip netns exec cu-ns tcpdump -i veth-cu-n2 -n   # só ESP, nunca GTP puro
```

### Endereços do enlace N2/N3 (via `5gc-edge-ns`)

| Endereço | Papel | Onde vive |
|---|---|---|
| `10.97.0.1` / `10.97.0.2` | Link direto cu-ns ↔ 5gc-edge-ns, endpoint do túnel IPsec | `veth-cu-n2` / `veth-edge-cu` |
| `10.97.0.{11,12}` / `.{21,22}` / `.{31,32}` | Endereços dedicados das 3 conexões N3 (urllc/embb/miot), cada par próprio evita downgrade silencioso de proposta | `/32` em `veth-cu-n2` / `veth-edge-cu` |
| `10.98.0.98` | Alias da CU pro N2 (NGAP/SCTP com a AMF), via proxy-ARP | alias `/32` em `veth-cu-n2` |
| `172.18.0.99` | Alias da CU pro N3 (GTP-U com o UPF), via proxy-ARP | alias `/32` em `veth-cu-n2` |

## 5. Parar tudo

```bash
sudo bash ~/oai-lab-conf/stop-all-ipsec.sh   # se o IPsec estiver de pé
sudo pkill -9 -f "apps/gnb/gnb"
sudo pkill -9 -f "multi_ue_scenario.py"
sudo pkill -9 -f "srsue ue_"
cd ~/pqc-oran-local-lab/5gc && docker compose down   # só se quiser derrubar o 5GC também
```
Não precisa desmontar a rede virtual — é idempotente e o systemd cuida
dela no próximo boot.

## Troubleshooting — problemas reais encontrados e corrigidos nesta sessão de avaliação

Esses são achados genuínos rodando campanhas longas (horas) contra este
laboratório — ver histórico de commits em `evaluation/` pro contexto
completo de cada um.

**`/tmp` enche (tmpfs de 12GB) depois de horas de campanha, e tudo para de
funcionar de forma difícil de diagnosticar:**
Os logs do gNB (`gnb_combined.log`) e das 3 UEs (`ue_*.log`) crescem sem
limite — confirmado que os 4 somados batem exatamente nos 12GB do tmpfs.
Depois disso, escritas em `/tmp` podem falhar silenciosamente, e como
reiniciar processos não libera espaço, o problema nunca se resolve
sozinho. `evaluation/run_experiment.py` já chama
`lab_control.ensure_disk_headroom()` automaticamente (no início e entre
cada execução) — trunca os 4 logs e reinicia a RAN via
`watchdog_start.sh` quando `/tmp` passa de 60%. Se for operar o
laboratório manualmente por muitas horas fora do pipeline de avaliação,
rode isso à mão de vez em quando:
```bash
sudo truncate -s 0 /tmp/gnb_combined.log /tmp/ue_{urllc,embb,miot}.log
sudo bash ~/ocudu-lab/watchdog_start.sh
```
**Ordem importa**: truncar ANTES de reiniciar — truncar depois apaga as
linhas de TEID que o próprio restart acabou de escrever durante o attach
das UEs (achado real: isso quebrou 90/90 execuções de uma campanha
inteira que dependia de ler o TEID do log pra marcar o tráfego por
fatia).

**eMBB perde pacotes/interface intermitentemente sob carga alta de CPU:**
~2-3 núcleos da VM já ficam ocupados só com a simulação de RF via ZMQ
(gNB + 3 UEs). Sob essa carga, a resolução de endereço IP da interface da
eMBB (`ip netns exec ue-embb ip addr show tun_srsue`) falha
transitoriamente em ~5-40% das execuções de uma campanha longa — não é
RLF nem perda de sessão PDU (confirmado inspecionando o log da UE), não
reproduz isolado. `evaluation/run_experiment.py` já tem retry com backoff
e um jitter de 10-50ms entre as 3 sondas pra mitigar.

**Throughput da eMBB parece baixo (~0.6-2.2 Mbps) pros padrões de "banda
larga":**
Não é bug — a RF é **simulada via ZMQ** (software, CPU-bound), não
hardware real. O teto é bem abaixo do que um canal real de 10MHz/64QAM
permitiria, mesmo isolado sem concorrência. Números absolutos de
throughput neste laboratório não devem ser lidos como representativos de
eMBB real — a comparação *relativa* entre cenários (baseline vs. PQC)
continua válida.

**Conexão IPsec de túnel único (ex: cenário de rekey fixo) degrada e
nunca mais volta a passar tráfego depois de várias dezenas de ciclos
destruir+recriar seguidos, mesmo com `setup()`/`teardown()` completos a
cada vez:**
Causa raiz real era o `/tmp` cheio (ver acima), não a conexão em si —
mas no caminho até achar isso, também corrigimos dois bugs reais e
menores: `_mirror()` não trocava os traffic selectors entre os lados
(SA subia `ESTABLISHED` mas 0 pacotes passavam — ver commit
`fix: TS narrowing`), e `start_action = start` nos dois lados causava
corrida de iniciação simultânea (ver commit `fix: start_action`).

**`watchdog_start.sh` precisa matar TUDO (gNB+broker+UEs), não só uma
peça, quando a sincronização falha:**
Achado documentado no próprio script — reiniciar só o gNB (ou só uma UE)
depois de uma falha de sincronização ZMQ fria não resolve; o estado
preso fica espalhado entre os processos REQ/REP do broker.

**`iptables -t mangle` em vez de eBPF/TC pra classificação por fatia:**
Decisão documentada em `evaluation/README.md` e
`docs/ARQUITETURA-PROTOTIPO-COMPLETA.md` seção 4.1 — não é falta de
implementação (o classificador eBPF existe, compilado e testado), é um
achado de topologia: pra tráfego gerado localmente pela CU, o XFRM já
cifra o pacote (decisão de rota) antes de qualquer gancho TC egress
nessa mesma interface rodar — tarde demais no pipeline do kernel.
`iptables -t mangle -A OUTPUT` roda antes da decisão de rota, cedo o
suficiente pra influenciar a escolha de SA.
