# Plano de implementação — OAI na VM (substitui srsRAN/OCUDU)

Ponto de partida: a mesma VM de antes (Ubuntu 26.04, 8 vCPU, ~23 GB RAM), com o
Open5GS já funcionando. A mudança é só no lado RAN — em vez de OCUDU (gNB) +
srsRAN_4G (`srsue`), passamos a usar o **OpenAirInterface (OAI)** pros três
papéis: CU, DU e UE, todos do mesmo repositório.

## 0. O que continua igual, o que muda

**Continua igual (não refaz):**
- Open5GS (5GC) — já validado, com 3 assinantes cadastrados.
- `ufw` + túnel SSH pro WebUI (passo 0 do `IMPLEMENTACAO-VM.md` antigo).
- A lógica de rede virtual por enlace (uma sub-rede pro F1, outra pro N2/N3) —
  só os binários que rodam dentro dela mudam.
- Os esqueletos de IPsec (`ipsec-f1.conf.example`, `ipsec-n2n3.conf.example`) —
  reaproveitáveis quase sem alteração, já que o enlace continua sendo uma
  interface de rede real entre dois processos.
- `scripts/diagnostico.sh` do pacote de correção anterior — mesma VM, mesma
  CPU, a suspeita de AVX-512/steal time pode voltar a valer pro build do OAI.

**Muda:**
- gNB do OCUDU + `srsue` → **CU (OAI) + DU (OAI) + UE (OAI)**, três processos
  do mesmo binário `nr-softmodem` (CU e DU) e `nr-uesoftmodem` (UE),
  diferenciados pelo arquivo de config.
- ZMQ → **rfsimulator** (driver de RF simulada nativo do OAI, equivalente
  conceitual ao ZMQ mas mantido/testado pelo próprio projeto).
- Banda/PRB: em vez de tentar replicar a banda 3 que usávamos no srsRAN,
  recomendo começar pela configuração de referência que o próprio OAI testa
  e documenta — **banda n78, 106 PRB** (numerologia 1, ~40 MHz TDS, 3.5 GHz).
  Não há motivo pra brigar com uma banda não testada pela comunidade; a
  banda em si é irrelevante pro que você está medindo (rotação de chave via
  IPsec), então usar a referência oficial reduz risco de bug novo.

## 1. Pré-requisitos

```bash
sudo apt update && sudo apt install -y git cmake build-essential
```

O próprio OAI resolve o resto das dependências com o script de build (próximo
passo) — ele detecta a distro e instala o que falta. Numa distro tão nova
(Ubuntu 26.04) é bem possível que o script erre algum nome de pacote; se
travar em "package not found", roda `apt search <nome-parecido>` igual
fizemos com o `libconfig++-dev` antes, e segue.

## 2. Clonar o OAI

```bash
cd ~
git clone https://gitlab.eurecom.fr/oai/openairinterface5g.git
cd openairinterface5g
git checkout develop
```

(Existe também um espelho no GitHub, `github.com/OPENAIRINTERFACE/openairinterface5g`,
caso o GitLab dê algum problema de acesso — mesmo conteúdo.)

## 3. Instalar dependências e compilar

```bash
cd ~/openairinterface5g/cmake_targets
./build_oai -I
```

**Antes de compilar, confirme os flags exatos na documentação oficial** —
encontrei comandos um pouco divergentes entre tutoriais da comunidade
(alguns usam `-w SIMU`, outros usam só `--rfsim` em tempo de execução sem
precisar declarar o driver em tempo de build). Roda:

```bash
./build_oai --help | grep -A2 -- "-w "
```

pra ver as opções de driver de RF disponíveis nessa versão exata antes de
escolher. O comando abaixo é o ponto de partida mais comum documentado —
ajuste o driver conforme o que o `--help` mostrar:

```bash
./build_oai --ninja --gNB --nrUE -c
```

Isso compila o `nr-softmodem` (usado tanto pra CU quanto pra DU — o papel é
definido pelo arquivo de config, não pelo binário) e o `nr-uesoftmodem`.

## 4. Rede virtual (adaptando o que já existia)

Mesma filosofia do `setup-network.sh` anterior: uma sub-rede pro F1 (CU↔DU),
e o `core-net` do Docker pro N2/N3 (CU↔5GC) — só que agora ambos os lados do
F1 são processos do OAI em vez de OCUDU.

```bash
# F1 (CU <-> DU) — reaproveita netns + veth
sudo ip netns add cu-ns 2>/dev/null || true
sudo ip netns add du-ns 2>/dev/null || true
sudo ip link add veth-cu type veth peer name veth-du 2>/dev/null || true
sudo ip link set veth-cu netns cu-ns 2>/dev/null || true
sudo ip link set veth-du netns du-ns 2>/dev/null || true
sudo ip netns exec cu-ns ip addr add 10.99.0.1/24 dev veth-cu 2>/dev/null || true
sudo ip netns exec du-ns ip addr add 10.99.0.2/24 dev veth-du 2>/dev/null || true
sudo ip netns exec cu-ns ip link set veth-cu up
sudo ip netns exec du-ns ip link set veth-du up
sudo ip netns exec cu-ns ip link set lo up
sudo ip netns exec du-ns ip link set lo up
```

O `core-net` do Docker (N2/N3) já existe do trabalho anterior — não precisa
recriar, só confirmar que o AMF ainda está de pé (`docker compose ps` dentro
de `5gc/`).

Pra CU dentro do `cu-ns` alcançar o `core-net`, reaproveita a mesma lógica de
rota extra que já tínhamos (`veth-cu-host`/`veth-host-cu`, 10.100.0.0/24) —
está no `scripts/setup-network.sh` do pacote de correção anterior, não muda
nada nessa parte.

## 5. Configs — comece pelo exemplo oficial, não do zero

O repositório já vem com configs de referência prontas em:

```
~/openairinterface5g/targets/PROJECTS/GENERIC-NR-5GC/CONF/
```

Procure por algo como `gnb.sa.band78.fr1.106PRB*.conf` (o nome exato pode
variar por versão — `ls` a pasta pra confirmar) e use como ponto de partida
pros três papéis:

- **DU**: copie o exemplo, ajuste `rfsimulator` pra rodar como servidor
  (é o lado que "tem" o rádio simulado), e configure o endereço F1 local
  como `10.99.0.2` (a IP do `du-ns`).
- **CU**: copie o mesmo exemplo, remova a parte de PHY/RF (a CU não toca
  rádio), configure o F1 remoto apontando pra `10.99.0.2`, e o endereço do
  AMF apontando pra dentro do `core-net` (mesmo IP que você já usava no
  `gnb_zmq.yaml` do OCUDU).
- **UE**: usa `nr-uesoftmodem` com `--rfsim`, apontando o endereço do
  servidor rfsimulator pro IP da DU (`10.99.0.2`).

Os nomes exatos dos campos de config do OAI são bem diferentes do formato
YAML do OCUDU e do INI do srsue — **não tente adivinhar por analogia**, abra
o `.conf` de exemplo e edite os campos que já existem lá (é isso que o passo
6 vai confirmar linha por linha, do jeito que fizemos com o `ue_zmq.conf`).

## 6. Sequência de subida

1. Confirma que o Open5GS está de pé: `docker compose -f 5gc/docker-compose.yaml ps`
2. Sobe a DU primeiro (ela é quem "liga o rádio simulado"):
   ```bash
   sudo ip netns exec du-ns ~/openairinterface5g/cmake_targets/ran_build/build/nr-softmodem \
     -O <caminho-do-conf-du> --rfsim
   ```
3. Sobe a CU (conecta na DU via F1, e no AMF via N2):
   ```bash
   sudo ip netns exec cu-ns ~/openairinterface5g/cmake_targets/ran_build/build/nr-softmodem \
     -O <caminho-do-conf-cu>
   ```
   Confirme no log da CU que o F1 subiu com a DU e que o NGAP conectou no AMF
   antes de seguir.
4. Sobe a UE:
   ```bash
   sudo ~/openairinterface5g/cmake_targets/ran_build/build/nr-uesoftmodem \
     -O <caminho-do-conf-ue> --rfsim
   ```
5. Confirma registro: mesma lógica de antes — se a UE pegar IP na subnet
   certa (10.45.x.x conforme a fatia), a pilha básica está de pé.

**Não pule etapa** — se a DU não conseguiu erguer o F1 com a CU, a UE nunca
vai ter célula pra sincronizar, e você vai gastar tempo debugando a UE por um
problema que está no F1.

## 7. IPsec (reaproveitado quase sem mudança)

Mesma sequência do `security/README-integration.md` anterior: sobe o túnel
manualmente primeiro com os `.conf.example` (só ajustando os IPs se você
tiver mudado alguma sub-rede), confirma com `ipsec status`, só depois liga o
agente do seu orquestrador via VICI.

## 8. Diagnóstico se travar de novo

Antes de assumir que é outro bug estrutural: roda de novo o
`scripts/diagnostico.sh` (AVX-512 exposto? steal time alto?) — é a mesma VM,
a mesma CPU, a mesma classe de problema pode se repetir no build do OAI. Se
o build do OAI tiver algum flag equivalente a desabilitar SIMD/AVX-512, o
`./build_oai --help` deve listar — confirme antes de rebuildar às cegas.

## 9. Depois de validar o básico

Só depois de UE registrada + F1 confirmado + IPsec manual funcionando nos
dois enlaces, parte pra integração com o orquestrador (passo 8 do
`IMPLEMENTACAO-VM.md` antigo, sem mudança) e pros 4 cenários do plano de
experimentação — essa parte não muda nada com a troca de RAN, já que o
orquestrador não sabe (nem precisa saber) qual implementação está do outro
lado do túnel IPsec.

---

**Nota de honestidade**: os comandos de build e execução do OAI acima vêm de
tutoriais oficiais e da comunidade, mas encontrei pequenas divergências
entre versões (flags de driver de RF, nomes exatos de campo nos `.conf`).
Diferente do plano do OCUDU/srsRAN (que fomos corrigindo passo a passo com
base no que sua VM realmente retornava), este é um plano de partida — espere
precisar ajustar 1-2 detalhes na primeira rodada, e me manda o log/erro exato
que eu sigo corrigindo do mesmo jeito que fizemos até aqui.

## Fontes usadas neste plano

- [OAI F1-Handover and multi-DU test — HackMD](https://hackmd.io/@saffanazyan/r1G3AMNjyx)
- [F1-design.md — openairinterface5g](https://github.com/OPENAIRINTERFACE/openairinterface5g/blob/develop/doc/F1AP/F1-design.md)
- [rfsimulator README — OAI GitLab](https://gitlab.eurecom.fr/oai/openairinterface5g/-/blob/develop/radio/rfsimulator/README.md)
- [NR_SA_Tutorial_OAI_nrUE.md — openairinterface5g](https://github.com/OPENAIRINTERFACE/openairinterface5g/blob/develop/doc/NR_SA_Tutorial_OAI_nrUE.md)
- [RF simulator and OAI UE tutorial — open-cells.com](https://open-cells.com/index.php/2019/09/23/rf-simulator-and-oai-ue-tutorial/)
