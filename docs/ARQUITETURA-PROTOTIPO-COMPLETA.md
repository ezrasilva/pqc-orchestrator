# Roteiro de arquitetura — Protótipo de diferenciação PQC+QKD por fatia sobre interfaces O-RAN/3GPP não modificadas

Alvo: SBRC 2027. Base: Open5GS + OAI já configurados na sua VM.

## 0. Ideia central (uma frase)

Proteger F1-U/N3 com IPsec, aplicando um perfil criptográfico híbrido
PQC+QKD diferente por fatia (URLLC, eMBB e mIoT), sem alterar o protocolo ou
o endereçamento da interface — a diferenciação acontece inteiramente
dentro do nó de segurança, via classificação de pacote no kernel
(TEID → marca) associada a Security Associations distintas.

## 1. Diagrama geral

```
+---------------------------------------------------------------------------------+
|                                  VM LINUX                                        |
|                                                                                   |
|  [ MÓDULO 1 — Plano de dados 5G/O-RAN ]                                          |
|  Open5GS (AMF/SMF) <--N4/PFCP(udp/8805)--> UPF                                   |
|         |                                    ^                                   |
|    (sinalização N1/N2)                       |                                   |
|         v                                    | (N3 / F1-U — GTP-U, udp/2152)     |
|  OAI CU-CP -------- E1 -------- OAI CU-UP ---+                                   |
|                                    ^                                             |
|                                    | F1-U                                        |
|                                   OAI DU / UE emulado                            |
|                                                                                   |
|  [ MÓDULO 2 — Extrator de contexto de fatia ]                                    |
|  pfcp_sniffer.py escuta udp/8805, casa Request(S-NSSAI, IE 257) com              |
|  Response(F-TEID) pelo SEID  ---->  emite (TEID, SST, mark)                      |
|         |                                                                        |
|         v                                                                        |
|  [ MÓDULO 3 — Classificador in-kernel (eBPF/TC) ]                                |
|  gancho TC na interface do enlace protegido:                                     |
|  lê TEID (offset fixo, byte 4-7 do GTP-U) -> BPF hash map -> skb->mark           |
|         |                                                                        |
|         v                                                                        |
|  [ MÓDULO 4 — Gerenciador de chaves e cifragem IPsec ]                           |
|  XFRM seleciona a SA pelo mark (ip xfrm policy ... mark 0x10/0x20/0x30)          |
|  strongSwan + liboqs (PQC, RFC 9370) + plugin PPK (QKD simulado, RFC 8784)       |
|  SA mark 0x10 (URLLC, SST2): ML-KEM-768 + PPK + AES-128-GCM                      |
|  SA mark 0x20 (eMBB,  SST1): ML-KEM-512 + AES-256-GCM, sem PPK                   |
|  SA mark 0x30 (mIoT,  SST3): ML-KEM-512 + AES-128-GCM, sem PPK                   |
|                                                                                   |
+---------------------------------------------------------------------------------+
```

**Nota sobre o diagrama vs. o laboratório real**: o desenho mostra CU-CP e
CU-UP como caixas separadas, ligadas por E1 — isso é a arquitetura
3GPP/O-RAN de referência, mas **não é como a VM está rodando hoje**. No
laboratório atual (ver `RUNBOOK-OAI.md`), a CU roda como **um processo
único** (`nr-softmodem -O cu.conf`) que concentra CU-CP e CU-UP — o E1AP
que aparece nos logs é tráfego interno ao processo, não um enlace de rede
real entre dois binários. Isso não invalida o protótipo (o Módulo 4 só
precisa proteger N3, e N3 já é um enlace de rede de verdade nessa
topologia, CU↔UPF), mas quer dizer que **não existe hoje um enlace E1
físico pra proteger** — se o protótipo algum dia quiser demonstrar
diferenciação por fatia também no E1, isso exige primeiro rodar `nr-cuup`
como processo separado do CU-CP, o que não está feito.

## 2. Módulo 1 — Gerador de tráfego e pilha 5G/O-RAN

**Papel**: produzir o tráfego real de duas fatias simultâneas pra validar
os módulos seguintes.

**Componentes**: Open5GS (AMF, SMF, UPF) + OAI (CU-CP, CU-UP, DU/UE
emulado via `rfsimulator`, conforme o `PLANO-IMPLEMENTACAO-OAI.md` que já
fizemos).

**Interface sob proteção**: escolha uma pra começar — N3 (CU-UP↔UPF) é
mais simples de isolar que F1-U, porque só tem um salto. Comece por N3;
F1-U entra depois, reaproveitando o mesmo mecanismo.

**Configuração de fatias** (SST conforme TS 23.501 — já confirmado que
bate com o `smf.yaml`/`nssf.yaml` do Open5GS desta VM: SST 1 = eMBB,
SST 2 = URLLC, SST 3 = mIoT):

| Fatia | S-NSSAI | Perfil de tráfego de teste |
|---|---|---|
| URLLC | SST 2, SD 0x000002 | `iperf3` UDP, pacotes pequenos, intervalo curto |
| eMBB | SST 1, SD 0x000001 | `iperf3` TCP, alto throughput |
| mIoT | SST 3, SD 0x000003 | `iperf3` UDP, taxa baixa, envios periódicos e esparsos (simula sensor/telemetria) |

Três fatias simultâneas exigem três UEs (ou três sessões PDU) emuladas ao
mesmo tempo no OAI — confirme que sua config de UE/rfsimulator suporta
isso antes de avançar pra Fase 1 com as três ligadas de uma vez; se não
suportar de imediato, valide primeiro URLLC+eMBB (como já estava) e some
a mIoT como uma terceira sessão depois de confirmar que o mecanismo
escala pra três marks sem retrabalho.

**Entregável desta etapa**: duas UEs (ou duas sessões PDU da mesma UE, se
o OAI emulado suportar isso) conectadas simultaneamente, cada uma numa
fatia, trocando tráfego, **sem IPsec ainda** — só confirmando que o
core+RAN aceitam e roteiam as duas fatias corretamente.

## 3. Módulo 2 — Extrator de contexto de fatia (sniffer PFCP)

Detalhamento completo (parser, casamento Request/Response por SEID,
tratamento de Modification/Deletion, checklist de validação) já está no
`ROTEIRO-MODULO2-SNIFFER-PFCP.md` que te mandei antes — não repito aqui,
só o resumo de papel e interface. **Essa hipótese já foi validada com
tráfego real desta VM** (captura `tshark` numa sessão PDU de verdade,
mais conferência byte-a-byte do TEID no GTP-U) — ver seção 2b daquele
documento.

**Papel**: descobrir, em tempo real, qual TEID de GTP-U pertence a qual
S-NSSAI, sem tocar em Open5GS ou OAI.

**Como**: sniffer passivo no tráfego N4 (udp/8805) entre SMF e UPF,
lendo o IE 257 (S-NSSAI) da Session Establishment Request e casando com
o F-TEID da Response pelo SEID. Confirmado via leitura do código-fonte da
Open5GS (`src/smf/n4-build.c`) **e** via captura ao vivo que esse IE
realmente é enviado pra toda sessão 5G.

**Saída**: tripla `(TEID, SST, mark)` — `mark = 0x10` se SST=2 (URLLC),
`mark = 0x20` se SST=1 (eMBB), `mark = 0x30` se SST=3 (mIoT) — entregue
ao Módulo 3. Com três fatias, troque a lógica `if/else` do
`emit_mapping()` (no outro roteiro) por um dicionário
`SST_TO_MARK = {2: 0x10, 1: 0x20, 3: 0x30}` — mais fácil de estender se
uma quarta fatia (ex.: V2X, SST 4) entrar depois.

## 4. Módulo 3 — Classificador in-kernel (eBPF no gancho TC)

**Papel**: marcar o pacote de saída pela fatia, sem alterar o cabeçalho
GTP-U/IP — a interface continua padrão do ponto de vista de quem a
observa de fora.

**Onde roda**: acoplado (via `tc`) na interface por onde passa o tráfego
GTP-U do enlace protegido — ver seção 5 pra qual interface é essa de
verdade nesta VM (não é tão direto quanto "a interface do N3" sugere,
por causa de como o N3 já está roteado hoje).

**Mecanismo**:

1. Programa eBPF em C, carregado num gancho TC de egress.
2. Filtra por porta UDP 2152 (GTP-U).
3. Lê os bytes 4–7 do payload GTP-U (offset fixo — **confirmado com
   captura real nesta VM**, inclusive num pacote com flag de extensão
   ligada, que não muda o offset porque a extensão vem depois do TEID,
   não antes).
4. Consulta um BPF Hash Map (`teid_to_mark` — nome encurtado de
   `map_teid_to_mark` porque o kernel trunca nomes de map BPF em 15
   bytes, chave = TEID, valor = mark) — populado e atualizado pelo
   Módulo 2.
5. Se encontrar, `skb->mark = valor` (via `bpf_skb_set_mark` ou
   equivalente no gancho TC).
6. Se não encontrar (TEID novo, ainda não processado pelo Módulo 2),
   define um mark default/fallback — decida agora qual comportamento
   você quer nesse caso (deixar sem cifra reforçada até classificar, ou
   bloquear até classificar — isso é uma decisão de política, não só de
   implementação, e vale documentar no artigo).

**Comunicação com Módulo 2**: na Fase 2, atualização do map via
`bpftool map update` chamado por subprocess a partir do
`pfcp_sniffer.py`. Otimizar pra uma lib nativa (libbpf/pyroute2) só se a
latência disso se mostrar um problema real.

**Comunicação com Módulo 4**: nenhuma direta — o Módulo 3 só marca o
pacote; quem decide o que fazer com a marca é o XFRM (Módulo 4), não o
eBPF.

### 4.1 Status (implementado e testado; achado crítico resolvido)

O classificador em si está **implementado, compilado e validado** — 5
testes determinísticos (GTP-U sintético via scapy, veth descartável) e
validação manual contra tráfego real do laboratório (populado com o TEID
real de uma sessão eMBB, confirmado via `bpftool map dump` que o
contador `matched` bate exatamente com a contagem de pings enviados).
Detalhes em `prototype/ebpf_classifier/README.md`. Também corrigiu, no
caminho, um bug real: o nome do map `map_teid_to_mark` (16 bytes) era
truncado pelo kernel pro limite de 15 bytes, fazendo o loader nunca
encontrar o map pelo nome — renomeado pra `teid_to_mark`.

**Achado crítico, encontrado e depois resolvido**: testando contra o
laboratório real, confirmei que marcar via TC egress **não funciona**
pra influenciar a escolha de SA do XFRM, no caso específico de tráfego
gerado localmente pelo processo da CU (o socket GTP-U do OAI) — que é
exatamente o caso do Módulo 4. Dois testes independentes confirmaram
isso:

1. `tcpdump` em `veth-cu-n2` (interface de saída real do N3 da CU) com o
   túnel IPsec ativo nunca mostra GTP-U em claro de saída, só ESP — o
   XFRM já cifrou como parte da decisão de rota, antes de qualquer TC
   egress daquela interface rodar.
2. Um contador `iptables -t mangle -A FORWARD` pro mesmo mark nunca
   incrementou, mesmo com o eBPF confirmando `matched` crescendo — porque
   `FORWARD`/`POSTROUTING` do netfilter rodam antes do TC egress, não
   depois.

Ou seja: pra tráfego gerado localmente, TC egress na mesma interface que
o IPsec protege é tarde demais no pipeline do kernel pra influenciar
qual SA cifra o pacote. Isso **não invalidou** o classificador (ele lê o
TEID certo e marca certo, confirmado com tráfego real) — era uma
limitação de topologia: onde o gancho estava acoplado, não o que ele
fazia.

**Correção validada empiricamente**: mover o ponto de marcação de TC
egress pra `iptables -t mangle -A OUTPUT`. O hook `OUTPUT` da tabela
`mangle` tem um comportamento específico do kernel
(`iptable_mangle.c`/`ipt_mangle_out`): quando o mark do pacote muda
dentro desse hook, o kernel chama `ip_route_me_harder()`, que refaz a
resolução de rota — incluindo o `xfrm_lookup`, agora com o mark novo.
Validado em dois passos num ambiente isolado (netns descartáveis, sem
tocar nos túneis reais):

1. Reroteamento puro: regra `mangle OUTPUT` com `-m u32` lendo o TEID do
   payload GTP-U — pacotes saindo pela interface certa conforme o TEID
   batia ou não na regra.
2. SA real do XFRM: duas conexões strongSwan reais entre o mesmo par de
   endereços, diferenciadas só pelo `mark` (`mark=0x10`/`mark=0x20`).
   Enviei 1 pacote GTP-U mapeado pro mark `0x10` e 3 mapeados pro mark
   `0x20` — `ip -s xfrm state` confirmou exatamente 1 pacote na SA do
   mark `0x10` e exatamente 3 na SA do mark `0x20`, sem nenhum na SA
   errada.

Detalhes completos (comandos, config strongSwan de teste, números) em
`prototype/ebpf_classifier/README.md`. **Não bloqueia mais o Módulo 4**
— o próximo passo é portar a lógica TEID→mark do classificador pro
ponto de anexação `mangle OUTPUT` (via `xt_bpf`/`-m u32`, ou regras
atualizadas dinamicamente pelo Módulo 2), em vez de `tc egress`.

## 5. Módulo 4 — Gerenciador de chaves e cifragem IPsec (XFRM + strongSwan)

**Papel**: aplicar a Security Association certa, com o perfil
criptográfico certo, com base na marca que o Módulo 3 deixou no pacote.

### 5.0 Decisão de topologia (resolvida — reaproveita o `5gc-edge-ns`)

O enlace N3 desta VM **não é** uma ligação direta CU↔UPF. Ele passa pelo
`5gc-edge-ns` (ver `RUNBOOK-OAI.md`) — um netns de borda criado porque:
(a) o Docker bloqueia por padrão tráfego roteado-de-fora pra IPs de
container (proteção anti-spoofing), e (b) NAT nesse caminho corrompia o
checksum do SCTP do N2 — então o `5gc-edge-ns` entra como membro real das
redes Docker (sem NAT), expondo pra CU um alias roteado por proxy-ARP
(`172.18.0.99`) que é como a UPF enxerga a CU hoje.

Duas opções pra encaixar o Módulo 4 nisso:

- **(A) Construir um caminho novo e mais simples**, direto CU↔UPF, só pra
  este protótipo — mais fiel ao diagrama original, mas reintroduz os dois
  problemas que o `5gc-edge-ns` já resolveu (anti-spoofing e checksum),
  exigindo resolvê-los de novo ou aceitar uma topologia de rede diferente
  da que o resto do laboratório usa.
- **(B) Reaproveitar o `5gc-edge-ns`** — os três perfis de SA do Módulo 4
  terminam no `5gc-edge-ns` (não na UPF diretamente), que decripta e
  encaminha o tráfego já classificado até a UPF do mesmo jeito que faz
  hoje com o N3 "normal". A CU continua vendo um único peer de túnel
  (`10.97.0.1 ↔ 10.97.0.2`); a diferenciação por mark acontece nas
  políticas XFRM da CU, não na topologia de rede.

**Escolhida: (B)**. Reaproveita infraestrutura já validada (menos uma
fonte nova de bugs de rede antes mesmo de chegar na parte de criptografia
que é o foco do artigo), e não há nada na tese do protótipo ("a
diferenciação acontece inteiramente dentro do nó de segurança") que exija
contato direto CU↔UPF — só exige que a UPF, do lado de fora, continue
vendo o mesmo endereçamento de sempre, o que o `5gc-edge-ns` já garante
(é opaco pra UPF: ela recebe tráfego decriptado de um peer com o mesmo IP
de sempre).

Consequência prática: o enlace **N2** (NGAP, controle, SCTP) continua
usando a conexão única já existente (`n2n3-cu-edge`, um PSK só — não tem
por que diferenciar por fatia um enlace de controle que não carrega dados
de usuário). Só o **N3** (GTP-U, dado de usuário) é que se divide nas três
SAs por mark descritas abaixo. Isso implica dividir a conexão
`n2n3-cu-edge` atual em duas: uma só pra N2 (mantém o nome, perfil único)
e três novas só pra N3 (uma por fatia).

### 5.1 Seleção de SA por marca

A forma mais robusta de fazer isso com strongSwan **não** é escrever
`ip xfrm policy` à mão (como num rascunho anterior) — strongSwan já
suporta marca como parâmetro de conexão (`mark_in`/`mark_out`, ou `mark`
quando os dois lados usam o mesmo valor), e instala a política XFRM
correspondente sozinho quando a SA sobe. Isso evita a política e a SA
ficarem dessincronizadas se a SA for renegociada.

```
# cu-ns (initiator) — três conexões tunnel-mode pro mesmo peer
# (5gc-edge-ns), cada uma com seu próprio mark e perfil de cifra.
# leftsubnet/rightsubnet seguem o mesmo alias N3 (172.18.0.99) e a
# sub-rede da UPF (172.18.0.0/16) que o n2n3-cu-edge já usa hoje.

conn n3-urllc-cu-edge
    type=tunnel
    authby=psk
    left=10.97.0.1
    leftsubnet=172.18.0.99/32
    right=10.97.0.2
    rightsubnet=172.18.0.0/16
    mark_out=0x10
    mark_in=0x10
    ike=ML-KEM-768-aes128gcm16-...   # proposta exata depende do plugin PQC (ver 5.3)
    esp=aes128gcm16-...
    auto=add   # Módulo 4 dispara "swanctl --initiate" quando a fatia aparecer

conn n3-embb-cu-edge
    type=tunnel
    authby=psk
    left=10.97.0.1
    leftsubnet=172.18.0.99/32
    right=10.97.0.2
    rightsubnet=172.18.0.0/16
    mark_out=0x20
    mark_in=0x20
    ike=ML-KEM-512-aes256gcm16-...
    esp=aes256gcm16-...
    auto=add

conn n3-miot-cu-edge
    type=tunnel
    authby=psk
    left=10.97.0.1
    leftsubnet=172.18.0.99/32
    right=10.97.0.2
    rightsubnet=172.18.0.0/16
    mark_out=0x30
    mark_in=0x30
    ike=ML-KEM-512-aes128gcm16-...
    esp=aes128gcm16-...
    auto=add
```

`auto=add` nas três (não `auto=start`) porque o gatilho de subir cada uma
é o Módulo 2 ver aquela fatia pela primeira vez (seção 4), não o boot do
sistema — igual ao `n2n3-cu-edge`/`f1-cu-du` já fazem hoje com o papel de
initiator único (ver `ARQUITETURA-ORQUESTRADOR.md`, "papéis assimétricos").
O lado `5gc-edge-ns` espelha as três com `auto=add`, mesmo papel de
responder passivo que já tem hoje.

**Perfis por fatia** (sem mudança da versão anterior — a tabela já estava
certa):

| Marca | Fatia | KEM (RFC 9370) | Material QKD simulado (RFC 8784, PPK) | Cifra simétrica |
|---|---|---|---|---|
| 0x10 | URLLC (SST2) | ML-KEM-768 | Sim — PPK injetado no strongSwan | AES-128-GCM (prioriza latência) |
| 0x20 | eMBB (SST1) | ML-KEM-512 | Não | AES-256-GCM (prioriza margem de segurança, sem pressão de latência) |
| 0x30 | mIoT (SST3) | ML-KEM-512 | Não | AES-128-GCM (prioriza custo computacional/energético do dispositivo, não latência) |

A mIoT reaproveita o mesmo KEM da eMBB (ML-KEM-512 já é o menor parâmetro
padronizado, não tem um "menor ainda" pra usar) e fica sem PPK, seguindo
o mesmo raciocínio de reservar o material QKD só pra fatia crítica — a
diferença entre eMBB e mIoT fica só na cifra simétrica: AES-256 quando
throughput importa mais que economia de CPU (eMBB), AES-128 quando o
oposto é verdade (mIoT, tipicamente dispositivo constrangido/bateria).
Vale registrar esse raciocínio no artigo — é uma decisão de design, não
só um valor escolhido arbitrariamente.

### 5.2 Agente de Segurança

**Papel do "Agente de Segurança" (versão simplificada, nesta fase, do
IPsec Agent da arquitetura maior)**: recebe do Módulo 2 a informação de
qual fatia é nova, garante (via `swanctl`/VICI) que a conexão `n3-<fatia>-
cu-edge` correspondente está ativa (`swanctl --initiate --child n3-
<fatia>-cu-edge` se ainda não estiver), e injeta o PPK simulando QKD
quando a fatia exigir (`ppk_id`/segredo carregado via
`swanctl --load-shared` ou `ipsec.secrets`).

### 5.3 Pré-requisito de versão e disponibilidade real nesta VM (resolvido)

strongSwan **6.0.0+** pra RFC 9370/ML-KEM (via plugin `botan`, `wolfssl`,
`openssl`/AWS-LC, ou o novo plugin `ml`); PPK (RFC 8784) já existe desde a
5.7.0.

**Checagem inicial (incompleta) vs. o que de fato está disponível**: a
primeira verificação nesta VM olhou só os `.so` de plugin instalados
(`libstrongswan-standard-plugins`/`libcharon-extra-plugins` do Ubuntu
26.04 não trazem `ml`, `wolfssl`, `botan` nem `awslc` pré-compilados) e
concluiu, erradamente, que ML-KEM estava bloqueado. **Não estava**: o
plugin `openssl` (esse sim já vinha instalado) ganha suporte a ML-KEM
automaticamente quando ligado a uma libssl recente o bastante — e esta VM
já tem **OpenSSL 3.5.5**, que inclui ML-KEM nativamente. Confirmado com

```bash
swanctl --list-algs | grep -A1 '^ke:'
#   ML_KEM_512[openssl]
#   ML_KEM_768[openssl]
#   ML_KEM_1024[openssl]
```

**mesmo antes** de compilar nada — o `[openssl]` ali já diz de onde vem.
Ou seja: **nenhum compile era estritamente necessário** pra desbloquear a
Fase 4 nesta VM. Mesmo assim, compilamos o strongSwan 6.0.4 a partir do
pacote-fonte do Ubuntu (mesma versão, patches de segurança da Ubuntu
incluídos) com `--enable-ml` adicionado, instalando via `.deb` reconstruído
(não `make install` cru, pra manter o pacote gerenciável pelo `dpkg`) — o
plugin nativo `ml` fica como segundo provedor de ML-KEM, independente da
versão do OpenSSL, útil se este laboratório algum dia rodar numa máquina
com libssl mais antiga. Os pacotes foram marcados com `apt-mark hold` pra
um `apt upgrade` não substituir esse build por engano. Nenhuma mudança foi
necessária nos túneis já ativos (`f1-cu-du`, `n2n3-cu-edge` continuam com
o mesmo `ike=`/`esp=` de sempre — PQC só entra quando as três conexões
`n3-<fatia>-cu-edge` da seção 5.1 forem configuradas de fato, na Fase 4).

## 6. Fluxo de execução passo a passo (visão consolidada)

1. UE (OAI) solicita sessão PDU associada a um S-NSSAI.
2. Open5GS SMF estabelece a sessão via N4 com a UPF, atribuindo um TEID —
   essa troca carrega o S-NSSAI (Módulo 2 observa isso).
3. Módulo 2 resolve `(TEID, SST)`, decide o mark, atualiza o BPF map
   (Módulo 3) e confirma com o Agente de Segurança (Módulo 4) que a
   conexão `n3-<fatia>-cu-edge` daquele mark está ativa — dispara IKEv2
   se ainda não estiver.
4. OAI CU-UP gera tráfego GTP-U real na interface protegida.
5. O eBPF (Módulo 3) intercepta no gancho TC, lê o TEID, aplica o mark.
6. O XFRM (Módulo 4) vê o mark e aplica a SA/perfil correspondente
   (política instalada automaticamente pelo strongSwan via `mark_out`).
7. Pacote sai cifrado via ESP rumo ao `5gc-edge-ns`, que decripta e
   encaminha pra UPF do jeito que já faz hoje com o N3 — do ponto de
   vista da UPF, o endereçamento é idêntico ao de uma implantação padrão
   sem diferenciação por fatia.

## 7. Como isso se encaixa na arquitetura maior do orquestrador

Este protótipo de 4 módulos é uma versão de nó único do que o
`ARQUITETURA-ORQUESTRADOR.md` desenhou de forma distribuída:

- O **"Agente de Segurança" do Módulo 4** é a versão inicial, simplificada
  e local, do **IPsec Agent nativo** daquela arquitetura — e já herda dele
  a decisão de rodar no `cu-ns` como initiator único, com os outros lados
  (`5gc-edge-ns`) como responders passivos.
- O **Módulo 2** faz hoje, de forma ad-hoc, parte do que o **KMS/SMO**
  fariam de forma mais geral (saber qual fatia existe e qual perfil
  aplicar).
- O que **ainda não está aqui** e fica pra depois: o **Global Scheduler**
  com a fórmula de risco decidindo *quando* rotacionar cada SA — nesta
  fase, a rotação pode ser manual/por tempo fixo. Isso vira a Fase 5.

Vale deixar essa correspondência explícita na seção de arquitetura do
artigo, pra mostrar que o protótipo não é uma ideia solta, é a primeira
concretização (num nó só, sem distribuição ainda) do design mais amplo do
projeto.

## 8. Roteiro faseado de implementação

- [x] **Fase 1 — Baseline (concluída)**: as **três** fatias simultâneas
  estão de pé numa UE só (não duas — subiu direto pras três, já que o
  mecanismo é o mesmo), cada uma com sua própria sessão PDU/TEID. Os três
  perfis `iperf3` da tabela da seção 2 rodados de verdade contra um
  servidor na própria UPF (`10.45.0.1:5201`, já que é o único endereço
  real — ver achado abaixo): eMBB TCP ~35 Mbit/s, URLLC UDP 2 Mbit/s
  (128B/pacote, 0% perda, jitter ~0.7ms), mIoT UDP 10 kbit/s esparso (64B/
  pacote, 0% perda) — nenhuma fatia derrubou os túneis IPsec já ativos
  (`f1-cu-du`, `n2n3-cu-edge`) nem as outras duas sessões. Duas coisas
  descobertas no processo, corrigidas na config, não no código do OAI:
  - A UE do OAI **não envia `Requested NSSAI`** no Registration Request —
    o AMF só libera (`Allowed NSSAI`) as fatias com `default_indicator:
    true` na assinatura. Corrigido marcando as três fatias do assinante de
    teste (`001010000000004`) como default — ver `RUNBOOK-OAI.md`.
  - A UPF usa **uma única interface** `ogstun` (`10.45.0.1/16`) pras três
    sub-redes, não uma por fatia — os "gateways" por DNN no `smf.yaml`
    (`10.45.1.1`, `10.45.2.1`) são só contabilidade da SMF pra alocação de
    IP, não endereços reais bindados na UPF. Testar conectividade de uma
    fatia que não seja `embb` pingando o "gateway" dela dá timeout; o
    teste certo é pingar `10.45.0.1` (o endereço real), de qualquer fatia.
- [x] **Fase 2 — Classificação (Módulo 2 e Módulo 3 implementados e
  testados; integração Módulo 3→4 validada contra XFRM real)**:
  `pfcp_sniffer/` implementado e validado — tanto via replay de uma
  captura real salva (três sessões simultâneas, 6 testes automatizados)
  quanto ao vivo contra a bridge Docker real durante um restart de UE de
  verdade, usando a classe `PfcpSniffer` de ponta a ponta, não só o
  parser isolado. Achados reais corrigidos no processo (não no
  pseudocódigo original do roteiro): o cálculo do tamanho do header PFCP
  com SEID estava errado (16 bytes, não 12); o SEID do cabeçalho não é
  um ID de sessão único (é "de quem recebe a mensagem", CP ou UP têm
  valores diferentes — a correlação certa usa o IE F-SEID); e um FAR
  aponta pra `CP-function`, não pro enlace N3, então extrair o primeiro
  Outer Header Creation sem checar a interface pega o TEID/IP errado.
  Ver `prototype/README.md` pros detalhes. O classificador eBPF/TC
  (Módulo 3) também está implementado, compilado e validado — tanto por
  5 testes determinísticos quanto contra tráfego real, confirmado via
  `bpftool map dump`. Encontrei e resolvi um achado crítico na
  integração com o Módulo 4: TC egress na interface do N3 não
  influencia a seleção de SA do XFRM pra tráfego gerado localmente pela
  CU (confirmado via tcpdump e contador iptables) — a correção, marcar
  via `iptables -t mangle -A OUTPUT` em vez de `tc egress`, foi validada
  empiricamente contra SAs reais do strongSwan (duas conexões
  diferenciadas só por mark, tráfego real roteado pra SA certa conforme
  o TEID). Detalhes e números em seção 4.1 acima e
  `prototype/ebpf_classifier/README.md`. A Fase 3 já pode contar com
  esse mecanismo pra seleção de SA por fatia.
- [x] **Fase 3 — Cifragem manual**: feita e validada contra o laboratório
  real. A antiga `n2n3-cu-edge` foi dividida em `n2-cu-edge` (controle,
  perfil único) e três `n3-<fatia>-cu-edge` (dado de usuário, uma por
  fatia, diferenciadas só por `mark_in`/`mark_out`), com
  `ike=aes256-sha256-modp2048`/`esp=aes256-sha256` fixos (sem PQC ainda —
  isso é Fase 4). Capturei os TEIDs reais das três sessões PDU ativas
  (eMBB/URLLC/mIoT) via o sniffer PFCP ao vivo (Módulo 2) durante um
  restart de UE de verdade, apliquei `iptables -t mangle -A OUTPUT`
  mapeando cada TEID real pro mark certo (script
  `lab/ipsec/apply-n3-slice-marks.sh`), e gerei tráfego real por fatia
  (ping pelas três interfaces `oaitun_ue1*` da UE). Resultado: `ip -s
  xfrm state` mostrou as três SAs com tráfego **exclusivamente** na SA
  certa (mark 0x10/URLLC: 5 pacotes: mark 0x20/eMBB: 3 pacotes; mark
  0x30/mIoT: 7 pacotes), zero pacotes na SA errada em qualquer uma —
  confirma de ponta a ponta que a classificação por TEID (Módulo 2/3) e
  a seleção de SA por mark (Módulo 4, via `mangle OUTPUT`) funcionam
  juntas contra o laboratório real, não só em teste isolado. Achado
  operacional (não um bug, mas vale registrar): matar o charon com
  `kill -9` não limpa o `xfrm state`/`policy` instalado no kernel — um
  restart de config exige `ip xfrm state flush`/`ip xfrm policy flush`
  explícito no netns antes de subir a instância nova, senão a SA antiga
  continua roteando tráfego não marcado e compete com as políticas
  novas.
- [ ] **Fase 4 — Hibridização PQC+QKD**: primeiro compilar strongSwan com
  um backend PQC (ver 5.3 — não está disponível via `apt` nesta VM), só
  depois automatizar liboqs+PPK e aplicar os perfis da tabela da seção
  5.1 de verdade. Critério de saída: handshake IKEv2 com ML-KEM confirmado
  no log do charon, PPK confirmado ativo na SA da URLLC.
- [ ] **Fase 5 (futuro/próximo artigo ou seção de trabalhos futuros)**:
  conectar o Scheduler com fórmula de risco pra decidir rotação
  dinâmica, em vez de rotação fixa/manual.

## 9. Riscos e pontos de atenção já identificados (não deixar passar)

- ~~SST invertido em documentos antigos do projeto~~ — **já corrigido**
  no `ARQUITETURA-ORQUESTRADOR.md` (SST 2 = URLLC, SST 1 = eMBB,
  confirmado também contra `smf.yaml`/`nssf.yaml` do Open5GS desta VM).
- F-TEID vem dentro de um Grouped IE (Created/Create PDR) — parser do
  Módulo 2 precisa lidar com IEs aninhados, não só top-level.
  **Confirmado com captura real.**
- O F-TEID de **downlink** (lado CU) só aparece numa **Session
  Modification Request**, não na Establishment — confirmado com captura
  real nesta VM. Um sniffer que só escuta Establishment fica com só
  metade do par de TEIDs.
- TEID pode ser reaproveitado após `Session Deletion` — sem limpeza do
  BPF map nessa hora, uma fatia pode herdar o mark errado.
- O enlace N3 desta VM passa pelo `5gc-edge-ns` (proxy-ARP, sem NAT), não
  é uma ligação direta CU↔UPF — o Módulo 4 tem que terminar as três SAs
  ali, não na UPF (ver seção 5.0). Um exemplo de `ip xfrm policy` com
  `dst <IP_UPF>` direto, copiado sem adaptar, não vai funcionar nesta VM.
- CU-CP e CU-UP rodam no **mesmo processo** nesta VM (não há E1 de rede
  de verdade pra proteger hoje) — só importa se o protótipo quiser
  estender a diferenciação por fatia pro E1 também.
- ~~strongSwan sem plugin ML-KEM, bloqueante pra Fase 4~~ — **resolvido,
  e nem era bem assim**: o plugin `openssl` já instalado ganha ML-KEM
  sozinho com a libssl 3.5.5 desta VM (confirmado via `swanctl
  --list-algs`), sem precisar compilar nada. Compilamos o strongSwan com
  `--enable-ml` mesmo assim (ver 5.3), como provedor nativo adicional —
  não é mais um bloqueio de jeito nenhum, nos dois caminhos.
- Decida explicitamente o comportamento do Módulo 3 pra pacote com TEID
  ainda não classificado (fallback inseguro vs. bloqueio) — isso é
  decisão de design, vale estar no texto do artigo, não só no código.
