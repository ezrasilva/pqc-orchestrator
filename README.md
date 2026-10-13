# pqc-orchestrator

Orquestrador de rotação/revogação de chaves híbridas PQC(+QKD simulado)
protegendo IPsec num laboratório O-RAN + Open5GS, e o laboratório em si.

> **Nota sobre o RAN usado**: o protótipo original (Fases 1-5, SBRC) rodou
> em **OAI** (`nr-softmodem`/`nr-uesoftmodem`). O **pipeline de avaliação
> experimental** (`evaluation/`, cenários 0-4 — o trabalho ativo hoje) foi
> portado de OAI pra **OCUDU + srsRAN_4G** depois (commit `4ed5048`) — um
> testbed com 3 processos `srsue` reais (um por fatia) em vez de uma UE
> OAI só multiplexando 3 sessões PDU. Pra subir o laboratório **hoje**,
> use `docs/RUNBOOK-OCUDU.md`; `docs/RUNBOOK-OAI.md` não existe mais.

Leia nessa ordem:
1. [`docs/RUNBOOK-OCUDU.md`](docs/RUNBOOK-OCUDU.md) — como subir tudo de novo do zero (Open5GS, gNB OCUDU + 3 UEs srsRAN_4G, o túnel IPsec de N2/N3), incluindo o troubleshooting dos bugs reais encontrados no caminho.
2. [`docs/ARQUITETURA-ORQUESTRADOR.md`](docs/ARQUITETURA-ORQUESTRADOR.md) — a arquitetura do orquestrador em si (SMO, Scheduler, KMS, IPsec Agent, Admin API) e as decisões de design já fechadas.
3. [`docs/ARQUITETURA-PROTOTIPO-COMPLETA.md`](docs/ARQUITETURA-PROTOTIPO-COMPLETA.md) — protótipo de nó único (sniffer PFCP + eBPF + XFRM/strongSwan) visando SBRC 2027, rodado em OAI; concretiza, num escopo menor, as mesmas decisões do documento acima.
4. [`docs/ROTEIRO-MODULO2-SNIFFER-PFCP.md`](docs/ROTEIRO-MODULO2-SNIFFER-PFCP.md) — detalhamento do sniffer PFCP do protótipo acima, com os achados de uma captura real já validada nesta VM.
5. [`docs/CENARIOS-TESTE-AVALIACAO.md`](docs/CENARIOS-TESTE-AVALIACAO.md) — cenários e métricas da avaliação experimental (Risk-Aware Scheduler vs. baselines), implementados em `evaluation/` (OCUDU).
6. [`docs/PLANO-IMPLEMENTACAO-OAI.md`](docs/PLANO-IMPLEMENTACAO-OAI.md) — como o RAN do protótipo (itens 3-4 acima) foi montado em OAI.

## Estrutura

```
docs/            Os cinco documentos acima.
orchestrator/     Código do orquestrador distribuído — contratos gRPC, KMS,
                   IPsec Agent, Scheduler (fórmula de risco) e SMO
                   implementados e testados; Admin API avaliada e
                   deliberadamente não implementada (ver orchestrator/README.md).
prototype/        Código do protótipo de nó único pro SBRC 2027 — sniffer
                   PFCP, classificador eBPF/TC e as 5 fases (Baseline até
                   Rotação dinâmica) implementadas e validadas contra o
                   laboratório real (ver prototype/README.md).
evaluation/       Pipeline de coleta experimental (cenários 0-4, métricas,
                   análise) pra avaliação do Risk-Aware Scheduler — ver
                   evaluation/README.md.
lab/              Configs e scripts do laboratório Open5GS+IPsec que os docs
                   acima descrevem — não é código do orquestrador, é a
                   infraestrutura que ele vai gerenciar.
  5gc/            docker-compose + configs do núcleo Open5GS (3 fatias).
  ran/            Vazio — tinha os configs de DU/CU/UE do protótipo em OAI
                   (ver `PLANO-IMPLEMENTACAO-OAI.md`), removidos no port do
                   pipeline de avaliação pra OCUDU (commit `4ed5048`); os
                   configs reais de hoje vivem em `~/ocudu-lab/` na VM, fora
                   deste repo (ver `RUNBOOK-OCUDU.md`).
  ipsec/          ipsec.conf por lado (cu/du/edge) + scripts de subida/parada.
  network/        Script que monta toda a rede virtual (netns/veth/proxy-ARP)
                   e a unit systemd que o roda no boot.
```

## Sobre os caminhos nos documentos

Os documentos em `docs/` foram escritos descrevendo a VM de laboratório
original — eles referenciam caminhos absolutos como `~/openairinterface5g`,
`~/oai-lab-conf`, `/usr/local/bin/pqc-lab-network.sh`. Esses caminhos
continuam corretos *naquela VM*; não foram reescritos pra apontar pra dentro
deste repositório porque os documentos são runbooks operacionais (comandos
reais pra copiar/colar numa VM real), não documentação abstrata. Os arquivos
em `lab/` aqui são uma cópia limpa desses mesmos configs, prontos pra servir
de ponto de partida numa VM nova — ajuste os caminhos conforme onde você
clonar este repo.

## Segredos

Nenhum segredo real está neste repositório. `lab/ipsec/*/ipsec.secrets`
(PSKs do IPsec) está no `.gitignore` — os arquivos `.example` ao lado
mostram o formato esperado. Credenciais de UE/PSK do pipeline de
avaliação atual (OCUDU) vivem em `~/ocudu-lab/` e `~/oai-lab-conf/`,
fora deste repo. Gere valores novos localmente (`openssl rand -base64 32` pros
PSKs) em vez de reaproveitar qualquer coisa que já tenha existido em outra
cópia deste laboratório.

## Estado do orquestrador

Ver `orchestrator/README.md` pro estado detalhado. Resumo: contratos gRPC
(item 1), KMS isolado e testável (item 2), IPsec Agent nativo mínimo
(item 3), Scheduler com fórmula de risco (item 4) e SMO amarrando os
quatro (item 5) prontos — validado de ponta a ponta contra o
laboratório real (Scheduler → SMO → KMS → IPsec Agent → SA reestabelece
com PSK e PPK novos). No caminho, corrigiu duas divergências reais entre
o desenho original e a topologia de verdade do laboratório (ver
`orchestrator/README.md` e `docs/ARQUITETURA-ORQUESTRADOR.md`): o IPsec
Agent só conhecia 2 conexões (agora conhece as 5 reais), e o PSK
combinado do KMS divergia do PPK real (RFC 8784) já validado na Fase 4
(agora são campos separados). Admin API (item 6) avaliada e
deliberadamente não implementada — ver justificativa no README do
orquestrador.

## Estado do protótipo (SBRC 2027)

Ver `prototype/README.md` pro estado detalhado. Resumo: sniffer PFCP
(Módulo 2) e classificador eBPF/TC (Módulo 3) implementados e validados
(replay de captura real + captura ao vivo / tráfego real do laboratório).
Encontrei e resolvi um achado crítico na integração Módulo 3→4: a marca
definida via TC egress não influencia a seleção de SA do XFRM pra
tráfego gerado localmente pela CU — a correção (marcar via `iptables -t
mangle -A OUTPUT`, que dispara `ip_route_me_harder()` e reavalia a SA)
foi validada contra SAs reais do strongSwan. **Fase 3 (cifragem manual,
Módulo 4) concluída**: três SAs N3 por fatia, diferenciadas só por mark,
validadas com tráfego real do laboratório — `ip -s xfrm state` confirmou
cada fatia indo exclusivamente pra sua própria SA, zero cruzamento.
**Fase 4 (hibridização PQC+QKD) concluída**: as três SAs N3 negociam os
perfis reais da tabela (URLLC ML-KEM-768+PPK simulando QKD, eMBB/mIoT
ML-KEM-512), confirmado via `swanctl --list-sas`. Dois achados críticos
resolvidos no processo — PPK não existe no parser clássico do
`ipsec.conf`, e conexões que compartilham endereço externo podem sofrer
downgrade silencioso de proposta — ambos documentados com a correção em
`docs/ARQUITETURA-PROTOTIPO-COMPLETA.md` (seção 5.4). **Fase 5 (rotação
dinâmica via risco) concluída**: `orchestrator/scheduler/` liga a fórmula
de risco da arquitetura às três SAs N3 reais — lê a idade de cada uma,
calcula o risco contra um SLA por fatia, e dispara a rotação (`swanctl
--rekey`) na de maior risco. Rodado contra o laboratório de verdade,
escolheu a URLLC corretamente (risco muito acima das outras duas) e
confirmou a rotação via mudança real de SPI.

## Estado do pipeline de avaliação experimental

Ver `evaluation/README.md` pro estado detalhado. Resumo: os 5 cenários
(baseline nativo, PQC estático, diferenciado+EDF, risco, contenção), a
instrumentação (decisão do scheduler, geração de chave PQC, confirmação
de SPI) e os coletores (estado do kernel IPsec, classificação por fatia,
CPU/memória, latência/throughput) estão implementados e **validados
contra o laboratório real** — rotação real acontecendo durante a coleta,
isolamento entre fatias confirmado nos números (eMBB/mIoT com
correspondência exata, URLLC a 2 pacotes por efeito de amostragem). Oito
achados reais corrigidos no processo (ver a lista completa no README do
pipeline) — de um bug silencioso no `pidstat` a uma falha genuína no
laço de rotação que acumulava fila sem limite. As campanhas estatísticas
completas (10 execuções × 5 min por cenário, como a metodologia pede)
ainda não foram rodadas — isso fica pro próximo passo, usando o
`run_experiment.py --iterations N` já pronto.
