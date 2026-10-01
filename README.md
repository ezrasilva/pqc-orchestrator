# pqc-orchestrator

Orquestrador de rotação/revogação de chaves híbridas PQC(+QKD simulado)
protegendo IPsec num laboratório O-RAN (OpenAirInterface + Open5GS), e o
laboratório em si.

Leia nessa ordem:
1. [`docs/PLANO-IMPLEMENTACAO-OAI.md`](docs/PLANO-IMPLEMENTACAO-OAI.md) — como o laboratório RAN+5GC foi montado (OAI no lugar do srsRAN/OCUDU original).
2. [`docs/RUNBOOK-OAI.md`](docs/RUNBOOK-OAI.md) — como subir tudo de novo do zero (Open5GS, DU/CU/UE, os dois túneis IPsec), incluindo o troubleshooting dos bugs reais encontrados no caminho.
3. [`docs/ARQUITETURA-ORQUESTRADOR.md`](docs/ARQUITETURA-ORQUESTRADOR.md) — a arquitetura do orquestrador em si (SMO, Scheduler, KMS, IPsec Agent, Admin API) e as decisões de design já fechadas.
4. [`docs/ARQUITETURA-PROTOTIPO-COMPLETA.md`](docs/ARQUITETURA-PROTOTIPO-COMPLETA.md) — protótipo de nó único (sniffer PFCP + eBPF + XFRM/strongSwan) visando SBRC 2027; concretiza, num escopo menor, as mesmas decisões do documento acima.
5. [`docs/ROTEIRO-MODULO2-SNIFFER-PFCP.md`](docs/ROTEIRO-MODULO2-SNIFFER-PFCP.md) — detalhamento do sniffer PFCP do protótipo acima, com os achados de uma captura real já validada nesta VM.

## Estrutura

```
docs/            Os cinco documentos acima.
orchestrator/     Código do orquestrador distribuído (contratos gRPC + KMS +
                   IPsec Agent implementados; Scheduler/SMO/Admin API ainda não).
prototype/        Código do protótipo de nó único pro SBRC 2027 (sniffer PFCP
                   implementado; classificador eBPF ainda não — reaproveita
                   orchestrator/ipsec_agent/ como Módulo 4).
lab/              Configs e scripts do laboratório OAI+Open5GS+IPsec que os
                   docs acima descrevem — não é código do orquestrador, é a
                   infraestrutura que ele vai gerenciar.
  5gc/            docker-compose + configs do núcleo Open5GS (3 fatias).
  ran/            Configs do DU/CU (OAI) e template do UE simulado.
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

Nenhum segredo real está neste repositório. `lab/ipsec/*/ipsec.secrets` e
`lab/ran/ue.conf` (PSKs do IPsec e credenciais IMSI/key/opc da UE de teste)
estão no `.gitignore` — os arquivos `.example` ao lado mostram o formato
esperado. Gere valores novos localmente (`openssl rand -base64 32` pros
PSKs) em vez de reaproveitar qualquer coisa que já tenha existido em outra
cópia deste laboratório.

## Estado do orquestrador

Ver `orchestrator/README.md` pro estado detalhado. Resumo: contratos gRPC
(item 1), KMS isolado e testável (item 2) e IPsec Agent nativo mínimo
(item 3) prontos; Scheduler, SMO e Admin API (itens 4-6) ainda não
implementados.

## Estado do protótipo (SBRC 2027)

Ver `prototype/README.md` pro estado detalhado. Resumo: sniffer PFCP
(Módulo 2) e classificador eBPF/TC (Módulo 3) implementados e validados
(replay de captura real + captura ao vivo / tráfego real do laboratório).
Encontrei e resolvi um achado crítico na integração Módulo 3→4: a marca
definida via TC egress não influencia a seleção de SA do XFRM pra
tráfego gerado localmente pela CU (confirmado via tcpdump e contador
iptables) — a correção (marcar via `iptables -t mangle -A OUTPUT`, que
dispara `ip_route_me_harder()` e reavalia a SA) foi validada contra SAs
reais do strongSwan, ver `prototype/ebpf_classifier/README.md`. Módulo 4
(Agente de Segurança) reaproveita `orchestrator/ipsec_agent/`.
