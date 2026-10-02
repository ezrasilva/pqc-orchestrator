# Cenários de Teste e Pipeline de Coleta — Avaliação Experimental (SBRC 2027)

**Implementado em `../evaluation/`** — ver `../evaluation/README.md` pro
estado real (pipeline completo, validado contra o laboratório; campanhas
estatísticas completas ainda não rodadas) e os dois desvios documentados
(classificação via `iptables mangle`, não eBPF; latência via `ping`, não
`sockperf` — ambos com a justificativa no README).

## 0. Objetivo

Definir um conjunto de cenários experimentais e métricas que permitam comparar o
Risk-Aware Scheduler (per-slice PQC/QKD via PFCP→eBPF→XFRM) contra baselines
representativos da literatura/prática atual, gerando os dados para a seção de
avaliação do artigo.

Regra metodológica central, válida para todos os cenários: **o limite máximo de
vida útil de uma SA (max SA lifetime) é o mesmo em todos os cenários**. A única
variável entre eles é *como e quando* a decisão de rotação é tomada dentro
desse limite — nunca a frequência-base de rotação. Isso evita que um revisor
alegue que o baseline só "rotacionou mais vezes" por construção.

## 1. Cenários

### Cenário 0 — Baseline Nativo (sem IPsec / sem PQC)
Tráfego Open5GS + OAI fluindo direto por N3/F1-U, sem cifragem nenhuma.
Objetivo: estabelecer o piso de latência e o teto de vazão do hardware/VM,
sem overhead de segurança. Serve de referência para "custo total da segurança"
nos demais cenários.

### Cenário 1 — IPsec PQC Estático Tradicional (sem diferenciação por fatia)
Um único túnel IPsec com PQC fixo (ML-KEM-768) protegendo todo o tráfego do
enlace, independentemente da fatia. Rekeying em intervalo fixo (ex.: a cada
30s) igual para todo o tráfego.
Objetivo: mostrar o problema do rekeying "cego à fatia" — o spike de latência
da troca de chave atinge o URLLC no mesmo instante em que atinge eMBB/mIoT,
sem qualquer prioridade.

### Cenário 2 — Diferenciado por Fatia + Escalonador Tradicional (EDF / idade)
Tráfego já separado por eBPF/fwmark em 3 SAs (URLLC, eMBB, mIoT — a
diferenciação criptográfica do Módulo 3/4 já está ativa), mas a decisão de
*qual SA rotacionar e quando* segue EDF/idade pura (SA mais próxima do limite
de vida útil rotaciona primeiro, sem olhar para SLA ou classe de tráfego).
Objetivo: isolar o efeito da diferenciação por si só, mostrando que ela não
basta — ainda é possível rotacionar a SA do URLLC num momento ruim porque o
critério é só cronológico.

### Cenário 3 — Proposta Completa (Risk-Aware Scheduler + PQC/QKD por fatia)
Mapeamento dinâmico PFCP→eBPF→XFRM com SAs diferenciadas (URLLC: ML-KEM-768 +
PPK/QKD; eMBB/mIoT: ML-KEM-512) e o scheduler aplicando a fórmula de risco
(`risk(i) = -slack(i)/custo_estimado(i) + slice_bonus(i) + interface_bonus(i)
+ aging(i)`) para decidir a ordem de rotação.
Objetivo: demonstrar que o scheduler prioriza janelas seguras para o URLLC,
zera estouros de SLA e mantém isolamento de 100% entre fatias.

### Cenário 4 — Contenção / Carga Concorrente (novo, recomendado)
Mesma configuração do Cenário 3 (e, como contraponto, do Cenário 2), mas com
múltiplas sessões simultâneas por fatia e/ou uma rotação forçada simultânea
nas três SAs (ex.: um gatilho externo de "suspeita de comprometimento" que
expira as três ao mesmo tempo).

**Por que este cenário é necessário**: com apenas uma sessão por fatia (como
nos Cenários 2 e 3 isolados), dificilmente existe disputa real por recurso —
nenhuma das duas políticas (EDF vs. risco) precisa decidir "quem rotaciona
primeiro" porque não há conflito. O valor do escalonador por risco só aparece
quando há contenção: várias rotações expirando perto umas das outras, ou
pico de tráfego eMBB coincidindo com expiração do URLLC. Sem esse cenário, os
Cenários 2 e 3 tendem a produzir números quase idênticos, e isso é exatamente
o tipo de lacuna que um revisor do SBRC vai apontar.

## 2. Métricas

### A. Desempenho de Rede (Data Plane / QoE)
- Latência E2E/RTT: média, P50, P95, P99 (o P95/P99 é o que revela os spikes
  de rekeying — a média os esconde).
- Jitter.
- Throughput útil (Mbps), por fatia.
- Taxa de perda de pacotes (%) e retransmissões.

### B. Plano de Controle e Gerenciamento de Segurança
- Tempo de rekeying/rotação de SA (ms), **decomposto em sub-etapas** (ver nota
  abaixo): decisão do scheduler → geração de material PQC/PPK no KMS →
  instalação da nova SA no kernel (confirmação de SPI).
- Taxa de violação de SLA por fatia — **definir limiar por fatia, não só para
  URLLC**: URLLC (ex.: latência > 10ms), eMBB (ex.: vazão mínima não atingida),
  mIoT (ex.: confiabilidade/duty-cycle, não necessariamente latência).
- Verificação de isolamento inter-fatia (zero-leakage): contadores de
  pacotes/bytes por SPI em `ip -s xfrm state` confirmando 100% do tráfego de
  cada fatia na SA correspondente.

### C. Consumo de Recursos (System Overhead)
- CPU (%): pico e médio, no nó do IPsec Agent e na O-CU/UPF, durante handshake
  PQC e tráfego ativo.
- Memória (MB): processos strongSwan, Python (Agent/KMS), mapas eBPF no kernel.

**Nota sobre a decomposição do tempo de rekeying**: vale instrumentar
separadamente o tempo de geração de chave PQC/PPK (dentro de
`kms/crypto.py`) e o tempo de espera por confirmação de SPI (já existe um
ponto natural para isso em `ipsec_agent/agent.py`, na função
`_wait_for_fresh_sa()`). Isso é barato — só adicionar timestamps — e permite
um gráfico de "onde o tempo é gasto" muito mais informativo que um número
único, além de facilitar discutir no artigo se o gargalo é a criptografia PQC
em si ou a instalação no kernel.

## 3. Rigor Experimental (checklist)

- **Repetições**: cada cenário deve ser executado múltiplas vezes (ex.: 10
  execuções de 5 min), reportando intervalo de confiança no P95/P99, não um
  número de uma única coleta.
- **Warm-up**: descartar os primeiros segundos de cada execução (handshake
  inicial do strongSwan, ARP, etc.) antes de calcular estatísticas.
- **Sincronização**: usar timestamps com relógio comum (NTP/chrony ou mesma
  máquina coletora) e um `run_id` único por execução, para poder correlacionar
  evento de rekeying ↔ spike de latência ↔ uso de CPU sem ambiguidade.
- **Perfil de tráfego por fatia**: para URLLC, preferir um gerador de padrão
  determinístico (pacotes pequenos periódicos, ex. sockperf ping-pong
  sustentado) em vez de um teste de throughput genérico — mais fiel ao
  tráfego que motiva a fatia na literatura 3GPP.

## 4. Pipeline de Coleta

```
+-------------------------------------------------------------------------------+
|                            PIPELINE DE COLETA                                 |
|                                                                                |
| [ Gerador de Tráfego ]  ---> sockperf / iperf3 -J (JSON)                      |
|                                    |                                          |
| [ Monitor do Kernel ]   ---> ip -s xfrm state / eBPF RingBuffer (JSON, 500ms) |
|                                    |                                          |
| [ Log do Scheduler/KMS/Agent ] ---> timestamps decisão/keygen/SPI (JSON/CSV)  |
|                                    |                                          |
| [ pidstat / mpstat ]    ---> CPU/RAM de charon, KMS, Agent (log)              |
|                                    v                                          |
| [ Processador Python ]  ---> pandas + matplotlib (CDF, P95/P99, tabelas)      |
+-------------------------------------------------------------------------------+
```

Ferramentas por tipo de coleta (como no rascunho original, mantidas):
latência fina via `sockperf`/`nping`; throughput/jitter via `iperf3 -J`;
estado do kernel IPsec via script Python rodando `ip -s xfrm state` a cada
500ms; log de decisão do scheduler como CSV/JSON emitido pelo próprio módulo
em `prototype/`; CPU/memória via `pidstat -p $(pgrep charon) -u -r 1 60`.

## 5. Coletor "padrão OpenRAN" vs. Prometheus/Grafana — qual usar, e quando

Isso não é uma escolha de "um ou outro" — são duas camadas diferentes, com
papéis diferentes, e a resposta muda dependendo se o alvo é **o artigo agora**
ou **uma versão operacional futura**.

**Para o artigo (coleta experimental agora): manter o coletor Python leve
acima.** O "coletor padrão" do ecossistema O-RAN é o **VES Collector**
(VNF Event Streaming), especificado pela ETSI (TS 103 982) e implementado de
referência pelo projeto `smo/ves` da O-RAN Software Community, normalmente
alimentado por um **PM Mapper** (`ric-plt-vespamgr`) que converte medições de
performance em eventos VES enviados via O1 ao SMO. Esse coletor foi desenhado
para **interoperabilidade de telemetria entre componentes de produção** dentro
de um SMO completo — é orientado a eventos/arquivos PM em lote, não a
latência fina de pacote por pacote. Para o tipo de medição que o artigo
precisa (P95/P99 de RTT, correlação exata entre instante de rekeying e spike
de latência), um coletor síncrono e leve como o pipeline acima dá dados mais
precisos, com menos overhead introduzido pela própria medição, e é o padrão
usado em artigos de avaliação de desempenho de rede (não telemetria de
operação).

**Dito isso, vale uma frase no artigo** situando a escolha frente ao padrão
O-RAN — algo como: "optamos por um coletor local leve para medições de
latência fina; a integração com o barramento VES/O1 do SMO é discutida como
trabalho futuro para operação em produção" — isso mostra consciência do
ecossistema sem exigir montar um SMO completo só para rodar o experimento.

**Prometheus + Grafana como versão futura: faz sentido, mas como camada de
visualização/operação, não como substituto do coletor experimental.** Na
prática, mesmo dentro do O-RAN SC, é comum que os dados vindos do VES acabem
exportados para um backend tipo Prometheus/InfluxDB e visualizados em Grafana
— ou seja, Prometheus/Grafana não compete com VES, ele normalmente fica
*depois* do VES na cadeia. Para uma versão operacional do seu orquestrador
(não o experimento do artigo), a migração natural seria: o scheduler/KMS/Agent
exportam métricas num endpoint `/metrics` (formato Prometheus, ex. via
`prometheus_client` em Python), o Prometheus faz scrape periódico, e o Grafana
monta os dashboards ao vivo (risco por fatia, SPIs ativos, violações de SLA
em tempo real). Isso é ótimo para *operação contínua* mas não é o ideal para
gerar as figuras do artigo (CDF, boxplot com anotações específicas) — isso
continua sendo mais preciso e controlável com pandas/matplotlib direto dos
logs JSON/CSV brutos.

**Resumo da recomendação**: coletor Python leve agora (dados do artigo),
nota de alinhamento com VES/O1 como trabalho futuro de interoperabilidade
O-RAN, e Prometheus/Grafana como trabalho futuro de operação/observabilidade
contínua — não como ferramenta de coleta para as métricas do artigo em si.

## 6. Mapeamento com o repositório

| Métrica/Evento | Onde instrumentar |
|---|---|
| Decisão de risco / ordem de rotação | `orchestrator/scheduler/policy.py` (`compute_risk`) |
| Geração de material PQC/PPK (tempo) | `orchestrator/kms/crypto.py` (`generate_hybrid_material`) |
| Confirmação de SPI novo (tempo) | `orchestrator/ipsec_agent/agent.py` (`_wait_for_fresh_sa`) |
| Classificação por fatia / contadores por mark | `prototype/ebpf_classifier/loader.py` (`read_stats`) |
| Mapeamento TEID→S-NSSAI | `prototype/pfcp_sniffer/session_tracker.py` |
