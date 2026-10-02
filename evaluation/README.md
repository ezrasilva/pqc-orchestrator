# evaluation

Pipeline de coleta experimental pra avaliação do Risk-Aware Scheduler
contra os baselines — ver `../docs/CENARIOS-TESTE-AVALIACAO.md` (leia
esse documento primeiro, este README só situa o estado do código).

## Estado atual: pipeline completo implementado e validado contra o laboratório real

Todas as peças abaixo foram testadas contra o laboratório real (não só
unitariamente) — rotação real acontecendo, tráfego real passando,
isolamento confirmado via contadores reais. O que **não** foi rodado
nesta sessão são as campanhas completas (10 execuções × 5 min por
cenário, como a seção 3 do documento pede) — isso fica pro usuário rodar
(leva horas; só 1 execução de 20s do Cenário 3 já levou ~1 min de
setup/teardown).

```bash
source .venv/bin/activate
pip install -r ../orchestrator/requirements.txt   # kms/scheduler/ipsec_agent/smo
pip install pandas matplotlib vici

# smoke test rápido (recomendado antes de uma campanha longa)
sudo PYTHONPATH=.:../orchestrator:../prototype .venv/bin/python3 run_experiment.py \
  --scenario 3 --iterations 1 --duration 20 --warmup 2

# campanha completa (iterations é configurável, default 10 — ver seção 3 do documento)
sudo PYTHONPATH=.:../orchestrator:../prototype .venv/bin/python3 run_experiment.py \
  --scenario all --iterations 10 --duration 300 --warmup 10

# processa os resultados (CDF, P95/P99, tabelas)
.venv/bin/python3 analyze.py --input-dir results/ --output-dir report/
```

Precisa de root (fala com os netns do laboratório) e do laboratório já
de pé (RAN/5GC/rede — ver `../docs/RUNBOOK-OAI.md` passos 0-3; este
pipeline cuida só da camada IPsec de cada cenário).

## Estrutura

```
instrumentation.py    # emit()/timed() — timestamps compartilhados entre os
                        # três componentes do orquestrador e os coletores,
                        # custo zero quando não há experimento rodando
lab_control.py          # operações de controle do laboratório (restart IPsec,
                          # captura de TEID real, health-check da UE)
rotation_driver.py       # liga o Scheduler/SMO ao estado real das SAs,
                           # continuamente, durante a janela de um cenário
run_experiment.py          # orquestrador principal — CLI com --iterations
collectors/
  xfrm_state.py             # ip -s xfrm state, a cada 500ms
  classification_stats.py    # iptables mangle OUTPUT (ver nota abaixo sobre
                               # por que não é o eBPF do Módulo 3)
  resource.py                 # CPU/memória via pidstat
  traffic.py                   # latência (ping) e throughput (iperf3)
scenarios/
  scenario0_baseline_native.py   # sem IPsec
  scenario1_static_pqc.py         # 1 túnel ML-KEM-768 pra tudo, rekey fixo
  scenario2_diff_no_risk.py        # 3 SAs reais, EDF (WEIGHTED_EDF)
  scenario3_risk_aware.py           # 3 SAs reais, risco (RISK_AWARE) — padrão
  scenario4_contention.py            # rotação forçada simultânea nas 3
analyze.py                           # pandas + matplotlib — CDF, P95/P99, tabelas
tests/
  test_instrumentation.py            # únicos testes unitários puros (o resto
                                       # é testado contra o laboratório real)
```

## Desvios do documento original, todos documentados no código onde acontecem

1. **Classificação por fatia via `iptables mangle`, não eBPF/TC**
   (`collectors/classification_stats.py`) — o classificador eBPF do
   Módulo 3 não é o que está de pé no laboratório desde a Fase 3 (achado
   crítico documentado em `../docs/ARQUITETURA-PROTOTIPO-COMPLETA.md`
   seção 4.1); confirmei contra o laboratório que não há nada anexado
   via `tc filter show ... egress`.
2. **Latência via `ping`, não `sockperf`** (`collectors/traffic.py`) —
   `sockperf` precisa de um processo servidor do lado remoto (a UPF,
   rodando `gradiant/open5gs:2.8.0`, sem `sockperf` instalado); `ping`
   dá a mesma propriedade (pacotes pequenos, periódicos, RTT real) sem
   precisar modificar a imagem.

## Achados reais encontrados construindo e validando este pipeline (não escondidos)

Esta seção documenta bugs genuínos encontrados testando contra o
laboratório real — não "deveria funcionar", funcionou depois de
corrigido e confirmado:

1. **`pidstat` rejeita intervalo fracionário** (`1.0` em vez de `1`) com
   um erro de uso que ficava escondido quando `stderr=DEVNULL` — o
   coletor de recursos simplesmente não emitia nada, sem erro visível.
2. **`Path.home()` sob `sudo` resolve pra `/root`**, não pro usuário
   real — quebrou a localização dos scripts do laboratório
   (`lab_control.py`) e do binário da UE, também silenciado por
   `stderr=DEVNULL`. Corrigido lendo `$SUDO_USER`.
3. **`pidstat` bloqueia a saída em buffer de bloco quando o stdout é um
   pipe** (não um terminal) — sem `stdbuf -oL`, nenhum evento aparecia
   em janelas de coleta curtas.
4. **O laço de decisão do Scheduler acumulava fila sem limite** — a
   primeira versão só processava a tarefa de maior risco por tick, mas
   enfileirava as três fatias a cada tick; líquido +2 na fila por tick,
   crescendo sem parar, e eMBB/mIoT nunca chegavam a rotacionar de
   verdade (URLLC sempre vencia o risco). Corrigido: drena a fila
   inteira a cada tick.
5. **As três sondas de tráfego rodavam sequencialmente**, não em
   paralelo — fazia a duração real da janela virar `3 × duration`
   (uma sonda de latência de 20s, depois throughput de 20s, depois mais
   20s) em vez de três sondas simultâneas de 20s. Corrigido com threads.
6. **TEIDs ficam órfãos depois de reiniciar a UE** — cada nova sessão
   PDU ganha um TEID novo; as regras `mangle` antigas continuam
   "válidas" (sem erro), só que não casam com nada, e o tráfego de
   teste sai sem mark. Automatizado (`capture_and_apply_slice_marks`):
   sniffa `udp/2152` enquanto gera uma rajada de tráfego por fatia e lê
   o TEID real dos bytes 4-7 do payload GTP-U.
7. **Reiniciar o IPsec com a UE já conectada deixa o plano de dados
   "preso"** — N2/SCTP continua `ESTABLISHED`, as interfaces continuam
   com IP, mas nenhum pacote de dados novo flui. Não isolamos a causa
   raiz; reiniciar a UE resolve (`ensure_ue_data_plane`/`restart_ue`).
   As três sessões PDU também não terminam de se reestabelecer ao mesmo
   tempo depois de um restart — `all_slices_data_plane_healthy` checa
   as três, não só uma.
8. **Comparar isolamento por "pico de uma SA" subestima o tráfego real
   quando há rotação no meio da janela** — cada rotação cria uma SA
   nova (contador zerado) pro mesmo mark; `analyze_isolation` corrigido
   pra somar o pico de cada SPI individual antes de agrupar por mark.
   Validado contra tráfego real: eMBB e mIoT batem exatamente
   (`classified_packets == sa_packets_total`), URLLC fica a 2 pacotes
   de diferença (efeito de borda esperado da amostragem a 500ms — os
   últimos pacotes da janela podem não ter sido capturados pela última
   amostra antes do fim da coleta, não é um vazamento).

## Resultado real já observado (1 execução, Cenário 3, 35s)

Só pra ilustrar que o pipeline produz dado real, não só "roda sem
erro" — de uma única execução curta:

- **B.1 (decomposição do tempo de rekeying)**: geração de material PQC
  ~0.6-7ms (P50/P99), confirmação de SPI no kernel ~505ms —
  confirma que o gargalo é a instalação da SA no kernel
  (reauth/handshake IKE), não a criptografia PQC em si.
- **B.3 (isolamento)**: eMBB e mIoT com correspondência exata entre o
  que foi classificado e o que a SA carregou; URLLC a 2 pacotes de
  diferença por efeito de amostragem.

Esses números vêm de 1 execução curta, não da campanha estatística
completa (10× por cenário) — servem só de prova de que o pipeline
funciona, não como resultado pro artigo.
