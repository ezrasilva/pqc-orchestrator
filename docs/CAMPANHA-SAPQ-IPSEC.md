# Nova campanha de testes do SAPQ-IPsec

Oct 14, 2026 · @Esdras Silva

## Objetivo e perguntas de pesquisa

A nova campanha deve responder qual perfil criptográfico cada fatia O-RAN exige no backhaul N3 e quais combinações de PQC atendem esse perfil sem violar os requisitos da fatia. A campanha de 12–13/10 não responde a isso: as três fatias usaram a mesma rotação e o mesmo tipo de PQC, e a latência medida foi dominada pelo rádio simulado.

- **P1. Requisito:** quanto cada fatia tolera de custo de handshake, de interrupção durante o rekey e de overhead no plano de dados?
- **P2. Oferta:** quanto custa cada perfil PQC (nível do ML-KEM, híbrido clássico+PQC, PPK de QKD, cifra do ESP, autenticação) nessas mesmas dimensões?
- **P3. Casamento:** o perfil escolhido pelo SAPQ-IPsec para cada fatia cumpre o requisito dela, e o faz melhor do que um perfil único para todas?
- **P4. Proteção:** a microsegmentação mantém o isolamento entre fatias e prioriza as críticas quando o rekey é forçado ou falta entropia QKD?

P1 e P2 saem da Fase A (bancada no N3, sem rádio). P3 e P4 saem da Fase B (ponta a ponta com OCUDU + srsUE + Open5GS).

## Arquitetura de chaves adotada

O IKEv2 negocia as chaves com ML-KEM, e o KMS contribui com uma chave QKD como PPK. O PSK volta a ser só autenticação. Isso corrige o furo herdado do WQuNets (chave híbrida carregada como PSK, que não entra na derivação do ESP).

| Camada | Mecanismo | Onde roda | Renovada em |
| --- | --- | --- | --- |
| Troca de chaves | ECDH/x25519 e/ou ML-KEM no IKE (RFC 9370) | charon | todo rekey e todo reauth |
| Material externo | PPK de QKD via ETSI 014 (RFC 8784), `ppk_required = yes` | KMS de cada ponta → charon | só no reauth |
| Cifra do tráfego | ESP AES-GCM ou ChaCha20-Poly1305 | kernel (XFRM) | todo rekey |
| Autenticação | PSK, ECDSA ou ML-DSA | charon | reauth |

A rotação passa a ter dois níveis por fatia:

1. **Rekey da Child SA, a cada Tr\_child.** Gera chaves de ESP novas com um ML-KEM novo, herda o PPK pelo SK\_d e não consome QKD.
2. **Reauth com PPK novo, a cada Tr\_ppk.** O KMS de cada ponta obtém a mesma chave QKD pelo ID, o agente carrega via VICI (`load_shared type=ppk`) e dispara o reauth. Consome k bits de QKD.

O consumo de QKD segue o modelo do WQuNets por fatia: Σ k / Tr\_ppk,i ≤ R\_qkd. O KEM local do KMS sai do caminho, porque o ML-KEM do IKE já é renovado a cada rekey.

## Perfis por fatia e catálogo de perfis criptográficos

Os perfis por fatia abaixo são hipóteses que a campanha confirma ou derruba, não premissas. No N3, quem cifra são a CU e o UPF, não o UE. Por isso a restrição de energia do dispositivo mIoT não pesa aqui; o que diferencia as fatias é a tolerância a interrupção, o volume por chave e o horizonte de confidencialidade dos dados.

| Fatia | Requisito dominante (hipótese) | Horizonte de confidencialidade | Perfil candidato | Tr\_child / Tr\_ppk |
| --- | --- | --- | --- | --- |
| URLLC | Nenhuma perda e nenhum pico de latência durante o rekey; handshake curto | Médio (comandos de controle) | Híbrido x25519 + ML-KEM-768, PPK QKD, AES-256-GCM | curto / curto |
| eMBB | Throughput; volume alto por chave | Curto a médio (mídia) | ML-KEM-768, AES-GCM com AES-NI, vida da SA por bytes | médio / longo |
| mIoT | Muitos fluxos pequenos; custo por fluxo | Longo (medição, telemetria) | ML-KEM-1024, AES-256-GCM | longo / longo |

Os valores de Tr e o limite de interrupção por fatia dependem da definição de criticidade, que segue em aberto (última seção).

**Catálogo de perfis da Fase A.** Varia-se um eixo por vez a partir do perfil de referência K2 + AES-128-GCM + PSK.

| Perfil | Troca de chaves no IKE | Segurança (categoria NIST) | Observação |
| --- | --- | --- | --- |
| K0 | x25519 | clássica, quebrável por HNDL | linha de base |
| K1 | ML-KEM-512 | 1 |  |
| K2 | ML-KEM-768 | 3 | referência |
| K3 | x25519 + ML-KEM-768 (`ke1_`) | 3 + clássica | híbrido recomendado |
| K4 | ML-KEM-1024 | 5 |  |
| K5 | K3 + PPK QKD | 3 + QKD | perfil da URLLC |
| K6 | outros KEMs (HQC, FrodoKEM) | 1–5 | fora do build atual (só ML-KEM via OpenSSL): apenas microbenchmark via liboqs, como no WQuNets |

Eixos adicionais: cifra do ESP (AES-128-GCM, AES-256-GCM, ChaCha20-Poly1305) e autenticação (PSK, ECDSA P-256). O strongSwan 6.0.4 do lab não implementa ML-DSA, embora o OpenSSL 3.5.5 tenha ML-DSA-44/65/87 e SLH-DSA. Por isso a ML-DSA entra só como microbenchmark (custo e tamanho de assinatura via OpenSSL) e como limitação. Isso não afeta o HNDL: quebrar a autenticação exige um computador quântico durante o handshake, não depois.

> **Validado contra o laboratório (14/10).** ML-KEM **puro** como método de
> troca de chaves primário funciona no strongSwan 6.0.4 desta VM:
> `aes128gcm16-prfsha256-mlkem768` negocia
> `IKE:AES_GCM_16_128/PRF_HMAC_SHA2_256/ML_KEM_768`, sem nenhum KE clássico.
> Isso confirma que K1/K2/K4 são expressáveis como o catálogo assume, e
> corrige o folclore registrado no repositório (comentários em
> `scenario1_static_pqc.py` e `connections.conf` afirmando que o ML-KEM só
> entraria como round híbrido adicional via `ke1_`, com um grupo clássico
> obrigatório de base). O `ke1_` só é necessário para o caso **híbrido**
> (K3/K5, dois KEs na mesma negociação, RFC 9370).

## Fase A: caracterização dos perfis no N3, sem rádio

A Fase A mede o custo de cada perfil no próprio enlace N3, entre os namespaces da CU e do UPF, sem OCUDU nem srsUE. Assim o rádio ZMQ não mascara diferenças da ordem de 1 ms nem limita o throughput a 0,65 Mbps.

> **Ganho de resolução medido (14/10).** RTT pelo túnel N3 direto
> (`cu-ns` ↔ `5gc-edge-ns`) é **0,098 ms**, contra ~57 ms quando o mesmo
> tráfego passa pelo rádio simulado — cerca de 580× mais resolução. Uma
> interrupção de rekey de 1–20 ms é nítida na bancada e invisível pelo rádio.

1. **Handshake:** 30 reauths por perfil, medindo o tempo total e cada troca (IKE\_SA\_INIT, IKE\_INTERMEDIATE, IKE\_AUTH), bytes no fio, número de mensagens e fragmentos.
2. **Rekey e reauth sob tráfego:** ping a **1 kHz** e iperf3 UDP a taxa fixa atravessando o túnel, com 30 eventos por perfil. Mede perda de pacotes, pico de RTT e duração da interrupção, em três combinações: rekey de Child SA, reauth com make-before-break e reauth sem. Ver "Duas correções de método na A.2" abaixo — a especificação original (100 Hz, make-before-break aplicado ao rekey de Child SA) não se sustentou na medição.
3. **Plano de dados:** iperf3 TCP saturando o N3 com cada cifra do ESP (e sem IPsec), mais RTT a vazio e sob carga. Reporta throughput máximo, P50/P95/P99 de RTT e CPU em softirq.
4. **Escala:** 3, 10 e 30 Child SAs simultâneas fazendo rekey juntas, para ver se o custo cresce linearmente.
5. **Microbenchmark de KEM:** keygen, encaps e decaps de todos os KEMs do catálogo via liboqs, para os que o strongSwan não suportar.
6. **RTT do enlace como eixo:** repetir A.1 e A.2 com latência artificial no caminho N3 (`tc qdisc ... netem delay`), em pelo menos 0 ms (bancada pura), 5 ms e 20 ms por sentido.

### Nota de método: a carga do hospedeiro tem de ser registrada

A Fase A é especificada para rodar **sem OCUDU nem srsUE**, e a primeira execução dela não respeitou isso — o rádio ficou rodando, consumindo ~5 dos 8 núcleos, e nada registrava a condição. Medido depois, comparando as duas condições:

| Medição | com rádio | sem rádio | Desvio |
| --- | --- | --- | --- |
| A.5, ML-KEM-512/768/1024 | — | idêntico a 0,1 µs | **0%** |
| A.1, handshake K0/K2/K3 (p50) | 29,2 / 29,8 / 31,2 ms | 24,8 / 25,0 / 25,9 ms | ~17%, **constante** |
| A.3, AES-256 contra AES-128 | −9,2% | **−1,4%** | inverte a decisão |

O que isso diz, por medição:

* **A.5 não foi afetada.** O microbenchmark reproduz exatamente, o que mostra que a execução de 15/10 estava sob carga moderada, não severa. (Num momento de `load` 18 medido em 17/10, o mesmo benchmark inflou 3× e chegou a dar ML-KEM-1024 mais rápido que o 768 — fisicamente impossível, e um bom indicador de condições inutilizáveis.)
* **A.1 levou um deslocamento constante de ~17%**, que cancela nas conclusões estruturais: o custo por RTT continua valendo exatamente o número de trocas de cada perfil, porque isso é uma diferença.
* **A.3 foi a única a mudar uma decisão**, porque vazão é limitada por CPU e o gap entre as cifras era do mesmo tamanho do artefato.

`bench_n3.py` passou a registrar `load`, contagem de núcleos e quais processos de rádio estão de pé a cada execução e a cada ponto de RTT, e a **avisar em voz alta** quando a premissa é violada. Registrar não corrige a medição; corrige a possibilidade de confiar nela depois.

### Resultados da Fase A: a tabela que alimenta a Fase B

**Os números estão em [`FASE-A-DADOS-CONSOLIDADOS.md`](FASE-A-DADOS-CONSOLIDADOS.md), gerado dos dados** por `evaluation/phase_a/consolidate.py`. Esta seção guarda só a interpretação.

A separação é deliberada: as tabelas desta seção já foram escritas à mão e já precisaram de **duas correções manuais** — a decisão da cifra e o `R_qkd` —, cada uma arriscando ficar divergente dos arquivos de resultado. Gerar do dado elimina essa classe de erro, e o gerador **rejeita automaticamente** execuções colhidas em condição inválida, declarando a procedência de cada arquivo.

Três filtros de procedência, cada um por um defeito que aconteceu de verdade:

| Filtro | O defeito que ele previne |
| --- | --- |
| `radio_ligado` | A Fase A é especificada sem OCUDU nem srsUE; as primeiras execuções não respeitaram isso. Efeito: 0% na A.5, ~17% constante na A.1 e o bastante na A.3 para **inverter a decisão da cifra**. |
| `toggle_nao_verificado` | O drop-in da Fase B fixava `make_before_break = yes` e anulava o toggle da A.2 em silêncio: as execuções com `no` mediam `yes`. Detectado porque as duas configurações deram resultados **idênticos**. |
| `sem_registro` | Anterior à instrumentação de carga: a condição é desconhecida, então não entra. |

**O que os dados sustentam:**

1. **O custo do perfil é de round-trips, não de bytes nem de CPU.** A inclinação do tempo de handshake por RTT vale exatamente o número de trocas de cada perfil, nos seis. E K4 (ML-KEM-1024, 2077 B) custa o mesmo que K0 (x25519, 541 B) em todos os pontos: quatro vezes os bytes, zero de diferença. Bytes só custam quando forçam uma troca a mais.

2. **A A.6 se pagou.** Na bancada o híbrido parece quase gratuito; a 40 ms de RTT a penalidade é de ~40%. Medir só a 0,04 ms levaria o artigo à conclusão oposta, justamente para a URLLC — a fatia que o catálogo quer atender com K5.

3. **A interrupção de rotação tem duas componentes, e o `make_before_break` mata a que escala.** A de ida vale **exatamente 4 round-trips** — (163,38 − 3,12)/40,2 = 3,99 — e por isso cresce com o RTT; a de volta é de 1,5 a 3,2 ms e **não depende do RTT**, porque é a corrida de troca de SA no responder. Com o `make_before_break` ligado a componente de ida desaparece em todos os RTTs e sobra só a local, de ~1,6 a 1,8 ms num sentido. Num backhaul de 20 ms por sentido isso é a diferença entre **163 ms e 1,8 ms de interrupção a cada renovação de PPK** — e como renovar PPK exige reauth, é requisito da proposta, não afinação.

4. **O rekey de Child SA não perde um único pacote**, em nenhum perfil, sentido ou RTT, com linha de base zero. É o que justifica a arquitetura de dois níveis: a rotação frequente sai de graça e só a renovação de PPK paga.

5. **AES-256-GCM nas três fatias.** A diferença de vazão contra o AES-128 cabe dentro da variação entre execuções do próprio AES-128, e a latência é indistinguível. Não há eixo em que o AES-128 compense.

6. **O custo de rekey simultâneo é sublinear**, então a URLLC não paga fila linear pelas outras fatias e a proposta tem folga para escalar além de três.

### Resultado da A.5: o custo do PQC no handshake não é de CPU

41 KEMs medidos via liboqs 0.16.0, 100 repetições cada, todos bem-sucedidos (p50, em µs). A coluna "strongSwan" diz se o KEM também é mediável fim a fim pela A.1; os demais só existem aqui.

| KEM | NIST | keygen | encaps | decaps | total | pk (B) | ct (B) | strongSwan |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| ML-KEM-512 | 1 | 15.4 | 18.0 | 18.6 | 52 | 800 | 768 | sim |
| ML-KEM-768 | 3 | 21.9 | 24.2 | 26.3 | 72 | 1184 | 1088 | sim |
| ML-KEM-1024 | 5 | 27.4 | 30.5 | 34.2 | 92 | 1568 | 1568 | sim |
| HQC-1 | 1 | 2785.0 | 5548.0 | 8431.9 | 16765 | 2241 | 4433 | — |
| HQC-3 | 3 | 8426.5 | 16803.2 | 25345.3 | 50575 | 4514 | 8978 | — |
| HQC-5 | 5 | 20655.5 | 41234.3 | 62128.2 | 124018 | 7237 | 14421 | — |
| FrodoKEM-640-AES | 1 | 602.9 | 903.5 | 869.0 | 2375 | 9616 | 9752 | — |
| FrodoKEM-976-AES | 3 | 1191.8 | 1656.0 | 1600.5 | 4448 | 15632 | 15792 | — |
| FrodoKEM-1344-AES | 5 | 2057.8 | 2868.2 | 2806.2 | 7732 | 21520 | 21696 | — |
| BIKE-L1 | 1 | 558.8 | 63.5 | 985.6 | 1608 | 1541 | 1573 | — |
| BIKE-L3 | 3 | 1115.1 | 132.3 | 3215.4 | 4463 | 3083 | 3115 | — |
| BIKE-L5 | 5 | 2493.1 | 264.3 | 7985.0 | 10742 | 5122 | 5154 | — |
| sntrup761 | 2 | 10179.2 | 209.6 | 407.0 | 10796 | 1158 | 1039 | — |
| Classic-McEliece-348864 | 1 | 60976.8 | 69.2 | 71.9 | 61118 | 261120 | 96 | — |

**O que isto fecha.** O ML-KEM-768 custa ~72 µs somando as três operações, contra um handshake de ~30 ms medido na A.1: **0,2%**. Esse é o número que explica, quantitativamente, por que a A.1 não vê diferença de tempo entre K0 (x25519) e K4 (ML-KEM-1024) — o custo de CPU do KEM é duas ordens de grandeza menor que o ruído de agendamento do charon. O custo do PQC no plano de controle é de **bytes no fio** e de **round-trips**, não de processamento. É também por isso que a A.6 existe.

**O que isto NÃO autoriza concluir.** Que um KEM mais rápido em liboqs produza handshake mais rápido — a A.1 mostrou que não produz nesta bancada. As duas medições são complementares e a tabela final de custo × perfil precisa das duas colunas, porque é a de bytes que manda.

**Onde a assimetria importa.** O initiator paga keygen + decaps e o responder paga encaps, então as operações são cronometradas separadamente e não em pipeline. Nos KEMs baseados em código a assimetria é extrema: o Classic-McEliece-348864 tem keygen de 61 ms (mil vezes o ML-KEM-768) mas encaps/decaps de ~70 µs, com chave pública de 261 kB — inviável para IKE, onde a chave pública vai no fio.

### Duas correções de método na A.2

Levantadas ao implementar e medir (15/10). As duas invalidariam resultados se não fossem corrigidas.

**1. O make-before-break não se aplica ao rekey de Child SA.** A especificação original pedia a A.2 "com make-before-break ligado e desligado" sobre o rekey de Child SA. Lendo o strongSwan 6.0.4, `charon.make_before_break` (default `yes`) governa a **reautenticação IKEv2**; o rekey de Child SA é sempre make-before-break por imposição da RFC 7296. O caminho é `vici rekey` → `rekey_ike_sa_job` → `ike_sa->reauth()` → `queue_ike_reauth()`, e é nesta última que a opção decide. Confirmado também nos logs do charon, cuja ordem é inequívoca:

| `make_before_break` | Sequência nos logs |
| --- | --- |
| `yes` | reauth → **establishing** CHILD_SA → established → deleting IKE_SA → deleted |
| `no` | reauth → **deleting** IKE_SA → deleted → restarting CHILD_SA → establishing |

Isso **melhora** a medição em vez de enfraquecê-la: a renovação de PPK exige reauth, porque o PPK só entra na derivação no IKE\_AUTH. Logo o toggle incide exatamente sobre o mecanismo central da proposta, e o custo de renovar PPK é o da linha de reauth, não o da linha de rekey de Child SA. A A.2 passou a medir as três combinações.

**2. A sonda de 100 Hz é grosseira demais.** A 100 Hz, uma reauth em break-before-make deu **perda zero em todas as repetições** — o que levaria à conclusão errada de que não há interrupção. Repetindo a 1 kHz na mesma configuração: 1 pacote perdido, interrupção de ~1 ms. Os 100 Hz foram dimensionados supondo que o break-before-make custaria um handshake inteiro (~30 ms); não custa, porque a política XFRM permanece instalada e só o estado é refeito.

Resultado da K2 com a sonda corrigida, 30 repetições por combinação:

| Evento | `make_before_break` | Repetições com perda | Interrupção |
| --- | --- | --- | --- |
| rekey de Child SA | n/a (sempre MBB) | **0/30** | 0 ms |
| reauth | `yes` | 20/30 | 1 ms |
| reauth | `no` | 27/30 | 1 ms |

As quatro linhas de base (mesmo tráfego, nenhum evento) deram **0 perda em ~8000 pacotes**, o que torna o pacote perdido atribuível ao evento e não a ruído. O make-before-break reduz a **frequência** da perda, não a magnitude.

A linha de base é o que pegou um terceiro erro, este meu: a primeira versão da métrica de interrupção usava o intervalo entre chegadas e dava ~2,1 ms tanto nos rekeys quanto na linha de base sem evento — ou seja, media o jitter de agendamento do próprio `ping`. Passou a ser derivada de números de sequência ausentes.

### Por que o RTT do enlace precisa ser um eixo

A primeira execução da A.1 (14/10, 6 perfis × 30 repetições, 180/180 handshakes bem-sucedidos) mostrou que **o tempo de handshake quase não varia entre perfis** — p50 entre 29 e 32 ms — enquanto **os bytes no fio variam 4×**:

| Perfil | p50 | p95 | Bytes enviados | Trocas | Fragmentos |
| --- | --- | --- | --- | --- | --- |
| K0 (x25519) | 30,1 ms | 34,0 ms | 541 B | 2 | 0 |
| K1 (ML-KEM-512) | 29,1 ms | 30,4 ms | 1309 B | 2 | 0 |
| K2 (ML-KEM-768) | 29,7 ms | 35,1 ms | 1693 B | 2 | 0 |
| K3 (híbrido) | 31,6 ms | 35,3 ms | 1871 B | **3** | **2** |
| K4 (ML-KEM-1024) | 32,3 ms | 37,2 ms | 2077 B | 2 | 0 |
| K5 (K3 + PPK) | 31,4 ms | 38,0 ms | 1898 B | **3** | **2** |

Ou seja: o custo do PQC no handshake **não está em CPU** (o ML-KEM é rápido o bastante para sumir no ruído de agendamento do charon), está em **bytes transmitidos** e no **round-trip extra** que o híbrido exige (IKE\_INTERMEDIATE, que com ML-KEM-768 ainda sai fragmentado em dois pacotes). O PPK custa apenas 27 B sobre o K3.

O problema metodológico: a bancada tem RTT de ~0,1 ms, então **esse round-trip extra sai praticamente de graça** (K3 em 31,6 ms contra K2 em 29,7 ms). Num backhaul N3 real, com 5–20 ms de RTT, a troca adicional custaria de 10 a 40 ms — o que inverte a conclusão justamente para a URLLC, a fatia que o catálogo propõe atender com K5 (híbrido + PPK). Medir só a 0,1 ms levaria o artigo a concluir que "o híbrido é barato" por artefato da bancada, e essa conclusão não se sustentaria num enlace real.

Por isso a A.6: o eixo de RTT separa o custo de **processamento** (constante, medido a 0 ms) do custo de **protocolo** (proporcional ao número de trocas, que só aparece com RTT realista). A tabela final de custo × perfil deve reportar as duas componentes, e a escolha de perfil por fatia na Fase B deve usar o RTT representativo do backhaul que se quer modelar — não o da bancada.

Ordem das execuções aleatória entre perfis, 30 repetições, warm-up descartado. O resultado da Fase A é uma tabela custo × perfil que alimenta a escolha de perfil por fatia na Fase B.

## Fase B: proteção das fatias ponta a ponta

A Fase B roda o testbed completo (OCUDU + srsUE + Open5GS) e compara o SAPQ-IPsec com alternativas sem ciência de criticidade. Diferente da campanha anterior, todos os cenários usam as mesmas regras de rotação onde elas se aplicam e têm tráfego na janela inteira.

| Cenário | SAs | Perfil criptográfico | Rotação | O que mostra |
| --- | --- | --- | --- | --- |
| C0 | nenhuma | sem IPsec | — | piso de latência e teto de throughput |
| C1 | 1 túnel para tudo | K2 uniforme | Tr\_child da URLLC para todo o tráfego | rekey cego à fatia |
| C2 | 3, uma por fatia | perfil da URLLC (K5) para todas | Tr curtos para todas | proteção máxima sem critério: custo de CPU e de QKD |
| C3 | 3, uma por fatia | perfil de cada fatia (tabela de perfis) | Tr por fatia, escalonador risk-aware | a proposta |
| C4a | igual a C3 | igual a C3 | R\_qkd abaixo da demanda total | quem perde PPK novo quando falta entropia |
| C4b | igual a C3 | igual a C3 | rotação forçada das 3 fatias no meio da janela, com tráfego antes, durante e depois | impacto da contenção e ordem de atendimento |

C4a e C4b rodam com risk-aware e com EDF. Só há diferença entre as políticas quando há disputa, então é aí que a comparação entre elas aparece.

**Isolamento.** Além de comparar contadores marca × SA, captura-se o ESP no fio para confirmar que cada SPI só carrega a fatia certa. Um teste negativo envia tráfego com TEID não classificado e verifica o destino dele (SA padrão ou descarte, conforme a política decidida).

**Execução.** 30 repetições de 300 s por cenário, com ordem intercalada e sorteada entre cenários, warm-up descartado e tráfego desde t = 0.


### Resultados da Fase B

**Os números estão em [`FASE-B-DADOS-CONSOLIDADOS.md`](FASE-B-DADOS-CONSOLIDADOS.md)**, gerado dos dados por `evaluation/consolidate_phase_b.py`, com a procedência de cada execução declarada. Esta seção guarda a interpretação e a única comparação que o gerador não cobre: entre as duas versões da implementação.

Duas campanhas completas, de 300 s por iteração e ordem em blocos aleatorizados:

| Campanha | Quando | Iterações | Válidas | O que distingue |
| --- | --- | --- | --- | --- |
| **v1** | 19–21/10 | 240 | 170 + 109 | poço de entropia em round-robin |
| **v2** | 21–22/10 | 240 | **223** | poço de entropia por criticidade |

#### 1. O túnel único paga 2,7× a latência de túnel

N3 p50 de **0,162 ms** no C1 contra **0,060 ms** nos cenários diferenciados, sobre um piso de 0,048 ms sem IPsec. Um SA só carrega todo o tráfego e tudo disputa ali. É o argumento mais direto a favor de separar as fatias, e só é visível na sonda de alta resolução: no fim a fim o C1 parece *melhor* (55,9 contra 59,5 ms), porque lá o rádio domina.

#### 2. A prioridade na entropia é necessária, não decorativa

Rebaixamentos da URLLC por execução de 300 s, média ± IC95:

| Cenário | v1 round-robin | **v2 por criticidade** |
| --- | --- | --- |
| C3 proposta | 0,68 ± 0,38 | **0,00 ± 0,00** |
| **C4a escassez** | **28,85 ± 0,56** | **0,00 ± 0,00** |
| C2 proteção máxima | 0,68 ± 0,35 | **0,00 ± 0,00** |
| C4b contenção | 0,73 ± 0,26 | **0,00 ± 0,00** |

Zero em 153 execuções, com IC de ±0,00 — não é "menos", é nenhum. No C4a a fração da entropia que vai para a URLLC sobe de **36% para 100%**: sob escassez severa, eMBB e mIoT recebem **zero** PPK e as 543 chaves vão todas para a fatia de maior impacto.

O escalonador ordenar tarefas por criticidade **não basta**: se o poço distribui chaves em round-robin, a fatia crítica rebaixa quando chega a vez dela e o poço está vazio. A partilha de entropia precisa da mesma ordem — que é o que o modelo já dizia (`I` define "a prioridade **e a partilha de QKD**") e o que a v1 não implementava.

> **A v1 não era mais rápida, era menos segura.** A URLLC fica ~1 ms mais lenta na v2 (p50 de 58,38 para 59,45 ms, significativo com IC de ±0,14). Isso não é regressão: ela passou a **pagar pela renovação de PPK em vez de pulá-la**. O desvio entre execuções também caiu (±0,40 para ±0,14), porque ela deixou de alternar entre renovar e rebaixar ao sabor do round-robin.

#### 3. A ordem do vetor de criticidade produz uma consequência não óbvia

No C2, a **mIoT é atendida em 32,2% das tentativas de PPK e a eMBB em 0%** (842 chaves contra zero, em 2.611 tentativas cada). Pelo desempate lexicográfico as duas empatam em `I` (média) e decide o `H`: a mIoT tem horizonte de confidencialidade **alto** (telemetria precisa seguir secreta por anos, logo é mais exposta a *harvest now, decrypt later*) contra o **baixo** da eMBB, cuja mídia perde valor em dias. Ninguém ordenaria mIoT acima de eMBB por intuição — é o vetor que produz isso, e é um argumento a favor de derivar a prioridade do descritor de fatia em vez de escolhê-la.

#### 4. Proteção máxima custa o dobro pelo mesmo resultado

C2 e C3 alcançam a mesma proteção da URLLC (zero rebaixamentos), mas o C2 paga **76 rebaixamentos por execução contra 23** do C3, e **106 rekeys de Child SA contra 60**. Proteger tudo no máximo não compra segurança a mais onde importa; compra escassez para as outras fatias.

#### 5. Com prioridade na entropia, a política de escalonamento importa menos

| Cenário | risk-aware | EDF | Diferença |
| --- | --- | --- | --- |
| C4a | 56,90 ± 0,27 ms | 57,30 ± 0,37 ms | 0,40 ms, **não significativa** |
| C4b | 59,27 ± 0,09 ms | 59,62 ± 0,18 ms | 0,35 ms, significativa |

Na v1 as mesmas diferenças eram de **1,95 e 1,26 ms**. Os dois mecanismos se sobrepõem: quando a alocação de entropia já protege a fatia crítica, sobra menos efeito para a ordenação de tarefas produzir. É uma ressalva honesta ao valor isolado do escalonador risk-aware — ele continua melhor, mas a margem encolhe quando a entropia é alocada corretamente.

#### 6. O fim a fim não sustenta afirmação fina

O piso sem IPsec é de 54,8 ms, e os cenários diferenciados somam ~4,7 ms. Qualquer p99 fim a fim é inutilizável: o C0, **sem cripto nenhuma**, chega a 1069 ms em execuções isoladas. É a justificativa medida para a sonda de alta resolução no N3, e o motivo de a Fase A existir.

#### 7. A contagem crua de PPK mede retentativa, não alocação

Achado conferindo o notebook contra as tabelas: pela contagem absoluta a
**mIoT obtém mais PPK que a URLLC** no C2, C3 e C4b (589 contra 260 no C3),
o que inverteria a leitura da tese. Não é o mecanismo priorizando a mIoT — é
viés de amostragem do laço de retentativa.

Uma reauth que falha por poço vazio **não reautentica nada**, logo não zera
`established Ns ago` da IKE_SA. O portão de idade do `rotation_driver`
compara essa idade com o `Tr_ppk`, então, uma vez vencido o prazo, a fatia
faminta re-enfileira a cada tick até o fim da execução. Medido num C3
(intervalos entre `ppk_fetch_start`):

| Fatia | tentativas em 300 s | intervalo | leitura |
| --- | --- | --- | --- |
| URLLC | 10 | 29,9 s | o próprio `Tr_ppk`: acerta e zera a idade |
| eMBB | 104 | 2,5 s | o intervalo do tick |
| mIoT | 72 | 2,5 s | o intervalo do tick |

A mIoT acumula 72 tentativas contra 10 da URLLC; com ~36% de sucesso, sai
com mais chaves em números absolutos. **A métrica válida é a taxa de
sucesso**, que não depende do número de tentativas — e ela sai na ordem
pretendida em todos os cenários:

| Cenário | URLLC | mIoT | eMBB |
| --- | --- | --- | --- |
| C2 proteção máxima | 100,0% | 32,2% | 0,0% |
| C3 proposta | 100,0% | 36,5% | 13,7% |
| C4a escassez | 100,0% | 0,0% | 0,0% |
| C4b contenção | 100,0% | 36,9% | 13,3% |

URLLC > mIoT > eMBB, que é exatamente o vetor `I > H > D`. A tese se
sustenta; o que estava errado era a métrica. As tabelas geradas passaram a
reportar tentativas e taxa ao lado da contagem.

**Corrigido, pendente de recampanha.** O `rotation_driver` ganhou um segundo
portão, por tempo desde a última TENTATIVA (`_pode_tentar_ppk`), e não só por
idade da SA. O período escolhido é o próprio `Tr_ppk`, não um recuo
exponencial: o que a arquitetura especifica é "renova a cada `Tr_ppk`, e se a
entropia não estiver lá passa o período só com ML-KEM no ESP"; um recuo
exponencial faria a fatia tentar menos que o projetado depois de a entropia
voltar, atrasando a recuperação. Quando a tentativa dá certo os dois portões
concordam, porque o sucesso zera a idade da IKE_SA — eles divergem só no caso
que importa, o da tentativa que falha.

Coberto por `evaluation/tests/test_rotation_driver_backoff.py`, que falha
contra o código antigo com o número exato do defeito (120 tentativas em 300 s
contra as 10 projetadas). O teste existe porque este defeito atravessou uma
campanha inteira sem aparecer como erro — só como um número impossível numa
tabela — e revalidar a mão custa ~20 h.

**O que muda nos números da próxima campanha.** A taxa de sucesso deve ficar
onde está, porque é imune ao viés; o que cai em uma ordem de grandeza são as
contagens de tentativa, de `poço vazio` e de **rebaixamento** — a eMBB sai de
~43 rebaixamentos por execução para ~3, já que passa a ser rebaixada uma vez
por período e não uma vez por tick. A constatação 4 ("proteção máxima custa o
dobro") compara rebaixamentos entre cenários e por isso sobrevive à mudança de
escala, mas os valores absolutos citados nela terão de ser regerados.

#### 8. Renovar PPK colide com o rekey de Child SA

**31,5% das reauths da URLLC levam de 6 a 15 s** em vez dos ~26 ms medianos
— e nenhuma outra fatia apresenta isso. A causa está no log do charon:

```
13:16:18.648967  unable to reauthenticate in CHILD_SA DELETED state, delaying for 11s
13:16:29.649454  reauthenticating IKE_SA n3-urllc-cu-edge[7]
13:16:29.667606  state change: CONNECTING => ESTABLISHED
```

Dos 11.021 ms medidos, 11.000 são adiamento deliberado do charon e 18 ms são
a reauth real. Ao rekeyar uma Child SA o strongSwan mantém a antiga por
`delay closing of inbound CHILD_SA ... for 5s`, e **recusa reautenticar a
IKE_SA enquanto uma Child SA dela está em `DELETED`**. A URLLC é a única
fatia que rotaciona as duas coisas rápido o bastante para colidir
(`Tr_child` 12 s contra `Tr_ppk` 30 s), e a fase da colisão é uniforme — daí
a distribuição achatada entre 6 e 15 s em vez de picos em 4/8/16 s de
retransmissão.

Consequências: (a) o plano de dados **não** sofre, porque o
`make_before_break` cobre a troca — é cauda de plano de controle; (b) um
projeto de rotação não pode escolher `Tr_child` e `Tr_ppk`
independentemente: períodos que colidem fazem o PPK atrasar até duas ordens
de grandeza; (c) só apareceu porque o consolidador passou a retomar as
durações dos estágios — as tabelas de contagem não mostravam nada.

## Métricas e instrumentação

Cada métrica precisa de um ponto de medição que não dependa do rádio. A tabela diz o que medir e com quê.

| Métrica | Fase | Como medir |
| --- | --- | --- |
| Tempo de handshake por troca | A, B | log `ike` do charon com timestamp, ou eventos VICI por etapa |
| Bytes e fragmentos do IKE | A | tcpdump nas portas UDP 500/4500 |
| Instalação da SA no kernel | A, B | `ip xfrm monitor` com timestamp |
| Custo de orquestração (KMS, VICI) | B | `timed()` em volta da busca do PPK e de cada `load_shared` |
| Interrupção no rekey (perda, pico de RTT) | A, B | ping a 1 kHz e iperf3 UDP atravessando o N3 |
| RTT do N3 (P50/P95/P99) | A, B | ping entre os namespaces da CU e do UPF pelo túnel |
| RTT ponta a ponta da URLLC | B | ping pelo UE, como complemento |
| Throughput do N3 | A | iperf3 TCP saturando o túnel, por cifra |
| CPU e memória | A, B | charon, KMS, OCUDU, UPF e softirq do kernel (`mpstat`, `pidstat`) |
| Consumo de QKD | B | bits de PPK pedidos ao KMS por fatia, comparados com R\_qkd |
| Volume protegido por chave | B | bytes por SPI no XFRM ao fim de cada SA |
| Isolamento | B | contadores marca × SA e captura de ESP por SPI |
| RTT artificial aplicado no N3 | A | `tc qdisc show` no veth do caminho, registrado junto de cada medição |

A decomposição do rekey fica: decisão do escalonador → obtenção do PPK → `load_shared` → IKE (por troca) → instalação no XFRM. Assim a parte PQC (IKE\_INTERMEDIATE) aparece separada da parte de kernel.

## Ajustes no código antes de rodar

Os itens abaixo são do repositório ezrasilva/pqc-orchestrator (commit a3ba1d6). Os quatro primeiros corrigem defeitos da campanha de 12–13/10; os demais implementam a nova arquitetura.

- [x] `evaluation/rotation_driver.py`: enfileirar por idade, com dois tipos de tarefa. *(Feito em 17/10.)* `TaskType.REKEY_CHILD` e `TaskType.REAUTH_PPK` novos; o driver lê **duas** idades por fatia (a da Child SA governa o `Tr_child`, a da IKE_SA governa o `Tr_ppk` — linhas diferentes do `swanctl`) e só enfileira quando o prazo vence. O tick caiu de 10 s para 2 s: com enfileiramento por idade o tick é só amostragem, e 10 s contra um `Tr_child` de 12 s daria erro de quantização de até 83%.

  **Rebaixamento sob escassez de QKD.** Medido ao vivo: a primeira versão deixava a fatia sem QKD **sem rotação nenhuma** — o `continue` que evita trabalho duplicado fazia a reauth vencida bloquear o rekey de Child SA, então eMBB e mIoT paravam de renovar também o ESP. É o oposto do propósito de ter dois níveis. Agora, quando a reauth falha por poço vazio, a fatia cai para o nível barato na mesma passagem, que é o comportamento que esta seção já especificava para o C4a. Validado: com poço vazio em eMBB/mIoT, 10 e 11 rebaixamentos em 60 s, enquanto a URLLC manteve o PPK.
- [x] `evaluation/run_experiment.py`: no C4, tráfego em t = 0 e contenção no meio da janela com o tráfego rodando. *(Feito em 17/10. A versão anterior dormia metade da janela sem tráfego, disparava a contenção num enlace OCIOSO e só então iniciava o tráfego — media o efeito da contenção sobre nada, e perdia metade da amostra de tráfego.)*
- [x] `evaluation/scenarios/scenario1_static_pqc.py`: rekey da Child SA no `Tr_child`. *(Feito em 17/10. Era `--rekey --ike`, o caminho caro: daria ao cenário 1 uma desvantagem vinda do MECANISMO e não da política de escalonamento, que é o que ele existe para isolar. O intervalo fixo passou a ser o `Tr_child` da URLLC (12 s), importado de `rotation_driver` — uma política cega à fatia tem de adotar o prazo mais apertado, senão viola o SLA da URLLC, e comparar contra uma linha de base que já viola SLA seria atacar um espantalho.)*
- [x] Runner: blocos aleatorizados — uma rodada por repetição, cenários sorteados dentro dela. *(Feito em 17/10. O laço anterior rodava todas as iterações de um cenário antes do próximo, o que confunde PERFEITAMENTE deriva temporal com cenário — e esta VM tem derivas reais e documentadas: o tmpfs de 12 GB que os logs enchem, a CPU do rádio ZMQ, o estado da QKDN. Flag `--no-shuffle` só para depuração.)*
- [x] `orchestrator/kms/crypto.py`: remover o ML-KEM local; o KMS entrega a chave QKD (ETSI GS QKD 014 do QuDitto) buscada fora do caminho crítico; a chave entra no charon como PPK. *(Feito em 16/10. Novo `kms/qkd.py` com cliente ETSI 014 e poço de pré-busca por fatia; `crypto.py` reduzido a `fetch_ppk`; `KeyManagementCore.generate()` virou `provision_ppk()`, e o `key_id` passa a vir da QKDN em vez de cunhado local — é por ele que a outra ponta recupera a MESMA chave no `dec_keys`. O SMO usa `reauth_with_ppk`.)*

  Medido no caminho crítico, com o poço aquecido: busca **0,2 ms**, instalação do PPK 1,5 ms, reauth 8,3 ms. A pré-busca tirou os 15,4 s da simulação do caminho do rekey e deixou ~10 ms.

  **`R_qkd` medido: a QKDN serializa a geração.** Três threads pedindo em paralelo renderam ~1 chave a cada 15 s, não três — ou seja ~256 bits / 15,2 s ≈ **16,8 bits/s** de taxa agregada, não por fatia. É o `R_qkd` do modelo `Σ k / Tr_ppk,i ≤ R_qkd`, e é um teto baixo: só a URLLC, com `Tr_ppk` de 30 s e chave de 256 bits, já consome 8,5 bits/s. Poço vazio é tratado como **escassez de QKD e não como erro** — a rotação é adiada e o evento `ppk_pool_empty` fica no registro, porque violar o modelo tem de produzir efeito observável.
- [x] `orchestrator/ipsec_agent/agent.py`: separar `rekey_child()` de `reauth_with_ppk()`; o PSK fica fixo, só para autenticação. *(Feito em 16/10. `rekey_child()` não carrega segredo nenhum e mediu 2,4–3,2 ms nas três fatias; `reauth_with_ppk()` instala o PPK nos dois lados e reautentica, e recusa conexão sem `ppk_id`. Exigiu `rekey_child`/`listen_child_rekey` novos no `vici_client.py` e um `_wait_for_fresh_child_sa` próprio, porque o payload de evento de Child SA tem forma diferente do de IKE_SA. `apply_key_material` fica como caminho legado dos cenários antigos.)*
- [x] `lab/ipsec/swanctl-*/conf.d/connections.conf`: `ppk_id` e `ppk_required = yes` nas três fatias; propostas por perfil; `make_before_break` explícito. *(Feito em 16/10, validado ao vivo — as três sobem com `/PPK` na proposta negociada:)*

  | Fatia | Perfil | Negociado no IKE | ESP | KE do rekey de Child SA |
  | --- | --- | --- | --- | --- |
  | urllc | K5 | AES-256 / CURVE\_25519 + KE1\_ML\_KEM\_768 / **PPK** | AES-256-GCM | ML-KEM-768 |
  | embb | K2 | AES-128 / ML\_KEM\_768 / **PPK** | AES-128-GCM | ML-KEM-768 |
  | miot | K4 | AES-256 / ML\_KEM\_1024 / **PPK** | AES-256-GCM | ML-KEM-1024 |

  O `modp2048` saiu das três propostas: a Fase A confirmou que ML-KEM puro é KE primário válido e que o grupo clássico só é necessário no caso híbrido (urllc). A cifra da eMBB é AES-128 por decisão da A.3 — ela é limitada por vazão, e o AES-128 entrega 9,2% mais. O `make_before_break = yes` ficou explícito em `lab/ipsec/strongswan.d/zz-sapq-ipsec.conf` em vez de herdado do default, porque a A.2 mostrou que é requisito.
- [x] Instrumentação: `timed()` na busca do PPK e no `load_shared`, coletor de `ip xfrm monitor`, log `ike` do charon com timestamp. *(Feito em 17/10.)*

  O `timed()` saiu no mesmo commit do KMS (`ppk_fetch`, `ppk_install`, `reauth`, `child_rekey`). O novo `evaluation/collectors/xfrm_monitor.py` é **orientado a evento**, nos dois lados do túnel: o poller de `xfrm_state` amostra contadores a cada 0,1 s e serve ao isolamento, mas não responde *quando* uma SA entrou ou saiu — um rekey inteiro acontece entre duas amostras. O log do IKE sai com timestamp de **microssegundo**, um arquivo por lado, arquivado por execução junto do `.jsonl`.

  **O monitor confirmou, pelo relógio do kernel, o mecanismo que a A.2 só media de forma indireta.** Num rekey de Child SA:

  | Lado | Instante | Ação | SPI |
  | --- | --- | --- | --- |
  | borda (responder) | .205060 | **added out** | 0xc09fef4e |
  | CU (initiator) | .206466 | **updated in** | 0xc09fef4e |

  A borda instala a SA de saída **1,4 ms antes** de a CU terminar de instalar a de entrada correspondente; nessa janela ela transmite numa SA que a CU ainda não aceita. É a perda de ~1,8 ms que a A.2 mediu no sentido responder → initiator, agora com a causa visível em vez de inferida. No sentido oposto o monitor mostra a SA nova entrando **417 µs antes** de a velha sair — sobreposição, não lacuna —, o que explica os zero pacotes perdidos na ida.

  Filtrar ruído era essencial: numa janela de 30 s o monitor emitiu **1169 `replay update` contra 13 eventos úteis** por lado. Os descartados são contados e reportados em agregado, para a filtragem ser auditável.
- [x] Coletores novos: sonda direto no N3, CPU do testbed e softirq. *(Feito em 17/10.)*

  `evaluation/collectors/n3_probe.py` sonda o túnel N3 a 100 Hz **em paralelo** às sondas que atravessam o rádio — as duas respondem perguntas diferentes: a do rádio diz se o usuário sente a rotação, a do N3 diz se e por quanto o túnel foi interrompido. Medido numa execução de 30 s: RTT p50 de **0,051 ms** com máximo de **1,560 ms** (pico de 30×), que é a escala da interrupção de rotação. Pelo rádio, com RTT de ~57 ms, isso é invisível. A sonda usa 100 Hz e não o 1 kHz da Fase A porque roda a janela inteira: a 1 kHz seriam 300 mil eventos por execução.

  `SoftirqPoller` existe porque o ESP cifra em contexto de **softirq**, no kernel — nenhum processo de userspace é creditado por isso, então o `pidstat` não o vê. `find_pids_by_name` traz `gnb`, os três `srsue`, `open5gs-upfd` e `open5gs-smfd` para o mesmo `pidstat`, porque eles competem por CPU com a simulação de QKD e determinam em que ponto da faixa de `R_qkd` (6,6 a 16,8 bit/s) a execução estava.

  Primeira execução instrumentada já mostrou **`idle` de 10,9%**: a máquina está quase saturada durante uma coleta, o que confirma pela medição a causa da degradação do `R_qkd` e passa a ficar registrado por execução em vez de inferido.
- [x] Script da Fase A: roda cada perfil no N3 sem o testbed de rádio. *(Completo em 15/10: `evaluation/phase_a/` com as seis medições — `profiles.py`, `bench_n3.py` (A.1/A.2/A.3/A.4), `rekey_traffic.py`, `dataplane.py`, `scale.py`, `kem_bench.py` (A.5) e `netem.py` (A.6).)*
- [x] Fase A: eixo de RTT com `netem` (A.6). *(Feito em 15/10: `phase_a/netem.py`; validado em 0/5/20 ms por sentido → 0,03 / 10,09 / 40,08 ms de RTT medido.)*

## Decisões em aberto

Estas respostas fixam os números da tabela de perfis e o escopo da Fase A.

- [x] **Criticidade:** decidido em 14/10. A criticidade é um vetor de três dimensões, cada uma em nível alto/médio/baixo, derivado dos atributos do descritor de fatia (GST/NEST): H, o horizonte de confidencialidade (o x de Mosca), que escolhe o nível do ML-KEM, a cifra e o uso de PPK; I, o impacto do comprometimento, que define a prioridade e a partilha de QKD; e D, a tolerância a interrupção, que define o Tr\_child mínimo e o make-before-break. Na disputa por rekey ou entropia, o desempate é lexicográfico I > H > D, sem pesos.

  *(Fechado em 17/10: os níveis por fatia e os Tr correspondentes estão na tabela "Valores fixados (14/10)" abaixo, e o código passou a usá-los — `TR_CHILD_SECONDS` e `TR_PPK_SECONDS` em `evaluation/rotation_driver.py`, com os valores reais ao lado para o fator de escala de 1/10 ser auditável. O vetor H/I/D também se materializou: H escolhe o perfil por fatia em `connections.conf` (K5/K2/K4 e a cifra do ESP), I decide a ordem sob escassez de QKD — validado ao vivo, a URLLC fica com o PPK e as outras são rebaixadas para só ML-KEM —, e D fixou o `make_before_break = yes` em `lab/ipsec/strongswan.d/zz-sapq-ipsec.conf`.)*
- [x] **KEMs disponíveis:** rodar `swanctl --list-algs` no lab e listar os KEMs e as assinaturas do build atual. Resolvido em 14/10 para KE: ML-KEM-512/768/1024 (provider OpenSSL), x25519, x448, ECP e MODP; K6 fica só no microbenchmark. ML-DSA não existe no strongSwan 6.0.4 (confirmado no código-fonte); autenticação fica em PSK e ECDSA.
- [x] **Fonte de QKD:** o QuKayDee introduz muita latência por causa do HTTP; vamos usar o QuDitto, que é um gêmeo digital de redes QKD com ETSI GS QKD 014. *(Resolvido em 15/10 — ver `lab/qkd/`.)* Subido via Docker a partir de `ezrasilva/Quditto_tutorial`: rede `qkdn` 172.20.0.0/16, topologia A↔B de 20 km. **O backend de simulação foi trocado de NetSquid para SeQUeNCe**: o NetSquid não está no PyPI público e as credenciais do índice privado que vinham no repositório passaram a retornar HTTP 401. A troca é localizada porque o `controller.py` do QuDitto não importa o simulador — ele chama o protocolo como subprocesso e lê JSON do stdout (`alice_key`, `bob_key`, `time`), então bastou escrever `lab/qkd/protocols/bb84_sequence.py` com o mesmo contrato e apontar o `config.yaml` para ele.

  Dois pontos dessa troca afetam a campanha:

  - **A pilha precisa de BB84 + Cascade, não BB84 sozinho.** Medido: o BB84 cru do SeQUeNCe devolve chaves que DIFEREM entre as pontas (QBER real do canal — 3 bits divergentes em 128, a 20 km). Como o PPK tem de ser idêntico nos dois lados, sem a reconciliação do Cascade o IKE falharia na autenticação. Com Cascade, as chaves batem (validado com 256 bits, o tamanho do PPK da campanha; QBER ~1,4%).
  - **Custo de entrega da chave, medido pela API ETSI 014 e não só pelo protocolo:** `enc_keys` (lado master, dispara a simulação) **~15,4 s**; `dec_keys` (lado slave, chave já distribuída) **~1,1 s**. O custo é dominado pela reconciliação, não pelo tamanho — 128 e 256 bits custam praticamente o mesmo. Isso reforça a decisão de buscar o PPK fora do caminho crítico do rekey: o `Tr_ppk` da URLLC em escala de teste é 30 s, então a pré-busca tem de ser assíncrona de verdade, não um `fetch` síncrono antes do reauth. **Somado ao resultado da A.2** — a renovação de PPK exige reauth, e com `make_before_break = yes` a reauth não interrompe tráfego —, o desenho fica fechado: busca assíncrona do PPK, reauth com make-before-break.
- [x] **TEID não classificado:** decidido em 14/10, descartar e registrar no log.
- [x] **AES-128 na URLLC:** decidido pela A.3 — **AES-256-GCM**, e nas três fatias, não só na URLLC. Com o rádio parado (condição que a Fase A especifica) a diferença de vazão contra o AES-128 é de 1,4%, dentro da variação entre execuções, e a latência é indistinguível. A medição de 15/10, que dava 9,2% a favor do AES-128, estava contaminada por contenção de CPU. Ver "Resultados da Fase A".

## Valores fixados (14/10)

Esdras aceitou estes valores em 14/10; são eles que a implementação deve usar.

| Fatia | H | I | D | Tr\_child (real) | Tr\_ppk (real) | Tr\_child no teste | Tr\_ppk no teste |
| --- | --- | --- | --- | --- | --- | --- | --- |
| URLLC | média | alta | baixa | 120 s | 300 s | 12 s | 30 s |
| eMBB | baixa | média | média | 300 s ou 1 GB, o que vier antes | 900 s | 30 s | 90 s |
| mIoT | alta | média | alta | 600 s | 1800 s | 60 s | 180 s |

- **Escala de tempo:** os Tr reais (Tr\_ppk = os SLAs já usados no `rotation_driver`: 300, 900 e 1800 s) não cabem em janelas de 300 s. Os testes usam fator 1/10, mantendo as razões entre fatias; o artigo precisa declarar isso.
- **R\_qkd no C4a:** com PPK de 256 bits, a demanda escalada é 256/30 + 256/90 + 256/180 ≈ 12,8 bit/s. O C4a usa R\_qkd ≈ 8,5 bit/s.

  **`R_qkd` medido não é uma constante da QKDN — depende da carga de CPU do hospedeiro.** A simulação BB84+Cascade é CPU-bound e disputa os mesmos 8 núcleos do testbed de rádio:

  | Condição | Tempo por chave de 256 bits | `R_qkd` |
  | --- | --- | --- |
  | rádio ocioso (gNB/UE parados) | 15,2 s | **16,8 bit/s** |
  | rádio rodando (condição normal de campanha, *load* ~16) | 38–39 s | **~6,6 bit/s** |

  A QKDN também **serializa** a geração: pedidos concorrentes de fatias diferentes enfileiram, não paralelizam.

  Consequência para o desenho: **sob condição de campanha a demanda escalada (12,8 bit/s) excede a oferta (~6,6) por quase 2×**, então a escassez de QKD acontece naturalmente e não precisa ser induzida — e o `R_qkd ≈ 8,5 bit/s` planejado para o C4a está próximo da taxa natural, não abaixo dela. O rebaixamento para "renovar só o ML-KEM" deixa de ser um caminho de exceção e passa a ser o regime comum das fatias de prazo longo.

  *(Este número foi reportado errado duas vezes antes, em 16 e 17/10, por ter sido medido sem controlar a carga do hospedeiro: primeiro como "teto apertado", depois como "30% de folga". A lição de método é que qualquer medição de `R_qkd` tem de declarar se o rádio estava rodando.)* Pela ordem I > H > D, a URLLC fica com o PPK e eMBB e mIoT passam a renovar só o ML-KEM.
- **TEID não classificado:** descartar no `mangle` e registrar no log.
- **Perfis por fatia:** URLLC = K5 (x25519 + ML-KEM-768 + PPK) com AES-256-GCM; eMBB = K2 (ML-KEM-768) com **AES-256-GCM**; mIoT = K4 (ML-KEM-1024) com AES-256-GCM. Autenticação por PSK em todas. *(A eMBB era AES-128 até 17/10, por um gap de vazão de 9,2% que se revelou artefato de contenção de CPU — ver a correção na A.3.)*
