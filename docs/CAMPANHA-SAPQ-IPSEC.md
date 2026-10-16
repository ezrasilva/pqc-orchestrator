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

### Resultados da Fase A (15/10): a tabela que alimenta a Fase B

Execuções completas, sem falha: A.1 540/540 handshakes, A.2 560 eventos, A.3 4 pontos, A.4 90 rodadas, A.5 41 KEMs.

**A.1 + A.6 — o custo do perfil é de round-trips, não de bytes nem de CPU.** p50 de handshake, em ms:

| Perfil | Trocas | RTT 0,03 ms | RTT 10,1 ms | RTT 40,1 ms | Δ(0→40) / RTT |
| --- | --- | --- | --- | --- | --- |
| K0 (x25519, 541 B) | 2 | 29,2 | 49,8 | 110,8 | **2,04** |
| K1 (ML-KEM-512, 1309 B) | 2 | 31,8 | 49,6 | 110,5 | **1,97** |
| K2 (ML-KEM-768, 1693 B) | 2 | 29,8 | 49,6 | 110,0 | **2,00** |
| K3 (híbrido, 1871 B) | **3** | 31,2 | 62,4 | 152,6 | **3,03** |
| K4 (ML-KEM-1024, 2077 B) | 2 | 29,8 | 49,9 | 110,8 | **2,02** |
| K5 (K3 + PPK, 1898 B) | **3** | 34,3 | 63,8 | 152,2 | **2,94** |

A última coluna é exatamente o número de trocas de cada perfil. Duas consequências:

* **K4 custa o mesmo que K0 em todos os RTTs**, com quatro vezes os bytes. Nas faixas em jogo (até ~2 kB), bytes no fio não custam tempo mensurável; só custam quando forçam uma troca a mais.
* **A A.6 se pagou.** A 0,03 ms o híbrido parece barato (K3 em 31,2 contra K2 em 29,8: +1,4 ms, 5%). A 40 ms de RTT a penalidade é de **+42,6 ms (39%)**. Medir só na bancada levaria o artigo à conclusão oposta, justamente para a URLLC — a fatia que o catálogo quer atender com K5.

**A.2 + A.6 — a interrupção tem duas componentes, e o make-before-break mata só uma (a que importa).** Interrupção p50 medida pelos fluxos UDP, **por sentido** — ver "Por que a A.2 precisa medir os dois sentidos" abaixo:

| Evento | `make_before_break` | Sentido | RTT 0,04 ms | RTT 10,1 ms | RTT 40,1 ms |
| --- | --- | --- | --- | --- | --- |
| rekey de Child SA | indiferente | ida e volta | **0** | **0** | **0** |
| reauth | `yes` | ida (initiator→responder) | **0** | **0** | **0** |
| reauth | `yes` | volta (responder→initiator) | 1,7 ms | 1,8–2,1 ms | 1,8–2,1 ms |
| reauth | `no` | ida | 3,2–3,8 ms | **43,5 ms** | **163,7 ms** |
| reauth | `no` | volta | 3,0–3,8 ms | 3,2–3,8 ms | 3,6 ms |

(6 perfis × 20 repetições a RTT 0; K2 e K5 × 20 nos outros pontos. Todas as linhas de base: 0 perda nos dois sentidos.)

A estrutura é clara:

* **A componente de ida escala com o RTT e vale exatamente 4 round-trips**: (163,71 − 3,57)/40,09 = 4,00 e (43,49 − 3,57)/10,11 = 3,95. É o custo de o initiator ficar sem SA de saída enquanto espera o delete e o handshake novo inteiro.
* **A componente de volta é de 2 a 4 ms e NÃO depende do RTT**, em nenhuma configuração. É a corrida de troca de SA no responder: a reauth é iniciada pela CU, que troca a própria SA de saída atomicamente, mas a borda troca a dela ao processar a troca e há um instante em que a SA de saída que ela usa não casa com a de entrada instalada na CU. Efeito local, não de protocolo.
* **O make-before-break elimina a componente que escala** (ida: zero em todos os RTTs) e reduz a local pela metade (1,7–2,1 contra 3,0–3,8 ms). A 40 ms de RTT isso leva o pior caso de **163,7 ms para ~1,8 ms, ou 90×** — mas **não a zero**.

A interrupção é a mesma em K0 (x25519) e K4 (ML-KEM-1024), ou seja **não é do KEM**: é o custo de reinstalar a SA, e o que escala com o RTT é o número de trocas que isso embute.

Consequência direta para a proposta: a renovação de PPK exige reauth, e num backhaul de 20 ms por sentido deixar `make_before_break = no` custaria **163 ms de interrupção a cada renovação** — inviável para URLLC. Com ele ligado sobram ~1,8 ms num sentido só, o que cabe no orçamento da URLLC. É a configuração que a Fase B tem de fixar, e o artigo deve reportar o resíduo de 1,8 ms em vez de afirmar interrupção nula.

### Por que a A.2 precisa medir os dois sentidos

A primeira versão da A.2 media só CU → borda e concluiu que o make-before-break dava **interrupção zero**. Está errado, e o erro era do instrumento: com make-before-break a interrupção existe **apenas no sentido responder → initiator**, que era justamente o que não estava sendo medido.

O que denunciou foi uma divergência entre instrumentos. O ping a 1 kHz reportava 1 pacote perdido em 101 de 120 reauths, enquanto o fluxo UDP, a nove vezes a taxa, reportava zero — se houvesse lacuna de tráfego o fluxo mais rápido perderia mais, não menos. Os contadores ICMP do kernel nos dois netns resolveram (8 reauths, MBB ligado):

| Contador | Valor |
| --- | --- |
| CU `OutEchos` (requests enviados) | 16165 |
| Borda `InEchos` (requests recebidos) | **16165** → ida sem perda |
| Borda `OutEchoReps` (replies enviados) | 16165 |
| CU `InEchoReps` (replies recebidos) | **16158** → **7 perdidos na volta** |

Com fluxo UDP nos dois sentidos, 197275 pacotes cada: 0 na ida, 64 na volta (8 por reauth). Com o sentido certo medido, os dois instrumentos **sempre concordaram**: 1 pacote a 1 kHz e 8 a 9 kHz são ambos ~0,9 ms.

Duas lições de método que ficam registradas porque custaram tempo:

1. **No iperf3, a perda só existe no relatório do RECEPTOR.** No UDP ela é calculada por quem recebe; o emissor só sabe o que enviou. Inverter o sentido com `-R` mantém o servidor como emissor e move a perda para o relatório do cliente — ler o campo do servidor nesse modo devolve ausência de informação, que é fácil confundir com ausência de perda. A sonda passou a escolher o sentido trocando quem é servidor e quem é cliente, com o servidor sempre no papel de receptor.
2. **Divergência entre dois instrumentos é informação, não ruído.** A tentação era declarar o ping pouco confiável (e eu cheguei a atribuir a diferença a travamento do processo de sonda, o que era falso). O ping estava certo; o erro era o sentido medido.

**A.3 — resolve a decisão AES-128 × AES-256.** 30 s, 4 fluxos TCP, ordem sorteada:

| Perfil | Vazão | % do bruto | RTT sob carga p50/p95/p99 (ms) | softirq |
| --- | --- | --- | --- | --- |
| sem IPsec | 15196,6 Mbps | 100,0% | 0,022 / 0,042 / 0,096 | 31,4% |
| ESP-AES128GCM | 2649,0 Mbps | 17,4% | 0,039 / 0,066 / 0,108 | 36,4% |
| ESP-AES256GCM | 2405,3 Mbps | 15,8% | 0,040 / 0,060 / 0,096 | 35,9% |
| ESP-CHACHA20 | 1908,3 Mbps | 12,6% | 0,043 / 0,077 / 0,111 | 34,8% |

**Decisão: AES-256-GCM para a URLLC.** Custa 9,2% de vazão contra o AES-128 e **nenhuma latência mensurável** (p99 de 0,096 contra 0,108 ms — o AES-256 fica até marginalmente melhor, dentro do ruído). A URLLC é limitada por latência, não por vazão, então o nível de segurança maior sai de graça no que importa para ela. O ChaCha20 fica 28% abaixo do AES-128, consistente com não haver AES-NI para ele — só se justifica em hardware sem aceleração de AES.

**A.4 — o custo de rekey simultâneo é sublinear.** K2, 10 rodadas por ponto, todas com 100% de sucesso:

| Child SAs | Parede p50 | Por filho p50 | Por filho max | ms por filho |
| --- | --- | --- | --- | --- |
| 3 | 26,5 ms | 24,5 ms | 25,6 ms | 8,83 |
| 10 | 50,8 ms | 31,9 ms | 48,0 ms | 5,08 |
| 30 | 128,8 ms | 94,5 ms | 121,4 ms | 4,29 |

Dez vezes mais Child SAs custam 4,9 vezes de parede. A Fase B rotaciona três fatias e pode enfileirá-las na mesma janela; o resultado diz que a URLLC **não paga fila linear** pelas outras duas, e que a proposta tem folga para escalar além de três fatias.

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

- [ ] `evaluation/rotation_driver.py`: enfileirar uma fatia só quando a idade da SA passar do seu Tr, com dois tipos de tarefa (rekey de Child SA e reauth com PPK). Hoje as três fatias são enfileiradas a cada tick de 10 s. *(Confirmado no código em 14/10: o `_tick()` enfileira as três incondicionalmente; a idade entra só como `slack_seconds` no cálculo de risco.)*
- [ ] `evaluation/run_experiment.py:221-226`: no C4, iniciar o tráfego em t = 0 e disparar a rotação forçada no meio da janela, com o tráfego rodando. *(Confirmado em 14/10: hoje dorme metade da janela SEM tráfego, dispara a contenção e só então inicia o tráfego pela metade restante.)*
- [ ] `evaluation/scenarios/scenario1_static_pqc.py`: trocar `swanctl --rekey --ike` por rekey da Child SA, no mesmo Tr\_child dos demais cenários.
- [ ] Runner: sortear e intercalar a ordem dos cenários entre as repetições.
- [ ] `orchestrator/kms/crypto.py`: remover o ML-KEM local; o KMS passa a entregar a chave QKD (ETSI GS QKD 014 do QuDitto, rodando local) e a busca é feita antes do reauth, fora do caminho crítico do rekey; a chave entra no charon como PPK.
- [x] `orchestrator/ipsec_agent/agent.py`: separar `rekey_child()` de `reauth_with_ppk()`; o PSK fica fixo, só para autenticação. *(Feito em 16/10. `rekey_child()` não carrega segredo nenhum e mediu 2,4–3,2 ms nas três fatias; `reauth_with_ppk()` instala o PPK nos dois lados e reautentica, e recusa conexão sem `ppk_id`. Exigiu `rekey_child`/`listen_child_rekey` novos no `vici_client.py` e um `_wait_for_fresh_child_sa` próprio, porque o payload de evento de Child SA tem forma diferente do de IKE_SA. `apply_key_material` fica como caminho legado dos cenários antigos.)*
- [ ] `lab/ipsec/swanctl-*/conf.d/connections.conf`: `ppk_id` e `ppk_required = yes` nas três fatias; propostas parametrizadas por perfil (K0–K5); conferir `make_before_break` no strongswan.conf.
- [ ] Instrumentação: `timed()` em volta da busca do PPK e de cada `load_shared`, coletor de `ip xfrm monitor`, log `ike` do charon com timestamp.
- [ ] Coletores novos: ping e iperf3 direto no N3 (namespace da CU → namespace do UPF), CPU de OCUDU, UPF e softirq.
- [x] Script da Fase A: roda cada perfil no N3 sem o testbed de rádio. *(Completo em 15/10: `evaluation/phase_a/` com as seis medições — `profiles.py`, `bench_n3.py` (A.1/A.2/A.3/A.4), `rekey_traffic.py`, `dataplane.py`, `scale.py`, `kem_bench.py` (A.5) e `netem.py` (A.6).)*
- [x] Fase A: eixo de RTT com `netem` (A.6). *(Feito em 15/10: `phase_a/netem.py`; validado em 0/5/20 ms por sentido → 0,03 / 10,09 / 40,08 ms de RTT medido.)*

## Decisões em aberto

Estas respostas fixam os números da tabela de perfis e o escopo da Fase A.

- [ ] **Criticidade:** decidido em 14/10. A criticidade é um vetor de três dimensões, cada uma em nível alto/médio/baixo, derivado dos atributos do descritor de fatia (GST/NEST): H, o horizonte de confidencialidade (o x de Mosca), que escolhe o nível do ML-KEM, a cifra e o uso de PPK; I, o impacto do comprometimento, que define a prioridade e a partilha de QKD; e D, a tolerância a interrupção, que define o Tr\_child mínimo e o make-before-break. Na disputa por rekey ou entropia, o desempate é lexicográfico I > H > D, sem pesos. Falta fixar os níveis de cada fatia e os Tr correspondentes.
- [x] **KEMs disponíveis:** rodar `swanctl --list-algs` no lab e listar os KEMs e as assinaturas do build atual. Resolvido em 14/10 para KE: ML-KEM-512/768/1024 (provider OpenSSL), x25519, x448, ECP e MODP; K6 fica só no microbenchmark. ML-DSA não existe no strongSwan 6.0.4 (confirmado no código-fonte); autenticação fica em PSK e ECDSA.
- [x] **Fonte de QKD:** o QuKayDee introduz muita latência por causa do HTTP; vamos usar o QuDitto, que é um gêmeo digital de redes QKD com ETSI GS QKD 014. *(Resolvido em 15/10 — ver `lab/qkd/`.)* Subido via Docker a partir de `ezrasilva/Quditto_tutorial`: rede `qkdn` 172.20.0.0/16, topologia A↔B de 20 km. **O backend de simulação foi trocado de NetSquid para SeQUeNCe**: o NetSquid não está no PyPI público e as credenciais do índice privado que vinham no repositório passaram a retornar HTTP 401. A troca é localizada porque o `controller.py` do QuDitto não importa o simulador — ele chama o protocolo como subprocesso e lê JSON do stdout (`alice_key`, `bob_key`, `time`), então bastou escrever `lab/qkd/protocols/bb84_sequence.py` com o mesmo contrato e apontar o `config.yaml` para ele.

  Dois pontos dessa troca afetam a campanha:

  - **A pilha precisa de BB84 + Cascade, não BB84 sozinho.** Medido: o BB84 cru do SeQUeNCe devolve chaves que DIFEREM entre as pontas (QBER real do canal — 3 bits divergentes em 128, a 20 km). Como o PPK tem de ser idêntico nos dois lados, sem a reconciliação do Cascade o IKE falharia na autenticação. Com Cascade, as chaves batem (validado com 256 bits, o tamanho do PPK da campanha; QBER ~1,4%).
  - **Custo de entrega da chave, medido pela API ETSI 014 e não só pelo protocolo:** `enc_keys` (lado master, dispara a simulação) **~15,4 s**; `dec_keys` (lado slave, chave já distribuída) **~1,1 s**. O custo é dominado pela reconciliação, não pelo tamanho — 128 e 256 bits custam praticamente o mesmo. Isso reforça a decisão de buscar o PPK fora do caminho crítico do rekey: o `Tr_ppk` da URLLC em escala de teste é 30 s, então a pré-busca tem de ser assíncrona de verdade, não um `fetch` síncrono antes do reauth. **Somado ao resultado da A.2** — a renovação de PPK exige reauth, e com `make_before_break = yes` a reauth não interrompe tráfego —, o desenho fica fechado: busca assíncrona do PPK, reauth com make-before-break.
- [x] **TEID não classificado:** decidido em 14/10, descartar e registrar no log.
- [x] **AES-128 na URLLC:** decidido pela A.3 (15/10) — **AES-256-GCM**, que era a intuição registrada aqui e a medição confirma. Custa 9,2% de vazão contra o AES-128 (2405 contra 2649 Mbps) e **nenhuma latência mensurável** (p99 sob carga de 0,096 contra 0,108 ms — o AES-256 fica até marginalmente melhor, dentro do ruído). A URLLC é limitada por latência, não por vazão, então o nível de segurança maior sai de graça no que importa para ela. Ver "Resultados da Fase A".

## Valores fixados (14/10)

Esdras aceitou estes valores em 14/10; são eles que a implementação deve usar.

| Fatia | H | I | D | Tr\_child (real) | Tr\_ppk (real) | Tr\_child no teste | Tr\_ppk no teste |
| --- | --- | --- | --- | --- | --- | --- | --- |
| URLLC | média | alta | baixa | 120 s | 300 s | 12 s | 30 s |
| eMBB | baixa | média | média | 300 s ou 1 GB, o que vier antes | 900 s | 30 s | 90 s |
| mIoT | alta | média | alta | 600 s | 1800 s | 60 s | 180 s |

- **Escala de tempo:** os Tr reais (Tr\_ppk = os SLAs já usados no `rotation_driver`: 300, 900 e 1800 s) não cabem em janelas de 300 s. Os testes usam fator 1/10, mantendo as razões entre fatias; o artigo precisa declarar isso.
- **R\_qkd no C4a:** com PPK de 256 bits, a demanda escalada é 256/30 + 256/90 + 256/180 ≈ 12,8 bit/s. O C4a usa R\_qkd ≈ 8,5 bit/s (demanda ≈ 1,5× a oferta). Pela ordem I > H > D, a URLLC fica com o PPK e eMBB e mIoT passam a renovar só o ML-KEM.
- **TEID não classificado:** descartar no `mangle` e registrar no log.
- **Perfis por fatia:** URLLC = K5 (x25519 + ML-KEM-768 + PPK) com AES-256-GCM; eMBB = K2 (ML-KEM-768) com AES-128-GCM; mIoT = K4 (ML-KEM-1024) com AES-256-GCM. Autenticação por PSK em todas.
