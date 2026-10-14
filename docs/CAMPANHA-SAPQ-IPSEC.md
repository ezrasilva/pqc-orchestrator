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
2. **Rekey da Child SA sob tráfego:** ping a 100 Hz e iperf3 UDP a taxa fixa atravessando o túnel, com 30 rekeys por perfil. Mede perda de pacotes, pico de RTT e duração da interrupção, com make-before-break ligado e desligado.
3. **Plano de dados:** iperf3 TCP saturando o N3 com cada cifra do ESP (e sem IPsec), mais RTT a vazio e sob carga. Reporta throughput máximo, P50/P95/P99 de RTT e CPU em softirq.
4. **Escala:** 3, 10 e 30 Child SAs simultâneas fazendo rekey juntas, para ver se o custo cresce linearmente.
5. **Microbenchmark de KEM:** keygen, encaps e decaps de todos os KEMs do catálogo via liboqs, para os que o strongSwan não suportar.
6. **RTT do enlace como eixo:** repetir A.1 e A.2 com latência artificial no caminho N3 (`tc qdisc ... netem delay`), em pelo menos 0 ms (bancada pura), 5 ms e 20 ms por sentido.

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
| Interrupção no rekey (perda, pico de RTT) | A, B | ping a 100 Hz e iperf3 UDP atravessando o N3 |
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
- [ ] `orchestrator/ipsec_agent/agent.py`: separar `rekey_child()` de `reauth_with_ppk()`; o PSK fica fixo, só para autenticação.
- [ ] `lab/ipsec/swanctl-*/conf.d/connections.conf`: `ppk_id` e `ppk_required = yes` nas três fatias; propostas parametrizadas por perfil (K0–K5); conferir `make_before_break` no strongswan.conf.
- [ ] Instrumentação: `timed()` em volta da busca do PPK e de cada `load_shared`, coletor de `ip xfrm monitor`, log `ike` do charon com timestamp.
- [ ] Coletores novos: ping e iperf3 direto no N3 (namespace da CU → namespace do UPF), CPU de OCUDU, UPF e softirq.
- [x] Script da Fase A: roda cada perfil no N3 sem o testbed de rádio. *(Feito em 14/10: `evaluation/phase_a/` — catálogo `profiles.py` e harness `bench_n3.py` com a medição A.1; A.2–A.6 pendentes.)*
- [ ] Fase A: eixo de RTT com `netem` (A.6), conforme a seção "Por que o RTT do enlace precisa ser um eixo".

## Decisões em aberto

Estas respostas fixam os números da tabela de perfis e o escopo da Fase A.

- [ ] **Criticidade:** decidido em 14/10. A criticidade é um vetor de três dimensões, cada uma em nível alto/médio/baixo, derivado dos atributos do descritor de fatia (GST/NEST): H, o horizonte de confidencialidade (o x de Mosca), que escolhe o nível do ML-KEM, a cifra e o uso de PPK; I, o impacto do comprometimento, que define a prioridade e a partilha de QKD; e D, a tolerância a interrupção, que define o Tr\_child mínimo e o make-before-break. Na disputa por rekey ou entropia, o desempate é lexicográfico I > H > D, sem pesos. Falta fixar os níveis de cada fatia e os Tr correspondentes.
- [x] **KEMs disponíveis:** rodar `swanctl --list-algs` no lab e listar os KEMs e as assinaturas do build atual. Resolvido em 14/10 para KE: ML-KEM-512/768/1024 (provider OpenSSL), x25519, x448, ECP e MODP; K6 fica só no microbenchmark. ML-DSA não existe no strongSwan 6.0.4 (confirmado no código-fonte); autenticação fica em PSK e ECDSA.
- [ ] **Fonte de QKD:** o QuKayDee introduz muita latência por causa do HTTP; vamos usar o QuDitto, que é um gêmeo digital de redes QKD com ETSI GS QKD 014. *(Em 14/10: QuDitto não estava instalado na VM; subido via Docker a partir de `ezrasilva/Quditto_tutorial` — rede `quantum_net` 172.20.0.0/16, topologia A↔B de 20 km, BB84 com atenuação, backend NetSquid.)*
- [x] **TEID não classificado:** decidido em 14/10, descartar e registrar no log.
- [ ] **AES-128 na URLLC:** manter, ou a Fase A decide entre AES-128 e AES-256 pelo custo medido? melhor seria o aes256 eu acho

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
