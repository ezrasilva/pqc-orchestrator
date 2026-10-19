# Fase A — dados consolidados

## Procedência das execuções

| Condição | Arquivos | O que significa |
| --- | --- | --- |
| `valido` | 16 | rádio parado e carga registrada — **condição que a Fase A especifica** |
| `radio_ligado` | 1 | rádio de pé durante a medição: premissa violada, descartado |
| `toggle_nao_verificado` | 2 | A.2 anterior à correção do conflito de drop-in: o toggle de `make_before_break` podia estar anulado, descartado |

`load_1min` máximo entre as execuções usadas: **4.28**

### A.1 + A.6 — handshake por perfil e RTT

| Perfil | Trocas | Frag. | Bytes env. | p50 @ 0.04 ms | p50 @ 10.11 ms | p50 @ 40.18 ms | Δ/RTT |
| --- | --- | --- | --- | --- | --- | --- | --- |
| K0 | 2 | 0 | 541 | 25.1 ms | 45.6 ms | 105.9 ms | **2.01** |
| K1 | 2 | 0 | 1309 | 25.1 ms | 45.9 ms | 105.6 ms | **2.00** |
| K2 | 2 | 0 | 1693 | 25.1 ms | 45.5 ms | 105.7 ms | **2.01** |
| K3 | 3 | 2 | 1871 | 26.0 ms | 57.7 ms | 147.3 ms | **3.02** |
| K4 | 2 | 0 | 2077 | 25.5 ms | 45.9 ms | 105.7 ms | **2.00** |
| K5 | 3 | 2 | 1898 | 28.5 ms | 57.8 ms | 147.2 ms | **2.96** |

A coluna Δ/RTT é a inclinação entre o primeiro e o último ponto, em múltiplos de RTT: ela vale o número de trocas de cada perfil, e por ser uma diferença é imune a deslocamento constante de carga.

### A.2 + A.6 — interrupção por evento, sentido e RTT

| Evento | `make_before_break` | Sentido | RTT | n | p50 | p95 | máx | reps c/ perda | base |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| child_rekey | no | ida | 0.0 ms | 120 | 0.00 ms | 0.00 ms | 0.00 ms | 0/120 | 0 |
| child_rekey | no | ida | 10.1 ms | 40 | 0.00 ms | 0.00 ms | 0.00 ms | 0/40 | 0 |
| child_rekey | no | ida | 40.2 ms | 40 | 0.00 ms | 0.00 ms | 0.00 ms | 0/40 | 0 |
| child_rekey | no | volta | 0.0 ms | 120 | 0.00 ms | 0.00 ms | 0.00 ms | 0/120 | 0 |
| child_rekey | no | volta | 10.1 ms | 40 | 0.00 ms | 0.00 ms | 0.00 ms | 0/40 | 0 |
| child_rekey | no | volta | 40.2 ms | 40 | 0.00 ms | 0.00 ms | 0.00 ms | 0/40 | 0 |
| child_rekey | yes | ida | 0.0 ms | 120 | 0.00 ms | 0.00 ms | 0.00 ms | 0/120 | 0 |
| child_rekey | yes | ida | 10.1 ms | 40 | 0.00 ms | 0.00 ms | 0.00 ms | 0/40 | 0 |
| child_rekey | yes | ida | 40.2 ms | 40 | 0.00 ms | 0.00 ms | 0.00 ms | 0/40 | 0 |
| child_rekey | yes | volta | 0.0 ms | 120 | 0.00 ms | 0.00 ms | 0.00 ms | 0/120 | 0 |
| child_rekey | yes | volta | 10.1 ms | 40 | 0.00 ms | 0.00 ms | 0.00 ms | 0/40 | 0 |
| child_rekey | yes | volta | 40.2 ms | 40 | 0.00 ms | 0.00 ms | 0.00 ms | 0/40 | 0 |
| ike_reauth | no | ida | 0.0 ms | 120 | 3.12 ms | 3.68 ms | 4.24 ms | 120/120 | 0 |
| ike_reauth | no | ida | 10.1 ms | 40 | 43.27 ms | 43.83 ms | 44.05 ms | 40/40 | 0 |
| ike_reauth | no | ida | 40.2 ms | 40 | 163.38 ms | 163.71 ms | 163.71 ms | 40/40 | 0 |
| ike_reauth | no | volta | 0.0 ms | 120 | 3.01 ms | 3.79 ms | 4.13 ms | 120/120 | 0 |
| ike_reauth | no | volta | 10.1 ms | 40 | 3.12 ms | 3.68 ms | 3.79 ms | 40/40 | 0 |
| ike_reauth | no | volta | 40.2 ms | 40 | 3.23 ms | 3.57 ms | 3.57 ms | 40/40 | 0 |
| ike_reauth | yes | ida | 0.0 ms | 120 | 0.00 ms | 0.00 ms | 0.00 ms | 0/120 | 0 |
| ike_reauth | yes | ida | 10.1 ms | 40 | 0.00 ms | 0.00 ms | 0.00 ms | 0/40 | 0 |
| ike_reauth | yes | ida | 40.2 ms | 40 | 0.00 ms | 0.00 ms | 0.00 ms | 0/40 | 0 |
| ike_reauth | yes | volta | 0.0 ms | 120 | 1.56 ms | 1.78 ms | 2.45 ms | 120/120 | 0 |
| ike_reauth | yes | volta | 10.1 ms | 40 | 1.67 ms | 2.01 ms | 2.23 ms | 40/40 | 0 |
| ike_reauth | yes | volta | 40.2 ms | 40 | 1.78 ms | 2.12 ms | 2.12 ms | 40/40 | 0 |

A coluna `base` soma os pacotes perdidos nas janelas de linha de base (mesmo tráfego, nenhum evento): zero é o que torna a perda atribuível ao evento e não ao ruído.

### A.3 — plano de dados por cifra do ESP

| Perfil | n | Vazão média | Variação | RTT carga p50/p95/p99 | softirq |
| --- | --- | --- | --- | --- | --- |
| SEM-IPSEC | 5 | 14819.3 Mbps | 5.6% | 0.019 / 0.030 / 0.044 ms | 32.3% |
| ESP-AES128GCM | 3 | 2706.7 Mbps | 2.0% | 0.040 / 0.084 / 0.230 ms | 36.9% |
| ESP-AES256GCM | 3 | 2669.3 Mbps | 0.4% | 0.040 / 0.084 / 0.210 ms | 36.7% |
| ESP-CHACHA20 | 3 | 2220.2 Mbps | 7.4% | 0.045 / 0.089 / 0.144 ms | 36.8% |

### A.4 — rekey simultâneo de N Child SAs

| Child SAs | n | Todas ok | Parede p50 | Por filho p50 | Por filho máx | ms/filho |
| --- | --- | --- | --- | --- | --- | --- |
| 3 | 10 | 10/10 | 24.3 ms | 23.1 ms | 23.4 ms | 8.10 |
| 10 | 10 | 10/10 | 39.4 ms | 28.9 ms | 35.6 ms | 3.94 |
| 30 | 10 | 10/10 | 102.8 ms | 79.3 ms | 95.5 ms | 3.43 |

Se o custo fosse linear, `ms/filho` seria constante.

### A.5 — microbenchmark de KEM (41 medidos via liboqs)

| KEM | NIST | keygen | encaps | decaps | total | pk | ct | strongSwan |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| ML-KEM-512 | 1 | 15.8 | 18.4 | 19.0 | 53 µs | 800 B | 768 B | sim |
| ML-KEM-768 | 3 | 22.0 | 24.7 | 26.7 | 73 µs | 1184 B | 1088 B | sim |
| ML-KEM-1024 | 5 | 27.6 | 30.9 | 34.6 | 93 µs | 1568 B | 1568 B | sim |
| HQC-1 | 1 | 2783.9 | 5550.9 | 8429.8 | 16765 µs | 2241 B | 4433 B | — |
| HQC-3 | 3 | 8417.1 | 16795.9 | 25333.6 | 50547 µs | 4514 B | 8978 B | — |
| HQC-5 | 5 | 20648.6 | 41215.4 | 62120.4 | 123984 µs | 7237 B | 14421 B | — |
| FrodoKEM-640-AES | 1 | 592.0 | 893.6 | 858.8 | 2344 µs | 9616 B | 9752 B | — |
| FrodoKEM-976-AES | 3 | 1187.5 | 1690.5 | 1632.3 | 4510 µs | 15632 B | 15792 B | — |
| FrodoKEM-1344-AES | 5 | 2155.8 | 2936.1 | 2865.5 | 7957 µs | 21520 B | 21696 B | — |
| BIKE-L1 | 1 | 542.3 | 76.0 | 982.1 | 1600 µs | 1541 B | 1573 B | — |
| BIKE-L3 | 3 | 1099.9 | 131.2 | 3196.0 | 4427 µs | 3083 B | 3115 B | — |
| BIKE-L5 | 5 | 2455.2 | 262.0 | 7938.5 | 10656 µs | 5122 B | 5154 B | — |
| sntrup761 | 2 | 10171.5 | 210.5 | 415.7 | 10798 µs | 1158 B | 1039 B | — |
| Classic-McEliece-348864 | 1 | 60854.5 | 71.1 | 74.4 | 61000 µs | 261120 B | 96 B | — |
