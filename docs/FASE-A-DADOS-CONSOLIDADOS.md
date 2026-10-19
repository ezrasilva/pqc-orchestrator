# Fase A — dados consolidados

## Procedência das execuções

| Condição | Arquivos | O que significa |
| --- | --- | --- |
| `valido` | 14 | rádio parado e carga registrada — **condição que a Fase A especifica** |
| `radio_ligado` | 1 | rádio de pé durante a medição: premissa violada, descartado |

`load_1min` máximo entre as execuções usadas: **4.28**

### A.1 + A.6 — handshake por perfil e RTT

| Perfil | Trocas | Frag. | Bytes env. | p50 @ 0.04 ms | p50 @ 10.10 ms | p50 @ 40.14 ms | Δ/RTT |
| --- | --- | --- | --- | --- | --- | --- | --- |
| K0 | 2 | 0 | 541 | 25.1 ms | 45.6 ms | 105.9 ms | **2.02** |
| K1 | 2 | 0 | 1309 | 25.1 ms | 45.9 ms | 105.6 ms | **2.01** |
| K2 | 2 | 0 | 1693 | 25.1 ms | 45.5 ms | 105.7 ms | **2.01** |
| K3 | 3 | 2 | 1871 | 26.0 ms | 57.7 ms | 147.3 ms | **3.02** |
| K4 | 2 | 0 | 2077 | 25.5 ms | 45.9 ms | 105.7 ms | **2.00** |
| K5 | 3 | 2 | 1898 | 28.5 ms | 57.8 ms | 147.2 ms | **2.96** |

A coluna Δ/RTT é a inclinação entre o primeiro e o último ponto, em múltiplos de RTT: ela vale o número de trocas de cada perfil, e por ser uma diferença é imune a deslocamento constante de carga.

### A.2 + A.6 — interrupção por evento, sentido e RTT

| Evento | `make_before_break` | Sentido | RTT | n | p50 | p95 | máx | reps c/ perda | base |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| child_rekey | no | ida | 0.0 ms | 240 | 0.00 ms | 0.00 ms | 0.00 ms | 0/240 | 0 |
| child_rekey | no | ida | 10.1 ms | 80 | 0.00 ms | 0.00 ms | 0.00 ms | 0/80 | 0 |
| child_rekey | no | ida | 40.1 ms | 40 | 0.00 ms | 0.00 ms | 0.00 ms | 0/40 | 0 |
| child_rekey | no | ida | 40.2 ms | 40 | 0.00 ms | 0.00 ms | 0.00 ms | 0/40 | 0 |
| child_rekey | no | volta | 0.0 ms | 240 | 0.00 ms | 0.00 ms | 0.00 ms | 0/240 | 0 |
| child_rekey | no | volta | 10.1 ms | 80 | 0.00 ms | 0.00 ms | 0.00 ms | 0/80 | 0 |
| child_rekey | no | volta | 40.1 ms | 40 | 0.00 ms | 0.00 ms | 0.00 ms | 0/40 | 0 |
| child_rekey | no | volta | 40.2 ms | 40 | 0.00 ms | 0.00 ms | 0.00 ms | 0/40 | 0 |
| child_rekey | yes | ida | 0.0 ms | 240 | 0.00 ms | 0.00 ms | 0.00 ms | 0/240 | 0 |
| child_rekey | yes | ida | 10.1 ms | 80 | 0.00 ms | 0.00 ms | 0.00 ms | 0/80 | 0 |
| child_rekey | yes | ida | 40.1 ms | 40 | 0.00 ms | 0.00 ms | 0.00 ms | 0/40 | 0 |
| child_rekey | yes | ida | 40.2 ms | 40 | 0.00 ms | 0.00 ms | 0.00 ms | 0/40 | 0 |
| child_rekey | yes | volta | 0.0 ms | 240 | 0.00 ms | 0.00 ms | 0.00 ms | 0/240 | 0 |
| child_rekey | yes | volta | 10.1 ms | 80 | 0.00 ms | 0.00 ms | 0.00 ms | 0/80 | 0 |
| child_rekey | yes | volta | 40.1 ms | 40 | 0.00 ms | 0.00 ms | 0.00 ms | 0/40 | 0 |
| child_rekey | yes | volta | 40.2 ms | 40 | 0.00 ms | 0.00 ms | 0.00 ms | 0/40 | 0 |
| ike_reauth | no | ida | 0.0 ms | 240 | 1.34 ms | 3.46 ms | 4.24 ms | 120/240 | 0 |
| ike_reauth | no | ida | 10.1 ms | 80 | 21.52 ms | 43.72 ms | 44.05 ms | 40/80 | 0 |
| ike_reauth | no | ida | 40.1 ms | 40 | 0.00 ms | 0.00 ms | 0.00 ms | 0/40 | 0 |
| ike_reauth | no | ida | 40.2 ms | 40 | 163.38 ms | 163.71 ms | 163.71 ms | 40/40 | 0 |
| ike_reauth | no | volta | 0.0 ms | 240 | 1.56 ms | 3.35 ms | 4.13 ms | 240/240 | 0 |
| ike_reauth | no | volta | 10.1 ms | 80 | 1.67 ms | 3.57 ms | 3.79 ms | 80/80 | 0 |
| ike_reauth | no | volta | 40.1 ms | 40 | 1.34 ms | 1.56 ms | 1.67 ms | 40/40 | 0 |
| ike_reauth | no | volta | 40.2 ms | 40 | 3.23 ms | 3.57 ms | 3.57 ms | 40/40 | 0 |
| ike_reauth | yes | ida | 0.0 ms | 240 | 0.00 ms | 0.00 ms | 0.00 ms | 0/240 | 0 |
| ike_reauth | yes | ida | 10.1 ms | 80 | 0.00 ms | 0.00 ms | 0.00 ms | 0/80 | 0 |
| ike_reauth | yes | ida | 40.1 ms | 40 | 0.00 ms | 0.00 ms | 0.00 ms | 0/40 | 0 |
| ike_reauth | yes | ida | 40.2 ms | 40 | 0.00 ms | 0.00 ms | 0.00 ms | 0/40 | 0 |
| ike_reauth | yes | volta | 0.0 ms | 240 | 1.45 ms | 1.78 ms | 3.01 ms | 240/240 | 0 |
| ike_reauth | yes | volta | 10.1 ms | 80 | 1.56 ms | 2.01 ms | 2.23 ms | 80/80 | 0 |
| ike_reauth | yes | volta | 40.1 ms | 40 | 1.34 ms | 1.56 ms | 1.67 ms | 40/40 | 0 |
| ike_reauth | yes | volta | 40.2 ms | 40 | 1.78 ms | 2.12 ms | 2.12 ms | 40/40 | 0 |

A coluna `base` soma os pacotes perdidos nas janelas de linha de base (mesmo tráfego, nenhum evento): zero é o que torna a perda atribuível ao evento e não ao ruído.

### A.3 — plano de dados por cifra do ESP

| Perfil | n | Vazão média | Variação | RTT carga p50/p95/p99 | softirq |
| --- | --- | --- | --- | --- | --- |
| SEM-IPSEC | 5 | 8906.3 Mbps | 172.8% | 0.019 / 0.030 / 0.044 ms | 32.3% |
| ESP-AES128GCM | 3 | 2706.7 Mbps | 2.0% | 0.040 / 0.084 / 0.230 ms | 36.9% |
| ESP-AES256GCM | 3 | 2669.3 Mbps | 0.4% | 0.040 / 0.084 / 0.210 ms | 36.7% |
| ESP-CHACHA20 | 3 | 705.6 Mbps | 300.0% | 0.045 / 0.089 / 0.144 ms | 36.8% |

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
| ML-KEM-512 | 1 | 15.5 | 18.1 | 18.7 | 52 µs | 800 B | 768 B | sim |
| ML-KEM-768 | 3 | 21.9 | 24.3 | 26.2 | 72 µs | 1184 B | 1088 B | sim |
| ML-KEM-1024 | 5 | 27.2 | 30.7 | 34.4 | 92 µs | 1568 B | 1568 B | sim |
| HQC-1 | 1 | 2775.6 | 5531.1 | 8408.5 | 16715 µs | 2241 B | 4433 B | — |
| HQC-3 | 3 | 8396.6 | 16753.5 | 25274.3 | 50424 µs | 4514 B | 8978 B | — |
| HQC-5 | 5 | 20594.8 | 41102.6 | 61954.2 | 123652 µs | 7237 B | 14421 B | — |
| FrodoKEM-640-AES | 1 | 595.3 | 879.3 | 844.1 | 2319 µs | 9616 B | 9752 B | — |
| FrodoKEM-976-AES | 3 | 1196.1 | 1657.4 | 1593.9 | 4447 µs | 15632 B | 15792 B | — |
| FrodoKEM-1344-AES | 5 | 2061.4 | 2859.5 | 2802.8 | 7724 µs | 21520 B | 21696 B | — |
| BIKE-L1 | 1 | 539.9 | 76.7 | 980.7 | 1597 µs | 1541 B | 1573 B | — |
| BIKE-L3 | 3 | 1111.4 | 131.6 | 3199.6 | 4443 µs | 3083 B | 3115 B | — |
| BIKE-L5 | 5 | 2459.7 | 264.6 | 7948.8 | 10673 µs | 5122 B | 5154 B | — |
| sntrup761 | 2 | 8909.3 | 182.8 | 362.3 | 9454 µs | 1158 B | 1039 B | — |
| Classic-McEliece-348864 | 1 | 60741.6 | 63.5 | 71.1 | 60876 µs | 261120 B | 96 B | — |
