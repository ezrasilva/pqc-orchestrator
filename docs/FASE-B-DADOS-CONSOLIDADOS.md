# Fase B — dados consolidados

## Procedência das execuções

| Cenário | válidas | descartadas | motivos |
| --- | --- | --- | --- |
| C0 sem IPsec | 31 | 0 | — |
| C1 túnel único | 28 | 2 | tick_falhou=2 |
| C2 proteção máxima | 25 | 5 | radio_degradado=2, tick_falhou=3 |
| C3 proposta | 29 | 1 | radio_degradado=1 |
| C4a escassez de QKD | 27 | 3 | radio_degradado=1, tick_falhou=2 |
| C4b contenção | 30 | 0 | — |

Total: **170 válidas** de 181.

### Desempenho por cenário

Mediana entre execuções válidas. `N3` é a sonda de alta resolução no túnel (0,1 ms de piso); o fim a fim atravessa o rádio ZMQ, cujo piso é ~54 ms e cuja cauda domina qualquer p99.

| Cenário | n | N3 p50 | N3 p99 | URLLC fim a fim p50 | URLLC p95 | eMBB | mIoT perda |
| --- | --- | --- | --- | --- | --- | --- | --- |
| C0 sem IPsec | 31 | 0.047 ms | 0.374 ms | 53.7 ms | 92.7 ms | 0.61 Mbps | 0.00% |
| C1 túnel único | 28 | 0.155 ms | 1.045 ms | 55.6 ms | 95.2 ms | 0.58 Mbps | 0.00% |
| C2 proteção máxima | 25 | 0.059 ms | 0.541 ms | 58.8 ms | 104.0 ms | 0.51 Mbps | 0.00% |
| C3 proposta | 29 | 0.059 ms | 0.547 ms | 58.7 ms | 105.0 ms | 0.51 Mbps | 0.00% |
| C4a escassez de QKD | 27 | 0.058 ms | 0.467 ms | 55.6 ms | 98.1 ms | 0.57 Mbps | 0.00% |
| C4b contenção | 30 | 0.059 ms | 0.557 ms | 58.9 ms | 105.0 ms | 0.50 Mbps | 0.00% |

### Economia de rotação e de entropia

Mediana por execução de 300 s. `rebaixada` é a fatia que perdeu o PPK novo e renovou só o ML-KEM do ESP por falta de entropia.

| Cenário | n | rekey de Child SA | reauth c/ PPK | PPK obtido | poço vazio | rebaixamentos |
| --- | --- | --- | --- | --- | --- | --- |
| C2 proteção máxima | 25 | 109 | 10 | 42 | 191 | 81 |
| C3 proposta | 29 | 63 | 10 | 37 | 129 | 24 |
| C4a escassez de QKD | 27 | 80 | 4 | 11 | 212 | 56 |
| C4b contenção | 30 | 64 | 9 | 36 | 123 | 24 |

### Quem fica com o PPK sob escassez

Soma sobre as execuções válidas. É a tabela que testa a tese: pela ordem de criticidade I > H > D a URLLC deveria manter o PPK e as outras fatias renovar só o ML-KEM.

| Cenário | Fatia | PPK obtido | rebaixada | poço vazio |
| --- | --- | --- | --- | --- |
| C2 proteção máxima | URLLC | 240 | 17 | 29 |
|  | EMBB | 408 | 1009 | 2378 |
|  | MIOT | 405 | 1002 | 2381 |
| C3 proposta | URLLC | 277 | 19 | 25 |
|  | EMBB | 464 | 500 | 2288 |
|  | MIOT | 336 | 205 | 1444 |
| C4a escassez de QKD | URLLC | 108 | 786 | 1768 |
|  | EMBB | 108 | 508 | 2504 |
|  | MIOT | 81 | 205 | 1617 |
| C4b contenção | URLLC | 281 | 23 | 29 |
|  | EMBB | 477 | 510 | 2297 |
|  | MIOT | 337 | 193 | 1448 |
