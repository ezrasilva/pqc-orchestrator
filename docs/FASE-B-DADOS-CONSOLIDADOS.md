# Fase B — dados consolidados

## Procedência das execuções

| Cenário | válidas | descartadas | motivos |
| --- | --- | --- | --- |
| C0 sem IPsec | 29 | 2 | sonda_incompleta=2 |
| C1 túnel único | 28 | 2 | tick_falhou=2 |
| C2 proteção máxima | 25 | 5 | radio_degradado=2, tick_falhou=3 |
| C3 proposta | 28 | 2 | radio_degradado=1, sonda_incompleta=1 |
| C4a escassez de QKD | 55 | 5 | radio_degradado=2, sonda_incompleta=1, tick_falhou=2 |
| C4b contenção | 55 | 5 | radio_degradado=1, sonda_incompleta=4 |

Total: **220 válidas** de 241.

### Desempenho por cenário

Mediana entre execuções válidas. `N3` é a sonda de alta resolução no túnel (0,1 ms de piso); o fim a fim atravessa o rádio ZMQ, cujo piso é ~54 ms e cuja cauda domina qualquer p99.

| Cenário | n | N3 p50 | N3 p99 | URLLC fim a fim p50 | URLLC p95 | eMBB | mIoT perda |
| --- | --- | --- | --- | --- | --- | --- | --- |
| C0 sem IPsec | 29 | 0.047 ms | 0.374 ms | 53.7 ms | 92.6 ms | 0.61 Mbps | 0.00% |
| C1 túnel único | 28 | 0.155 ms | 1.045 ms | 55.6 ms | 95.2 ms | 0.58 Mbps | 0.00% |
| C2 proteção máxima | 25 | 0.059 ms | 0.541 ms | 58.8 ms | 104.0 ms | 0.51 Mbps | 0.00% |
| C3 proposta | 28 | 0.059 ms | 0.552 ms | 58.7 ms | 104.0 ms | 0.51 Mbps | 0.00% |
| C4a escassez de QKD | 55 | 0.059 ms | 0.481 ms | 56.5 ms | 99.2 ms | 0.55 Mbps | 0.00% |
| C4b contenção | 55 | 0.060 ms | 0.570 ms | 59.4 ms | 106.0 ms | 0.49 Mbps | 0.00% |

### Economia de rotação e de entropia

Mediana por execução de 300 s. `rebaixada` é a fatia que perdeu o PPK novo e renovou só o ML-KEM do ESP por falta de entropia.

| Cenário | n | rekey de Child SA | reauth c/ PPK | PPK obtido | poço vazio | rebaixamentos |
| --- | --- | --- | --- | --- | --- | --- |
| C2 proteção máxima | 25 | 109 | 10 | 42 | 191 | 81 |
| C3 proposta | 28 | 63 | 10 | 37 | 128 | 24 |
| C4a escassez de QKD | 55 | 80 | 4 | 11 | 213 | 56 |
| C4b contenção | 55 | 61 | 9 | 36 | 121 | 23 |

### Quem fica com o PPK sob escassez

Soma sobre as execuções válidas. É a tabela que testa a tese: pela ordem de criticidade I > H > D a URLLC deveria manter o PPK e as outras fatias renovar só o ML-KEM.

| Cenário | Fatia | PPK obtido | rebaixada | poço vazio |
| --- | --- | --- | --- | --- |
| C2 proteção máxima | URLLC | 240 | 17 | 29 |
|  | EMBB | 408 | 1009 | 2378 |
|  | MIOT | 405 | 1002 | 2381 |
| C3 proposta | URLLC | 267 | 19 | 25 |
|  | EMBB | 446 | 481 | 2207 |
|  | MIOT | 322 | 198 | 1391 |
| C4a escassez de QKD | URLLC | 220 | 1587 | 3610 |
|  | EMBB | 220 | 1023 | 5052 |
|  | MIOT | 165 | 404 | 3276 |
| C4b contenção | URLLC | 510 | 40 | 49 |
|  | EMBB | 871 | 896 | 4148 |
|  | MIOT | 624 | 345 | 2612 |

### Risk-aware contra EDF, sob disputa

Média entre execuções ± IC95. A política ordena TAREFAS; ela não muda quanta entropia se consome, e é por isso que o efeito aparece na latência da URLLC e não na contagem de PPK.

| Cenário | Política | n | URLLC p50 | URLLC p95 | rebaixamentos | PPK obtido |
| --- | --- | --- | --- | --- | --- | --- |
| C4a escassez de QKD | RISK_AWARE | 26 | 55.53 ± 0.37 ms | 98.0 ± 1.0 ms | 56 | 11 |
| C4a escassez de QKD | WEIGHTED_EDF | 29 | 57.48 ± 0.47 ms | 135.1 ± 67.9 ms | 54 | 11 |
| C4b contenção | RISK_AWARE | 28 | 58.70 ± 0.48 ms | 127.8 ± 42.7 ms | 24 | 36 |
| C4b contenção | WEIGHTED_EDF | 27 | 59.96 ± 0.39 ms | 143.3 ± 70.2 ms | 22 | 37 |
