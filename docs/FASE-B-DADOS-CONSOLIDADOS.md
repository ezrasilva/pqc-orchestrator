# Fase B — dados consolidados

## Procedência das execuções

| Cenário | válidas | descartadas | motivos |
| --- | --- | --- | --- |
| C0 sem IPsec | 29 | 1 | sonda_incompleta=1 |
| C1 túnel único | 29 | 1 | sonda_incompleta=1 |
| C2 proteção máxima | 24 | 6 | incompleta=2, radio_degradado=2, sonda_incompleta=2 |
| C3 proposta | 27 | 3 | incompleta=1, sonda_incompleta=2 |
| C4a escassez de QKD | 58 | 2 | incompleta=1, sonda_incompleta=1 |
| C4b contenção | 56 | 4 | incompleta=1, radio_degradado=2, sonda_incompleta=1 |

Total: **223 válidas** de 240.

### Desempenho por cenário

Mediana entre execuções válidas. `N3` é a sonda de alta resolução no túnel (0,1 ms de piso); o fim a fim atravessa o rádio ZMQ, cujo piso é ~54 ms e cuja cauda domina qualquer p99.

| Cenário | n | N3 p50 | N3 p99 | URLLC fim a fim p50 | URLLC p95 | eMBB | mIoT perda |
| --- | --- | --- | --- | --- | --- | --- | --- |
| C0 sem IPsec | 29 | 0.048 ms | 0.389 ms | 54.8 ms | 95.0 ms | 0.59 Mbps | 0.00% |
| C1 túnel único | 29 | 0.162 ms | 1.100 ms | 55.9 ms | 97.3 ms | 0.56 Mbps | 0.00% |
| C2 proteção máxima | 24 | 0.060 ms | 0.576 ms | 59.4 ms | 108.0 ms | 0.49 Mbps | 0.00% |
| C3 proposta | 27 | 0.060 ms | 0.586 ms | 59.5 ms | 107.0 ms | 0.50 Mbps | 0.00% |
| C4a escassez de QKD | 58 | 0.060 ms | 0.499 ms | 56.9 ms | 100.0 ms | 0.53 Mbps | 0.00% |
| C4b contenção | 56 | 0.060 ms | 0.587 ms | 59.3 ms | 107.0 ms | 0.48 Mbps | 0.00% |

### Economia de rotação e de entropia

Mediana por execução de 300 s. `rebaixada` é a fatia que perdeu o PPK novo e renovou só o ML-KEM do ESP por falta de entropia.

| Cenário | n | rekey de Child SA | reauth c/ PPK | PPK obtido | poço vazio | rebaixamentos |
| --- | --- | --- | --- | --- | --- | --- |
| C2 proteção máxima | 24 | 106 | 10 | 45 | 182 | 76 |
| C3 proposta | 27 | 60 | 10 | 44 | 117 | 23 |
| C4a escassez de QKD | 58 | 65 | 9 | 9 | 150 | 26 |
| C4b contenção | 56 | 60 | 10 | 45 | 118 | 24 |

### Quem fica com o PPK sob escassez

Soma sobre as execuções válidas. É a tabela que testa a tese: pela ordem de criticidade I > H > D a URLLC deveria manter o PPK e as outras fatias renovar só o ML-KEM.

| Cenário | Fatia | PPK obtido | rebaixada | poço vazio |
| --- | --- | --- | --- | --- |
| C2 proteção máxima | URLLC | 229 | 0 | 0 |
|  | EMBB | 0 | 1039 | 2611 |
|  | MIOT | 842 | 784 | 1769 |
| C3 proposta | URLLC | 260 | 0 | 0 |
|  | EMBB | 343 | 460 | 2161 |
|  | MIOT | 589 | 153 | 1023 |
| C4a escassez de QKD | URLLC | 543 | 0 | 0 |
|  | EMBB | 0 | 1095 | 5355 |
|  | MIOT | 0 | 414 | 3476 |
| C4b contenção | URLLC | 542 | 0 | 0 |
|  | EMBB | 697 | 973 | 4554 |
|  | MIOT | 1251 | 321 | 2139 |

### Risk-aware contra EDF, sob disputa

Média entre execuções ± IC95. A política ordena TAREFAS; ela não muda quanta entropia se consome, e é por isso que o efeito aparece na latência da URLLC e não na contagem de PPK.

| Cenário | Política | n | URLLC p50 | URLLC p95 | rebaixamentos | PPK obtido |
| --- | --- | --- | --- | --- | --- | --- |
| C4a escassez de QKD | RISK_AWARE | 28 | 56.90 ± 0.27 ms | 141.3 ± 79.5 ms | 26 | 9 |
| C4a escassez de QKD | WEIGHTED_EDF | 30 | 57.30 ± 0.37 ms | 101.0 ± 1.2 ms | 26 | 9 |
| C4b contenção | RISK_AWARE | 28 | 59.27 ± 0.09 ms | 107.0 ± 0.6 ms | 24 | 45 |
| C4b contenção | WEIGHTED_EDF | 28 | 59.62 ± 0.18 ms | 106.6 ± 0.5 ms | 24 | 45 |
