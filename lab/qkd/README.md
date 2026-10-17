# Rede QKD (`qkdn`) para o SAPQ-IPsec — QuDitto com backend SeQUeNCe

Gêmeo digital de rede QKD que fornece as chaves usadas como PPK (RFC 8784)
na Fase B da campanha — ver `~/Desktop/pqc-orchestrator/docs/CAMPANHA-SAPQ-IPSEC.md`.

Baseado em [`ezrasilva/Quditto_tutorial`](https://github.com/ezrasilva/Quditto_tutorial)
(clonado em `Quditto_tutorial/`, não versionado aqui), com o backend de
simulação trocado de **NetSquid** para **SeQUeNCe**.

## Estado (15/10/2026): servindo chaves pela API ETSI 014

| Componente | Estado |
| --- | --- |
| Rede `qkdn` (172.20.0.0/16) | criada |
| `qkdn-node-a` (172.20.0.11) | nó + RabbitMQ + `controller.py` |
| `qkdn-node-b` (172.20.0.12) | nó |
| `qkdn-orchestrator` (172.20.0.10) | de pé, **não usado** — ver abaixo |

```bash
cd ~/quditto-lab
sudo docker compose up -d
./bootstrap_qkdn.sh          # equivale ao `qd2_orchestrator start`
```

Validado de ponta a ponta — chave de 256 bits (tamanho do PPK da campanha),
**idêntica nas duas pontas**:

```
A  GET /api/v1/keys/B/enc_keys?size=256
   -> key_ID 0e2202b9-…, key Z0X3Iqe4nM24jJITNsqmhqwi7Yurq2aAt9rdF/PDjMw=
B  GET /api/v1/keys/A/dec_keys?key_ID=0e2202b9-…
   -> key Z0X3Iqe4nM24jJITNsqmhqwi7Yurq2aAt9rdF/PDjMw=    (igual)
```

## Por que não se usa o `qd2_orchestrator`

O `install()` dele é incompatível com este lab por dois motivos
independentes (lidos em `orchestratorlib.py` 2.1.2):

1. Exige `netsquid_user`/`netsquid_pwd` no `config.yaml` — `KeyError` sem
   elas — e monta com esses valores um
   `pip install --extra-index-url https://USER:PWD@pypi.netsquid.org netsquid`.
   O índice responde **401**, e aqui o backend é o SeQUeNCe: o NetSquid
   nunca é chamado. A task falharia e abortaria o resto do play.
2. As tasks usam `/usr/bin/pip` (pip do sistema), mas os pacotes desta
   imagem vivem no venv `/opt/venv`; e reinstalariam do PyPI o
   `qd2_node`/`qd2_controller` que já vêm na imagem.

Fora o `install()`, o orchestrator só faz via Ansible/SSH o que o
`bootstrap_qkdn.sh` faz via `docker exec`. **O código executado é o do
próprio QuDitto, sem patch** (`receive_qd2.py`, `http_receptor.py`,
`controller.py`); só o transporte da orquestração muda — o que também
dispensa manter as credenciais SSH do `inventory.yaml` em sincronia com a
imagem. O script documenta a equivalência play por play.

O container do orchestrator fica de pé só para consulta ao pacote.

## Por que o backend foi trocado

O NetSquid não está no PyPI público; só no índice privado
`pypi.netsquid.org`, que exige conta. As credenciais que vinham no
repositório original (usuário e senha em texto claro, num repositório
**público**) retornam **HTTP 401** — provavelmente revogadas por terem sido
expostas. Vale trocar a senha dessa conta de qualquer forma.

O **SeQUeNCe** (Argonne/Northwestern) é aberto, está no PyPI e traz BB84 e
Cascade prontos.

## Por que a troca é localizada

O `controller.py` do QuDitto **não importa o simulador**. Ele invoca o
protocolo como subprocesso e lê JSON do stdout:

```python
command = ['python3', <protocol>, <key_length>, <distance_km>, <params.yaml>]
output  = json.loads(result.stdout)   # {"alice_key", "bob_key", "time"}
```

O script apontado vem do `config.yaml`, por enlace. Então bastou escrever
`protocols/bb84_sequence.py` com o mesmo contrato e apontar o
`config.yaml` para ele — os scripts que importam netsquid continuam no
pacote, apenas nunca são chamados.

Duas consequências práticas exigiram ajuste:

1. **`qd2_controller` declara `netsquid` como dependência obrigatória** e
   pina `numpy==1.24.4`/`scipy==1.9.3`, que conflitam com o SeQUeNCe. Por
   isso ele é instalado com `--no-deps` (novo arg `PYTHON_PACKAGES_NODEPS`
   no `Dockerfile.ssh`), junto das dependências que o `controller.py`
   realmente usa (`pika`, `pyyaml`). `pydynaa` e `cryptomite` são do mesmo
   ecossistema mas **estão** no PyPI público — ficaram de fora porque só
   os protocolos NetSquid os usam.
2. **BB84 sozinho não serve para PPK.** Medido: o BB84 cru do SeQUeNCe
   entrega chaves que DIFEREM entre Alice e Bob (QBER real do canal; 3 bits
   divergentes em 128 a 20 km). Como as duas pontas do IPsec precisam do
   PPK idêntico, o script usa a pilha BB84 + **Cascade** (reconciliação de
   erro) — aí as chaves batem.

## Custo de entrega da chave, e onde ele estava

Decomposto por medição (17/10), para uma chave de 256 bits:

| Parcela | Custo | Fração dos 36 s originais |
| --- | --- | --- |
| **Cascade simulado passo a passo** | ~29 s | **81%** |
| `import sequence` (pago a cada invocação) | 4,85 s | 13% |
| BB84 fotônico a 256 bits | ~1,0 s | 3% |
| `docker exec` + Python vazio | 0,2 s | <1% |

Dois resultados dessa decomposição:

* **O RabbitMQ é irrelevante.** O `beam.smp` fica em 0,1% de CPU, e a
  diferença entre a simulação rodada direto (36,2 s) e a chamada
  completa pela API ETSI 014 (~38 s) é de ~2 s, ou 5%. A fila não é o
  gargalo.
* **O custo é a reconciliação, não o canal quântico.** O BB84 fotônico
  escala linearmente e é barato (0,69 s a 128 bits, 1,85 s a 1024). Os
  29 s do Cascade não são física: são o preço de simular cada passagem
  dele como eventos discretos de mensagens clássicas atravessando 20 km.

Por isso existem **dois protocolos**, e os dois ficam no repositório:

| Script | Reconciliação | Custo | Para quê |
| --- | --- | --- | --- |
| `bb84_sequence.py` | Cascade simulado | ~36 s | **caracterização**: roda poucas vezes, e é o que justifica os parâmetros do outro |
| `bb84_reconciliation_model.py` | modelada pelo vazamento | **~6,2 s** | **campanha**: precisa de centenas de chaves |

O segundo preserva por simulação de evento discreto a atenuação, a perda
de fóton, a fidelidade de polarização e o peneiramento — logo o **QBER
sai medido, não postulado** (2,2–3,0% nas execuções de validação). Só a
reconciliação é modelada, pela taxa secreta assintótica
`r = 1 − (1 + f)·h₂(e)` com `f = 1,16` (eficiência usual do Cascade), e
os bits finais saem por SHAKE256, que faz o papel da amplificação de
privacidade e garante chave idêntica nas duas pontas — requisito do PPK,
que falha na autenticação se divergir um bit.

**O que isso não autoriza afirmar**: que a reconciliação foi executada.
O número de passagens, as mensagens e a latência do Cascade não são
simulados ali. O artigo tem de declarar a modelagem, e é para isso que o
script com Cascade real continua aqui.

Com ~6,2 s por chave o `R_qkd` efetivo é de **41 bit/s**, contra 12,8 de
demanda escalada da campanha. Como isso deixa de ser escasso, a escassez
passa a ser **induzida por um limitador declarado** no
`PpkProvider` (`r_qkd_bits_per_second`), agregado entre as fatias —
validado convergindo para 8,5 bit/s, o valor que o desenho do C4a pede.
Isso é melhor metodologicamente do que o estado anterior, em que o
`R_qkd` oscilava 6,6–16,8 bit/s conforme a carga do hospedeiro, variável
não controlada contaminando a razão demanda/oferta que decide quais
fatias são rebaixadas.

## Topologia simulada

Dois nós (A ↔ B), enlace de 20 km, BB84 + Cascade, atenuação de fibra
0,2 dB/km (1550 nm), fidelidade de polarização 0,97. Parâmetros por enlace
no `config.yaml`; o `params.yaml` gerado pelo controller pode sobrescrever
`attenuation` e `polarization_fidelity`.

## Credenciais

O `.env` (gitignored) só é necessário se alguém quiser voltar ao NetSquid.
Com o SeQUeNCe o build não precisa de credencial nenhuma.

> **Nota (15/10)**: os containers em execução foram construídos antes de o
> usuário/senha virarem `ARG` no `Dockerfile.ssh`; eles seguem funcionando
> com as credenciais antigas. Um `docker compose build --no-cache` passa a
> valer os novos (`NODE_USER`/`NODE_PASSWORD`), e aí o `inventory.yaml`
> precisa bater com eles.
