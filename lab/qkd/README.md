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

## Custo de entrega da chave (relevante para o Tr_ppk da campanha)

Medido pela API, não só pelo protocolo:

| Operação | Tempo de parede |
| --- | --- |
| `enc_keys` (lado master, dispara a simulação) | **~15,4 s** |
| `dec_keys` (lado slave, chave já distribuída) | **~1,1 s** |

O custo é dominado pela reconciliação (Cascade), não pelo tamanho da
chave: 128 e 256 bits custam praticamente o mesmo. Como o `Tr_ppk` da
URLLC em escala de teste é 30 s, **a pré-busca tem de ser assíncrona** —
15 s dentro do caminho crítico do rekey seria inaceitável. O desenho da
campanha já prevê buscar o PPK fora desse caminho; esses números são a
justificativa quantitativa dessa escolha.

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
