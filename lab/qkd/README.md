# Rede QKD (`qkdn`) para o SAPQ-IPsec — QuDitto com backend SeQUeNCe

Gêmeo digital de rede QKD que fornece as chaves usadas como PPK (RFC 8784)
na Fase B da campanha — ver `~/Desktop/pqc-orchestrator/docs/CAMPANHA-SAPQ-IPSEC.md`.

Baseado em [`ezrasilva/Quditto_tutorial`](https://github.com/ezrasilva/Quditto_tutorial)
(clonado em `Quditto_tutorial/`, não versionado aqui), com o backend de
simulação trocado de **NetSquid** para **SeQUeNCe**.

## Estado (15/10/2026): funcionando

| Componente | Estado |
| --- | --- |
| Rede `qkdn` (172.20.0.0/16) | criada |
| `qkdn-orchestrator` (172.20.0.10) | de pé — `qd2_orchestrator 2.1.2` |
| `qkdn-node-a` (172.20.0.11) | de pé — SeQUeNCe 1.3.0 |
| `qkdn-node-b` (172.20.0.12) | de pé — SeQUeNCe 1.3.0 |

Validado dentro do container: chave de 256 bits (tamanho do PPK da
campanha), idêntica nas duas pontas, QBER ~1,4%, 0,22 s de tempo simulado.

```bash
cd ~/quditto-lab
sudo docker compose up -d
# teste do protocolo, no mesmo contrato que o controller usa:
sudo docker exec qkdn-node-a sh -c 'echo "attenuation: 0.2" > /tmp/p.yaml'
sudo docker exec qkdn-node-a /opt/venv/bin/python3 \
    /opt/protocols/bb84_sequence.py 256 20 /tmp/p.yaml
```

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

## Custo de simulação (relevante para o Tr_ppk da campanha)

~11 s de relógio real por chave, tanto para 128 quanto para 256 bits — o
custo é dominado pela reconciliação, não pelo tamanho da chave. O desenho
da campanha já prevê buscar o PPK **fora do caminho crítico do rekey**, o
que acomoda isso; mas vale lembrar que o `Tr_ppk` da URLLC em escala de
teste é 30 s, então a pré-busca precisa mesmo ser assíncrona.

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
