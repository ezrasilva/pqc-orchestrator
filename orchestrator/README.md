# pqc-orchestrator

Implementação do orquestrador de chaves PQC por fatia descrito em
`../docs/ARQUITETURA-ORQUESTRADOR.md` (leia esse documento primeiro — este README
só situa o estado do código).

## Estado atual: item 4 da ordem de construção (Scheduler com fórmula de risco)

`scheduler/` implementa a fila priorizada (`EMERGENCY > CRITICAL >
NORMAL`, com a fórmula de risco `-slack/cost + slice_bonus +
interface_bonus + aging` decidindo a ordem dentro de cada classe) e as
três políticas de escalonamento intercambiáveis (risk-aware,
weighted-EDF, FIFO) — sem gRPC ainda, mesmo padrão do KMS/IPsec Agent
(núcleo isolado e testável primeiro). 21 testes cobrindo a fórmula, as
três políticas, prioridade de classe sobre risco, aging anti-starvation,
cancelamento e troca de política em runtime.

**Validado contra o laboratório real** (`scheduler/live_demo.py`, Fase 5
do protótipo SBRC — ver `../docs/ARQUITETURA-PROTOTIPO-COMPLETA.md`):
lê a idade real das três SAs N3 (`swanctl --list-sas`), calcula o risco
de cada uma contra um SLA de rotação por fatia, enfileira as três e
dispara `swanctl --rekey` na de maior risco. Rodado contra o laboratório
de verdade: identificou a URLLC como maior risco (risco calculado
890.5 vs. 588.5 da eMBB vs. -880.5 da mIoT, que estava dentro do SLA) e
confirmou a rotação real via mudança de SPI de saída. Achado no
processo: `swanctl --initiate` falha numa child já `ESTABLISHED`
("existing duplicate") — o comando certo pra rotacionar uma SA já ativa
é `swanctl --rekey`.

```bash
source .venv/bin/activate
pip install -r requirements.txt
pytest scheduler/tests            # núcleo isolado, sem root
sudo .venv/bin/python3 -m scheduler.live_demo   # contra o laboratório real, precisa de root
```

Estrutura:
```
scheduler/
  models.py       # Task, SchedulingPolicy, TaskPriority + PRIORITY_RANK
  policy.py        # fórmula de risco + sort_key das três políticas
  service.py        # SchedulerCore — fila em memória, thread-safe
  live_demo.py       # Fase 5: liga a fórmula de risco às 3 SAs N3 reais
  tests/
```

Próximo item da ordem (5): SMO, amarrando KMS + Scheduler + IPsec Agent
atrás de uma Admin API.

## Item 3 — IPsec Agent nativo mínimo (concluído)

`ipsec_agent/` fala VICI direto com os `charon` do laboratório (ver
`docs/RUNBOOK-OAI.md`) e implementa `apply_key_material` (carrega PSK
via `load-shared` + `rekey` com `reauth=true`, exatamente o mecanismo
descrito em `../docs/ARQUITETURA-ORQUESTRADOR.md`), `get_connection_status`
e `terminate_connection`. Testado contra as duas conexões reais do
laboratório (`f1-cu-du`, `n2n3-cu-edge`) — rotaciona o PSK de verdade e
confirma reautenticação completa.

**Lacuna de arquitetura encontrada e documentada (não escondida)**: PSK é
bilateral, mas a arquitetura só previa um Agent (no `cu-ns`, lado
initiator). Nesta fase de VM única isso não é problema — o Agent tem
acesso direto aos sockets VICI dos dois lados (ver `ipsec_agent/config.py`
pro porquê e pras duas saídas possíveis quando isso for pra uma
implantação distribuída de verdade).

```bash
source .venv/bin/activate
pip install -r requirements.txt
sudo .venv/bin/python3 -m pytest   # precisa de root (socket VICI é root:root)
```

Estrutura:
```
ipsec_agent/
  models.py        # ConnectionName, ConnectionState (independente do .proto)
  config.py         # registro das duas conexões + a lacuna arquitetural acima
  vici_client.py    # wrapper fino sobre a lib `vici`, schema conferido contra o C do strongSwan
  agent.py          # IpsecAgentCore — a lógica em si
  tests/            # integração contra o charon real do laboratório (pula sem root/sem o lab de pé)
```

## Item 2 — KMS isolado e testável (concluído)

`kms/` implementa o ciclo de vida de chave (geração híbrida ML-KEM+HKDF,
transições de estado, persistência SQLite) sem nenhuma dependência de rede
— nem gRPC, nem VICI, nem os outros componentes. Rodar os testes:

```bash
source .venv/bin/activate
pip install -r requirements.txt   # primeira vez: compila liboqs, demora
pytest
```

Estrutura:
```
kms/
  models.py       # SliceType, InterfaceType, KeyState + tabela de transições válidas
  crypto.py       # geração do material híbrido (ML-KEM real via liboqs + HKDF)
  store.py        # persistência SQLite (metadados + segredo em tabelas separadas)
  service.py      # KeyManagementCore — a lógica de ciclo de vida em si
  exceptions.py
  tests/          # pytest, cobre crypto/store/service isoladamente
```

Próximo item da ordem (3): IPsec Agent nativo mínimo, dentro do `cu-ns`.

## Item 1 — contratos gRPC (concluído)

Só os `.proto` existem ainda — nenhuma lógica implementada. Ver a seção
"Ordem sugerida pra começar a construir" na arquitetura pros próximos
passos (KMS isolado → IPsec Agent nativo mínimo → Scheduler → SMO → Admin
API).

```
proto/
  common.proto        # enums e tipos compartilhados (SliceType, KeyState, ...)
  kms.proto            # KeyManagementService
  scheduler.proto      # SchedulerService (fila priorizada, fórmula de risco)
  ipsec_agent.proto    # IpsecAgentService (roda nativo dentro do cu-ns)
  macsec_agent.proto   # MacsecAgentService — RESERVADO, sem implementação
  smo.proto            # SmoService (orquestrador central)
  admin_api.proto      # AdminApiService (fronteira externa, gRPC+mTLS)
```

Regenerar os stubs Python depois de editar qualquer `.proto`:
```bash
bash scripts/gen_proto.sh
```
Isso cria/atualiza `.venv/` e gera os stubs em `gen/python/` (não versionado
— ver `.gitignore`; cada dev/máquina regenera localmente).

## Decisões já fechadas (não reabrir sem motivo novo)

- Nome real da conexão N2/N3 é `n2n3-cu-edge` (termina no `5gc-edge-ns`),
  não `n2n3-ran-5gc`.
- Rotação de chave = PSK dinâmico via VICI (`load-shared` + `rekey`), não
  certificado.
- `cu-ns` é o único initiator IPsec (`auto=start`); `du-ns` e
  `5gc-edge-ns` são responders passivos (`auto=add`).
- Stack: Python em todos os componentes.

## Mapeamento SliceType -> SST (resolvido)

O mapeamento `SliceType -> SST` numérico **não está fixado no `.proto`** de
propósito (fica em config de cada componente, não no contrato de rede) —
ver comentário em `common.proto`. O valor autoritativo é o do núcleo
Open5GS já implantado: `SST=1 → eMBB, SST=2 → URLLC, SST=3 → mIoT`
(`5gc/config/smf.yaml`). A arquitetura tinha esse mapeamento errado numa
versão anterior (SST=1 → URLLC) — já corrigido em
`../docs/ARQUITETURA-ORQUESTRADOR.md`, a política de qual fatia recebe ML-KEM-768
+ componente quântico vs. ML-KEM-512 continua a mesma (URLLC é quem recebe
o híbrido mais forte, só o número do SST que estava trocado).
