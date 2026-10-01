# pqc-orchestrator

Implementação do orquestrador de chaves PQC por fatia descrito em
`../docs/ARQUITETURA-ORQUESTRADOR.md` (leia esse documento primeiro — este README
só situa o estado do código).

## Estado atual: item 5 da ordem de construção (SMO amarrando os quatro)

`smo/` implementa o `SmoCore` — coordena KMS + Scheduler + IPsec Agent
(`process_next_task`, `force_rotate`, `revoke_key`, `quarantine_key`,
`release_quarantine`, `get_system_status`, `set_scheduling_policy`,
`list_audit_log`), mesmo padrão isolado/testável dos outros três. Admin
API (item 6) foi deliberadamente deixada de fora desta fase — ver
decisão abaixo.

**Duas divergências reais encontradas e resolvidas antes de poder ligar
os quatro componentes** (não escondidas — mudam código já existente):

1. **`ConnectionName` do IPsec Agent estava desatualizado.** Só
   conhecia `f1-cu-du`/`n2n3-cu-edge` — mas desde a Fase 3/4 do
   protótipo SBRC essa segunda conexão não existe mais (virou `n2-cu-
   edge` + três `n3-<fatia>-cu-edge`, cada uma com endereço externo
   próprio e perfil PQC próprio, ver `ARQUITETURA-PROTOTIPO-COMPLETA.md`
   seção 5.4). Atualizado `ipsec_agent/config.py` pras cinco conexões
   reais. `kms/models.py`'s `InterfaceType` também dividiu `N2N3` em
   `N2`/`N3` pelo mesmo motivo — só `N3` é realmente diferenciada por
   fatia.
2. **O PSK combinado do KMS divergia do PPK real (RFC 8784) já validado
   na Fase 4.** `kms/crypto.py` misturava o segredo ML-KEM com o
   componente "quântico simulado" num único PSK via HKDF — mas a Fase 4
   usa o mecanismo nativo de PPK do strongSwan, que exige um segredo
   *separado* do PSK do IKE. Corrigido: `HybridMaterial`/`KeyMaterial`
   ganharam um campo `ppk` (só preenchido pra URLLC), e o IPsec Agent
   carrega os dois via VICI (`load_shared_psk` + `load_shared_ppk`,
   tipos `IKE` e `PPK` respectivamente) antes do reauth. Confirmado
   contra o laboratório real: `swanctl --list-sas` mostra `ppk: yes` na
   SA da URLLC depois da rotação completa via SMO.

Validado de ponta a ponta contra o laboratório real
(`smo/tests/test_live.py`): Scheduler enfileira → SMO consulta → KMS
gera material de verdade (ML-KEM real via liboqs) → IPsec Agent aplica
via VICI real → SA reestabelece com o novo PSK (e PPK, pra URLLC) — as
cinco conexões reais, não um fake.

```bash
source .venv/bin/activate
pip install -r requirements.txt
pytest smo/tests                           # núcleo isolado, com dublê de IPsec Agent, sem root
sudo .venv/bin/python3 -m pytest smo/tests  # inclui os testes de integração real (precisa do laboratório de pé)
```

Estrutura:
```
smo/
  models.py       # ProcessTaskResult, AuditEvent, SystemStatus
  service.py       # SmoCore + resolve_connection((slice, interface) -> ConnectionName)
  exceptions.py
  tests/
    fakes.py        # FakeIpsecAgent, pros testes isolados
    test_service.py  # isolado, sem root
    test_live.py      # integração real, requires_live_lab
```

Próximo item da ordem (6): Admin API — avaliado e **deliberadamente não
implementado nesta fase**. Pro objetivo do artigo (SBRC 2027), o valor
de pesquisa está na coordenação SMO/KMS/Scheduler/IPsec Agent com
rotação por risco, não numa fronteira administrativa externa
(gRPC+mTLS); `smo/tests/test_live.py` já demonstra o fluxo completo sem
precisar dela. Fica documentada como lacuna conhecida, mesmo tratamento
que o MACsec Agent já recebe.

## Item 4 — Scheduler com fórmula de risco (concluído)

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

## Item 3 — IPsec Agent nativo mínimo (concluído)

`ipsec_agent/` fala VICI direto com os `charon` do laboratório (ver
`docs/RUNBOOK-OAI.md`) e implementa `apply_key_material` (carrega PSK
via `load-shared` + `rekey` com `reauth=true`, exatamente o mecanismo
descrito em `../docs/ARQUITETURA-ORQUESTRADOR.md`), `get_connection_status`
e `terminate_connection`. Testado contra as cinco conexões reais do
laboratório (`f1-cu-du`, `n2-cu-edge`, e as três `n3-<fatia>-cu-edge` —
ver "Estado atual" acima pra quando isso deixou de ser duas conexões) —
rotaciona o PSK (e o PPK, na URLLC) de verdade e confirma reautenticação
completa.

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
