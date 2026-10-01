# pqc-orchestrator

Implementação do orquestrador de chaves PQC por fatia descrito em
`../docs/ARQUITETURA-ORQUESTRADOR.md` (leia esse documento primeiro — este README
só situa o estado do código).

## Estado atual: item 3 da ordem de construção (IPsec Agent nativo mínimo)

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

Próximo item da ordem (4): Scheduler com a fórmula de risco.

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
