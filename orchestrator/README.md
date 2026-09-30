# pqc-orchestrator

Implementação do orquestrador de chaves PQC por fatia descrito em
[`../docs/ARQUITETURA-ORQUESTRADOR.md`](../docs/ARQUITETURA-ORQUESTRADOR.md)
(leia esse documento primeiro — este README só situa o estado do código).

## Estado atual: item 2 da ordem de construção (KMS isolado e testável)

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
(`../lab/5gc/config/smf.yaml`). A arquitetura tinha esse mapeamento errado
numa versão anterior (SST=1 → URLLC) — já corrigido em
[`../docs/ARQUITETURA-ORQUESTRADOR.md`](../docs/ARQUITETURA-ORQUESTRADOR.md),
a política de qual fatia recebe ML-KEM-768
+ componente quântico vs. ML-KEM-512 continua a mesma (URLLC é quem recebe
o híbrido mais forte, só o número do SST que estava trocado).
