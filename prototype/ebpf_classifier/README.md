# ebpf_classifier (Módulo 3)

Classificador TC/eBPF descrito em
[`../../docs/ARQUITETURA-PROTOTIPO-COMPLETA.md`](../../docs/ARQUITETURA-PROTOTIPO-COMPLETA.md)
seção 4: lê o TEID do GTP-U (udp/2152), consulta um BPF hash map
(`teid_to_mark`, populado pelo Módulo 2) e marca o `skb` — sem alterar o
cabeçalho GTP-U/IP, a interface continua padrão vista de fora.

## Build e uso

```bash
clang -O2 -g -target bpf -D__TARGET_ARCH_x86 \
  -I/usr/include/$(uname -m)-linux-gnu \
  -c src/classifier.bpf.c -o src/classifier.bpf.o

sudo python3 -m venv .venv && source .venv/bin/activate   # (compartilha com prototype/, ver requirements.txt)
pip install -r ../requirements.txt
sudo .venv/bin/python3 -m pytest ebpf_classifier/tests -v   # precisa de root
```

```python
from loader import TcClassifier

clf = TcClassifier("eth0", direction="egress")   # ou netns="algum-netns"
clf.attach()
clf.update_teid_mark(0x1a1b, 0x20)   # TEID -> mark, chamado pelo Módulo 2
print(clf.read_stats())              # {'matched': N, 'unknown_teid': N, 'not_gtpu': N}
```

Testado com **5 testes determinísticos** (pacotes GTP-U sintéticos via
scapy, injetados num par veth descartável criado por teste — não depende
do laboratório OAI de pé) e também **contra tráfego real** do laboratório
(ver seção "Achado crítico" abaixo pra onde isso foi possível e onde não).

## Achado crítico — e a correção, validada contra XFRM real

**O problema, encontrado testando contra tráfego real**: o Módulo 4
precisa que o mark influencie qual SA IPsec criptografa o pacote de
saída (CU→UPF). TC egress acoplado na mesma interface que o IPsec
protege **não funciona** pra isso — confirmado de duas formas:

1. `tcpdump` em `veth-cu-n2` com o túnel `n2n3-cu-edge` ativo nunca
   mostra GTP-U em claro de saída, só ESP — o XFRM já cifrou antes de
   qualquer qdisc/TC daquela interface rodar (a política XFRM é
   resolvida como parte da decisão de rota, que acontece antes do TC
   egress, pra tráfego gerado localmente).
2. Um contador `iptables -t mangle -A FORWARD` pro mesmo mark nunca
   incrementou, mesmo com o eBPF confirmando `matched` crescendo —
   `FORWARD`/`POSTROUTING` do netfilter rodam antes do TC egress, não
   depois.

**A correção, validada empiricamente**: trocar o ponto de marcação de
TC egress pra `iptables -t mangle -A OUTPUT`. O hook `OUTPUT` da tabela
`mangle` tem um comportamento específico do kernel (`iptable_mangle.c`,
função `ipt_mangle_out`): se o mark do pacote mudar dentro desse hook,
o kernel chama `ip_route_me_harder()`, que **refaz a resolução de
rota** — e isso inclui refazer o `xfrm_lookup`, agora já com o mark
novo. É o mesmo mecanismo por trás do truque clássico de policy routing
("`iptables mangle OUTPUT` + `ip rule fwmark`"), só que aqui aplicado à
seleção de SA IPsec em vez de tabela de rota.

Validado em dois passos, num ambiente totalmente isolado (netns
descartáveis, sem tocar nos túneis `f1-cu-du`/`n2n3-cu-edge` reais):

1. **Reroteamento puro**: regra `mangle OUTPUT` com `-m u32` lendo o
   TEID do payload GTP-U (offset 32, 4 bytes) e setando o mark —
   pacotes UDP/GTP-U reais, cada um com TEID diferente, saindo pela
   interface certa conforme a regra batia ou não (confirmado via
   `tcpdump` simultâneo em duas interfaces).
2. **SA real do XFRM**: duas conexões strongSwan reais entre o mesmo
   par de endereços, diferenciadas só pelo `mark` (`mark=0x10` /
   `mark=0x20` no `ipsec.conf`, igual ao mecanismo `mark_in`/`mark_out`
   já referenciado na arquitetura). Com a mesma regra `mangle OUTPUT`
   baseada em TEID, enviei 1 pacote GTP-U com TEID mapeado pro mark
   `0x10` e 3 pacotes com TEID mapeado pro mark `0x20` — `ip -s xfrm
   state` confirmou exatamente 1 pacote na SA do mark `0x10` (SPI
   `c87e0211`) e exatamente 3 pacotes na SA do mark `0x20` (SPI
   `c451928a`), sem nenhum pacote na SA errada.

**Conclusão**: o classificador (lógica TEID→mark, já implementada e
testada) continua válido — só muda o ponto de anexação, de `tc filter
... egress` pra uma regra `iptables -t mangle -A OUTPUT`. A forma mais
simples de reaproveitar a lógica já escrita é portar a leitura do TEID
e o lookup no map pra uma regra `xt_bpf`/`-m u32`, ou manter o
`BPF_MAP_TYPE_HASH` existente e consultá-lo via `bpftool` a partir de
um pequeno daemon que atualiza regras `iptables` dinamicamente (mesmo
padrão operacional que o Módulo 2 já usa pra atualizar o BPF map, só
trocando o alvo de atualização). **Não bloqueia mais o Módulo 4** — fica
como o próximo passo de implementação, não mais como lacuna de
arquitetura em aberto.

## Estrutura

```
src/classifier.bpf.c   # o programa eBPF em si (ver comentário no topo sobre a limitação acima)
loader.py               # anexa via tc clsact, popula o map via bpftool, lê stats
tests/
  conftest.py            # cria netns descartável + entra nele via os.setns (não ip netns exec — bpffs ficaria invisível)
  test_classifier.py     # 5 testes determinísticos, GTP-U sintético via scapy
```
