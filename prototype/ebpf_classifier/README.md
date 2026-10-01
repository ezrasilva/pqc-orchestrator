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

## Achado crítico: TC egress não vê o GTP-U em claro pra tráfego de saída da CU, uma vez que o IPsec já está ativo

**Isto não é um defeito no código acima — é uma limitação de ONDE esse
código pode ser acoplado nesta topologia, encontrada testando contra
tráfego real, não suposição.**

O Módulo 4 precisa que o `mark` setado pelo Módulo 3 influencie qual SA
IPsec criptografa o pacote de **saída** (CU→UPF) — é assim que a
diferenciação por fatia aconteceria. Pra isso, o TC precisa marcar o
pacote **antes** do XFRM decidir/aplicar a criptografia.

**Testado e confirmado nesta VM que isso não acontece** se o hook TC
estiver no mesmo dispositivo de saída que o XFRM protege:

1. Capturei `veth-cu-n2` (a interface de saída real do N3 da CU) com o
   túnel `n2n3-cu-edge` ativo — o tráfego de saída **nunca** aparece como
   UDP/GTP-U, só como ESP. O XFRM já criptografou antes de qualquer
   qdisc/TC daquela interface rodar (confirmado — é assim que o kernel
   trata saída de tráfego gerado localmente: a política XFRM é resolvida
   como parte da decisão de rota, que acontece antes do TC egress).
2. Testei marcar via `iptables -t mangle -A FORWARD` e comparei com o
   `matched` do eBPF rodando em TC egress na mesma interface
   (`veth-edge-def`, no `5gc-edge-ns`, com tráfego real da UPF):
   o eBPF via tráfego de verdade e incrementava `matched` corretamente,
   mas um contador `iptables` independente pro mesmo mark **nunca**
   incrementava — porque `FORWARD`/`POSTROUTING` (netfilter) rodam
   **antes** do TC egress no pipeline do kernel, não depois. Ou seja: uma
   marca setada em TC egress não fica visível pra mais nada processar
   depois, dentro da mesma máquina — é literalmente o último passo antes
   do fio.

**Consequência**: o classificador, do jeito que está (TC egress na
mesma interface que o IPsec protege), não consegue influenciar qual SA
criptografa o tráfego de saída da CU. Ele funciona perfeitamente como
classificador — lê o TEID certo, marca certo, confirmado com tráfego
real — só não está no ponto certo do pipeline pra essa finalidade
específica.

### Caminho de correção (não implementado ainda)

O padrão que **funciona de forma confiável e bem estabelecida** no Linux
é marcar tráfego que está sendo **encaminhado** (forwarded), não
**gerado localmente** — pra tráfego encaminhado, uma marca setada mais
cedo no pipeline (TC ingress ou `iptables -t mangle -A PREROUTING`) *é*
respeitada por uma decisão de rota/XFRM feita depois, porque o kernel
recalcula a rota do zero pro reencaminhamento.

Isso sugere inserir mais um salto antes do enlace protegido por IPsec —
o mesmo padrão que o `5gc-edge-ns` já usa do lado do núcleo (ver
`RUNBOOK-OAI.md`): um netns extra onde o socket GTP-U da CU bind na
verdade, com o classificador TC acoplado no egress **desse** netns
intermediário. Dali, o pacote (já marcado) é encaminhado pro `cu-ns`
real, onde agora é tráfego sendo roteado/reencaminhado — a marca deveria
sobreviver até a decisão de rota+XFRM que escolhe a SA.

**Não implementado nesta fase** — exige reestruturar onde o processo da
CU (OAI) faz bind do socket N3, o que é uma mudança de topologia, não só
mais um módulo. Fica como próximo passo explícito, não escondido.

## Estrutura

```
src/classifier.bpf.c   # o programa eBPF em si (ver comentário no topo sobre a limitação acima)
loader.py               # anexa via tc clsact, popula o map via bpftool, lê stats
tests/
  conftest.py            # cria netns descartável + entra nele via os.setns (não ip netns exec — bpffs ficaria invisível)
  test_classifier.py     # 5 testes determinísticos, GTP-U sintético via scapy
```
