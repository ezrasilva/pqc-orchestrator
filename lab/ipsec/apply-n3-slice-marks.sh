#!/usr/bin/env bash
# Fase 3 (cifragem manual): marca o tráfego GTP-U de saída da CU pelo TEID
# real de cada sessão PDU, via `iptables -t mangle -A OUTPUT` — não via TC
# egress (não funciona pra tráfego gerado localmente, ver
# prototype/ebpf_classifier/README.md pro porquê e a validação contra
# SAs reais do strongSwan).
#
# Os TEIDs de cada fatia vêm do Módulo 2 (pfcp_sniffer) — nesta fase ainda
# são aplicados à mão; a automação (Módulo 2 atualizando estas regras sob
# demanda, em vez de um operador rodar este script) é trabalho futuro, ver
# ARQUITETURA-PROTOTIPO-COMPLETA.md seção 4.1.
#
# Uso: sudo bash apply-n3-slice-marks.sh <netns-da-cu> <teid_urllc_hex> <teid_embb_hex> <teid_miot_hex>
# Exemplo: sudo bash apply-n3-slice-marks.sh cu-ns 0x85cb 0xe478 0x785b
set -euo pipefail

NS="$1"
TEID_URLLC="$2"
TEID_EMBB="$3"
TEID_MIOT="$4"

ip netns exec "$NS" iptables -t mangle -F OUTPUT
ip netns exec "$NS" iptables -t mangle -A OUTPUT -p udp --dport 2152 -m u32 --u32 "32=${TEID_URLLC}" -j MARK --set-mark 0x10
ip netns exec "$NS" iptables -t mangle -A OUTPUT -p udp --dport 2152 -m u32 --u32 "32=${TEID_EMBB}"  -j MARK --set-mark 0x20
ip netns exec "$NS" iptables -t mangle -A OUTPUT -p udp --dport 2152 -m u32 --u32 "32=${TEID_MIOT}"  -j MARK --set-mark 0x30

# FAIL-CLOSED: GTP-U que não casou com nenhum TEID conhecido é
# DESCARTADO e registrado, em vez de sair em claro.
#
# **Por que isto é necessário, medido.** Sem estas duas regras, um
# pacote GTP-U com TEID desconhecido não recebe mark, não casa com a
# política XFRM de nenhuma fatia e **sai em claro pelo veth externo** —
# verificado enviando 10 pacotes com TEID 0xDEADBEEF e capturando os 10
# no fio, sem cifra. O IPsec é contornado por completo.
#
# A decisão da campanha (14/10) é descartar e registrar, e é a escolha
# certa: as alternativas seriam mandar para uma SA padrão, o que daria a
# tráfego não classificado a proteção de uma fatia arbitrária, ou deixar
# passar, que é o furo acima.
#
# Consequência operacional aceita: se uma UE renegocia a sessão PDU o
# TEID muda, e o tráfego dela é descartado até os marks serem
# reaplicados (`capture_and_apply_slice_marks`). Falhar fechado é o
# comportamento desejado num plano de dados cifrado.
#
# O LOG é limitado a 10/min porque /tmp é um tmpfs de 12 GB nesta VM e
# uma inundação de log já o encheu antes, zerando execuções de campanha.
ip netns exec "$NS" iptables -t mangle -A OUTPUT -p udp --dport 2152 \
    -m limit --limit 10/min --limit-burst 5 \
    -j LOG --log-prefix "[n3-teid-nao-classificado] " --log-level 4
ip netns exec "$NS" iptables -t mangle -A OUTPUT -p udp --dport 2152 -j DROP

echo "[apply-n3-slice-marks] regras aplicadas em $NS:"
ip netns exec "$NS" iptables -t mangle -L OUTPUT -n -v
