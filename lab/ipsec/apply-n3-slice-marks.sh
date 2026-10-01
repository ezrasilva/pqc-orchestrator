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

echo "[apply-n3-slice-marks] regras aplicadas em $NS:"
ip netns exec "$NS" iptables -t mangle -L OUTPUT -n -v
