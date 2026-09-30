#!/usr/bin/env bash
# Recria toda a rede virtual do laboratório de forma idempotente: rede docker
# core-net, os netns cu-ns/du-ns com o veth-cu/veth-du original, E a rota extra
# veth-cu-host/veth-host-cu que você descobriu ser necessária pro gNB dentro do
# cu-ns alcançar o Docker (o gap que o IMPLEMENTACAO-VM.md original não previa).
#
# Seguro rodar de novo a qualquer momento (inclusive depois de um reboot) — cada
# etapa checa se já existe antes de tentar criar.
#
# IMPORTANTE: não tenho visibilidade dos comandos exatos que você digitou na VM
# pra criar o veth-cu-host original — reconstruí a lógica (rota + MASQUERADE)
# a partir do resultado que você descreveu (IP 10.100.0.1, cu-ns alcançando o
# core-net). Se depois de rodar isso o cu-ns ainda não alcançar o AMF, compare
# com o que você tinha digitado manualmente antes e ajusta — o mais provável de
# precisar de ajuste é a regra de MASQUERADE/NAT, que depende de como o Docker
# já configurou as próprias regras de iptables pra core-net.
set -euo pipefail

log() { echo "[setup-network] $*"; }

# --- 1. Rede docker core-net (N2/N3) ---------------------------------------
if ! docker network inspect core-net >/dev/null 2>&1; then
    log "Criando rede docker core-net (10.98.0.0/24)"
    docker network create --subnet=10.98.0.0/24 core-net
else
    log "core-net já existe, ok"
fi

# --- 2. Namespaces cu-ns / du-ns --------------------------------------------
for ns in cu-ns du-ns; do
    if ! ip netns list | grep -q "^${ns}\b"; then
        log "Criando namespace ${ns}"
        ip netns add "$ns"
        ip netns exec "$ns" ip link set lo up
    else
        log "Namespace ${ns} já existe, ok"
    fi
done

# --- 3. veth-cu <-> veth-du (F1, dentro dos namespaces) ---------------------
if ! ip netns exec cu-ns ip link show veth-cu >/dev/null 2>&1; then
    log "Criando par veth-cu <-> veth-du (F1, 10.99.0.0/24)"
    ip link add veth-cu type veth peer name veth-du
    ip link set veth-cu netns cu-ns
    ip link set veth-du netns du-ns
    ip netns exec cu-ns ip addr add 10.99.0.1/24 dev veth-cu
    ip netns exec du-ns ip addr add 10.99.0.2/24 dev veth-du
    ip netns exec cu-ns ip link set veth-cu up
    ip netns exec du-ns ip link set veth-du up
else
    log "veth-cu/veth-du já existem, ok"
fi

# --- 4. veth-cu-host <-> veth-host-cu (rota extra pro Docker) ---------------
# Isso é o workaround que você criou na mão: sem isso, o cu-ns não enxerga o
# core-net do Docker porque namespaces não roteiam pra outras redes do host
# por padrão.
if ! ip link show veth-host-cu >/dev/null 2>&1; then
    log "Criando par veth-cu-host <-> veth-host-cu (10.100.0.0/24)"
    ip link add veth-host-cu type veth peer name veth-cu-host
    ip link set veth-cu-host netns cu-ns
    ip addr add 10.100.0.1/24 dev veth-host-cu
    ip link set veth-host-cu up
    ip netns exec cu-ns ip addr add 10.100.0.2/24 dev veth-cu-host
    ip netns exec cu-ns ip link set veth-cu-host up
else
    log "veth-cu-host/veth-host-cu já existem, ok"
fi

# Roteamento: dentro do cu-ns, tráfego pra core-net (10.98.0.0/24) sai pela
# rota extra em vez de tentar sair pela veth-cu (que só serve F1).
if ! ip netns exec cu-ns ip route show | grep -q "10.98.0.0/24"; then
    log "Adicionando rota cu-ns -> core-net via 10.100.0.1"
    ip netns exec cu-ns ip route add 10.98.0.0/24 via 10.100.0.1
else
    log "Rota cu-ns -> core-net já existe, ok"
fi

# Habilita o host a rotear entre a veth-host-cu e a bridge do Docker, e ativa
# NAT/forwarding pra esse tráfego não ser bloqueado.
sysctl -w net.ipv4.ip_forward=1 >/dev/null
if ! iptables -t nat -C POSTROUTING -s 10.100.0.0/24 -d 10.98.0.0/24 -j MASQUERADE 2>/dev/null; then
    log "Adicionando regra de MASQUERADE pro tráfego cu-ns -> core-net"
    iptables -t nat -A POSTROUTING -s 10.100.0.0/24 -d 10.98.0.0/24 -j MASQUERADE
else
    log "Regra de MASQUERADE já existe, ok"
fi

# Docker 27+/29+ adiciona uma proteção anti-spoofing na tabela raw
# (PREROUTING) que dropa qualquer pacote destinado a um IP de container que
# não entre pela própria bridge da rede docker. Isso quebra justamente esse
# setup (netns externo roteando pro core-net via veth-host-cu), então
# precisamos de uma exceção pontual só pra essa interface conhecida, em vez
# de desabilitar a proteção inteira.
if ! iptables -t raw -C PREROUTING -i veth-host-cu -d 10.98.0.0/24 -j ACCEPT 2>/dev/null; then
    log "Adicionando exceção raw/PREROUTING pra veth-host-cu -> core-net (bypass da proteção anti-spoofing do Docker)"
    iptables -t raw -I PREROUTING -i veth-host-cu -d 10.98.0.0/24 -j ACCEPT
else
    log "Exceção raw/PREROUTING já existe, ok"
fi

if ! iptables -C DOCKER-USER -s 10.100.0.0/24 -d 10.98.0.0/24 -j ACCEPT 2>/dev/null; then
    log "Adicionando ACCEPT em DOCKER-USER pra cu-ns -> core-net"
    iptables -I DOCKER-USER -s 10.100.0.0/24 -d 10.98.0.0/24 -j ACCEPT
else
    log "ACCEPT DOCKER-USER cu-ns -> core-net já existe, ok"
fi
if ! iptables -C DOCKER-USER -s 10.98.0.0/24 -d 10.100.0.0/24 -j ACCEPT 2>/dev/null; then
    log "Adicionando ACCEPT em DOCKER-USER pra core-net -> cu-ns"
    iptables -I DOCKER-USER -s 10.98.0.0/24 -d 10.100.0.0/24 -j ACCEPT
else
    log "ACCEPT DOCKER-USER core-net -> cu-ns já existe, ok"
fi

# --- 5. N3 pro UPF (rede default do Docker, 172.18.0.0/16) ------------------
# O UPF fica só na rede "default" (não na core-net — colocá-lo lá o deixa
# multi-homed e o Open5GS passa a anunciar 127.0.0.1 no PFCP, o que o SMF
# rejeita, conforme comentário no docker-compose.yaml). O F-TEID de N3 que o
# UPF anuncia pro gNB (via PFCP/N4) é o IP dele na rede default, então o
# cu-ns precisa do mesmo tipo de rota/NAT/exceção que já tem pro core-net,
# só que apontando pra essa outra rede.
if ! ip netns exec cu-ns ip route show | grep -q "172.18.0.0/16"; then
    log "Adicionando rota cu-ns -> rede default do Docker (N3/UPF) via 10.100.0.1"
    ip netns exec cu-ns ip route add 172.18.0.0/16 via 10.100.0.1
else
    log "Rota cu-ns -> rede default do Docker já existe, ok"
fi

if ! iptables -t nat -C POSTROUTING -s 10.100.0.0/24 -d 172.18.0.0/16 -j MASQUERADE 2>/dev/null; then
    log "Adicionando regra de MASQUERADE pro tráfego cu-ns -> rede default (N3)"
    iptables -t nat -A POSTROUTING -s 10.100.0.0/24 -d 172.18.0.0/16 -j MASQUERADE
else
    log "Regra de MASQUERADE cu-ns -> rede default já existe, ok"
fi

if ! iptables -t raw -C PREROUTING -i veth-host-cu -d 172.18.0.0/16 -j ACCEPT 2>/dev/null; then
    log "Adicionando exceção raw/PREROUTING pra veth-host-cu -> rede default (N3/UPF)"
    iptables -t raw -I PREROUTING -i veth-host-cu -d 172.18.0.0/16 -j ACCEPT
else
    log "Exceção raw/PREROUTING pra rede default já existe, ok"
fi

if ! iptables -C DOCKER-USER -s 10.100.0.0/24 -d 172.18.0.0/16 -j ACCEPT 2>/dev/null; then
    log "Adicionando ACCEPT em DOCKER-USER pra cu-ns -> rede default (N3)"
    iptables -I DOCKER-USER -s 10.100.0.0/24 -d 172.18.0.0/16 -j ACCEPT
else
    log "ACCEPT DOCKER-USER cu-ns -> rede default já existe, ok"
fi
if ! iptables -C DOCKER-USER -s 172.18.0.0/16 -d 10.100.0.0/24 -j ACCEPT 2>/dev/null; then
    log "Adicionando ACCEPT em DOCKER-USER pra rede default -> cu-ns"
    iptables -I DOCKER-USER -s 172.18.0.0/16 -d 10.100.0.0/24 -j ACCEPT
else
    log "ACCEPT DOCKER-USER rede default -> cu-ns já existe, ok"
fi

# --- 6. 5gc-edge-ns: gateway de borda pro N2/N3, sem NAT ("máquina 5GC") ---
# As seções 4/5 acima (rota via veth-host-cu com NAT/MASQUERADE) foram o
# primeiro jeito que funcionou, mas NAT quebra o SCTP do N2 (ver
# RUNBOOK-OAI.md — checksum SCTP corrompido atravessando MASQUERADE/veth com
# checksum offload). A solução final é este netns extra, que atua como uma
# "máquina 5GC" de borda: entra como membro real das redes docker core-net e
# default (bridge, sem NAT/anti-spoofing), e expõe a cu-ns dois endereços de
# alias (10.98.0.98 pro N2/AMF, 172.18.0.99 pro N3/UPF) via proxy-ARP + rota,
# como se a CU estivesse fisicamente naquelas redes. O F1 continua igual.
if ! docker network inspect 5gc_default >/dev/null 2>&1; then
    log "AVISO: rede docker '5gc_default' ainda não existe (Open5GS não subiu"
    log "ainda neste boot). Pulando a seção do 5gc-edge-ns por agora — depois"
    log "de rodar 'docker compose up -d' no 5gc, rode este script de novo pra"
    log "montar o resto (rotas de N2/N3 pro edge-ns não ficam de pé sem isso)."
    log "Concluído (parcial)."
    exit 0
fi

CORE_NET_BRIDGE="br-$(docker network inspect core-net --format '{{slice .Id 0 12}}')"
DEFAULT_NET_BRIDGE="br-$(docker network inspect 5gc_default --format '{{slice .Id 0 12}}')"
log "Bridge core-net: $CORE_NET_BRIDGE | Bridge default: $DEFAULT_NET_BRIDGE"

if ! ip netns list | grep -q "^5gc-edge-ns\b"; then
    log "Criando namespace 5gc-edge-ns"
    ip netns add 5gc-edge-ns
    ip netns exec 5gc-edge-ns ip link set lo up
else
    log "Namespace 5gc-edge-ns já existe, ok"
fi

# 6.1 veth cu-ns <-> 5gc-edge-ns (nova "WAN" N2/N3, 10.97.0.0/24, sem NAT)
if ! ip netns exec cu-ns ip link show veth-cu-n2 >/dev/null 2>&1; then
    log "Criando par veth-cu-n2 <-> veth-edge-cu (10.97.0.0/24)"
    ip link add veth-cu-n2 type veth peer name veth-edge-cu
    ip link set veth-cu-n2 netns cu-ns
    ip link set veth-edge-cu netns 5gc-edge-ns
    ip netns exec cu-ns ip addr add 10.97.0.1/24 dev veth-cu-n2
    ip netns exec 5gc-edge-ns ip addr add 10.97.0.2/24 dev veth-edge-cu
    ip netns exec cu-ns ip link set veth-cu-n2 up
    ip netns exec 5gc-edge-ns ip link set veth-edge-cu up
else
    log "veth-cu-n2/veth-edge-cu já existem, ok"
fi

# 6.2 veth 5gc-edge-ns <-> bridge do core-net (membro real, sem NAT)
if ! ip netns exec 5gc-edge-ns ip link show veth-edge-core >/dev/null 2>&1; then
    log "Conectando 5gc-edge-ns na bridge do core-net (10.98.0.99)"
    ip link add veth-edge-core type veth peer name veth-core-edge
    ip link set veth-edge-core netns 5gc-edge-ns
    ip netns exec 5gc-edge-ns ip addr add 10.98.0.99/24 dev veth-edge-core
    ip netns exec 5gc-edge-ns ip link set veth-edge-core up
    ip link set veth-core-edge master "$CORE_NET_BRIDGE"
    ip link set veth-core-edge up
else
    log "veth-edge-core/veth-core-edge já existem, ok"
fi

# 6.3 veth 5gc-edge-ns <-> bridge default do Docker (pro N3/UPF, membro real)
if ! ip netns exec 5gc-edge-ns ip link show veth-edge-def >/dev/null 2>&1; then
    log "Conectando 5gc-edge-ns na bridge default do Docker (172.18.0.90)"
    ip link add veth-edge-def type veth peer name veth-def-edge
    ip link set veth-edge-def netns 5gc-edge-ns
    ip netns exec 5gc-edge-ns ip addr add 172.18.0.90/16 dev veth-edge-def
    ip netns exec 5gc-edge-ns ip link set veth-edge-def up
    ip link set veth-def-edge master "$DEFAULT_NET_BRIDGE"
    ip link set veth-def-edge up
else
    log "veth-edge-def/veth-def-edge já existem, ok"
fi

# 6.4 Forwarding dentro do 5gc-edge-ns (roteia entre os três links, sem NAT)
ip netns exec 5gc-edge-ns sysctl -w net.ipv4.ip_forward=1 >/dev/null

# 6.5 Proxy-ARP: 5gc-edge-ns responde pelos aliases da CU nas redes docker,
# e uma rota interna manda esse tráfego pra dentro do cu-ns. Do ponto de
# vista da AMF/UPF, a CU "está" naquela rede — sem NAT, sem quebrar SCTP.
ip netns exec 5gc-edge-ns sysctl -w net.ipv4.conf.veth-edge-core.proxy_arp=1 >/dev/null
ip netns exec 5gc-edge-ns sysctl -w net.ipv4.conf.veth-edge-def.proxy_arp=1 >/dev/null

if ! ip netns exec 5gc-edge-ns ip route show | grep -q "10.98.0.98"; then
    log "Adicionando rota 5gc-edge-ns -> cu-ns pro alias N2 (10.98.0.98)"
    ip netns exec 5gc-edge-ns ip route add 10.98.0.98/32 via 10.97.0.1 dev veth-edge-cu
else
    log "Rota do alias N2 (10.98.0.98) já existe, ok"
fi
if ! ip netns exec 5gc-edge-ns ip route show | grep -q "172.18.0.99"; then
    log "Adicionando rota 5gc-edge-ns -> cu-ns pro alias N3 (172.18.0.99)"
    ip netns exec 5gc-edge-ns ip route add 172.18.0.99/32 via 10.97.0.1 dev veth-edge-cu
else
    log "Rota do alias N3 (172.18.0.99) já existe, ok"
fi

# 6.6 Os aliases em si, dentro do cu-ns — é onde a CU efetivamente faz bind.
if ! ip netns exec cu-ns ip addr show dev veth-cu-n2 | grep -q "10.98.0.98/32"; then
    log "Adicionando alias 10.98.0.98/32 na cu-ns (N2/AMF)"
    ip netns exec cu-ns ip addr add 10.98.0.98/32 dev veth-cu-n2
else
    log "Alias 10.98.0.98/32 já existe na cu-ns, ok"
fi
if ! ip netns exec cu-ns ip addr show dev veth-cu-n2 | grep -q "172.18.0.99/32"; then
    log "Adicionando alias 172.18.0.99/32 na cu-ns (N3/UPF)"
    ip netns exec cu-ns ip addr add 172.18.0.99/32 dev veth-cu-n2
else
    log "Alias 172.18.0.99/32 já existe na cu-ns, ok"
fi

# 6.7 Rotas da cu-ns pras sub-redes do 5GC agora via edge-ns, substituindo
# (route replace, não add) a rota antiga via veth-host-cu da seção 4/5.
log "Apontando rotas cu-ns -> core-net/default pro 5gc-edge-ns (10.97.0.2)"
ip netns exec cu-ns ip route replace 10.98.0.0/24 via 10.97.0.2 dev veth-cu-n2
ip netns exec cu-ns ip route replace 172.18.0.0/16 via 10.97.0.2 dev veth-cu-n2

# 6.8 Checksum offload em veth quebra o checksum CRC32c do SCTP quando o
# pacote passa por decrypt/NAT/roteamento entre namespaces (ver
# RUNBOOK-OAI.md) — desliga em todas as interfaces do caminho N2/N3.
for iface_ns in "cu-ns veth-cu-n2" "5gc-edge-ns veth-edge-cu" "5gc-edge-ns veth-edge-core" "5gc-edge-ns veth-edge-def"; do
    ns=$(echo "$iface_ns" | cut -d' ' -f1)
    iface=$(echo "$iface_ns" | cut -d' ' -f2)
    ip netns exec "$ns" ethtool -K "$iface" tx off >/dev/null 2>&1 || true
done
ethtool -K veth-core-edge tx off >/dev/null 2>&1 || true
ethtool -K veth-def-edge tx off >/dev/null 2>&1 || true

log "Teste rápido: ip netns exec cu-ns ping -c1 <IP-DO-AMF-NO-CORE-NET>"
log "Concluído."
