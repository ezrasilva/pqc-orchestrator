#!/usr/bin/env bash
# Sobe uma instância isolada do strongSwan dentro de um network namespace
# (cu-ns, du-ns ou 5gc-edge-ns), com seu próprio mount namespace pra não
# brigar com as outras instâncias por /run (pidfile, socket VICI, etc) nem
# por /etc/ipsec.*. Cada netns tem seu próprio ipsec.conf/ipsec.secrets,
# porque cu-ns é o initiator (auto=start) e os outros dois são
# respondedores passivos (auto=add) — ver ARQUITETURA-ORQUESTRADOR.md.
#
# Desde a Fase 4 do protótipo SBRC (ver ARQUITETURA-PROTOTIPO-COMPLETA.md
# seção 5.3), cu-ns e 5gc-edge-ns também bind-montam duas config vici
# (connections.conf/secrets.conf) em /etc/swanctl/conf.d/ — as três
# conexões N3 (urllc/embb/miot) não cabem no parser clássico do
# ipsec.conf: precisam de PPK (RFC 8784, só existe via vici) e de
# endereço externo próprio cada uma (compartilhar left/right com outro
# conn de perfil mais fraco causa downgrade SILENCIOSO de proposta,
# achado confirmado nesta VM). F1 e N2 continuam só no ipsec.conf
# clássico. /etc/swanctl/swanctl.conf (não tocado aqui) já tem
# `include conf.d/*.conf` por padrão, então os dois arquivos bind-
# montados entram sozinhos — não precisa (nem deve) sobrescrever o
# swanctl.conf principal.
#
# As conexões N3 não sobem sozinhas (start_action=none, equivalente ao
# auto=add clássico) — depois de rodar este script dos dois lados, suba
# com: sudo bash load-and-initiate-n3.sh
#
# Uso: sudo bash start-ipsec-side.sh <cu-ns|du-ns|5gc-edge-ns>
set -euo pipefail

NS="$1"
BASE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

case "$NS" in
    cu-ns)       CONF_DIR="$BASE_DIR/ipsec-cu";   SWANCTL_DIR="$BASE_DIR/swanctl-cu" ;;
    du-ns)       CONF_DIR="$BASE_DIR/ipsec-du";   SWANCTL_DIR="" ;;
    5gc-edge-ns) CONF_DIR="$BASE_DIR/ipsec-edge"; SWANCTL_DIR="$BASE_DIR/swanctl-edge" ;;
    *) echo "netns desconhecido: $NS (use cu-ns, du-ns ou 5gc-edge-ns)" >&2; exit 1 ;;
esac

RUN_DIR="/run/ipsec-${NS}"
mkdir -p "$RUN_DIR"

SWANCTL_MOUNTS=""
if [ -n "$SWANCTL_DIR" ]; then
    SWANCTL_MOUNTS="
    mkdir -p /etc/swanctl/conf.d
    touch /etc/swanctl/conf.d/connections.conf /etc/swanctl/conf.d/secrets.conf
    mount --bind '$SWANCTL_DIR/conf.d/connections.conf' /etc/swanctl/conf.d/connections.conf
    mount --bind '$SWANCTL_DIR/conf.d/secrets.conf' /etc/swanctl/conf.d/secrets.conf
    "
fi

exec ip netns exec "$NS" unshare --mount -- bash -c "
    set -euo pipefail
    mkdir -p '$RUN_DIR'
    mount --bind '$RUN_DIR' /run
    mount --bind '$CONF_DIR/ipsec.conf' /etc/ipsec.conf
    mount --bind '$CONF_DIR/ipsec.secrets' /etc/ipsec.secrets
    $SWANCTL_MOUNTS
    exec ipsec start --nofork
"
