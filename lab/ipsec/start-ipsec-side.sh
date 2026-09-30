#!/usr/bin/env bash
# Sobe uma instância isolada do strongSwan dentro de um network namespace
# (cu-ns, du-ns ou 5gc-edge-ns), com seu próprio mount namespace pra não
# brigar com as outras instâncias por /run (pidfile, socket VICI, etc) nem
# por /etc/ipsec.*. Cada netns tem seu próprio ipsec.conf/ipsec.secrets,
# porque cu-ns é o initiator (auto=start) e os outros dois são
# respondedores passivos (auto=add) — ver ARQUITETURA-ORQUESTRADOR.md.
#
# Uso: sudo bash start-ipsec-side.sh <cu-ns|du-ns|5gc-edge-ns>
set -euo pipefail

NS="$1"
BASE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

case "$NS" in
    cu-ns)       CONF_DIR="$BASE_DIR/ipsec-cu" ;;
    du-ns)       CONF_DIR="$BASE_DIR/ipsec-du" ;;
    5gc-edge-ns) CONF_DIR="$BASE_DIR/ipsec-edge" ;;
    *) echo "netns desconhecido: $NS (use cu-ns, du-ns ou 5gc-edge-ns)" >&2; exit 1 ;;
esac

RUN_DIR="/run/ipsec-${NS}"
mkdir -p "$RUN_DIR"

exec ip netns exec "$NS" unshare --mount -- bash -c "
    set -euo pipefail
    mkdir -p '$RUN_DIR'
    mount --bind '$RUN_DIR' /run
    mount --bind '$CONF_DIR/ipsec.conf' /etc/ipsec.conf
    mount --bind '$CONF_DIR/ipsec.secrets' /etc/ipsec.secrets
    exec ipsec start --nofork
"
