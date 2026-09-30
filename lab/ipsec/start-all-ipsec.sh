#!/usr/bin/env bash
# Sobe as três instâncias isoladas do strongSwan (cu-ns, du-ns, 5gc-edge-ns)
# que juntas cobrem os dois enlaces do laboratório:
#   - F1 (CU <-> DU), transport mode, direto entre os dois netns.
#   - N2/N3 (CU <-> borda do 5GC), tunnel mode, terminando no 5gc-edge-ns.
#
# Pré-requisito: setup-network.sh já rodado (precisa dos netns cu-ns, du-ns
# e 5gc-edge-ns existindo, com os aliases/rotas/proxy-ARP já montados).
#
# Idempotente na prática: se alguma instância já estiver rodando, o `ipsec
# start` dela vai reclamar mas não derruba a que já está de pé. Pra reiniciar
# do zero, mate os processos charon/starter de cada netns antes
# (veja RUNBOOK-OAI.md).
set -euo pipefail

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

for ns in cu-ns du-ns 5gc-edge-ns; do
    echo "[start-all-ipsec] Subindo strongSwan em $ns..."
    sudo bash "$DIR/start-ipsec-side.sh" "$ns" > "/tmp/ipsec-${ns}.log" 2>&1 &
    disown
done

sleep 5
echo "[start-all-ipsec] Status (visto do lado da CU):"
CU_CHARON_PID=$(sudo ip netns pids cu-ns | while read -r p; do
    [ "$(ps -p "$p" -o comm= 2>/dev/null)" = "charon" ] && echo "$p" && break
done)
if [ -n "${CU_CHARON_PID:-}" ]; then
    sudo nsenter --mount="/proc/${CU_CHARON_PID}/ns/mnt" ipsec status
else
    echo "[start-all-ipsec] Não achei o charon da cu-ns ainda — espera mais um pouco e roda 'ipsec status' na mão (ver RUNBOOK-OAI.md)."
fi
