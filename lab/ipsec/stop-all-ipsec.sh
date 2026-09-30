#!/usr/bin/env bash
# Mata as três instâncias isoladas do strongSwan (charon + starter) rodando
# dentro de cu-ns, du-ns e 5gc-edge-ns. Útil antes de recarregar uma mudança
# de config (ipsec.conf/ipsec.secrets) — strongSwan não recarrega esses
# arquivos sozinho, precisa reiniciar o processo.
set -euo pipefail

for ns in cu-ns du-ns 5gc-edge-ns; do
    pids=$(sudo ip netns pids "$ns" 2>/dev/null || true)
    for p in $pids; do
        comm=$(ps -p "$p" -o comm= 2>/dev/null || true)
        if [ "$comm" = "charon" ] || [ "$comm" = "starter" ]; then
            echo "[stop-all-ipsec] Matando $comm (PID $p) em $ns"
            sudo kill -9 "$p" 2>/dev/null || true
        fi
    done
done
echo "[stop-all-ipsec] Concluído."
