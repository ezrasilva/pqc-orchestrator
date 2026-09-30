#!/usr/bin/env bash
# Diagnóstico rápido pro problema de sync da UE — roda os dois testes baratos
# antes de qualquer recompilação. Uso:
#
#   ./diagnostico.sh            -> só checa AVX-512 exposto, sai
#   ./diagnostico.sh --watch N  -> além do AVX-512, amostra %steal por N segundos
#                                  (rode isso em paralelo com uma tentativa de
#                                  attach da UE, em outro terminal/tmux pane)
#
set -euo pipefail

echo "== 1. Extensões AVX expostas pra esta VM =="
FLAGS=$(grep -o 'avx[a-z0-9_]*' /proc/cpuinfo | sort -u || true)
if [ -z "$FLAGS" ]; then
    echo "Nenhuma flag avx* encontrada em /proc/cpuinfo."
    echo "-> Hipótese de AVX-512 descartada. Não vale a pena recompilar com"
    echo "   -DENABLE_AVX512=OFF, o problema está em outro lugar."
else
    echo "$FLAGS"
    if echo "$FLAGS" | grep -q avx512; then
        echo "-> AVX-512 ESTÁ exposto pra VM. Vale testar o rebuild com SIMD"
        echo "   desabilitado (veja REBUILD-SIMD-OFF.md)."
    else
        echo "-> AVX2 (ou menos) exposto, sem AVX-512. A hipótese original"
        echo "   (AVX-512 quebrando o correlator) não se aplica aqui — mas"
        echo "   ainda pode valer testar -DENABLE_AVX2=OFF como controle."
    fi
fi

echo
echo "== 2. CPU steal time (%st) — indica se o host está sobrecarregando a VM =="
if [ "${1:-}" == "--watch" ]; then
    SECONDS_TO_WATCH="${2:-15}"
    echo "Amostrando por ${SECONDS_TO_WATCH}s — tente o attach da UE AGORA em outro terminal."
    vmstat 1 "$SECONDS_TO_WATCH" | tee /tmp/diagnostico-vmstat.log
    echo
    AVG_STEAL=$(awk 'NR>2 {sum+=$17; n++} END {if (n>0) printf "%.1f", sum/n; else print "0"}' /tmp/diagnostico-vmstat.log)
    echo "Média de %steal durante a janela: ${AVG_STEAL}%"
    if awk -v s="$AVG_STEAL" 'BEGIN{exit !(s > 5)}'; then
        echo "-> Steal time relevante (>5%). O host físico pode estar disputando"
        echo "   CPU o suficiente pra atrapalhar o timing do ZMQ. Considere pedir"
        echo "   uma VM menos disputada, ou reduzir ainda mais a banda de teste."
    else
        echo "-> Steal time baixo. Timing do hypervisor não parece ser o problema"
        echo "   principal aqui."
    fi
else
    echo "(rode com '--watch N' enquanto tenta o attach pra capturar isso de verdade)"
    echo "Snapshot único agora, só como referência:"
    top -bn1 | grep -i "%cpu\|cpu(s)" || true
fi

echo
echo "== Resumo =="
echo "Guarde a saída acima. Se AVX-512 não estiver exposto e o steal time for"
echo "baixo, volte pro UE-CONFIG-CHECK.md — é mais provável que o problema"
echo "ainda esteja em descompasso de config (banda/srate/ARFCN) do que em"
echo "hardware/virtualização."
