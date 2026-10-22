#!/usr/bin/env python3
"""Teste negativo de isolamento: GTP-U com TEID não classificado.

A especificação da campanha pede: *"um teste negativo envia tráfego com
TEID não classificado e verifica o destino dele (SA padrão ou descarte,
conforme a política decidida)"*. A política decidida em 14/10 é
**descartar e registrar**.

**O que este teste encontrou.** Antes da correção, 10 pacotes GTP-U com
TEID `0xDEADBEEF` saíram **em claro** no veth externo: nenhum mark
casava, nenhuma política XFRM se aplicava, e o IPsec era contornado por
completo. O `apply-n3-slice-marks.sh` tinha só as três regras de MARK,
sem nada depois delas — ou seja, a decisão registrada no documento não
estava implementada, e nada avisava.

A correção são duas regras ao fim da cadeia: LOG com limite de taxa e
DROP. O teste existe para que a propriedade seja **verificável**, e não
afirmada.

Uso (precisa de root, com o laboratório de pé):
    sudo PYTHONPATH=orchestrator .venv/bin/python3 -m evaluation.negative_teid_test
"""

from __future__ import annotations

import re
import subprocess
import sys
import tempfile
import time
from pathlib import Path

NETNS = "cu-ns"
IFACE_EXTERNA = "veth-cu-n2"
ORIGEM, DESTINO = "10.97.0.11", "10.97.0.12"
PORTA_GTPU = 2152
# TEID escolhido para não colidir com nenhum real: os do laboratório vêm
# do gNB e ficam na casa de 0x0000xxxx.
TEID_NAO_CLASSIFICADO = 0xDEADBEEF
TENTATIVAS = 10

# O `sendto` passa a devolver EPERM quando a regra DROP está ativa — o
# kernel recusa localmente em vez de enfileirar. Isso É o sinal de
# sucesso, então o emissor conta recusas em vez de abortar no primeiro
# erro, que foi o que mascarou a contagem na primeira versão deste teste.
EMISSOR = f"""
import socket, struct
enviados = recusados = 0
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.bind(("{ORIGEM}", 0))
pacote = (struct.pack("!BBH", 0x30, 0xFF, 8)
          + struct.pack("!I", {TEID_NAO_CLASSIFICADO}) + b"X" * 16)
for _ in range({TENTATIVAS}):
    try:
        s.sendto(pacote, ("{DESTINO}", {PORTA_GTPU}))
        enviados += 1
    except PermissionError:
        recusados += 1
print(f"{{enviados}} {{recusados}}")
"""


def _ns(*args: str) -> subprocess.CompletedProcess:
    return subprocess.run(["ip", "netns", "exec", NETNS, *args],
                          capture_output=True, text=True)


def _contador_regra(alvo: str) -> int:
    """Pacotes contados pela regra `alvo` na cadeia mangle OUTPUT."""
    saida = _ns("iptables", "-t", "mangle", "-L", "OUTPUT", "-n", "-v").stdout
    for linha in saida.splitlines():
        if f" {alvo} " in linha and str(PORTA_GTPU) in linha:
            campos = linha.split()
            if campos and campos[0].isdigit():
                return int(campos[0])
    return 0


def main() -> int:
    regras = _ns("iptables", "-t", "mangle", "-L", "OUTPUT", "-n").stdout
    tem_drop = bool(re.search(rf"DROP.*dpt:{PORTA_GTPU}", regras))
    print(f"regra de DROP para GTP-U presente: {tem_drop}")
    if not tem_drop:
        print("AVISO: sem a regra, o esperado é o tráfego SAIR EM CLARO — é o "
              "estado que este teste existe para detectar.")

    drop_antes = _contador_regra("DROP")
    log_antes = _contador_regra("LOG")

    with tempfile.TemporaryDirectory() as tmp:
        pcap = Path(tmp) / "captura.pcap"
        captura = subprocess.Popen(
            ["ip", "netns", "exec", NETNS, "tcpdump", "-ni", IFACE_EXTERNA,
             "-c", str(TENTATIVAS * 2), f"udp port {PORTA_GTPU}", "-w", str(pcap)],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        time.sleep(2)  # deixa o tcpdump começar a capturar antes de emitir

        resultado = _ns("python3", "-c", EMISSOR)
        try:
            enviados, recusados = (int(x) for x in resultado.stdout.split())
        except ValueError:
            print(f"emissor falhou: {resultado.stdout}{resultado.stderr}", file=sys.stderr)
            return 1

        time.sleep(3)  # escoa o que estiver em trânsito antes de fechar
        captura.terminate()
        captura.wait(timeout=10)

        leitura = subprocess.run(["tcpdump", "-nr", str(pcap)],
                                 capture_output=True, text=True)
        em_claro = [l for l in leitura.stdout.splitlines() if str(PORTA_GTPU) in l]

    drop = _contador_regra("DROP") - drop_antes
    log = _contador_regra("LOG") - log_antes

    print(f"\n  tentativas de envio:        {TENTATIVAS}")
    print(f"  aceitas pelo socket:        {enviados}")
    print(f"  recusadas com EPERM:        {recusados}")
    print(f"  contadas pela regra DROP:   {drop}")
    print(f"  contadas pela regra LOG:    {log}  (limitada a 10/min)")
    print(f"  CAPTURADAS EM CLARO no fio: {len(em_claro)}")

    # O critério é o único que importa para a afirmação de segurança: nada
    # com TEID desconhecido pode aparecer sem cifra no enlace. As recusas
    # por EPERM e os contadores de regra são evidência de COMO foi
    # barrado, não do fato de ter sido.
    if em_claro:
        print("\nFALHOU: tráfego com TEID não classificado saiu em claro.")
        for l in em_claro[:5]:
            print("   ", l)
        return 1
    print("\nPASSOU: nenhum pacote com TEID não classificado saiu em claro.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
