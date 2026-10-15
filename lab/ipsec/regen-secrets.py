#!/usr/bin/env python3
"""Regenera os `secrets.conf` do laboratório a partir do `connections.conf`.

**Por que existe.** O `secrets.conf` é a única peça da config do
laboratório que NÃO é versionada — tem PSK e PPK, e está no `.gitignore`.
O `connections.conf` se recupera com `git checkout`; o `secrets.conf`
não. Já se perdeu três vezes nesta campanha, porque a Fase A sobrescreve
os dois arquivos para medir seus próprios perfis e qualquer execução
interrompida antes do `restore` deixa o laboratório sem segredos.
Regenerar à mão exige acertar nome de conexão, par de endereços e
`ppk_id` de cada fatia — e errar qualquer um deles dá falha de
autenticação difícil de ler.

**Por que lê o `connections.conf` em vez de ter as constantes.** Os
nomes, os pares de endereço e os `ppk_id` são definidos lá. Repeti-los
aqui criaria duas fontes de verdade que divergiriam na primeira vez que
uma fatia mudasse de endereço — e o sintoma seria uma falha de
autenticação, não um erro de config.

Os dois lados recebem o MESMO conteúdo: PSK e PPK são segredos
simétricos, e o `id-1`/`id-2` de cada bloco já diz a que par de
endereços ele se aplica, independente do lado.

Uso:
    sudo lab/ipsec/regen-secrets.py            # escreve nos dois lados
    lab/ipsec/regen-secrets.py --print         # só mostra, não escreve
"""

from __future__ import annotations

import argparse
import re
import secrets
import sys
from pathlib import Path

LAB_DIR = Path.home() / "oai-lab-conf"
LADOS = ("swanctl-cu", "swanctl-edge")

_ATRIBUTO = re.compile(r"^\s*(local_addrs|remote_addrs|ppk_id)\s*=\s*(\S+)")
_ABRE_BLOCO = re.compile(r"^\s*([\w.-]+)\s*\{")


def parse_conexoes(texto: str) -> list[dict]:
    """Extrai as conexões de topo do `connections.conf`.

    Parser por profundidade de chaves, e não por regex sobre o arquivo
    todo: as conexões têm blocos `local {}`, `remote {}` e `children {}`
    aninhados, e um `local_addrs` só pertence à conexão quando aparece
    na profundidade dela. Pegar por regex solta misturaria os blocos de
    conexões diferentes.

    A profundidade é contada pelo saldo de chaves da LINHA, não por
    "abriu" ou "fechou". O motivo é concreto: o arquivo tem linhas como
    `local { auth = psk }`, que abrem e fecham na mesma linha. A primeira
    versão deste parser tratava a linha como abertura e descartava o
    fechamento, então a profundidade nunca voltava — o `ppk_id`, que vem
    depois dessas linhas, não era capturado, e nenhuma conexão chegava a
    ser fechada. O resultado era uma lista vazia.

    Comentários são removidos antes da contagem, para uma chave dentro de
    comentário não desalinhar a profundidade.
    """
    conexoes: list[dict] = []
    profundidade = 0
    atual: dict | None = None
    prof_conexao = 2  # 1 é o `connections {` de fora

    for linha in texto.splitlines():
        limpa = linha.split("#", 1)[0]
        abre, fecha = limpa.count("{"), limpa.count("}")
        prof_inicio = profundidade

        if abre and (m := _ABRE_BLOCO.match(limpa)):
            if prof_inicio == prof_conexao - 1:
                atual = {"name": m.group(1)}
        elif atual is not None and prof_inicio == prof_conexao:
            if (m := _ATRIBUTO.match(limpa)):
                atual[m.group(1)] = m.group(2)

        profundidade += abre - fecha
        if atual is not None and profundidade < prof_conexao:
            conexoes.append(atual)
            atual = None

    return [c for c in conexoes if "local_addrs" in c and "remote_addrs" in c]


def gerar_secrets(conexoes: list[dict]) -> str:
    blocos = []
    for c in conexoes:
        psk = secrets.token_urlsafe(32)
        blocos.append(
            f"    ike-{c['name']} {{\n"
            f"        id-1 = {c['local_addrs']}\n"
            f"        id-2 = {c['remote_addrs']}\n"
            f'        secret = "{psk}"\n'
            f"    }}"
        )
    # Um bloco por ppk_id DISTINTO: duas fatias podem compartilhar o
    # mesmo PPK (é o que "partilha de QKD" significa no catálogo), e
    # nesse caso elas têm de receber o mesmo segredo, não dois.
    for ppk_id in dict.fromkeys(c["ppk_id"] for c in conexoes if "ppk_id" in c):
        # O rótulo do bloco é arbitrário para o swanctl; só não
        # repete o prefixo quando o próprio ppk_id já começa com "ppk-".
        rotulo = ppk_id if ppk_id.startswith("ppk-") else f"ppk-{ppk_id}"
        blocos.append(
            f"    {rotulo} {{\n"
            f"        id = {ppk_id}\n"
            f"        secret = 0x{secrets.token_bytes(32).hex()}\n"
            f"    }}"
        )
    return "secrets {\n" + "\n".join(blocos) + "\n}\n"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--print", dest="apenas_mostrar", action="store_true",
                        help="mostra o conteúdo gerado sem escrever nada")
    parser.add_argument("--lab-dir", type=Path, default=LAB_DIR)
    args = parser.parse_args()

    conf = args.lab_dir / "swanctl-cu" / "conf.d" / "connections.conf"
    if not conf.exists():
        print(f"não achei {conf}", file=sys.stderr)
        return 1

    conexoes = parse_conexoes(conf.read_text())
    if not conexoes:
        print(f"nenhuma conexão com local_addrs/remote_addrs em {conf} — "
              f"o arquivo está com a config da Fase A? Rode primeiro: "
              f"git -C {args.lab_dir} checkout swanctl-cu swanctl-edge", file=sys.stderr)
        return 1

    conteudo = gerar_secrets(conexoes)
    com_ppk = [c["name"] for c in conexoes if "ppk_id" in c]
    print(f"conexões encontradas: {[c['name'] for c in conexoes]}")
    print(f"com PPK: {com_ppk or 'nenhuma'}")

    if args.apenas_mostrar:
        print("\n" + conteudo)
        return 0

    for lado in LADOS:
        destino = args.lab_dir / lado / "conf.d" / "secrets.conf"
        destino.write_text(conteudo)
        destino.chmod(0o600)
        print(f"escrito {destino} (0600)")
    print("\nAgora recarregue: sudo bash lab/ipsec/../../oai-lab-conf/load-and-initiate-n3.sh")
    return 0


if __name__ == "__main__":
    sys.exit(main())
