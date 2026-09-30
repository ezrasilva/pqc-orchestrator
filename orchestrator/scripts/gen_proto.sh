#!/usr/bin/env bash
# Regenera os stubs Python a partir dos .proto em proto/. Rode isso sempre
# que editar qualquer .proto — os arquivos gerados em gen/python/ não são
# editados à mão.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

if [ ! -d .venv ]; then
    echo "Criando venv em .venv/ ..."
    python3 -m venv .venv
fi
source .venv/bin/activate
pip install --quiet -r requirements.txt

rm -rf gen/python
mkdir -p gen/python

PROTO_FILES=(proto/*.proto)

python -m grpc_tools.protoc \
    -I proto \
    --python_out=gen/python \
    --grpc_python_out=gen/python \
    --pyi_out=gen/python \
    "${PROTO_FILES[@]}"

# grpc_tools gera imports absolutos (ex: "import common_pb2") que só
# funcionam com gen/python no PYTHONPATH — não tenta corrigir pra imports
# relativos de pacote aqui; times que quiserem virar um pacote de verdade
# (com __init__.py e imports relativos) ajustam isso quando o resto do
# código existir e ficar claro qual convenção o projeto quer.
touch gen/python/__init__.py

echo "Stubs gerados em gen/python/ (adicione ao PYTHONPATH ou instale como pacote editável)."
