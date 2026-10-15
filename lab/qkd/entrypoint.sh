#!/bin/bash

# Inicia o serviço do servidor SSH em background
echo "Iniciando o servidor SSH..."
sudo /usr/sbin/sshd

# Mantém o container rodando indefinidamente
# Isso permite que você se conecte via 'docker exec' ou SSH.
echo "Container iniciado e pronto para conexões."
tail -f /dev/null