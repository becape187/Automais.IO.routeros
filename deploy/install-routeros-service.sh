#!/bin/bash
# Script para instalar routeros.service manualmente
# Use este script se o arquivo não foi copiado automaticamente pelo deploy

set -e

echo "=== Instalando routeros.service ==="

# Verificar se estamos no diretório correto
if [ ! -f "deploy/routeros.service" ]; then
    echo "❌ Erro: Arquivo deploy/routeros.service não encontrado"
    echo "Execute este script do diretório /root/automais.io/routeros.io"
    exit 1
fi

# Copiar arquivo de serviço
echo "Copiando routeros.service..."
sudo cp deploy/routeros.service /etc/systemd/system/routeros.service
sudo chmod 644 /etc/systemd/system/routeros.service

# Recarregar systemd
echo "Recarregando systemd..."
sudo systemctl daemon-reload

# Habilitar serviço
echo "Habilitando routeros.service..."
sudo systemctl enable routeros.service

# Iniciar serviço
echo "Iniciando routeros.service..."
sudo systemctl start routeros.service

# Verificar status
echo ""
echo "Status do routeros.service:"
sudo systemctl status routeros.service --no-pager || true

echo ""
echo "✅ routeros.service instalado com sucesso!"
echo ""
echo "Para ver logs:"
echo "  sudo journalctl -u routeros.service -f"
