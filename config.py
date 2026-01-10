"""
Configurações do serviço RouterOS
"""
import os
import logging

logger = logging.getLogger(__name__)

# Configuração via variáveis de ambiente
API_C_SHARP_URL = os.getenv("API_C_SHARP_URL", "http://localhost:5000")
PORT = int(os.getenv("ROUTEROS_PORT", "8765"))  # Porta do WebSocket RouterOS
HTTP_PORT = int(os.getenv("ROUTEROS_HTTP_PORT", "8001"))  # Porta HTTP para API REST

# Configurações de monitoramento e sincronização
MONITOR_INTERVAL_SECONDS = int(os.getenv("MONITOR_INTERVAL_SECONDS", "60"))
SYNC_INTERVAL_SECONDS = int(os.getenv("SYNC_INTERVAL_SECONDS", "60"))
PING_ATTEMPTS = int(os.getenv("PING_ATTEMPTS", "3"))
PING_TIMEOUT_MS = int(os.getenv("PING_TIMEOUT_MS", "1000"))
MAX_CONCURRENT_PINGS = int(os.getenv("MAX_CONCURRENT_PINGS", "10"))

# Configurações de conexão RouterOS
ROUTEROS_CONNECTION_TIMEOUT = int(os.getenv("ROUTEROS_CONNECTION_TIMEOUT", "30"))
ROUTEROS_MAX_CONNECTIONS = int(os.getenv("ROUTEROS_MAX_CONNECTIONS", "10"))
