# RouterOS Service

Serviço dedicado exclusivamente ao gerenciamento de routers MikroTik via RouterOS API.

## Responsabilidades

Este serviço é responsável por:
- ✅ Gerenciamento de rotas estáticas nos routers
- ✅ Monitoramento de routers (ping, conectividade)
- ✅ Sincronização de rotas entre banco de dados e RouterOS
- ✅ Comunicação via WebSocket para o frontend
- ✅ API REST para operações RouterOS
- ✅ Reaplicação automática de rotas com erro

## Separação de Responsabilidades

**IMPORTANTE**: Este serviço é separado do `vpnserver.io`:

- **routeros.io**: Tudo relacionado a routers MikroTik e RouterOS
- **vpnserver.io**: Tudo relacionado a VPNs, WireGuard e devices

## Instalação

```bash
# Criar ambiente virtual
python3 -m venv venv
source venv/bin/activate  # Linux/Mac
# ou
venv\Scripts\activate  # Windows

# Instalar dependências
pip install -r requirements.txt

# Configurar variáveis de ambiente
cp routeros.env.example routeros.env
# Editar routeros.env com suas configurações
```

## Configuração

Variáveis de ambiente principais:

- `API_C_SHARP_URL`: URL da API C# (ex: http://localhost:5000)
- `ROUTEROS_PORT`: Porta do WebSocket (padrão: 8765)
- `ROUTEROS_HTTP_PORT`: Porta HTTP para API REST (padrão: 8001)
- `MONITOR_INTERVAL_SECONDS`: Intervalo de monitoramento (padrão: 60)
- `SYNC_INTERVAL_SECONDS`: Intervalo de sincronização (padrão: 60)

## Execução

```bash
# Desenvolvimento
python main.py

# Produção (com uvicorn)
uvicorn main:app --host 0.0.0.0 --port 8001
```

## Deploy

Ver `deploy/` para scripts de instalação e configuração do serviço systemd.
