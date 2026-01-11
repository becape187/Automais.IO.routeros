# Migração do RouterOS Service

Este documento descreve a separação do serviço RouterOS do `vpnserver.io` para o novo `routeros.io`.

## Motivação

- **vpnserver.io**: Dedicado EXCLUSIVAMENTE a gestão de VPNs, devices e tudo relacionado ao WireGuard
- **routeros.io**: Dedicado EXCLUSIVAMENTE a gestão de routers MikroTik via RouterOS API

## Arquivos Movidos

### Arquivos Completos Movidos:
- `routeros_websocket.py` → `routeros.io/routeros_websocket.py`
- `deploy/routeros.service` → `routeros.io/deploy/routeros.service`
- `deploy/install-routeros-service.sh` → `routeros.io/deploy/install-routeros-service.sh`

### Arquivos Criados no routeros.io:
- `main.py` - API REST para RouterOS
- `config.py` - Configurações do serviço RouterOS
- `api_client.py` - Cliente HTTP para API C# (apenas funções RouterOS)
- `models.py` - Modelos Pydantic (apenas RouterOS)
- `monitor.py` - Sincronização de rotas RouterOS
- `requirements.txt` - Dependências Python
- `.gitignore` - Arquivos ignorados
- `README.md` - Documentação
- `routeros.env.example` - Exemplo de variáveis de ambiente

## Arquivos que Precisam ser Limpos no vpnserver.io

### main.py
- Remover endpoints RouterOS (linhas 466-624)
- Remover imports relacionados a RouterOS

### models.py
- Remover `AddRouteRequest` e `RemoveRouteRequest`

### api_client.py
- Remover funções RouterOS:
  - `get_router_from_api`
  - `get_router_static_routes_from_api`
  - `get_router_wireguard_peers_from_api` (ou manter se usado para VPN)
  - `update_router_password_in_api`

### monitor.py
- Remover funções de sincronização de rotas RouterOS:
  - `sync_routes_for_router`
  - `retry_failed_routes`
  - `sync_routes_for_all_routers`
  - `update_route_status_in_api`
  - `delete_route_from_api`
- Manter apenas monitoramento de peers WireGuard

### deploy/
- Remover `routeros.service` e `install-routeros-service.sh`

## Próximos Passos

1. ✅ Criar estrutura routeros.io
2. ✅ Mover arquivos RouterOS
3. ⏳ Limpar vpnserver.io
4. ⏳ Atualizar documentação
5. ⏳ Testar serviços separados
6. ⏳ Criar repositório Git separado
