"""
Serviço RouterOS - Gerenciamento de Routers MikroTik
Serviço dedicado exclusivamente ao gerenciamento de routers via RouterOS API
"""
import asyncio
import logging
from contextlib import asynccontextmanager
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware

from config import HTTP_PORT, SYNC_INTERVAL_SECONDS, ROUTEROS_SERVER_ENDPOINT, PORT as WEBSOCKET_PORT
from models import AddRouteRequest, RemoveRouteRequest
from monitor import background_sync_loop
from routeros_websocket import (
    list_wireguard_interfaces,
    add_route_to_routeros,
    remove_route_from_routeros,
    get_router_password,
    start_websocket_server
)
from api_client import get_router_from_api, get_router_wireguard_peers_from_api

# Configurar logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Gerencia ciclo de vida da aplicação"""
    logger.info("🚀 Iniciando serviço RouterOS")
    
    # Iniciar servidor WebSocket em background
    logger.info(f"🌐 Iniciando servidor WebSocket na porta {WEBSOCKET_PORT}...")
    websocket_task = asyncio.create_task(start_websocket_server(host="0.0.0.0", port=WEBSOCKET_PORT))
    
    # Iniciar loop de sincronização em background
    sync_task = asyncio.create_task(background_sync_loop())
    
    yield
    
    # Cancelar tarefas
    sync_task.cancel()
    websocket_task.cancel()
    try:
        await sync_task
    except asyncio.CancelledError:
        pass
    try:
        await websocket_task
    except asyncio.CancelledError:
        pass
    logger.info("🛑 Serviço RouterOS encerrado")


app = FastAPI(
    title="RouterOS Service API",
    description="API para gerenciamento de routers MikroTik via RouterOS API",
    version="1.0.0",
    lifespan=lifespan
)

# CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.get("/health")
async def health():
    """Health check"""
    return {
        "status": "ok",
        "service": "routeros",
        "endpoint": ROUTEROS_SERVER_ENDPOINT or "Não configurado"
    }


@app.get(
    "/api/v1/routeros/{router_id}/wireguard-interfaces",
    tags=["RouterOS"],
    summary="Lista interfaces WireGuard do RouterOS",
    description="Lista todas as interfaces WireGuard do RouterOS, incluindo publickey para comparação."
)
async def list_wireguard_interfaces_endpoint(router_id: str):
    """
    Lista interfaces WireGuard do RouterOS
    
    - **router_id**: ID do router (UUID)
    """
    try:
        # Buscar router da API
        router = await get_router_from_api(router_id)
        if not router:
            raise HTTPException(status_code=404, detail="Router não encontrado")
        
        # Obter IP do router
        router_ip = router.get("routerOsApiUrl", "").replace("http://", "").replace("https://", "").split(":")[0]
        if not router_ip:
            # Tentar obter via peer WireGuard
            peers = await get_router_wireguard_peers_from_api(router_id)
            if peers:
                allowed_ips = peers[0].get("allowedIps", "")
                if allowed_ips:
                    router_ip = allowed_ips.split(",")[0].strip().split("/")[0]
        
        if not router_ip:
            raise HTTPException(status_code=400, detail="IP do router não encontrado")
        
        # Obter senha correta
        password = get_router_password(router)
        
        # Listar interfaces WireGuard
        interfaces = await list_wireguard_interfaces(
            router_id,
            router_ip,
            router.get("routerOsApiUsername", "admin"),
            password
        )
        
        return {
            "success": True,
            "interfaces": interfaces
        }
    except Exception as e:
        logger.error(f"Erro ao listar interfaces WireGuard: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.post(
    "/api/v1/routeros/add-route",
    tags=["RouterOS"],
    summary="Adiciona rota estática no RouterOS",
    description="Adiciona uma rota estática no RouterOS via API. A rota será marcada com comentário AUTOMAIS.IO."
)
async def add_route(request: AddRouteRequest):
    """
    Adiciona rota estática no RouterOS
    
    - **router_id**: ID do router (UUID)
    - **route_id**: ID da rota no banco (UUID)
    - **destination**: Destino da rota (ex: 0.0.0.0/0)
    - **gateway**: Gateway da rota (ex: 10.0.0.1)
    """
    # Log do conteúdo recebido no POST
    logger.info(f"📥 POST /api/v1/routeros/add-route recebido:")
    logger.info(f"   router_id: {request.router_id}")
    logger.info(f"   route_id: {request.route_id}")
    logger.info(f"   destination: {request.destination}")
    logger.info(f"   gateway: '{request.gateway}'")
    logger.info(f"   interface_name: '{request.interface_name}'")
    logger.info(f"   distance: {request.distance}")
    logger.info(f"   scope: {request.scope}")
    logger.info(f"   routing_table: '{request.routing_table}'")
    logger.info(f"   comment: '{request.comment}'")
    
    route_data = {
        "route_id": request.route_id,
        "destination": request.destination,
        "gateway": request.gateway,
        "interface_name": request.interface_name,
        "distance": request.distance,
        "scope": request.scope,
        "routing_table": request.routing_table,
        "comment": request.comment
    }
    
    result = await add_route_to_routeros(request.router_id, route_data)
    
    if result.get("success"):
        # Se RouterOS retornou um gateway usado (pode ser diferente do fornecido se gateway estava vazio)
        gateway_used = result.get("gateway_used")
        router_os_id = result.get("router_os_id")
        
        # Log da resposta que será enviada
        logger.info(f"📤 Resposta POST /api/v1/routeros/add-route:")
        logger.info(f"   success: {result.get('success')}")
        logger.info(f"   router_os_id: {router_os_id}")
        logger.info(f"   gateway_used: '{gateway_used or ''}'")
        
        # Retornar resposta com gateway_used - o controller C# fará a atualização no banco
        # Isso garante que o gateway seja sempre atualizado, mesmo se gateway_used for o nome da interface
        return {
            "success": True,
            "message": result.get("message"),
            "router_os_id": router_os_id,
            "gateway_used": gateway_used or ""  # Gateway realmente usado pelo RouterOS (pode ser IP ou nome de interface)
        }
    else:
        raise HTTPException(status_code=500, detail=result.get("error", "Erro desconhecido"))


@app.post(
    "/api/v1/routeros/remove-route",
    tags=["RouterOS"],
    summary="Remove rota estática do RouterOS",
    description="Remove uma rota estática do RouterOS via API."
)
async def remove_route(request: RemoveRouteRequest):
    """
    Remove rota estática do RouterOS
    
    - **router_id**: ID do router (UUID)
    - **router_os_route_id**: ID da rota no RouterOS
    """
    # Buscar router para obter credenciais
    router = await get_router_from_api(request.router_id)
    if not router:
        raise HTTPException(status_code=404, detail="Router não encontrado")
    
    # Obter IP do router
    router_ip = router.get("routerOsApiUrl", "").split(":")[0] if router.get("routerOsApiUrl") else None
    if not router_ip:
        # Tentar buscar do peer WireGuard
        peers = await get_router_wireguard_peers_from_api(request.router_id)
        if peers:
            allowed_ips = peers[0].get("allowedIps", "")
            if allowed_ips:
                router_ip = allowed_ips.split(",")[0].strip().split("/")[0]
    
    if not router_ip:
        raise HTTPException(status_code=400, detail="IP do router não encontrado")
    
    username = router.get("routerOsApiUsername", "admin")
    password = get_router_password(router)
    
    result = await remove_route_from_routeros(
        request.router_id,
        router_ip,
        username,
        password,
        request.router_os_route_id
    )
    
    if result.get("success"):
        return {
            "success": True,
            "message": result.get("message")
        }
    else:
        raise HTTPException(status_code=500, detail=result.get("error", "Erro desconhecido"))


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=HTTP_PORT)
