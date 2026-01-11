"""
Serviço de sincronização de rotas RouterOS
Sincroniza rotas entre banco de dados e RouterOS, e tenta reaplicar rotas com erro
"""
import asyncio
import os
import logging
from typing import Dict, Any, List
import httpx
from config import API_C_SHARP_URL, SYNC_INTERVAL_SECONDS, MONITOR_INTERVAL_SECONDS, ROUTEROS_SERVER_ENDPOINT
from api_client import (
    get_all_routers_from_api,
    get_router_static_routes_from_api,
    get_router_wireguard_peers_from_api,
    get_router_from_api,
    update_route_status_in_api,
    delete_route_from_api
)
from routeros_websocket import (
    get_router_connection,
    is_automais_route,
    extract_route_id_from_comment,
    add_route_to_routeros,
    remove_route_from_routeros,
    get_router_password
)

logger = logging.getLogger(__name__)


async def sync_routes_for_router(router: Dict[str, Any]) -> None:
    """Sincroniza rotas de um router: verifica se rotas Applied ainda existem no RouterOS e tenta reaplicar rotas com Error"""
    router_id = router.get("id")
    router_name = router.get("name", "Unknown")
    
    try:
        # Buscar todas as rotas do banco
        routes_db = await get_router_static_routes_from_api(router_id)
        
        # Rotas com status Applied (para verificar se ainda existem no RouterOS)
        routes_applied = [
            r for r in routes_db 
            if r.get("status") == "Applied" or r.get("status") == 3 or str(r.get("status")).lower() == "applied"
        ]
        
        # Rotas com status Error (para tentar reaplicar)
        routes_error = [
            r for r in routes_db 
            if r.get("status") == "Error" or r.get("status") == 4 or str(r.get("status")).lower() == "error"
        ]
        
        # Se não há rotas para processar, retornar
        if not routes_applied and not routes_error:
            return
        
        # Obter IP do router
        router_data = await get_router_from_api(router_id)
        if not router_data:
            return
        
        router_ip = router_data.get("routerOsApiUrl", "").split(":")[0] if router_data.get("routerOsApiUrl") else None
        if not router_ip:
            # Tentar buscar do peer WireGuard
            peers = await get_router_wireguard_peers_from_api(router_id)
            if peers:
                allowed_ips = peers[0].get("allowedIps", "")
                if allowed_ips:
                    router_ip = allowed_ips.split(",")[0].strip().split("/")[0]
        
        if not router_ip:
            logger.debug(f"Router {router_name} ({router_id}) não tem IP válido para sincronização de rotas")
            return
        
        # Conectar ao RouterOS
        password = get_router_password(router_data)
        api = await get_router_connection(
            router_id,
            router_ip,
            router_data.get("routerOsApiUsername", "admin"),
            password
        )
        
        if not api:
            logger.debug(f"Não foi possível conectar ao RouterOS para sincronizar rotas: {router_name} ({router_id})")
            return
        
        # Buscar rotas do RouterOS
        def get_routes_sync():
            route_resource = api.get_resource('/ip/route')
            return route_resource.get()
        
        loop = asyncio.get_event_loop()
        routes_routeros = await loop.run_in_executor(None, get_routes_sync)
        
        # Criar mapa de rotas RouterOS por ID (extraído do comment)
        routes_routeros_map = {}
        for route in routes_routeros:
            comment = route.get("comment", "")
            if is_automais_route(comment):
                route_id = extract_route_id_from_comment(comment)
                if route_id:
                    routes_routeros_map[route_id] = route
        
        # Verificar quais rotas Applied não existem mais no RouterOS
        routes_to_remove = []
        for route_db in routes_applied:
            route_id = route_db.get("id")
            if route_id and route_id not in routes_routeros_map:
                # Rota deveria existir mas não existe mais - marcar para remover
                routes_to_remove.append(route_id)
                logger.warning(
                    f"⚠️ Rota {route_id} (destino: {route_db.get('destination')}) "
                    f"deveria existir no RouterOS mas não foi encontrada. Removendo do banco."
                )
        
        # Remover rotas ausentes do banco via API C#
        for route_id in routes_to_remove:
            try:
                verify_ssl = os.getenv("API_C_SHARP_VERIFY_SSL", "true").lower() == "true"
                async with httpx.AsyncClient(timeout=30.0, verify=verify_ssl) as client:
                    response = await client.delete(
                        f"{API_C_SHARP_URL}/api/routers/{router_id}/routes/{route_id}",
                        headers={"Accept": "application/json"}
                    )
                    
                    if response.status_code in [200, 204]:
                        logger.info(f"✅ Rota {route_id} removida do banco (não existia no RouterOS)")
                    else:
                        logger.warning(f"⚠️ Erro ao remover rota {route_id} do banco: {response.status_code}")
            except Exception as e:
                logger.error(f"Erro ao remover rota {route_id} do banco: {e}")
        
        # Tentar reaplicar rotas com status Error
        if routes_error:
            logger.info(f"🔄 Tentando reaplicar {len(routes_error)} rota(s) com status Error do router {router_name}")
            await retry_failed_routes(router_id, router_name, router_ip, router_data, password, routes_error, routes_routeros_map)
        
    except Exception as e:
        logger.error(f"Erro ao sincronizar rotas do router {router_name} ({router_id}): {e}")


async def retry_failed_routes(
    router_id: str,
    router_name: str,
    router_ip: str,
    router_data: Dict[str, Any],
    password: str,
    routes_error: List[Dict[str, Any]],
    routes_routeros_map: Dict[str, Any]
) -> None:
    """Tenta reaplicar rotas com status Error
    
    Lógica:
    - Se RouterOsId está vazio/null → estava tentando adicionar
    - Se RouterOsId não está vazio → estava tentando remover
    """
    try:
        # Conectar ao RouterOS (se ainda não estiver conectado)
        api = await get_router_connection(
            router_id,
            router_ip,
            router_data.get("routerOsApiUsername", "admin"),
            password
        )
        
        if not api:
            logger.debug(f"Não foi possível conectar ao RouterOS para reaplicar rotas com erro: {router_name}")
            return
        
        for route_db in routes_error:
            route_id = route_db.get("id")
            router_os_id = route_db.get("routerOsId")
            destination = route_db.get("destination", "")
            
            try:
                # Determinar ação baseado no RouterOsId
                # Se RouterOsId está vazio → estava tentando adicionar
                # Se RouterOsId não está vazio → estava tentando remover
                if not router_os_id or router_os_id.strip() == "":
                    # Tentar adicionar novamente
                    logger.info(f"🔄 Tentando reaplicar adição da rota {route_id} (destino: {destination})")
                    
                    route_data = {
                        "route_id": route_id,
                        "destination": route_db.get("destination", ""),
                        "gateway": route_db.get("gateway", ""),
                        "interface_name": route_db.get("interface"),
                        "distance": route_db.get("distance"),
                        "scope": route_db.get("scope"),
                        "routing_table": route_db.get("routingTable"),
                        "router_ip": router_ip
                    }
                    
                    result = await add_route_to_routeros(router_id, route_data)
                    
                    if result.get("success"):
                        # Atualizar status para Applied via API
                        await update_route_status_in_api(
                            router_id,
                            route_id,
                            3,  # Applied
                            result.get("router_os_id")
                        )
                        logger.info(f"✅ Rota {route_id} reaplicada com sucesso (adicionada)")
                    else:
                        error_msg = result.get("error", "Erro desconhecido")
                        logger.warning(f"⚠️ Falha ao reaplicar rota {route_id}: {error_msg}")
                        # Manter status Error, mas atualizar mensagem
                        await update_route_status_in_api(
                            router_id,
                            route_id,
                            4,  # Error
                            None,
                            error_msg
                        )
                else:
                    # Tentar remover novamente
                    logger.info(f"🔄 Tentando reaplicar remoção da rota {route_id} (destino: {destination})")
                    
                    result = await remove_route_from_routeros(
                        router_id,
                        router_ip,
                        router_data.get("routerOsApiUsername", "admin"),
                        password,
                        router_os_id
                    )
                    
                    if result.get("success"):
                        # Deletar do banco via API
                        await delete_route_from_api(router_id, route_id)
                        logger.info(f"✅ Rota {route_id} reaplicada com sucesso (removida)")
                    else:
                        error_msg = result.get("error", "Erro desconhecido")
                        logger.warning(f"⚠️ Falha ao reaplicar remoção da rota {route_id}: {error_msg}")
                        # Manter status Error, mas atualizar mensagem
                        await update_route_status_in_api(
                            router_id,
                            route_id,
                            4,  # Error
                            router_os_id,
                            error_msg
                        )
                        
            except Exception as e:
                logger.error(f"Erro ao reaplicar rota {route_id}: {e}")
                # Manter status Error
                await update_route_status_in_api(
                    router_id,
                    route_id,
                    4,  # Error
                    router_os_id,
                    str(e)
                )
                
    except Exception as e:
        logger.error(f"Erro ao reaplicar rotas com erro do router {router_name}: {e}")


async def sync_routes_for_all_routers() -> None:
    """Sincroniza rotas de todos os routers baseado no ROUTEROS_SERVER_ENDPOINT"""
    try:
        if not ROUTEROS_SERVER_ENDPOINT:
            logger.warning("ROUTEROS_SERVER_ENDPOINT não configurado. Não é possível sincronizar recursos.")
            return
        
        routers = await get_all_routers_from_api(ROUTEROS_SERVER_ENDPOINT)
        
        if not routers:
            logger.debug(f"Nenhum router encontrado para endpoint '{ROUTEROS_SERVER_ENDPOINT}'")
            return
        
        logger.info(f"🔄 Sincronizando rotas de {len(routers)} router(s) para endpoint '{ROUTEROS_SERVER_ENDPOINT}'")
        
        # Sincronizar rotas de todos os routers em paralelo
        tasks = [sync_routes_for_router(router) for router in routers]
        await asyncio.gather(*tasks, return_exceptions=True)
        
    except Exception as e:
        logger.error(f"Erro ao sincronizar rotas: {e}")


async def background_sync_loop():
    """Loop em background para sincronizar rotas periodicamente"""
    logger.info(f"🔄 Iniciando loop de sincronização de rotas (intervalo: {SYNC_INTERVAL_SECONDS}s)")
    
    while True:
        try:
            await sync_routes_for_all_routers()
            await asyncio.sleep(SYNC_INTERVAL_SECONDS)
        except Exception as e:
            logger.error(f"Erro no loop de sincronização: {e}")
            await asyncio.sleep(SYNC_INTERVAL_SECONDS)
