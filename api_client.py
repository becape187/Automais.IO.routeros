"""
Cliente HTTP para comunicação com a API C# - RouterOS
Apenas funções relacionadas a routers e rotas RouterOS
"""
import os
import httpx
import logging
from typing import Optional, Dict, Any, List
from config import API_C_SHARP_URL

logger = logging.getLogger(__name__)


async def get_all_routers_from_api(server_endpoint: str = None) -> List[Dict[str, Any]]:
    """Busca routers da API C# baseado no ServerEndpoint
    
    Se server_endpoint for fornecido, busca routers associados a VpnNetworks
    com aquele ServerEndpoint (similar ao vpnserver.io).
    Se não fornecido, busca todos os routers (endpoint genérico).
    """
    try:
        verify_ssl = os.getenv("API_C_SHARP_VERIFY_SSL", "true").lower() == "true"
        async with httpx.AsyncClient(timeout=30.0, verify=verify_ssl) as client:
            if server_endpoint:
                # Buscar routers via endpoint do servidor (similar ao vpnserver.io)
                response = await client.get(
                    f"{API_C_SHARP_URL}/api/vpn/networks/{server_endpoint}/resources",
                    headers={"Accept": "application/json"}
                )
                
                if response.status_code == 200:
                    data = response.json()
                    routers = data.get("routers", [])
                    logger.debug(f"Encontrados {len(routers)} router(s) para endpoint '{server_endpoint}'")
                    return routers
                elif response.status_code == 404:
                    logger.warning(f"Nenhuma VpnNetwork encontrada com endpoint '{server_endpoint}' na API principal")
                    return []
                else:
                    logger.warning(f"Erro ao buscar routers para endpoint '{server_endpoint}': Status {response.status_code}")
                    return []
            else:
                # Fallback: buscar todos os routers (endpoint genérico)
                response = await client.get(
                    f"{API_C_SHARP_URL}/api/routers",
                    headers={"Accept": "application/json"}
                )
                
                if response.status_code == 200:
                    routers = response.json()
                    logger.debug(f"Encontrados {len(routers)} router(s) na API")
                    return routers
                elif response.status_code == 404:
                    logger.warning("Endpoint /api/routers não encontrado na API C#.")
                    return []
                else:
                    logger.warning(f"Erro ao buscar routers: Status {response.status_code}")
                    return []
    except httpx.RequestError as e:
        logger.error(f"Erro de conexão ao buscar routers da API: {e}")
        return []
    except Exception as e:
        logger.error(f"Erro ao buscar routers da API: {e}")
        return []


async def get_router_from_api(router_id: str) -> Optional[Dict[str, Any]]:
    """Busca dados completos de um Router da API C#"""
    try:
        verify_ssl = os.getenv("API_C_SHARP_VERIFY_SSL", "true").lower() == "true"
        async with httpx.AsyncClient(timeout=30.0, verify=verify_ssl) as client:
            response = await client.get(
                f"{API_C_SHARP_URL}/api/routers/{router_id}",
                headers={"Accept": "application/json"}
            )
            if response.status_code == 200:
                return response.json()
    except Exception as e:
        logger.error(f"Erro ao buscar Router {router_id}: {e}")
    return None


async def get_router_static_routes_from_api(router_id: str) -> List[Dict[str, Any]]:
    """Busca rotas estáticas de um router da API C#"""
    try:
        verify_ssl = os.getenv("API_C_SHARP_VERIFY_SSL", "true").lower() == "true"
        async with httpx.AsyncClient(timeout=30.0, verify=verify_ssl) as client:
            response = await client.get(
                f"{API_C_SHARP_URL}/api/routers/{router_id}/routes",
                headers={"Accept": "application/json"}
            )
            if response.status_code == 200:
                return response.json()
    except Exception as e:
        logger.error(f"Erro ao buscar rotas do router {router_id}: {e}")
    return []


async def get_router_wireguard_peers_from_api(router_id: str) -> List[Dict[str, Any]]:
    """Busca peers WireGuard de um router da API C# (para obter IP do router)"""
    try:
        verify_ssl = os.getenv("API_C_SHARP_VERIFY_SSL", "true").lower() == "true"
        async with httpx.AsyncClient(timeout=30.0, verify=verify_ssl) as client:
            response = await client.get(
                f"{API_C_SHARP_URL}/api/routers/{router_id}/wireguard/peers",
                headers={"Accept": "application/json"}
            )
            if response.status_code == 200:
                return response.json()
    except Exception as e:
        logger.error(f"Erro ao buscar peers do router {router_id}: {e}")
    return []


async def update_router_password_in_api(router_id: str, new_password: str) -> bool:
    """Atualiza a senha do router no banco de dados via API C#
    
    Atualiza:
    - RouterOsApiPassword -> NULL
    - AutomaisApiPassword -> nova senha forte
    """
    try:
        verify_ssl = os.getenv("API_C_SHARP_VERIFY_SSL", "true").lower() == "true"
        async with httpx.AsyncClient(timeout=30.0, verify=verify_ssl) as client:
            response = await client.put(
                f"{API_C_SHARP_URL}/api/routers/{router_id}/password",
                json={"password": new_password},
                headers={"Accept": "application/json", "Content-Type": "application/json"}
            )
            if response.status_code == 200:
                logger.info(f"Senha do router {router_id} atualizada no banco (RouterOsApiPassword=NULL, AutomaisApiPassword=nova senha)")
                return True
            else:
                logger.error(f"Erro ao atualizar senha do router {router_id}: Status {response.status_code}")
                return False
    except Exception as e:
        logger.error(f"Erro ao atualizar senha do router {router_id} no banco: {e}")
        return False


async def update_route_status_in_api(
    router_id: str,
    route_id: str,
    status: int,
    router_os_id: str = None,
    error_message: str = None
) -> bool:
    """Atualiza status de uma rota via API C#
    
    Status: 1=PendingAdd, 2=PendingRemove, 3=Applied, 4=Error
    """
    try:
        verify_ssl = os.getenv("API_C_SHARP_VERIFY_SSL", "true").lower() == "true"
        async with httpx.AsyncClient(timeout=30.0, verify=verify_ssl) as client:
            payload = {
                "routeId": route_id,
                "status": status
            }
            if router_os_id:
                payload["routerOsId"] = router_os_id
            if error_message:
                payload["errorMessage"] = error_message
                
            response = await client.post(
                f"{API_C_SHARP_URL}/api/routers/{router_id}/routes/update-status",
                json=payload,
                headers={"Accept": "application/json", "Content-Type": "application/json"}
            )
            
            return response.status_code in [200, 204]
    except Exception as e:
        logger.error(f"Erro ao atualizar status da rota {route_id} no banco: {e}")
        return False


async def delete_route_from_api(router_id: str, route_id: str) -> bool:
    """Deleta uma rota do banco via API C#"""
    try:
        verify_ssl = os.getenv("API_C_SHARP_VERIFY_SSL", "true").lower() == "true"
        async with httpx.AsyncClient(timeout=30.0, verify=verify_ssl) as client:
            response = await client.delete(
                f"{API_C_SHARP_URL}/api/routers/{router_id}/routes/{route_id}",
                headers={"Accept": "application/json"}
            )
            
            return response.status_code in [200, 204]
    except Exception as e:
        logger.error(f"Erro ao deletar rota {route_id} do banco: {e}")
        return False
