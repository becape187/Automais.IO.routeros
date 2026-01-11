"""
Serviço WebSocket para gerenciamento RouterOS
Comunica com routers via RouterOS API e expõe via WebSocket para o frontend
"""
import asyncio
import json
import logging
import re
from typing import Dict, Any, Optional, List
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor

import websockets
from websockets.server import WebSocketServerProtocol
# Importação do routeros-api
# O pacote routeros-api versão 0.18.0 usa routeros_api.connect() ao invés de RouterOsApi()
import routeros_api
try:
    from routeros_api.exceptions import RouterOsApiConnectionError, RouterOsApiCommunicationError
except ImportError:
    # Se as exceções não existirem, criar classes vazias
    class RouterOsApiConnectionError(Exception):
        pass
    class RouterOsApiCommunicationError(Exception):
        pass

from api_client import (
    get_router_from_api,
    get_router_static_routes_from_api,
    get_router_wireguard_peers_from_api,
    update_router_password_in_api
)
from config import API_C_SHARP_URL
import secrets
import string

logger = logging.getLogger(__name__)

# Cache de conexões RouterOS (router_id -> routeros_api connection)
router_connections: Dict[str, 'routeros_api.Connection'] = {}

# Thread pool para executar operações RouterOS (não assíncrono)
executor = ThreadPoolExecutor(max_workers=10)

# Padrão para identificar rotas AUTOMAIS.IO
AUTOMAIS_ROUTE_PATTERN = re.compile(r'AUTOMAIS\.IO NÃO APAGAR:\s*([a-f0-9\-]{36})', re.IGNORECASE)


def is_automais_route(comment: Optional[str]) -> bool:
    """Verifica se uma rota foi criada pela plataforma AUTOMAIS.IO"""
    if not comment:
        return False
    return bool(AUTOMAIS_ROUTE_PATTERN.search(comment))


def extract_route_id_from_comment(comment: Optional[str]) -> Optional[str]:
    """Extrai o ID da rota do comentário AUTOMAIS.IO"""
    if not comment:
        return None
    match = AUTOMAIS_ROUTE_PATTERN.search(comment)
    return match.group(1) if match else None


def get_router_password(router: Dict[str, Any]) -> str:
    """Obtém a senha correta do router
    
    Lógica:
    - Se AutomaisApiPassword estiver disponível (não null e não vazio), usa ela
    - Senão, usa RouterOsApiPassword (senha original)
    
    Returns:
        Senha a ser usada para conectar ao RouterOS
    """
    router_id = router.get('id', 'unknown')
    
    # Priorizar AutomaisApiPassword se existir e não for vazio
    automais_password = router.get("automaisApiPassword")
    if automais_password and automais_password.strip():
        logger.debug(f"Usando AutomaisApiPassword para router {router_id}")
        return automais_password
    
    # Fallback para RouterOsApiPassword
    routeros_password = router.get("routerOsApiPassword") or ""
    if routeros_password and routeros_password.strip():
        logger.debug(f"Usando RouterOsApiPassword para router {router_id}")
        return routeros_password
    
    # Se ambos estão vazios/null, logar erro
    logger.error(f"⚠️ AMBAS as senhas estão vazias/null para router {router_id}!")
    logger.error(f"   AutomaisApiPassword: {'null' if automais_password is None else f'vazia (length={len(automais_password)})'}")
    logger.error(f"   RouterOsApiPassword: {'null' if routeros_password is None else f'vazia (length={len(routeros_password)})'}")
    return ""


def mask_password(password: str) -> str:
    """Mascara senha para logs (mostra primeiros 2 e últimos 2 caracteres)"""
    if not password or len(password) <= 4:
        return "***" if password else "(vazia)"
    return f"{password[:2]}...{password[-2:]}"


def generate_strong_password(length: int = 32) -> str:
    """Gera uma senha forte aleatória"""
    # Caracteres permitidos: letras maiúsculas, minúsculas, números e símbolos especiais
    alphabet = string.ascii_letters + string.digits + "!@#$%^&*()_+-=[]{}|;:,.<>?"
    # Garantir que tenha pelo menos um de cada tipo
    password = (
        secrets.choice(string.ascii_lowercase) +
        secrets.choice(string.ascii_uppercase) +
        secrets.choice(string.digits) +
        secrets.choice("!@#$%^&*()_+-=[]{}|;:,.<>?")
    )
    # Completar o resto da senha
    password += ''.join(secrets.choice(alphabet) for _ in range(length - 4))
    # Embaralhar os caracteres
    password_list = list(password)
    secrets.SystemRandom().shuffle(password_list)
    return ''.join(password_list)


def change_user_password_sync(api: 'routeros_api.Connection', username: str, new_password: str) -> bool:
    """Altera a senha do usuário no RouterOS (síncrono)"""
    try:
        # Buscar o usuário atual
        user_resource = api.get_resource('/user')
        users = user_resource.get(name=username)
        
        if not users:
            logger.warning(f"Usuário {username} não encontrado no RouterOS")
            return False
        
        user_id = users[0].get('id')
        if not user_id:
            logger.warning(f"ID do usuário {username} não encontrado")
            return False
        
        # Alterar senha usando /user/set
        user_resource.set(id=user_id, password=new_password)
        logger.info(f"Senha do usuário {username} alterada com sucesso no RouterOS")
        return True
    except Exception as e:
        logger.error(f"Erro ao alterar senha do usuário {username} no RouterOS: {e}")
        return False


def _get_router_connection_sync(router_id: str, router_ip: str, username: str, password: str, router_data: Optional[Dict[str, Any]] = None):
    """Obtém ou cria conexão RouterOS API (síncrono)
    
    Lógica de senha:
    - Se AutomaisApiPassword estiver nulo, tenta conectar com RouterOsApiPassword (senha original)
    - Se conseguir conectar, imediatamente altera a senha para uma senha forte
    - Atualiza RouterOsApiPassword para NULL e AutomaisApiPassword com a nova senha
    
    Args:
        router_id: ID do router
        router_ip: IP do router
        username: Usuário da API RouterOS
        password: Senha da API RouterOS (pode ser RouterOsApiPassword ou AutomaisApiPassword)
        router_data: Dados do router (opcional, para evitar buscar novamente)
    """
    try:
        # Log das credenciais que serão usadas
        password_type = "RouterOsApiPassword" if (router_data and not router_data.get("automaisApiPassword")) else "AutomaisApiPassword"
        logger.info(f"🔐 Tentando conectar RouterOS - Router: {router_id}, IP: {router_ip}, User: '{username}', Password: {mask_password(password)} (tipo: {password_type})")
        
        # Verificar se já existe conexão em cache
        if router_id in router_connections:
            try:
                # Testar conexão existente
                test_api = router_connections[router_id]
                test_resource = test_api.get_resource('/system/identity')
                identity = test_resource.get()
                logger.debug(f"✅ Usando conexão em cache para router {router_id} (identity: {identity})")
                return router_connections[router_id]
            except Exception as cache_error:
                # Conexão inválida, remover do cache
                logger.debug(f"⚠️ Conexão em cache inválida para router {router_id}, removendo do cache. Erro: {cache_error}")
                del router_connections[router_id]
        
        # Criar nova conexão usando routeros_api.connect()
        logger.debug(f"🔌 Criando nova conexão RouterOS para {router_ip} com usuário '{username}'")
        logger.debug(f"   Detalhes da senha: length={len(password) if password else 0}, tipo={type(password)}, primeiro_char={ord(password[0]) if password and len(password) > 0 else 'N/A'}, último_char={ord(password[-1]) if password and len(password) > 0 else 'N/A'}")
        
        try:
            # RouterOS 6.43+ requer plaintext_login=True
            # Tentar primeiro com plaintext_login (método moderno)
            try:
                api = routeros_api.connect(router_ip, username=username, password=password, plaintext_login=True)
                logger.info(f"✅ Conexão RouterOS estabelecida com sucesso (plaintext_login) para {router_ip} (usuário: {username})")
            except TypeError:
                # Se plaintext_login não for suportado na função connect(), tentar sem
                logger.debug(f"⚠️ plaintext_login não suportado em connect(), tentando método alternativo...")
                # Tentar usar RouterOsApiPool como alternativa
                pool = routeros_api.RouterOsApiPool(router_ip, username=username, password=password, plaintext_login=True)
                api = pool.get_api()
                logger.info(f"✅ Conexão RouterOS estabelecida com sucesso (via RouterOsApiPool) para {router_ip} (usuário: {username})")
            except Exception as e:
                # Se falhar, tentar sem plaintext_login (para RouterOS antigo)
                logger.debug(f"⚠️ Falha com plaintext_login, tentando método antigo (MD5)...")
                api = routeros_api.connect(router_ip, username=username, password=password)
                logger.info(f"✅ Conexão RouterOS estabelecida com sucesso (método antigo) para {router_ip} (usuário: {username})")
            
            # Testar a conexão imediatamente
            try:
                test_resource = api.get_resource('/system/identity')
                identity_result = test_resource.get()
                logger.debug(f"✅ Teste de conexão bem-sucedido: {identity_result}")
            except Exception as test_error:
                logger.warning(f"⚠️ Conexão estabelecida mas teste falhou: {test_error}")
                # Não falhar ainda, pode ser um problema temporário
                
        except RouterOsApiConnectionError as e:
            logger.error(f"❌ Erro de conexão RouterOS para {router_ip}: {e}")
            logger.error(f"   Detalhes: IP={router_ip}, User='{username}', Password length={len(password) if password else 0}")
            logger.error(f"   Tipo de exceção: RouterOsApiConnectionError")
            raise
        except RouterOsApiCommunicationError as e:
            error_str = str(e).lower()
            logger.error(f"❌ Erro de comunicação RouterOS para {router_ip}: {e}")
            logger.error(f"   Detalhes: IP={router_ip}, User='{username}', Password length={len(password) if password else 0}")
            logger.error(f"   Tipo de exceção: RouterOsApiCommunicationError")
            # Verificar se o erro é de autenticação
            if "invalid user" in error_str or "password" in error_str or "(6)" in error_str:
                logger.error(f"   ⚠️ Erro de autenticação detectado. Verifique:")
                logger.error(f"      - Usuário '{username}' existe no RouterOS?")
                logger.error(f"      - Senha está correta? (tipo: {password_type})")
                logger.error(f"      - Senha (primeiros 10): {password[:10] if password and len(password) >= 10 else password}")
                logger.error(f"      - Senha (últimos 5): {password[-5:] if password and len(password) >= 5 else ''}")
                logger.error(f"      - Senha contém caracteres especiais? Verifique encoding.")
            raise
        except Exception as e:
            error_str = str(e).lower()
            logger.error(f"❌ Erro inesperado ao conectar RouterOS para {router_ip}: {type(e).__name__}: {e}")
            logger.error(f"   Detalhes: IP={router_ip}, User='{username}', Password length={len(password) if password else 0}")
            logger.error(f"   Tipo de exceção: {type(e).__name__}")
            # Verificar se o erro é de autenticação mesmo sendo uma exceção genérica
            if "invalid user" in error_str or "password" in error_str or "(6)" in error_str:
                logger.error(f"   ⚠️ Erro de autenticação detectado em exceção genérica:")
                logger.error(f"      - Usuário '{username}' existe no RouterOS?")
                logger.error(f"      - Senha está correta? (tipo: {password_type})")
                logger.error(f"      - Senha (primeiros 10): {password[:10] if password and len(password) >= 10 else password}")
                logger.error(f"      - Senha (últimos 5): {password[-5:] if password and len(password) >= 5 else ''}")
            raise
        
        # Se AutomaisApiPassword estiver nulo, significa que ainda não foi trocada
        # Se conseguir conectar com RouterOsApiPassword, alterar imediatamente
        if router_data and not router_data.get("automaisApiPassword"):
            try:
                logger.info(f"Primeira conexão detectada para router {router_id} (AutomaisApiPassword nulo). Alterando senha para senha forte...")
                
                # Gerar senha forte
                new_password = generate_strong_password(32)
                
                # Alterar senha no RouterOS
                if change_user_password_sync(api, username, new_password):
                    # Fechar conexão antiga
                    try:
                        api.disconnect()
                    except:
                        pass
                    
                    # Reconectar com nova senha (usar plaintext_login para RouterOS 6.43+)
                    try:
                        api = routeros_api.connect(router_ip, username=username, password=new_password, plaintext_login=True)
                    except TypeError:
                        # Se plaintext_login não for suportado, usar RouterOsApiPool
                        pool = routeros_api.RouterOsApiPool(router_ip, username=username, password=new_password, plaintext_login=True)
                        api = pool.get_api()
                    
                    # Armazenar temporariamente para atualização assíncrona no banco
                    # RouterOsApiPassword -> NULL, AutomaisApiPassword -> nova senha
                    api._new_password = new_password
                    api._router_id = router_id
                    api._should_update_password = True
                    logger.info(f"✅ Senha do router {router_id} alterada com sucesso no RouterOS")
                else:
                    logger.warning(f"⚠️ Falhou ao alterar senha no RouterOS para router {router_id}")
            except Exception as e:
                logger.error(f"Erro ao alterar senha na primeira conexão para router {router_id}: {e}")
                # Continuar mesmo se falhar a alteração de senha
        
        # Testar conexão fazendo uma operação simples (mas não falhar se der erro)
        try:
            test_resource = api.get_resource('/system/identity')
            identity = test_resource.get()
            logger.info(f"✅ Teste de conexão bem-sucedido: {identity}")
        except Exception as test_error:
            error_str = str(test_error).lower()
            # Se for erro de autenticação, realmente falhar
            if "invalid user" in error_str or "password" in error_str or "(6)" in error_str:
                logger.error(f"❌ Erro de autenticação no teste de conexão: {test_error}")
                logger.error(f"   A conexão foi estabelecida mas a autenticação falhou ao executar comando")
                try:
                    api.disconnect()
                except:
                    pass
                raise Exception(f"Erro de autenticação ao testar conexão: {test_error}")
            else:
                # Outros erros podem ser temporários, apenas avisar
                logger.warning(f"⚠️ Conexão estabelecida mas teste falhou (não crítico): {test_error}")
                logger.warning(f"   Continuando mesmo assim - pode ser um problema temporário")
        
        router_connections[router_id] = api
        logger.info(f"✅ Conexão RouterOS estabelecida: {router_id} -> {router_ip}")
        return api
    except RouterOsApiConnectionError as e:
        logger.error(f"❌ Erro de conexão RouterOS {router_id} ({router_ip}): {e}")
        logger.error(f"   Verifique se o RouterOS está acessível em {router_ip}")
        return None
    except RouterOsApiCommunicationError as e:
        error_str = str(e).lower()
        if "invalid user" in error_str or "password" in error_str or "(6)" in error_str:
            logger.error(f"❌ Erro de autenticação RouterOS {router_id} ({router_ip}): {e}")
            logger.error(f"   Usuário: '{username}'")
            logger.error(f"   Tipo de senha: {password_type}")
            logger.error(f"   Senha (mascarada): {mask_password(password)}")
            logger.error(f"   Comprimento da senha: {len(password) if password else 0} caracteres")
        else:
            logger.error(f"❌ Erro de comunicação RouterOS {router_id} ({router_ip}): {e}")
        return None
    except Exception as e:
        logger.error(f"❌ Erro inesperado ao conectar RouterOS {router_id} ({router_ip}): {type(e).__name__}: {e}")
        logger.error(f"   Traceback completo será logado abaixo")
        import traceback
        logger.error(traceback.format_exc())
        return None


async def get_router_connection(router_id: str, router_ip: str, username: str, password: str, check_password_change: bool = True):
    """Obtém ou cria conexão RouterOS API (assíncrono wrapper)
    
    Lógica:
    - Se AutomaisApiPassword estiver nulo, usa RouterOsApiPassword para conectar
    - Se conseguir conectar, altera senha e atualiza banco
    
    Args:
        router_id: ID do router
        router_ip: IP do router
        username: Usuário da API RouterOS
        password: Senha da API RouterOS (pode ser RouterOsApiPassword ou AutomaisApiPassword)
        check_password_change: Se True, verifica e altera senha na primeira conexão
    """
    router_data = None
    password_to_use = password
    
    if check_password_change:
        # Buscar dados do router para verificar qual senha usar
        router_data = await get_router_from_api(router_id)
        
        # Se AutomaisApiPassword estiver nulo, usar RouterOsApiPassword (senha original)
        if router_data and not router_data.get("automaisApiPassword"):
            password_to_use = router_data.get("routerOsApiPassword", password)
            logger.info(f"AutomaisApiPassword nulo para router {router_id}. Usando RouterOsApiPassword para conectar.")
            logger.info(f"🔐 Credenciais RouterOS - Router: {router_id}, IP: {router_ip}, User: {username}, Password: {mask_password(password_to_use)}")
        else:
            logger.info(f"🔐 Credenciais RouterOS - Router: {router_id}, IP: {router_ip}, User: {username}, Password: {mask_password(password_to_use)} (AutomaisApiPassword)")
    else:
        logger.info(f"🔐 Credenciais RouterOS - Router: {router_id}, IP: {router_ip}, User: {username}, Password: {mask_password(password_to_use)}")
    
    loop = asyncio.get_event_loop()
    api = await loop.run_in_executor(executor, _get_router_connection_sync, router_id, router_ip, username, password_to_use, router_data)
    
    # Se a senha foi alterada, atualizar no banco de dados de forma assíncrona
    # RouterOsApiPassword -> NULL, AutomaisApiPassword -> nova senha
    if api and hasattr(api, '_should_update_password') and api._should_update_password:
        new_password = api._new_password
        router_id_to_update = api._router_id
        # Remover atributos temporários
        delattr(api, '_new_password')
        delattr(api, '_router_id')
        delattr(api, '_should_update_password')
        
        # Atualizar senha no banco de forma assíncrona (não bloquear)
        try:
            success = await update_router_password_in_api(router_id_to_update, new_password)
            if success:
                logger.info(f"✅ Senha do router {router_id_to_update} atualizada no banco (RouterOsApiPassword=NULL, AutomaisApiPassword=nova senha)")
            else:
                logger.error(f"⚠️ Falhou ao atualizar senha no banco para router {router_id_to_update}")
        except Exception as e:
            logger.error(f"Erro ao atualizar senha no banco para router {router_id_to_update}: {e}")
    
    return api


async def add_route_to_routeros(router_id: str, route_data: Dict[str, Any]) -> Dict[str, Any]:
    """Adiciona rota estática no RouterOS (função reutilizável para HTTP e WebSocket)"""
    try:
        # Buscar router da API
        router = await get_router_from_api(router_id)
        if not router:
            return {"success": False, "error": "Router não encontrado"}
        
        # Buscar rotas do banco para obter o Comment
        routes = await get_router_static_routes_from_api(router_id)
        route_db = next((r for r in routes if r.get("id") == route_data.get("route_id")), None)
        
        if not route_db:
            return {"success": False, "error": "Rota não encontrada no banco de dados"}
        
        # Obter IP do router via peer WireGuard
        router_ip = route_data.get("router_ip")
        if not router_ip:
            peers = await get_router_wireguard_peers_from_api(router_id)
            if peers:
                allowed_ips = peers[0].get("allowedIps", "")
                if allowed_ips:
                    router_ip = allowed_ips.split(",")[0].strip().split("/")[0]
        
        if not router_ip:
            return {"success": False, "error": "IP do router não encontrado. Configure RouterOsApiUrl ou crie um peer WireGuard."}
        
        # Conectar ao RouterOS (get_router_connection busca o router da API e usa a senha correta)
        # Passar senha vazia aqui, pois get_router_connection vai buscar o router completo da API
        api = await get_router_connection(
            router_id,
            router_ip,
            router.get("routerOsApiUsername", "admin"),
            ""  # get_router_connection busca o router da API e usa get_router_password internamente
        )
        
        if not api:
            return {"success": False, "error": "Não foi possível conectar ao RouterOS"}
        
        # Adicionar rota com comentário AUTOMAIS.IO (executar em thread)
        comment = route_db.get("comment", f"AUTOMAIS.IO NÃO APAGAR: {route_data.get('route_id')}")
        
        def add_route_sync():
            route_resource = api.get_resource('/ip/route')
            route_params = {
                "dst-address": route_data["destination"],  # Corrigido: RouterOS usa dst-address, não dst
                "gateway": route_data["gateway"],
                "comment": comment
            }
            
            if route_data.get("interface_name"):
                route_params["interface"] = route_data["interface_name"]
            if route_data.get("distance"):
                route_params["distance"] = str(route_data["distance"])
            if route_data.get("scope"):
                route_params["scope"] = str(route_data["scope"])
            if route_data.get("routing_table"):
                route_params["routing-table"] = route_data["routing_table"]
            
            result = route_resource.add(**route_params)
            return result.get("ret")
        
        loop = asyncio.get_event_loop()
        route_id_routeros = await loop.run_in_executor(executor, add_route_sync)
        
        return {
            "success": True,
            "message": "Rota adicionada com sucesso",
            "router_os_id": route_id_routeros
        }
        
    except Exception as e:
        logger.error(f"Erro ao adicionar rota: {e}")
        return {"success": False, "error": str(e)}


async def remove_route_from_routeros(router_id: str, router_ip: str, username: str, password: str, router_os_route_id: str) -> Dict[str, Any]:
    """Remove rota do RouterOS (função reutilizável para HTTP e WebSocket)"""
    try:
        api = await get_router_connection(router_id, router_ip, username, password)
        if not api:
            return {"success": False, "error": "Não foi possível conectar ao RouterOS"}
        
        def remove_route_sync():
            route_resource = api.get_resource('/ip/route')
            route_resource.remove(id=router_os_route_id)
        
        loop = asyncio.get_event_loop()
        await loop.run_in_executor(executor, remove_route_sync)
        
        return {
            "success": True,
            "message": "Rota removida com sucesso"
        }
        
    except Exception as e:
        logger.error(f"Erro ao remover rota: {e}")
        return {"success": False, "error": str(e)}


async def handle_add_route(router_id: str, route_data: Dict[str, Any], ws: WebSocketServerProtocol):
    """Adiciona rota estática no RouterOS"""
    try:
        # Buscar router da API
        router = await get_router_from_api(router_id)
        if not router:
            await ws.send(json.dumps({"error": "Router não encontrado"}))
            return
        
        # Buscar rotas do banco para obter o Comment
        routes = await get_router_static_routes_from_api(router_id)
        route_db = next((r for r in routes if r.get("id") == route_data.get("id")), None)
        
        if not route_db:
            await ws.send(json.dumps({"error": "Rota não encontrada no banco de dados"}))
            return
        
        # Obter IP do router via peer WireGuard
        router_ip = route_data.get("router_ip")
        if not router_ip:
            # Buscar do peer WireGuard
            peers = await get_router_wireguard_peers_from_api(router_id)
            if peers:
                allowed_ips = peers[0].get("allowedIps", "")
                if allowed_ips:
                    router_ip = allowed_ips.split(",")[0].strip().split("/")[0]
        
        if not router_ip:
            await ws.send(json.dumps({"error": "IP do router não encontrado. Configure RouterOsApiUrl ou crie um peer WireGuard."}))
            return
        
        # Conectar ao RouterOS
        # Usar função auxiliar para obter senha correta (AutomaisApiPassword ou RouterOsApiPassword)
        password = get_router_password(router)
        api = await get_router_connection(
            router_id,
            router_ip,
            router.get("routerOsApiUsername", "admin"),
            password
        )
        
        if not api:
            await ws.send(json.dumps({"error": "Não foi possível conectar ao RouterOS"}))
            return
        
        # Adicionar rota com comentário AUTOMAIS.IO (executar em thread)
        comment = route_db.get("comment", f"AUTOMAIS.IO NÃO APAGAR: {route_db.get('id')}")
        
        def add_route_sync():
            route_resource = api.get_resource('/ip/route')
            route_params = {
                "dst-address": route_data["destination"],  # Corrigido: RouterOS usa dst-address, não dst
                "gateway": route_data["gateway"],
                "comment": comment
            }
            
            if route_data.get("interface"):
                route_params["interface"] = route_data["interface"]
            if route_data.get("distance"):
                route_params["distance"] = str(route_data["distance"])
            if route_data.get("scope"):
                route_params["scope"] = str(route_data["scope"])
            if route_data.get("routingTable"):
                route_params["routing-table"] = route_data["routingTable"]
            
            result = route_resource.add(**route_params)
            return result.get("ret")
        
        loop = asyncio.get_event_loop()
        route_id_routeros = await loop.run_in_executor(executor, add_route_sync)
        
        await ws.send(json.dumps({
            "success": True,
            "message": "Rota adicionada com sucesso",
            "router_os_id": route_id_routeros
        }))
        
    except Exception as e:
        logger.error(f"Erro ao adicionar rota: {e}")
        await ws.send(json.dumps({"error": str(e)}))


async def list_wireguard_interfaces(router_id: str, router_ip: str, username: str, password: str) -> List[Dict[str, Any]]:
    """Lista interfaces WireGuard do RouterOS e retorna com publickey para comparação"""
    try:
        # Buscar router da API
        router = await get_router_from_api(router_id)
        if not router:
            raise ValueError("Router não encontrado")
        
        # Conectar ao RouterOS
        api = await get_router_connection(
            router_id,
            router_ip,
            username,
            password
        )
        
        if not api:
            raise ValueError("Não foi possível conectar ao RouterOS")
        
        def list_interfaces_sync():
            """Lista interfaces WireGuard do RouterOS (síncrono)"""
            interface_resource = api.get_resource('/interface/wireguard')
            interfaces = interface_resource.get()
            
            # Todas as interfaces retornadas já são WireGuard
            wireguard_interfaces = []
            for iface in interfaces:
                wireguard_interfaces.append({
                    'name': iface.get('name', ''),
                    'public-key': iface.get('public-key', ''),
                    'listen-port': iface.get('listen-port', ''),
                    'mtu': iface.get('mtu', ''),
                    'disabled': iface.get('disabled', 'false'),
                    'running': iface.get('running', 'false')
                })
            
            return wireguard_interfaces
        
        loop = asyncio.get_event_loop()
        interfaces = await loop.run_in_executor(executor, list_interfaces_sync)
        
        return interfaces
        
    except Exception as e:
        logger.error(f"Erro ao listar interfaces WireGuard: {e}")
        raise


async def handle_list_routes(router_id: str, router_ip: str, username: str, password: str, ws: WebSocketServerProtocol):
    """Lista rotas do RouterOS, identificando quais são AUTOMAIS.IO"""
    try:
        api = await get_router_connection(router_id, router_ip, username, password)
        if not api:
            await ws.send(json.dumps({"error": "Não foi possível conectar ao RouterOS"}))
            return
        
        def get_routes_sync():
            route_resource = api.get_resource('/ip/route')
            return route_resource.get()
        
        loop = asyncio.get_event_loop()
        routes = await loop.run_in_executor(executor, get_routes_sync)
        
        # Buscar rotas do banco para mapear
        routes_db = await get_router_static_routes_from_api(router_id)
        routes_db_map = {r.get("id"): r for r in routes_db}
        
        # Processar rotas e identificar AUTOMAIS.IO
        processed_routes = []
        for route in routes:
            comment = route.get("comment", "")
            is_automais = is_automais_route(comment)
            route_id = extract_route_id_from_comment(comment)
            
            route_data = {
                "id": route.get(".id"),
                "dst": route.get("dst", ""),
                "gateway": route.get("gateway", ""),
                "interface": route.get("interface", ""),
                "distance": route.get("distance", ""),
                "scope": route.get("scope", ""),
                "routing-table": route.get("routing-table", ""),
                "comment": comment,
                "is_automais": is_automais,
                "route_id": route_id,
                "active": route.get("active", "false") == "true",
                "disabled": route.get("disabled", "false") == "true"
            }
            
            # Adicionar dados do banco se for rota AUTOMAIS.IO
            if is_automais and route_id and route_id in routes_db_map:
                route_data["db_data"] = routes_db_map[route_id]
            
            processed_routes.append(route_data)
        
        await ws.send(json.dumps({
            "success": True,
            "routes": processed_routes
        }))
        
    except Exception as e:
        logger.error(f"Erro ao listar rotas: {e}")
        await ws.send(json.dumps({"error": str(e)}))


async def handle_delete_route(router_id: str, router_ip: str, username: str, password: str, route_routeros_id: str, ws: WebSocketServerProtocol):
    """Remove rota do RouterOS"""
    try:
        api = await get_router_connection(router_id, router_ip, username, password)
        if not api:
            await ws.send(json.dumps({"error": "Não foi possível conectar ao RouterOS"}))
            return
        
        def remove_route_sync():
            route_resource = api.get_resource('/ip/route')
            route_resource.remove(id=route_routeros_id)
        
        loop = asyncio.get_event_loop()
        await loop.run_in_executor(executor, remove_route_sync)
        
        await ws.send(json.dumps({
            "success": True,
            "message": "Rota removida com sucesso"
        }))
        
    except Exception as e:
        logger.error(f"Erro ao remover rota: {e}")
        await ws.send(json.dumps({"error": str(e)}))


async def handle_get_status(router_id: str, router_ip: str, username: str, password: str, ws: WebSocketServerProtocol, request_id: str = None):
    """Verifica status da conexão RouterOS"""
    try:
        api = await get_router_connection(router_id, router_ip, username, password)
        if not api:
            response = {
                "success": False,
                "connected": False,
                "error": "Não foi possível conectar ao RouterOS"
            }
            if request_id:
                response["id"] = request_id
            await ws.send(json.dumps(response))
            return
        
        # Testar conexão obtendo informações básicas do sistema
        def get_status_sync():
            try:
                identity_resource = api.get_resource('/system/identity')
                identity = identity_resource.get()
                
                resource_resource = api.get_resource('/system/resource')
                resource = resource_resource.get()
                
                return {
                    "connected": True,
                    "identity": identity[0] if identity else None,
                    "resource": resource[0] if resource else None,
                    "router_ip": router_ip
                }
            except Exception as e:
                return {
                    "connected": False,
                    "error": str(e)
                }
        
        loop = asyncio.get_event_loop()
        status = await loop.run_in_executor(executor, get_status_sync)
        
        response = {
            "success": status.get("connected", False),
            **status
        }
        if request_id:
            response["id"] = request_id
        
        await ws.send(json.dumps(response))
        
    except Exception as e:
        logger.error(f"Erro ao verificar status: {e}")
        await ws.send(json.dumps({
            "success": False,
            "connected": False,
            "error": str(e)
        }))


async def handle_execute_command(router_id: str, router_ip: str, username: str, password: str, command: str, ws: WebSocketServerProtocol, request_id: str = None):
    """Executa comando RouterOS genérico"""
    try:
        api = await get_router_connection(router_id, router_ip, username, password)
        if not api:
            await ws.send(json.dumps({"success": False, "error": "Não foi possível conectar ao RouterOS"}))
            return
        
        # Parse do comando RouterOS
        # Exemplos:
        #   /ip/firewall/filter/print
        #   /ip/firewall/filter/enable .id=*
        #   /ip/firewall/filter/disable .id=*
        #   /ip/firewall/filter/remove .id=*
        #   /ip/route/print
        #   /interface/print
        
        command = command.strip()
        parts = command.split()
        
        if not parts or not parts[0].startswith("/"):
            await ws.send(json.dumps({"success": False, "error": "Comando inválido. Deve começar com /"}))
            return
        
        # Extrair caminho do recurso e ação
        path_parts = parts[0].split("/")
        if len(path_parts) < 3:
            await ws.send(json.dumps({"success": False, "error": "Comando inválido. Formato: /categoria/recurso/acao"}))
            return
        
        resource_path = "/" + "/".join(path_parts[1:-1])
        action = path_parts[-1]
        
        # Parsear parâmetros (ex: .id=*, .id=123, etc)
        params = {}
        for part in parts[1:]:
            if "=" in part:
                key, value = part.split("=", 1)
                params[key] = value
        
        def execute_command_sync():
            resource = api.get_resource(resource_path)
            
            if action == "print":
                return resource.get()
            elif action == "enable":
                if ".id" not in params:
                    raise ValueError("Parâmetro .id é obrigatório para enable")
                return resource.set(id=params[".id"], disabled="false")
            elif action == "disable":
                if ".id" not in params:
                    raise ValueError("Parâmetro .id é obrigatório para disable")
                return resource.set(id=params[".id"], disabled="true")
            elif action == "remove":
                if ".id" not in params:
                    raise ValueError("Parâmetro .id é obrigatório para remove")
                return resource.remove(id=params[".id"])
            elif action == "add":
                # Remover .id se existir (não é usado em add)
                add_params = {k: v for k, v in params.items() if k != ".id"}
                return resource.add(**add_params)
            elif action == "set":
                if ".id" not in params:
                    raise ValueError("Parâmetro .id é obrigatório para set")
                set_params = {k: v for k, v in params.items() if k != ".id"}
                return resource.set(id=params[".id"], **set_params)
            else:
                raise ValueError(f"Ação '{action}' não suportada. Ações suportadas: print, enable, disable, remove, add, set")
        
        loop = asyncio.get_event_loop()
        result = await loop.run_in_executor(executor, execute_command_sync)
        
        # Incluir ID da requisição se fornecido
        response = {"success": True, "data": result}
        if request_id:
            response["id"] = request_id
        
        await ws.send(json.dumps(response))
        
    except Exception as e:
        logger.error(f"Erro ao executar comando: {e}")
        error_response = {"success": False, "error": str(e)}
        if request_id:
            error_response["id"] = request_id
        await ws.send(json.dumps(error_response))


async def handle_websocket(ws: WebSocketServerProtocol, path: str):
    """Handler principal do WebSocket"""
    logger.info(f"Nova conexão WebSocket: {ws.remote_address}")
    
    try:
        async for message in ws:
            try:
                data = json.loads(message)
                action = data.get("action")
                router_id = data.get("router_id")
                
                if not action or not router_id:
                    await ws.send(json.dumps({"error": "action e router_id são obrigatórios"}))
                    continue
                
                # Buscar router da API
                router = await get_router_from_api(router_id)
                if not router:
                    await ws.send(json.dumps({"error": "Router não encontrado"}))
                    continue
                
                # Obter IP do router (via peer WireGuard ou RouterOsApiUrl)
                router_ip = data.get("router_ip")
                if not router_ip:
                    # Tentar extrair do RouterOsApiUrl
                    router_ip = router.get("routerOsApiUrl", "").split(":")[0] if router.get("routerOsApiUrl") else None
                
                # Se ainda não tem IP, buscar do peer WireGuard
                if not router_ip:
                    peers = await get_router_wireguard_peers_from_api(router_id)
                    if peers:
                        # Extrair IP do primeiro peer (formato: "10.222.111.2/32" -> "10.222.111.2")
                        allowed_ips = peers[0].get("allowedIps", "")
                        if allowed_ips:
                            router_ip = allowed_ips.split(",")[0].strip().split("/")[0]
                
                if not router_ip:
                    await ws.send(json.dumps({"error": "IP do router não encontrado. Configure RouterOsApiUrl ou crie um peer WireGuard."}))
                    continue
                
                username = router.get("routerOsApiUsername", "admin")
                # Usar função auxiliar para obter senha correta (AutomaisApiPassword ou RouterOsApiPassword)
                password = get_router_password(router)
                
                # Roteamento de ações
                if action == "add_route":
                    await handle_add_route(router_id, data.get("route_data", {}), ws)
                elif action == "list_routes":
                    await handle_list_routes(router_id, router_ip, username, password, ws)
                elif action == "delete_route":
                    await handle_delete_route(router_id, router_ip, username, password, data.get("route_routeros_id"), ws)
                elif action == "get_status":
                    await handle_get_status(router_id, router_ip, username, password, ws, data.get("id"))
                elif action == "execute_command":
                    await handle_execute_command(router_id, router_ip, username, password, data.get("command", ""), ws, data.get("id"))
                else:
                    await ws.send(json.dumps({"error": f"Ação '{action}' não reconhecida"}))
                    
            except json.JSONDecodeError:
                await ws.send(json.dumps({"error": "JSON inválido"}))
            except Exception as e:
                logger.error(f"Erro ao processar mensagem: {e}")
                await ws.send(json.dumps({"error": str(e)}))
                
    except websockets.exceptions.ConnectionClosed:
        logger.info(f"Conexão WebSocket fechada: {ws.remote_address}")
    except Exception as e:
        logger.error(f"Erro na conexão WebSocket: {e}")


async def start_websocket_server(host: str = "0.0.0.0", port: int = 8765):
    """Inicia servidor WebSocket"""
    logger.info(f"🚀 Iniciando servidor WebSocket RouterOS em ws://{host}:{port}")
    
    async with websockets.serve(handle_websocket, host, port):
        await asyncio.Future()  # Rodar indefinidamente


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    asyncio.run(start_websocket_server())

