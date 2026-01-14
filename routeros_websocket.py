"""
Serviço WebSocket para gerenciamento RouterOS
Comunica com routers via RouterOS API e expõe via WebSocket para o frontend
"""
import asyncio
import json
import logging
import re
from typing import Dict, Any, Optional, List
from datetime import datetime, timezone
from concurrent.futures import ThreadPoolExecutor

import websockets
from websockets.server import WebSocketServerProtocol
# Importação do routeros-api
# O pacote routeros-api versão 0.18.0 usa routeros_api.connect() ao invés de RouterOsApi()
import routeros_api
import unicodedata
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
    update_router_password_in_api,
    update_router_data_in_api
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
# Aceita tanto "NÃO" (com acento) quanto "NAO" (sem acento) para compatibilidade
AUTOMAIS_ROUTE_PATTERN = re.compile(r'AUTOMAIS\.IO NA[OÕ] APAGAR:\s*([a-f0-9\-]{36})', re.IGNORECASE)


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


def normalize_comment_for_routeros(comment: str) -> str:
    """Normaliza comentário para RouterOS removendo acentos e caracteres especiais
    
    RouterOS pode ter problemas com UTF-8, então convertemos para ASCII
    removendo acentos e mantendo apenas caracteres ASCII seguros.
    
    Args:
        comment: Comentário original (pode conter acentos)
    
    Returns:
        Comentário normalizado sem acentos
    """
    if not comment:
        return comment
    
    # Normalizar para NFD (decomposição) e remover marcas diacríticas
    normalized = unicodedata.normalize('NFD', comment)
    # Remover caracteres de combinação (acentos)
    ascii_comment = ''.join(
        char for char in normalized 
        if unicodedata.category(char) != 'Mn'
    )
    
    # Garantir que está em ASCII
    try:
        ascii_comment.encode('ascii')
        return ascii_comment
    except UnicodeEncodeError:
        # Se ainda houver caracteres não-ASCII, substituir por equivalentes
        replacements = {
            'Ã': 'A', 'ã': 'a',
            'Õ': 'O', 'õ': 'o',
            'Ê': 'E', 'ê': 'e',
            'É': 'E', 'é': 'e',
            'Í': 'I', 'í': 'i',
            'Ó': 'O', 'ó': 'o',
            'Ú': 'U', 'ú': 'u',
            'Ç': 'C', 'ç': 'c',
            'À': 'A', 'à': 'a',
            'Á': 'A', 'á': 'a',
            'Â': 'A', 'â': 'a',
            'Ô': 'O', 'ô': 'o',
            'Ü': 'U', 'ü': 'u',
        }
        for old, new in replacements.items():
            ascii_comment = ascii_comment.replace(old, new)
        
        # Tentar novamente
        try:
            ascii_comment.encode('ascii')
            return ascii_comment
        except UnicodeEncodeError:
            # Último recurso: remover todos os caracteres não-ASCII
            return ''.join(char for char in ascii_comment if ord(char) < 128)


def sanitize_routeros_data(data):
    """Sanitiza dados do RouterOS para garantir codificação UTF-8 válida
    
    Converte recursivamente todos os valores de string para UTF-8 válido,
    tratando possíveis problemas de codificação (latin1, cp1252, etc.)
    
    Args:
        data: Dados do RouterOS (dict, list, str, ou outros tipos)
    
    Returns:
        Dados sanitizados com strings em UTF-8 válido
    """
    if isinstance(data, dict):
        return {key: sanitize_routeros_data(value) for key, value in data.items()}
    elif isinstance(data, list):
        return [sanitize_routeros_data(item) for item in data]
    elif isinstance(data, str):
        # Se já é uma string válida, retornar como está
        try:
            data.encode('utf-8')
            return data
        except (UnicodeEncodeError, UnicodeDecodeError, UnicodeError):
            # Se não é UTF-8 válido, tentar corrigir
            pass
        
        # Tentar corrigir problemas de codificação
        # O erro comum é quando dados latin1/iso-8859-1 são interpretados como UTF-8
        try:
            # Estratégia: codificar como latin1 (que sempre funciona para qualquer string)
            # e depois tentar decodificar como UTF-8
            # Isso funciona porque latin1 mapeia cada byte 0-255 para um caractere Unicode
            fixed_bytes = data.encode('latin1', errors='replace')
            # Tentar decodificar como UTF-8
            fixed = fixed_bytes.decode('utf-8', errors='replace')
            # Verificar se o resultado é válido UTF-8
            fixed.encode('utf-8')
            return fixed
        except (UnicodeDecodeError, UnicodeEncodeError, UnicodeError):
            # Se não funcionou, usar replace para substituir caracteres inválidos
            try:
                return data.encode('utf-8', errors='replace').decode('utf-8', errors='replace')
            except:
                # Último recurso: substituir caracteres problemáticos manualmente
                result = []
                for char in data:
                    try:
                        char.encode('utf-8')
                        result.append(char)
                    except:
                        result.append('?')
                return ''.join(result)
    elif isinstance(data, bytes):
        # Se for bytes, tentar decodificar
        try:
            return data.decode('utf-8', errors='replace')
        except:
            try:
                return data.decode('latin1', errors='replace')
            except:
                return data.decode('utf-8', errors='ignore')
    else:
        # Outros tipos (int, float, bool, None) retornar como estão
        return data


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
        # IMPORTANTE: routeros_api.connect() usa porta 8728 por padrão
        # O router_ip deve ser o IP da VPN (ex: 10.222.111.2), não o IP público
        logger.info(f"🔌 Criando nova conexão RouterOS para {router_ip}:8728 com usuário '{username}'")
        logger.info(f"   Router ID: {router_id}")
        logger.info(f"   IP usado: {router_ip} (deve ser IP da VPN, não IP público)")
        logger.debug(f"   Detalhes da senha: length={len(password) if password else 0}, tipo={type(password)}, primeiro_char={ord(password[0]) if password and len(password) > 0 else 'N/A'}, último_char={ord(password[-1]) if password and len(password) > 0 else 'N/A'}")
        
        # Verificar se o IP parece ser da VPN (começa com 10., 172.16-31., ou 192.168.)
        is_vpn_ip = (
            router_ip.startswith("10.") or 
            router_ip.startswith("172.16.") or router_ip.startswith("172.17.") or 
            router_ip.startswith("172.18.") or router_ip.startswith("172.19.") or
            router_ip.startswith("172.20.") or router_ip.startswith("172.21.") or
            router_ip.startswith("172.22.") or router_ip.startswith("172.23.") or
            router_ip.startswith("172.24.") or router_ip.startswith("172.25.") or
            router_ip.startswith("172.26.") or router_ip.startswith("172.27.") or
            router_ip.startswith("172.28.") or router_ip.startswith("172.29.") or
            router_ip.startswith("172.30.") or router_ip.startswith("172.31.") or
            router_ip.startswith("192.168.")
        )
        if not is_vpn_ip:
            logger.warning(f"⚠️ ATENÇÃO: IP {router_ip} não parece ser um IP privado/VPN. A conexão pode falhar se o router só aceita conexões via VPN.")
        
        try:
            # RouterOS 6.43+ requer plaintext_login=True
            # Tentar primeiro com plaintext_login (método moderno)
            # routeros_api.connect() usa porta 8728 por padrão
            try:
                api = routeros_api.connect(router_ip, username=username, password=password, plaintext_login=True)
                logger.info(f"✅ Conexão RouterOS estabelecida com sucesso (plaintext_login) para {router_ip}:8728 (usuário: {username})")
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
            logger.error(f"❌ Erro de conexão RouterOS para {router_ip}:8728: {e}")
            logger.error(f"   Detalhes: IP={router_ip}, Porta=8728 (padrão), User='{username}', Password length={len(password) if password else 0}")
            logger.error(f"   Tipo de exceção: RouterOsApiConnectionError")
            logger.error(f"   Possíveis causas:")
            logger.error(f"     1. Porta 8728 bloqueada no firewall do Mikrotik na interface WireGuard")
            logger.error(f"     2. IP {router_ip} não é acessível via VPN (verificar roteamento)")
            logger.error(f"     3. RouterOS API não está habilitada ou porta 8728 não está escutando")
            logger.error(f"     4. IP incorreto (deve ser IP da VPN, não IP público)")
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
        logger.info(f"🔄 Iniciando adição de rota - Router: {router_id}, Route: {route_data.get('route_id')}")
        logger.info(f"   Dados da rota: {route_data}")
        
        # Buscar router da API
        router = await get_router_from_api(router_id)
        if not router:
            logger.error(f"❌ Router {router_id} não encontrado na API")
            return {"success": False, "error": "Router não encontrado"}
        
        logger.debug(f"✅ Router encontrado: {router.get('name', 'N/A')}")
        
        # Buscar rotas do banco para obter o Comment
        routes = await get_router_static_routes_from_api(router_id)
        route_db = next((r for r in routes if r.get("id") == route_data.get("route_id")), None)
        
        if not route_db:
            logger.error(f"❌ Rota {route_data.get('route_id')} não encontrada no banco de dados")
            logger.debug(f"   Rotas disponíveis no banco: {[r.get('id') for r in routes]}")
            return {"success": False, "error": "Rota não encontrada no banco de dados"}
        
        logger.debug(f"✅ Rota encontrada no banco: {route_db.get('destination', 'N/A')}")
        
        # Obter IP do router via peer WireGuard
        router_ip = route_data.get("router_ip")
        if not router_ip:
            logger.debug(f"🔍 Buscando IP do router via peer WireGuard...")
            peers = await get_router_wireguard_peers_from_api(router_id)
            if peers:
                allowed_ips = peers[0].get("allowedIps", "")
                if allowed_ips:
                    router_ip = allowed_ips.split(",")[0].strip().split("/")[0]
                    logger.debug(f"✅ IP obtido do peer WireGuard: {router_ip}")
        
        if not router_ip:
            logger.error(f"❌ IP do router não encontrado para router {router_id}")
            return {"success": False, "error": "IP do router não encontrado. Configure RouterOsApiUrl ou crie um peer WireGuard."}
        
        logger.info(f"🔌 Conectando ao RouterOS - IP: {router_ip}, User: {router.get('routerOsApiUsername', 'admin')}")
        
        # Conectar ao RouterOS (get_router_connection busca o router da API e usa a senha correta)
        # Passar senha vazia aqui, pois get_router_connection vai buscar o router completo da API
        api = await get_router_connection(
            router_id,
            router_ip,
            router.get("routerOsApiUsername", "admin"),
            ""  # get_router_connection busca o router da API e usa get_router_password internamente
        )
        
        if not api:
            logger.error(f"❌ Falha ao conectar ao RouterOS {router_id} em {router_ip}")
            return {"success": False, "error": "Não foi possível conectar ao RouterOS"}
        
        logger.info(f"✅ Conectado ao RouterOS com sucesso")
        
        # Adicionar rota com comentário AUTOMAIS.IO (executar em thread)
        comment = route_db.get("comment", f"AUTOMAIS.IO NÃO APAGAR: {route_data.get('route_id')}")
        # Normalizar comentário para RouterOS (remover acentos para evitar problemas de encoding)
        comment_normalized = normalize_comment_for_routeros(comment)
        logger.debug(f"📝 Comentário original: {comment}")
        logger.debug(f"📝 Comentário normalizado: {comment_normalized}")
        
        # Verificar se gateway está vazio - se estiver, detectar interface WireGuard automaticamente
        gateway = route_data.get("gateway", "").strip() if route_data.get("gateway") else ""
        interface_name = route_data.get("interface_name", "").strip() if route_data.get("interface_name") else ""
        
        # Se gateway está vazio, detectar interface WireGuard automaticamente
        if not gateway and not interface_name:
            logger.info(f"🔍 Gateway vazio - detectando interface WireGuard automaticamente...")
            try:
                # Buscar interfaces WireGuard do RouterOS
                password = get_router_password(router)
                interfaces = await list_wireguard_interfaces(
                    router_id,
                    router_ip,
                    router.get("routerOsApiUsername", "admin"),
                    password
                )
                
                # Buscar peer WireGuard do router no banco
                peers = await get_router_wireguard_peers_from_api(router_id)
                
                if peers and len(peers) > 0 and interfaces and len(interfaces) > 0:
                    # Comparar publickey para encontrar a interface correta
                    router_public_key = peers[0].get("publicKey")
                    matching_interface = next(
                        (iface for iface in interfaces 
                         if (iface.get("publicKey") == router_public_key or 
                             iface.get("public-key") == router_public_key)),
                        None
                    )
                    
                    if matching_interface:
                        interface_name = matching_interface.get("name")
                        logger.info(f"✅ Interface WireGuard detectada automaticamente: '{interface_name}' (publicKey: {router_public_key[:20]}...)")
                    else:
                        logger.warning(f"⚠️ Interface WireGuard não encontrada para publicKey do router")
                        return {"success": False, "error": "Interface WireGuard não encontrada. Configure gateway ou interface manualmente."}
                else:
                    logger.warning(f"⚠️ Não foi possível detectar interface: peers={len(peers) if peers else 0}, interfaces={len(interfaces) if interfaces else 0}")
                    return {"success": False, "error": "Não foi possível detectar interface WireGuard. Configure gateway ou interface manualmente."}
            except Exception as e:
                logger.error(f"❌ Erro ao detectar interface WireGuard: {e}")
                return {"success": False, "error": f"Erro ao detectar interface WireGuard: {str(e)}"}
        
        if not gateway and not interface_name:
            logger.error(f"❌ Gateway e interface não podem estar ambos vazios")
            return {"success": False, "error": "Gateway ou interface deve ser fornecido"}
        
        def add_route_sync():
            try:
                route_resource = api.get_resource('/ip/route')
                route_params = {
                    "dst-address": route_data["destination"],  # Corrigido: RouterOS usa dst-address, não dst
                    "comment": comment_normalized  # Usar versão normalizada
                }
                
                # Se gateway está vazio mas temos interface, usar interface como gateway
                # No RouterOS, podemos especificar o nome da interface diretamente no campo gateway
                if gateway:
                    route_params["gateway"] = gateway
                elif interface_name:
                    # Quando gateway está vazio, usar o nome da interface como gateway
                    # RouterOS aceita nome de interface no campo gateway
                    route_params["gateway"] = interface_name
                    logger.info(f"📝 Gateway vazio - usando interface '{interface_name}' como gateway no RouterOS")
                else:
                    # Fallback: se não tem nem gateway nem interface, usar gateway vazio (RouterOS pode rejeitar)
                    route_params["gateway"] = ""
                
                # Se tem interface e gateway (IP), incluir ambos
                if interface_name and gateway:
                    route_params["interface"] = interface_name
                
                if route_data.get("distance"):
                    route_params["distance"] = str(route_data["distance"])
                if route_data.get("scope"):
                    route_params["scope"] = str(route_data["scope"])
                if route_data.get("routing_table"):
                    route_params["routing-table"] = route_data["routing_table"]
                
                # Log do comando que será enviado ao RouterOS
                logger.info(f"📤 Enviando comando RouterOS: /ip/route/add")
                logger.info(f"   Parâmetros: {route_params}")
                cmd_str = " ".join([f"={k}={v}" for k, v in route_params.items()])
                logger.info(f"   Comando completo: /ip/route/add {cmd_str}")
                
                result = route_resource.add(**route_params)
                
                # O resultado é um AsynchronousResponse com done_message['ret']
                route_id_routeros = None
                if hasattr(result, 'done_message'):
                    route_id_routeros = result.done_message.get('ret')
                elif isinstance(result, dict):
                    route_id_routeros = result.get('ret')
                
                if not route_id_routeros:
                    logger.error(f"❌ Rota adicionada mas ID não retornado. Resposta: {result}")
                    raise Exception(f"ID da rota não retornado pelo RouterOS")
                
                logger.info(f"✅ Rota adicionada com sucesso. ID RouterOS: {route_id_routeros}")
                
                # Buscar a rota criada para obter o gateway usado pelo RouterOS
                # Quando interface foi usada como gateway, RouterOS armazena o nome da interface no campo gateway
                created_routes = route_resource.get(id=route_id_routeros)
                if created_routes and len(created_routes) > 0:
                    created_route = created_routes[0]  # get() retorna uma lista
                    gateway_from_routeros = created_route.get("gateway", "")
                    interface_from_routeros = created_route.get("interface", "")
                    
                    # Sempre usar o gateway retornado pelo RouterOS (pode ser IP ou nome de interface)
                    # Isso garante que sempre temos o valor real do RouterOS, mesmo quando foi fornecido um IP
                    if gateway_from_routeros:
                        # RouterOS retornou um gateway (pode ser IP ou nome de interface) - sempre usar este valor
                        gateway_used = gateway_from_routeros
                        logger.info(f"📝 RouterOS retornou gateway: '{gateway_used}'")
                        return (route_id_routeros, gateway_used)
                    elif not gateway and interface_name:
                        # Gateway estava vazio e usamos interface como gateway
                        # RouterOS armazena o nome da interface no campo gateway, mas pode não estar ainda
                        gateway_used = interface_name
                        logger.info(f"📝 Interface '{interface_name}' usada como gateway: '{gateway_used}'")
                        return (route_id_routeros, gateway_used)
                    elif interface_from_routeros:
                        # Gateway vazio e RouterOS não retornou gateway - usar interface como gateway
                        gateway_used = interface_from_routeros
                        logger.info(f"📝 Usando interface como gateway: '{gateway_used}'")
                        return (route_id_routeros, gateway_used)
                    elif gateway:
                        # Gateway foi fornecido (IP), mas RouterOS não retornou - usar o fornecido como fallback
                        gateway_used = gateway
                        logger.info(f"📝 Usando gateway fornecido (fallback): '{gateway_used}'")
                        return (route_id_routeros, gateway_used)
                    else:
                        # Nenhum gateway ou interface encontrado
                        return (route_id_routeros, "")
                else:
                    logger.warning(f"⚠️ Não foi possível buscar rota criada para obter gateway. ID: {route_id_routeros}")
                    # Se não conseguiu buscar, usar gateway fornecido ou interface como fallback
                    # Se interface foi detectada, usar interface_name como gateway
                    if gateway:
                        gateway_used = gateway
                    elif interface_name:
                        # Interface foi detectada, usar como gateway
                        gateway_used = interface_name
                        logger.info(f"📝 Usando interface detectada como gateway (fallback): '{gateway_used}'")
                    else:
                        gateway_used = ""
                    return (route_id_routeros, gateway_used)
                    
            except Exception as sync_error:
                logger.error(f"❌ Erro ao executar comando no RouterOS: {sync_error}")
                import traceback
                logger.error(f"   Traceback: {traceback.format_exc()}")
                raise
        
        loop = asyncio.get_event_loop()
        result_tuple = await loop.run_in_executor(executor, add_route_sync)
        
        if not result_tuple or not result_tuple[0]:
            logger.error(f"❌ Rota não foi adicionada - route_id_routeros é None")
            return {"success": False, "error": "Rota não foi adicionada - ID não retornado pelo RouterOS"}
        
        route_id_routeros, gateway_used = result_tuple
        
        logger.info(f"✅ Rota adicionada com sucesso - RouterOS ID: {route_id_routeros}, Gateway usado: '{gateway_used}'")
        return {
            "success": True,
            "message": "Rota adicionada com sucesso",
            "router_os_id": route_id_routeros,
            "gateway_used": gateway_used  # Gateway realmente usado pelo RouterOS
        }
        
    except Exception as e:
        logger.error(f"❌ Erro ao adicionar rota: {e}")
        import traceback
        logger.error(f"   Traceback completo: {traceback.format_exc()}")
        return {"success": False, "error": str(e)}


async def remove_route_from_routeros(router_id: str, router_ip: str, username: str, password: str, router_os_route_id: str) -> Dict[str, Any]:
    """Remove rota do RouterOS (função reutilizável para HTTP e WebSocket)"""
    try:
        api = await get_router_connection(router_id, router_ip, username, password)
        if not api:
            return {"success": False, "error": "Não foi possível conectar ao RouterOS"}
        
        def remove_route_sync():
            route_resource = api.get_resource('/ip/route')
            
            # Log do comando que será enviado ao RouterOS
            logger.info(f"📤 Enviando comando RouterOS: /ip/route/remove")
            logger.info(f"   ID da rota: {router_os_route_id}")
            logger.info(f"   Comando completo: /ip/route/remove =.id={router_os_route_id}")
            
            route_resource.remove(id=router_os_route_id)
            logger.info(f"✅ Rota removida com sucesso. ID RouterOS: {router_os_route_id}")
        
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
        # Normalizar comentário para RouterOS (remover acentos para evitar problemas de encoding)
        comment_normalized = normalize_comment_for_routeros(comment)
        logger.debug(f"📝 Comentário original: {comment}")
        logger.debug(f"📝 Comentário normalizado: {comment_normalized}")
        
        # Verificar se gateway está vazio - se estiver, detectar interface WireGuard automaticamente
        gateway = route_data.get("gateway", "").strip() if route_data.get("gateway") else ""
        interface_name = route_data.get("interface", "").strip() if route_data.get("interface") else ""
        
        # Se gateway está vazio, detectar interface WireGuard automaticamente
        if not gateway and not interface_name:
            logger.info(f"🔍 Gateway vazio - detectando interface WireGuard automaticamente...")
            try:
                # Buscar interfaces WireGuard do RouterOS
                password = get_router_password(router)
                interfaces = await list_wireguard_interfaces(
                    router_id,
                    router_ip,
                    router.get("routerOsApiUsername", "admin"),
                    password
                )
                
                # Buscar peer WireGuard do router no banco
                peers = await get_router_wireguard_peers_from_api(router_id)
                
                if peers and len(peers) > 0 and interfaces and len(interfaces) > 0:
                    # Comparar publickey para encontrar a interface correta
                    router_public_key = peers[0].get("publicKey")
                    matching_interface = next(
                        (iface for iface in interfaces 
                         if (iface.get("publicKey") == router_public_key or 
                             iface.get("public-key") == router_public_key)),
                        None
                    )
                    
                    if matching_interface:
                        interface_name = matching_interface.get("name")
                        logger.info(f"✅ Interface WireGuard detectada automaticamente: '{interface_name}' (publicKey: {router_public_key[:20]}...)")
                    else:
                        logger.warning(f"⚠️ Interface WireGuard não encontrada para publicKey do router")
                        await ws.send(json.dumps({"error": "Interface WireGuard não encontrada. Configure gateway ou interface manualmente."}))
                        return
                else:
                    logger.warning(f"⚠️ Não foi possível detectar interface: peers={len(peers) if peers else 0}, interfaces={len(interfaces) if interfaces else 0}")
                    await ws.send(json.dumps({"error": "Não foi possível detectar interface WireGuard. Configure gateway ou interface manualmente."}))
                    return
            except Exception as e:
                logger.error(f"❌ Erro ao detectar interface WireGuard: {e}")
                error_msg = sanitize_routeros_data(f"Erro ao detectar interface WireGuard: {str(e)}")
                await ws.send(json.dumps({"error": error_msg}, ensure_ascii=False))
                return
        
        if not gateway and not interface_name:
            await ws.send(json.dumps({"error": "Gateway ou interface deve ser fornecido"}))
            return
        
        def add_route_sync():
            try:
                route_resource = api.get_resource('/ip/route')
                route_params = {
                    "dst-address": route_data["destination"],  # Corrigido: RouterOS usa dst-address, não dst
                    "comment": comment_normalized  # Usar versão normalizada
                }
                
                # Se gateway está vazio mas temos interface, usar interface como gateway
                # No RouterOS, podemos especificar o nome da interface diretamente no campo gateway
                if gateway:
                    route_params["gateway"] = gateway
                elif interface_name:
                    # Quando gateway está vazio, usar o nome da interface como gateway
                    # RouterOS aceita nome de interface no campo gateway
                    route_params["gateway"] = interface_name
                    logger.info(f"📝 Gateway vazio - usando interface '{interface_name}' como gateway no RouterOS")
                else:
                    # Fallback: se não tem nem gateway nem interface, usar gateway vazio
                    route_params["gateway"] = ""
                
                # Se tem interface e gateway (IP), incluir ambos
                if interface_name and gateway:
                    route_params["interface"] = interface_name
                
                if route_data.get("distance"):
                    route_params["distance"] = str(route_data["distance"])
                if route_data.get("scope"):
                    route_params["scope"] = str(route_data["scope"])
                if route_data.get("routingTable"):
                    route_params["routing-table"] = route_data["routingTable"]
                
                # Log do comando que será enviado ao RouterOS
                logger.info(f"📤 Enviando comando RouterOS: /ip/route/add")
                logger.info(f"   Parâmetros: {route_params}")
                cmd_str = " ".join([f"={k}={v}" for k, v in route_params.items()])
                logger.info(f"   Comando completo: /ip/route/add {cmd_str}")
                
                result = route_resource.add(**route_params)
                
                # O resultado é um AsynchronousResponse com done_message['ret']
                route_id_routeros = None
                if hasattr(result, 'done_message'):
                    route_id_routeros = result.done_message.get('ret')
                elif isinstance(result, dict):
                    route_id_routeros = result.get('ret')
                
                if not route_id_routeros:
                    logger.error(f"❌ Rota adicionada mas ID não retornado. Resposta: {result}")
                    raise Exception(f"ID da rota não retornado pelo RouterOS")
                
                logger.info(f"✅ Rota adicionada com sucesso. ID RouterOS: {route_id_routeros}")
                
                # Buscar a rota criada para obter o gateway usado pelo RouterOS
                # Quando interface foi usada como gateway, RouterOS armazena o nome da interface no campo gateway
                created_routes = route_resource.get(id=route_id_routeros)
                if created_routes and len(created_routes) > 0:
                    created_route = created_routes[0]  # get() retorna uma lista
                    gateway_from_routeros = created_route.get("gateway", "")
                    interface_from_routeros = created_route.get("interface", "")
                    
                    # Sempre usar o gateway retornado pelo RouterOS (pode ser IP ou nome de interface)
                    # Isso garante que sempre temos o valor real do RouterOS, mesmo quando foi fornecido um IP
                    if gateway_from_routeros:
                        # RouterOS retornou um gateway (pode ser IP ou nome de interface) - sempre usar este valor
                        gateway_used = gateway_from_routeros
                        logger.info(f"📝 RouterOS retornou gateway: '{gateway_used}'")
                        return (route_id_routeros, gateway_used)
                    elif not gateway and interface_name:
                        # Gateway estava vazio e usamos interface como gateway
                        # RouterOS armazena o nome da interface no campo gateway, mas pode não estar ainda
                        gateway_used = interface_name
                        logger.info(f"📝 Interface '{interface_name}' usada como gateway: '{gateway_used}'")
                        return (route_id_routeros, gateway_used)
                    elif interface_from_routeros:
                        # Gateway vazio e RouterOS não retornou gateway - usar interface como gateway
                        gateway_used = interface_from_routeros
                        logger.info(f"📝 Usando interface como gateway: '{gateway_used}'")
                        return (route_id_routeros, gateway_used)
                    elif gateway:
                        # Gateway foi fornecido (IP), mas RouterOS não retornou - usar o fornecido como fallback
                        gateway_used = gateway
                        logger.info(f"📝 Usando gateway fornecido (fallback): '{gateway_used}'")
                        return (route_id_routeros, gateway_used)
                    else:
                        # Nenhum gateway ou interface encontrado
                        return (route_id_routeros, "")
                else:
                    logger.warning(f"⚠️ Não foi possível buscar rota criada para obter gateway. ID: {route_id_routeros}")
                    # Se não conseguiu buscar, usar gateway fornecido ou interface como fallback
                    # Se interface foi detectada, usar interface_name como gateway
                    if gateway:
                        gateway_used = gateway
                    elif interface_name:
                        # Interface foi detectada, usar como gateway
                        gateway_used = interface_name
                        logger.info(f"📝 Usando interface detectada como gateway (fallback): '{gateway_used}'")
                    else:
                        gateway_used = ""
                    return (route_id_routeros, gateway_used)
                    
            except Exception as sync_error:
                logger.error(f"❌ Erro ao executar comando no RouterOS: {sync_error}")
                import traceback
                logger.error(f"   Traceback: {traceback.format_exc()}")
                raise
        
        loop = asyncio.get_event_loop()
        result_tuple = await loop.run_in_executor(executor, add_route_sync)
        
        if not result_tuple or not result_tuple[0]:
            await ws.send(json.dumps({"error": "Rota não foi adicionada - ID não retornado pelo RouterOS"}))
            return
        
        route_id_routeros, gateway_used = result_tuple
        
        await ws.send(json.dumps({
            "success": True,
            "message": "Rota adicionada com sucesso",
            "router_os_id": route_id_routeros,
            "gateway_used": gateway_used  # Gateway realmente usado pelo RouterOS
        }))
        
    except Exception as e:
        logger.error(f"Erro ao adicionar rota: {e}")
        error_message = sanitize_routeros_data(str(e))
        await ws.send(json.dumps({"error": error_message}, ensure_ascii=False))


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
        
        # Sanitizar dados do RouterOS para garantir UTF-8 válido
        routes = sanitize_routeros_data(routes)
        
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
        }, ensure_ascii=False))
        
    except Exception as e:
        logger.error(f"Erro ao listar rotas: {e}")
        error_message = sanitize_routeros_data(str(e))
        await ws.send(json.dumps({"error": error_message}, ensure_ascii=False))


async def handle_delete_route(router_id: str, router_ip: str, username: str, password: str, route_routeros_id: str, ws: WebSocketServerProtocol):
    """Remove rota do RouterOS"""
    try:
        api = await get_router_connection(router_id, router_ip, username, password)
        if not api:
            await ws.send(json.dumps({"error": "Não foi possível conectar ao RouterOS"}))
            return
        
        def remove_route_sync():
            route_resource = api.get_resource('/ip/route')
            
            # Log do comando que será enviado ao RouterOS
            logger.info(f"📤 Enviando comando RouterOS: /ip/route/remove")
            logger.info(f"   ID da rota: {route_routeros_id}")
            logger.info(f"   Comando completo: /ip/route/remove =.id={route_routeros_id}")
            
            route_resource.remove(id=route_routeros_id)
            logger.info(f"✅ Rota removida com sucesso. ID RouterOS: {route_routeros_id}")
        
        loop = asyncio.get_event_loop()
        await loop.run_in_executor(executor, remove_route_sync)
        
        await ws.send(json.dumps({
            "success": True,
            "message": "Rota removida com sucesso"
        }))
        
    except Exception as e:
        logger.error(f"Erro ao remover rota: {e}")
        error_message = sanitize_routeros_data(str(e))
        await ws.send(json.dumps({"error": error_message}, ensure_ascii=False))


async def handle_get_status(router_id: str, router_ip: str, username: str, password: str, ws: WebSocketServerProtocol, request_id: str = None):
    """Verifica status da conexão RouterOS"""
    try:
        # Timeout de 8 segundos para get_status (deve ser rápido)
        api = await asyncio.wait_for(
            get_router_connection(router_id, router_ip, username, password),
            timeout=8.0
        )
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
                logger.warning(f"Erro ao obter status do RouterOS: {e}")
                return {
                    "connected": False,
                    "error": str(e)
                }
        
        loop = asyncio.get_event_loop()
        # Timeout de 5 segundos para a operação síncrona
        status = await asyncio.wait_for(
            loop.run_in_executor(executor, get_status_sync),
            timeout=5.0
        )
        
        # Sanitizar dados do RouterOS para garantir UTF-8 válido
        sanitized_status = sanitize_routeros_data(status)
        
        # Se conectado com sucesso, extrair e atualizar dados do router no banco
        if sanitized_status.get("connected", False):
            try:
                resource = sanitized_status.get("resource", {})
                identity = sanitized_status.get("identity", {})
                
                # Preparar dados para atualização
                router_update_data = {
                    "status": 1  # RouterStatus.Online
                }
                
                # LastSeenAt - quando foi visto online
                router_update_data["lastSeenAt"] = datetime.now(timezone.utc).isoformat()
                
                # Extrair dados do resource (hardware info)
                if resource:
                    hardware_info = {}
                    
                    # CPU Load
                    if "cpu-load" in resource:
                        hardware_info["cpuLoad"] = str(resource["cpu-load"])
                    
                    # Memory
                    if "free-memory" in resource and "total-memory" in resource:
                        free_mem = int(resource["free-memory"])
                        total_mem = int(resource["total-memory"])
                        used_mem = total_mem - free_mem
                        hardware_info["memoryUsage"] = str(used_mem)
                        hardware_info["totalMemory"] = str(total_mem)
                    
                    # Uptime
                    if "uptime" in resource:
                        hardware_info["uptime"] = str(resource["uptime"])
                    
                    # Temperature (se disponível)
                    if "temperature" in resource:
                        hardware_info["temperature"] = str(resource["temperature"])
                    else:
                        hardware_info["temperature"] = None
                    
                    # Last updated timestamp
                    hardware_info["lastUpdated"] = datetime.now(timezone.utc).isoformat()
                    
                    # Converter para JSON string
                    router_update_data["hardwareInfo"] = json.dumps(hardware_info)
                    
                    # Firmware Version
                    if "version" in resource:
                        router_update_data["firmwareVersion"] = str(resource["version"])
                    
                    # Model (board-name ou architecture)
                    if "board-name" in resource:
                        router_update_data["model"] = str(resource["board-name"])
                    elif "architecture-name" in resource:
                        router_update_data["model"] = str(resource["architecture-name"])
                
                # Atualizar no banco (em background, não bloquear resposta)
                asyncio.create_task(update_router_data_in_api(router_id, router_update_data))
                logger.debug(f"📤 Dados do router {router_id} sendo atualizados no banco: {list(router_update_data.keys())}")
                
            except Exception as update_error:
                logger.warning(f"⚠️ Erro ao atualizar dados do router {router_id} no banco: {update_error}")
                # Não falhar a resposta, apenas logar o erro
        
        response = {
            "success": sanitized_status.get("connected", False),
            **sanitized_status
        }
        if request_id:
            response["id"] = request_id
        
        await ws.send(json.dumps(response, ensure_ascii=False))
        
    except asyncio.TimeoutError:
        logger.error(f"⏱️ Timeout ao verificar status do router {router_id} em {router_ip}:8728")
        logger.error(f"   Possíveis causas:")
        logger.error(f"     1. Porta 8728 não está acessível via VPN (firewall bloqueando)")
        logger.error(f"     2. IP {router_ip} não está roteando corretamente na VPN")
        logger.error(f"     3. RouterOS API não está respondendo (serviço desabilitado?)")
        logger.error(f"     4. Latência muito alta na VPN")
        error_message = f"Timeout ao verificar status (operação demorou mais de 5 segundos). IP usado: {router_ip}:8728"
        response = {
            "success": False,
            "connected": False,
            "error": error_message,
            "router_ip": router_ip,
            "port": 8728
        }
        if request_id:
            response["id"] = request_id
        await ws.send(json.dumps(response, ensure_ascii=False))
    except Exception as e:
        logger.error(f"Erro ao verificar status: {e}")
        error_message = sanitize_routeros_data(str(e))
        response = {
            "success": False,
            "connected": False,
            "error": error_message
        }
        if request_id:
            response["id"] = request_id
        await ws.send(json.dumps(response, ensure_ascii=False))


async def handle_execute_command(router_id: str, router_ip: str, username: str, password: str, command: str, ws: WebSocketServerProtocol, request_id: str = None):
    """Executa comando RouterOS genérico"""
    try:
        api = await get_router_connection(router_id, router_ip, username, password)
        if not api:
            await ws.send(json.dumps({"success": False, "error": "Não foi possível conectar ao RouterOS"}))
            return
        
        # Parse do comando RouterOS
        # Suporta dois formatos:
        #   1. Formato API (com barras): /ip/firewall/filter/add
        #   2. Formato linha de comando (com espaços): /ip firewall filter add
        # Exemplos:
        #   /ip/firewall/filter/print
        #   /ip firewall filter add chain=input action=accept
        #   /ip/route/print
        #   /interface/print
        
        command = command.strip()
        parts = command.split()
        
        if not parts or not parts[0].startswith("/"):
            await ws.send(json.dumps({"success": False, "error": "Comando inválido. Deve começar com /"}))
            return
        
        # Verificar se o primeiro elemento já contém o caminho completo (formato API)
        first_part = parts[0]
        # Verificar se tem pelo menos 2 barras (ex: /interface/print tem 2 barras, /ip/firewall/filter/add tem 4)
        # Split por "/" retorna: ["", "categoria", "recurso", "acao"] para /categoria/recurso/acao
        path_parts = first_part.split("/")
        # Se tem pelo menos 3 elementos após split (incluindo o vazio inicial), é formato API
        # Ex: "/interface/print" -> ["", "interface", "print"] = 3 elementos
        # Ex: "/ip/firewall/filter/add" -> ["", "ip", "firewall", "filter", "add"] = 5 elementos
        if len(path_parts) >= 3:
            # Formato API: /ip/firewall/filter/add ou /interface/print
            # Remover primeiro elemento vazio (antes da primeira barra)
            path_parts_clean = [p for p in path_parts if p]  # Remove strings vazias
            if len(path_parts_clean) >= 2:
                # Último elemento é a ação
                action = path_parts_clean[-1]
                # Resto é o caminho do recurso
                resource_path = "/" + "/".join(path_parts_clean[:-1])
            elif len(path_parts_clean) == 1:
                # Apenas uma parte (ex: /interface) - assumir print
                resource_path = "/" + path_parts_clean[0]
                action = "print"
            else:
                await ws.send(json.dumps({"success": False, "error": "Comando inválido. Caminho vazio"}))
                return
            # Parâmetros começam do segundo elemento
            param_start_idx = 1
        else:
            # Formato linha de comando: /ip firewall filter add
            # Encontrar onde termina o caminho (ação) e começam os parâmetros
            # Ações comuns: add, print, remove, set, enable, disable, etc.
            actions = ["add", "print", "remove", "set", "enable", "disable", "comment", "move", "get", "export", "find", "reset", "monitor", "ping", "traceroute"]
            
            path_elements = []
            action = None
            param_start_idx = len(parts)
            
            for i, part in enumerate(parts):
                # Se encontrar uma ação conhecida, é o fim do caminho
                if part.lower() in actions:
                    path_elements.append(part)
                    action = part.lower()
                    param_start_idx = i + 1
                    break
                # Se encontrar um parâmetro (contém =), o caminho terminou antes
                elif "=" in part:
                    # O elemento anterior era a ação (ou o caminho não tem ação explícita)
                    if i > 0:
                        # Tentar identificar ação do elemento anterior
                        prev_part = parts[i-1].lower()
                        if prev_part in actions:
                            action = prev_part
                            param_start_idx = i
                        else:
                            # Sem ação explícita, assumir "print" como padrão
                            action = "print"
                            param_start_idx = i
                    else:
                        # Primeiro elemento tem =, comando inválido
                        await ws.send(json.dumps({"success": False, "error": "Comando inválido. Formato esperado: /categoria recurso acao ou /categoria/recurso/acao"}))
                        return
                    break
                else:
                    # É parte do caminho
                    path_elements.append(part)
            
            # Se não encontrou ação nem parâmetros, assumir "print"
            if not action:
                action = "print"
                param_start_idx = len(parts)
            
            # Construir caminho do recurso (remover a barra inicial e a ação)
            if path_elements:
                # Remover barra inicial do primeiro elemento se existir
                first_elem = path_elements[0].lstrip("/")
                path_elements[0] = first_elem
                # Remover a ação se estiver no final
                if path_elements and path_elements[-1].lower() == action:
                    path_elements = path_elements[:-1]
                # Construir caminho
                resource_path = "/" + "/".join(path_elements)
            else:
                await ws.send(json.dumps({"success": False, "error": "Comando inválido. Caminho do recurso não encontrado"}))
                return
        
        # Parsear parâmetros (ex: chain=input, .id=123, etc)
        params = {}
        for part in parts[param_start_idx:]:
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
        # Timeout de 60 segundos para comandos (alguns podem demorar)
        result = await asyncio.wait_for(
            loop.run_in_executor(executor, execute_command_sync),
            timeout=60.0
        )
        
        # Sanitizar dados do RouterOS para garantir UTF-8 válido
        sanitized_result = sanitize_routeros_data(result)
        
        # Incluir ID da requisição se fornecido
        response = {"success": True, "data": sanitized_result}
        if request_id:
            response["id"] = request_id
        
        await ws.send(json.dumps(response, ensure_ascii=False))
        
    except asyncio.TimeoutError:
        logger.error(f"Timeout ao executar comando no router {router_id}: {command[:50]}...")
        error_message = "Timeout ao executar comando (operação demorou mais de 60 segundos)"
        error_response = {"success": False, "error": error_message}
        if request_id:
            error_response["id"] = request_id
        await ws.send(json.dumps(error_response, ensure_ascii=False))
    except Exception as e:
        logger.error(f"Erro ao executar comando: {e}")
        # Sanitizar mensagem de erro antes de enviar
        error_message = str(e)
        try:
            # Tentar sanitizar a mensagem de erro
            error_message = sanitize_routeros_data(error_message)
        except:
            # Se falhar, usar mensagem genérica
            error_message = "Erro ao executar comando no RouterOS"
        
        error_response = {"success": False, "error": error_message}
        if request_id:
            error_response["id"] = request_id
        await ws.send(json.dumps(error_response, ensure_ascii=False))


async def handle_websocket(ws: WebSocketServerProtocol, path: str):
    """Handler principal do WebSocket"""
    client_addr = f"{ws.remote_address[0]}:{ws.remote_address[1]}" if ws.remote_address else "unknown"
    
    try:
        async for message in ws:
            try:
                data = json.loads(message)
                action = data.get("action")
                router_id = data.get("router_id")
                request_id = data.get("id")
                
                if not action or not router_id:
                    await ws.send(json.dumps({"error": "action e router_id são obrigatórios"}))
                    continue
                
                # Buscar router da API
                router = await get_router_from_api(router_id)
                if not router:
                    logger.error(f"Router {router_id} não encontrado na API")
                    await ws.send(json.dumps({"error": "Router não encontrado"}))
                    continue
                
                logger.info(f"Router encontrado: routerOsApiUrl={router.get('routerOsApiUrl', 'não configurado')}")
                
                # Obter IP do router (via peer WireGuard ou RouterOsApiUrl)
                router_ip = data.get("router_ip")
                logger.info(f"router_ip da mensagem: {router_ip}")
                
                if not router_ip:
                    # Tentar extrair do RouterOsApiUrl
                    router_os_api_url = router.get("routerOsApiUrl", "")
                    if router_os_api_url:
                        logger.info(f"Tentando extrair IP de routerOsApiUrl: {router_os_api_url}")
                        # Remover protocolo se presente (http:// ou https://)
                        router_os_api_url = router_os_api_url.replace("http://", "").replace("https://", "")
                        # Pegar apenas o hostname/IP (antes de : ou /)
                        router_ip = router_os_api_url.split(":")[0].split("/")[0].strip()
                        logger.info(f"IP extraído do routerOsApiUrl: {router_ip}")
                
                # Se ainda não tem IP, buscar do peer WireGuard
                if not router_ip:
                    logger.info(f"Buscando IP do peer WireGuard para router {router_id}")
                    peers = await get_router_wireguard_peers_from_api(router_id)
                    if peers:
                        logger.info(f"Peers encontrados: {len(peers)}")
                        # Extrair IP do primeiro peer (formato: "10.222.111.2/32" -> "10.222.111.2")
                        allowed_ips = peers[0].get("allowedIps", "")
                        if allowed_ips:
                            router_ip = allowed_ips.split(",")[0].strip().split("/")[0]
                            logger.info(f"✅ IP extraído do peer WireGuard: {router_ip} (este é o IP da VPN que deve ser usado para conectar na porta 8728)")
                        else:
                            logger.warning(f"Peer encontrado mas allowedIps está vazio")
                    else:
                        logger.warning(f"Nenhum peer WireGuard encontrado para router {router_id}")
                
                if not router_ip:
                    error_msg = f"IP do router não encontrado para router {router_id}. Configure RouterOsApiUrl ou crie um peer WireGuard."
                    logger.error(error_msg)
                    await ws.send(json.dumps({"error": error_msg}))
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
                    
            except json.JSONDecodeError as e:
                logger.error(f"JSON inválido: {e}")
                error_response = {"error": "JSON inválido", "success": False}
                try:
                    await ws.send(json.dumps(error_response))
                except:
                    logger.warning(f"Não foi possível enviar resposta de erro (conexão fechada?)")
            except Exception as e:
                logger.error(f"Erro ao processar mensagem: {type(e).__name__}: {e}")
                import traceback
                logger.debug(f"Traceback: {traceback.format_exc()}")
                error_message = sanitize_routeros_data(str(e))
                error_response = {"error": error_message, "success": False}
                # Tentar obter request_id da mensagem se possível
                try:
                    parsed_data = json.loads(message) if isinstance(message, str) else {}
                    if parsed_data.get("id"):
                        error_response["id"] = parsed_data["id"]
                except:
                    pass
                try:
                    await ws.send(json.dumps(error_response, ensure_ascii=False))
                except:
                    logger.warning(f"Não foi possível enviar resposta de erro (conexão fechada?)")
                
    except websockets.exceptions.ConnectionClosed:
        # Conexão fechada normalmente - não logar
        pass
    except websockets.exceptions.ConnectionClosedError as e:
        logger.warning(f"Erro de conexão WebSocket: {e}")
    except Exception as e:
        logger.error(f"Erro inesperado na conexão WebSocket: {type(e).__name__}: {e}")
        import traceback
        logger.debug(f"Traceback: {traceback.format_exc()}")


async def start_websocket_server(host: str = "0.0.0.0", port: int = 8765):
    """Inicia servidor WebSocket"""
    logger.info(f"🚀 Iniciando servidor WebSocket RouterOS em ws://{host}:{port}")
    
    try:
        async with websockets.serve(handle_websocket, host, port):
            await asyncio.Future()  # Rodar indefinidamente
    except asyncio.CancelledError:
        logger.info("🛑 Servidor WebSocket RouterOS cancelado")
        raise
    except Exception as e:
        logger.error(f"❌ Erro no servidor WebSocket RouterOS: {e}")
        raise


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    asyncio.run(start_websocket_server())

