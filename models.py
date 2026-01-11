"""
Modelos Pydantic para requests e responses - RouterOS
"""
from pydantic import BaseModel, Field
from typing import Optional


class AddRouteRequest(BaseModel):
    """Request para adicionar rota estática no RouterOS"""
    router_id: str = Field(..., description="ID do router (UUID)")
    route_id: str = Field(..., description="ID da rota no banco (UUID)")
    destination: str = Field(..., description="Destino da rota (ex: 0.0.0.0/0)")
    gateway: str = Field(..., description="Gateway da rota (ex: 10.0.0.1)")
    interface_name: Optional[str] = Field(None, description="Interface de saída (opcional)")
    distance: Optional[int] = Field(None, description="Distância da rota (opcional)")
    scope: Optional[int] = Field(None, description="Escopo da rota (opcional)")
    routing_table: Optional[str] = Field(None, description="Tabela de roteamento (opcional)")
    comment: str = Field(..., description="Comentário da rota (formato AUTOMAIS.IO)")


class RemoveRouteRequest(BaseModel):
    """Request para remover rota estática do RouterOS"""
    router_id: str = Field(..., description="ID do router (UUID)")
    router_os_route_id: str = Field(..., description="ID da rota no RouterOS")
