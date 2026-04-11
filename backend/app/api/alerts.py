"""
Endpoints de alertas
"""
from fastapi import APIRouter, Depends, Query
from typing import Optional

from app.models import AlertResponse, AlertUpdate, AlertListResponse
from app.security import get_current_user
from app.services import AlertService
from app.main import pg_pool

router = APIRouter(prefix="/api/alerts", tags=["Alerts"])


@router.get("/", response_model=AlertListResponse)
async def list_alerts(
    status: Optional[str] = None,
    severity: Optional[str] = None,
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=200),
    current_user: dict = Depends(get_current_user)
):
    """Lista alertas com filtros."""
    alert_service = AlertService(pg_pool)
    return await alert_service.query_alerts(status, severity, page, page_size)


@router.get("/{alert_id}", response_model=AlertResponse)
async def get_alert(
    alert_id: str,
    current_user: dict = Depends(get_current_user)
):
    """Obtém alerta por ID."""
    alert_service = AlertService(pg_pool)
    # Implementar get_alert por ID
    from fastapi import HTTPException
    raise HTTPException(status_code=501, detail="Não implementado")


@router.patch("/{alert_id}", response_model=AlertResponse)
async def update_alert(
    alert_id: str,
    update_data: AlertUpdate,
    current_user: dict = Depends(get_current_user)
):
    """Atualiza status do alerta."""
    alert_service = AlertService(pg_pool)
    alert = await alert_service.update_alert_status(alert_id, update_data.status)
    if not alert:
        from fastapi import HTTPException
        raise HTTPException(status_code=404, detail="Alerta não encontrado")
    return alert
