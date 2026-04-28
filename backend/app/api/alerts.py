"""
Endpoints de alertas
"""
from fastapi import APIRouter, Depends, Query, Request
from typing import Optional

from app.models import AlertListResponse, AlertResponse, AlertStatusEnum, AlertUpdate, SeverityEnum
from app.security import get_current_user
from app.services import AlertService

router = APIRouter(prefix="/api/alerts", tags=["Alerts"])


@router.get("/", response_model=AlertListResponse)
async def list_alerts(
    request: Request,
    status: Optional[AlertStatusEnum] = None,
    severity: Optional[SeverityEnum] = None,
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=200),
    current_user: dict = Depends(get_current_user)
):
    """Lista alertas com filtros."""
    return await AlertService(request.app.state.pg_pool).query_alerts(
        status.value if status else None,
        severity.value if severity else None,
        page,
        page_size,
    )


@router.get("/{alert_id}", response_model=AlertResponse)
async def get_alert(alert_id: str, request: Request, current_user: dict = Depends(get_current_user)):
    """Obtém alerta por ID."""
    alert = await AlertService(request.app.state.pg_pool).get_alert(alert_id)
    if not alert:
        from fastapi import HTTPException
        raise HTTPException(status_code=404, detail="Alerta não encontrado")
    return alert


@router.patch("/{alert_id}", response_model=AlertResponse)
async def update_alert(
    alert_id: str,
    update_data: AlertUpdate,
    request: Request,
    current_user: dict = Depends(get_current_user)
):
    """Atualiza status do alerta."""
    alert = await AlertService(request.app.state.pg_pool).update_alert_status(
        alert_id,
        update_data.status.value if update_data.status else AlertStatusEnum.TRIGGERED.value,
    )
    if not alert:
        from fastapi import HTTPException
        raise HTTPException(status_code=404, detail="Alerta não encontrado")
    return alert
