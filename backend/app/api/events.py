"""
Endpoints de eventos
"""
from fastapi import APIRouter, Depends, Query, Request
from typing import Optional
from datetime import datetime

from app.models import EventListResponse, EventResponse, EventStatusEnum, EventUpdate, SeverityEnum
from app.security import get_current_user
from app.services import EventService

router = APIRouter(prefix="/api/events", tags=["Events"])


@router.get("/", response_model=EventListResponse)
async def list_events(
    request: Request,
    event_type: Optional[str] = None,
    severity: Optional[SeverityEnum] = None,
    source_ip: Optional[str] = None,
    status: Optional[EventStatusEnum] = None,
    mitre_technique_id: Optional[str] = None,
    start_time: Optional[datetime] = None,
    end_time: Optional[datetime] = None,
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=200),
    current_user: dict = Depends(get_current_user)
):
    """Lista eventos com filtros."""
    filters = {
        'event_type': event_type,
        'severity': severity.value if severity else None,
        'source_ip': source_ip,
        'status': status.value if status else None,
        'mitre_technique_id': mitre_technique_id,
        'start_time': start_time, 'end_time': end_time,
    }
    return await EventService(request.app.state.pg_pool, request.app.state.es_client).query_events(filters, page, page_size)


@router.get("/{event_id}", response_model=EventResponse)
async def get_event(event_id: str, request: Request, current_user: dict = Depends(get_current_user)):
    """Obtém evento por ID."""
    event = await EventService(request.app.state.pg_pool, request.app.state.es_client).get_event(event_id)
    if not event:
        from fastapi import HTTPException
        raise HTTPException(status_code=404, detail="Evento não encontrado")
    return event


@router.patch("/{event_id}", response_model=EventResponse)
async def update_event(
    event_id: str,
    update_data: EventUpdate,
    request: Request,
    current_user: dict = Depends(get_current_user)
):
    """Atualiza status do evento."""
    event = await EventService(request.app.state.pg_pool, request.app.state.es_client).update_event_status(
        event_id,
        update_data.status.value if update_data.status else None,
        current_user['user_id'],
        update_data.resolution_notes,
    )
    if not event:
        from fastapi import HTTPException
        raise HTTPException(status_code=404, detail="Evento não encontrado")
    return event
