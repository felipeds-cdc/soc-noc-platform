"""
Endpoints de eventos
"""
from fastapi import APIRouter, Depends, Query
from typing import Optional
from datetime import datetime

from app.models import EventResponse, EventUpdate, EventQuery, EventListResponse
from app.security import get_current_user
from app.services import EventService
from app.database import get_db

router = APIRouter(prefix="/api/events", tags=["Events"])


@router.get("/", response_model=EventListResponse)
async def list_events(
    event_type: Optional[str] = None,
    severity: Optional[str] = None,
    source_ip: Optional[str] = None,
    status: Optional[str] = None,
    mitre_technique_id: Optional[str] = None,
    start_time: Optional[datetime] = None,
    end_time: Optional[datetime] = None,
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=200),
    db=Depends(get_db),
    current_user: dict = Depends(get_current_user)
):
    """Lista eventos com filtros."""
    event_service = EventService(db.bind, None)  # Elasticsearch será injetado
    
    filters = {
        'event_type': event_type,
        'severity': severity,
        'source_ip': source_ip,
        'status': status,
        'mitre_technique_id': mitre_technique_id,
        'start_time': start_time,
        'end_time': end_time,
    }
    
    return await event_service.query_events(filters, page, page_size)


@router.get("/{event_id}", response_model=EventResponse)
async def get_event(
    event_id: str,
    db=Depends(get_db),
    current_user: dict = Depends(get_current_user)
):
    """Obtém evento por ID."""
    event_service = EventService(db.bind, None)
    event = await event_service.get_event(event_id)
    if not event:
        from fastapi import HTTPException
        raise HTTPException(status_code=404, detail="Evento não encontrado")
    return event


@router.patch("/{event_id}", response_model=EventResponse)
async def update_event(
    event_id: str,
    update_data: EventUpdate,
    db=Depends(get_db),
    current_user: dict = Depends(get_current_user)
):
    """Atualiza status do evento."""
    event_service = EventService(db.bind, None)
    event = await event_service.update_event_status(
        event_id,
        update_data.status,
        current_user['user_id'],
        update_data.resolution_notes
    )
    if not event:
        from fastapi import HTTPException
        raise HTTPException(status_code=404, detail="Evento não encontrado")
    return event
