"""
Endpoints de dashboard
"""
from fastapi import APIRouter, Depends, Request

from app.models import DashboardKPIs, DashboardTimeSeries, DashboardTopItems
from app.security import get_current_user
from app.services import DashboardService, HoneypotService

router = APIRouter(prefix="/api/dashboard", tags=["Dashboard"])


@router.get("/kpis", response_model=DashboardKPIs)
async def get_kpis(request: Request, current_user: dict = Depends(get_current_user)):
    """Obtém KPIs do dashboard."""
    return await DashboardService(request.app.state.es_client).get_kpis()


@router.get("/time-series", response_model=DashboardTimeSeries)
async def get_time_series(request: Request, interval: str = "1h", current_user: dict = Depends(get_current_user)):
    """Obtém séries temporais para gráficos."""
    return await DashboardService(request.app.state.es_client).get_time_series(interval)


@router.get("/top-items", response_model=DashboardTopItems)
async def get_top_items(request: Request, current_user: dict = Depends(get_current_user)):
    """Obtém top itens para dashboard."""
    return await DashboardService(request.app.state.es_client).get_top_items()


@router.get("/honeypot/sessions")
async def get_honeypot_sessions(request: Request, current_user: dict = Depends(get_current_user)):
    """Obtém sessões do honeypot."""
    svc = HoneypotService(request.app.state.pg_pool, request.app.state.es_client)
    return await svc.query_sessions({}, page=1, page_size=100)


@router.get("/honeypot/credentials")
async def get_honeypot_credentials(request: Request, current_user: dict = Depends(get_current_user)):
    """Obtém credenciais capturadas pelo honeypot."""
    svc = HoneypotService(request.app.state.pg_pool, request.app.state.es_client)
    result = await svc.query_sessions({}, page=1, page_size=1000)

    credentials = {}
    for session in result.get('sessions', []):
        key = f"{session.get('username')}:{session.get('password')}"
        if key not in credentials:
            credentials[key] = {
                'username': session.get('username'),
                'password': session.get('password'),
                'count': 0,
                'source_ips': set()
            }
        credentials[key]['count'] += 1
        credentials[key]['source_ips'].add(session.get('source_ip'))

    for cred in credentials.values():
        cred['source_ips'] = list(cred['source_ips'])

    return list(credentials.values())
