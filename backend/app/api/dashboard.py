"""
Endpoints de dashboard
"""
from fastapi import APIRouter, Depends

from app.models import DashboardKPIs, DashboardTimeSeries, DashboardTopItems
from app.security import get_current_user
from app.services import DashboardService, HoneypotService
from app.main import pg_pool, es_client

router = APIRouter(prefix="/api/dashboard", tags=["Dashboard"])


@router.get("/kpis", response_model=DashboardKPIs)
async def get_kpis(
    current_user: dict = Depends(get_current_user)
):
    """Obtém KPIs do dashboard."""
    dashboard_service = DashboardService(es_client)
    return await dashboard_service.get_kpis()


@router.get("/time-series", response_model=DashboardTimeSeries)
async def get_time_series(
    interval: str = "1h",
    current_user: dict = Depends(get_current_user)
):
    """Obtém séries temporais para gráficos."""
    dashboard_service = DashboardService(es_client)
    return await dashboard_service.get_time_series(interval)


@router.get("/top-items", response_model=DashboardTopItems)
async def get_top_items(
    current_user: dict = Depends(get_current_user)
):
    """Obtém top itens para dashboard."""
    dashboard_service = DashboardService(es_client)
    return await dashboard_service.get_top_items()


@router.get("/honeypot/sessions")
async def get_honeypot_sessions(
    current_user: dict = Depends(get_current_user)
):
    """Obtém sessões do honeypot."""
    honeypot_service = HoneypotService(pg_pool, es_client)
    return await honeypot_service.query_sessions({}, page=1, page_size=100)


@router.get("/honeypot/credentials")
async def get_honeypot_credentials(
    current_user: dict = Depends(get_current_user)
):
    """Obtém credenciais capturadas pelo honeypot."""
    honeypot_service = HoneypotService(pg_pool, es_client)
    result = await honeypot_service.query_sessions({}, page=1, page_size=1000)

    # Extrai credenciais únicas
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

    # Converte sets para listas
    for cred in credentials.values():
        cred['source_ips'] = list(cred['source_ips'])

    return list(credentials.values())
