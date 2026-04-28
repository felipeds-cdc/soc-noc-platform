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
    try:
        svc = DashboardService(request.app.state.es_client)
        return await svc.get_kpis()
    except Exception:
        return {
            "total_events_24h": 0,
            "total_alerts_24h": 0,
            "critical_alerts": 0,
            "high_alerts": 0,
            "honeypot_sessions_24h": 0,
            "unique_source_ips": 0,
            "brute_force_attempts": 0,
            "port_scan_attempts": 0,
        }


@router.get("/time-series", response_model=DashboardTimeSeries)
async def get_time_series(request: Request, interval: str = "1h", current_user: dict = Depends(get_current_user)):
    """Obtém séries temporais para gráficos."""
    return await DashboardService(request.app.state.es_client).get_time_series(interval)


@router.get("/top-items", response_model=DashboardTopItems)
async def get_top_items(request: Request, current_user: dict = Depends(get_current_user)):
    try:
        data = await DashboardService(request.app.state.es_client).get_top_items()
        return {
            "top_source_ips": data.get("top_source_ips", []),
            "top_event_types": data.get("top_event_types", []),
            "top_usernames": data.get("top_usernames", []),
            "top_countries": data.get("top_countries", []),
        }

    except Exception:
        return {
            "top_source_ips": [],
            "top_event_types": [],
            "top_usernames": [],
            "top_countries": [],
        }


@router.get("/honeypot/sessions")
async def get_honeypot_sessions(request: Request, current_user: dict = Depends(get_current_user)):
    try:
        svc = HoneypotService(request.app.state.es_client)
        result = await svc.query_sessions(page=1, page_size=100)
        return {"sessions": result.get("sessions", [])}
    except Exception:
        return {"sessions": []}


@router.get("/honeypot/credentials")
async def get_honeypot_credentials(request: Request, current_user: dict = Depends(get_current_user)):
    """Obtém credenciais capturadas pelo honeypot."""
    svc = HoneypotService(request.app.state.es_client)
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
