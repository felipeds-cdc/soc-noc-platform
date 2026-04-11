"""
Endpoints de threat hunting
"""
from fastapi import APIRouter, Depends, Query
from typing import Optional
from datetime import datetime
import time
import json

from app.models import ThreatHuntQuery, ThreatHuntResult, IPAnalysisResponse
from app.security import get_current_user, require_analyst_or_admin
from app.main import es_client

router = APIRouter(prefix="/api/threat-hunting", tags=["Threat Hunting"])


@router.post("/search", response_model=ThreatHuntResult)
async def search_events(
    search_query: ThreatHuntQuery,
    current_user: dict = Depends(require_analyst_or_admin)
):
    """Busca eventos customizados para threat hunting."""
    from app.config import get_settings

    settings = get_settings()

    start_time = time.time()

    try:
        # Parse da query (suporta query DSL simples ou Lucene)
        if search_query.query.startswith('{'):
            # Query DSL - usa json.loads para segurança ao invés de eval()
            try:
                query_body = json.loads(search_query.query)
            except json.JSONDecodeError as e:
                from fastapi import HTTPException
                raise HTTPException(
                    status_code=400,
                    detail=f"Query DSL inválida: {str(e)}"
                )
        else:
            # Query string simples
            query_body = {
                "query_string": {
                    "query": search_query.query,
                    "default_field": "*"
                }
            }

        # Aplica filtros
        if search_query.filters:
            if 'bool' not in query_body:
                query_body = {"bool": {"must": [query_body], "filter": []}}
            elif 'must' not in query_body.get('bool', {}):
                # Reestrutura query se necessário
                old_query = query_body.get('query_string') or query_body.get('match_all') or query_body
                if 'query_string' in query_body:
                    del query_body['query_string']
                query_body['bool']['must'] = [old_query]

            for key, value in search_query.filters.items():
                query_body['bool']['filter'].append({"term": {key: value}})

        # Time range
        if search_query.time_range:
            # Parse "24h", "7d", etc
            if search_query.time_range.endswith('h'):
                hours = int(search_query.time_range[:-1])
                gte = f"now-{hours}h"
            elif search_query.time_range.endswith('d'):
                days = int(search_query.time_range[:-1])
                gte = f"now-{days}d"
            else:
                gte = f"now-{search_query.time_range}"

            if 'bool' in query_body:
                query_body['bool']['filter'].append({"range": {"timestamp": {"gte": gte}}})
            else:
                query_body = {"bool": {"filter": [{"range": {"timestamp": {"gte": gte}}}]}}

        response = await es_client.search(
            index=search_query.index or "soc_events",
            query=query_body,
            size=1000
        )

        results = []
        for hit in response['hits']['hits']:
            result = hit['_source']
            result['_id'] = hit['_id']
            result['_score'] = hit.get('_score')
            results.append(result)

        execution_time = (time.time() - start_time) * 1000

        return ThreatHuntResult(
            query=search_query.query,
            total_hits=response['hits']['total']['value'],
            results=results,
            execution_time_ms=execution_time
        )

    except HTTPException:
        raise
    except Exception as e:
        from fastapi import HTTPException
        raise HTTPException(
            status_code=500,
            detail=f"Erro na busca: {str(e)}"
        )


@router.get("/ip-analysis/{ip_address}", response_model=IPAnalysisResponse)
async def analyze_ip(
    ip_address: str,
    current_user: dict = Depends(require_analyst_or_admin)
):
    """Analisa IP em detalhe."""
    try:
        # Total de eventos
        total = await es_client.count(
            index="soc_events",
            query={"term": {"source_ip": ip_address}}
        )

        # Event types
        type_agg = await es_client.search(
            index="soc_events",
            size=0,
            query={"term": {"source_ip": ip_address}},
            aggs={
                "event_types": {"terms": {"field": "event_type", "size": 20}},
                "severity_dist": {"terms": {"field": "severity", "size": 10}}
            }
        )

        # Primeiro e último evento
        time_sort = await es_client.search(
            index="soc_events",
            size=1,
            query={"term": {"source_ip": ip_address}},
            sort=[{"timestamp": {"order": "asc"}}]
        )

        time_sort_desc = await es_client.search(
            index="soc_events",
            size=1,
            query={"term": {"source_ip": ip_address}},
            sort=[{"timestamp": {"order": "desc"}}]
        )

        # Geo info
        geo_info = None
        if time_sort['hits']['hits']:
            first_event = time_sort['hits']['hits'][0]['_source']
            if first_event.get('geo_country'):
                geo_info = {
                    'country': first_event.get('geo_country'),
                    'city': first_event.get('geo_city'),
                    'latitude': first_event.get('geo_latitude'),
                    'longitude': first_event.get('geo_longitude'),
                    'asn': first_event.get('asn')
                }

        # Honeypot sessions
        honeypot_sessions = await es_client.count(
            index="honeypot_sessions",
            query={"term": {"source_ip": ip_address}}
        )

        # Commands executed
        commands_session = await es_client.search(
            index="honeypot_sessions",
            size=100,
            query={"term": {"source_ip": ip_address}}
        )

        commands = []
        for session in commands_session['hits']['hits']:
            cmds = session['_source'].get('commands_executed', [])
            if isinstance(cmds, str):
                try:
                    cmds = json.loads(cmds)
                except:
                    cmds = []
            for cmd in cmds:
                if isinstance(cmd, dict):
                    commands.append(cmd.get('command', ''))
                elif isinstance(cmd, str):
                    commands.append(cmd)

        event_types = {
            bucket['key']: bucket['doc_count']
            for bucket in type_agg.get('aggregations', {}).get('event_types', {}).get('buckets', [])
        }

        severity_dist = {
            bucket['key']: bucket['doc_count']
            for bucket in type_agg.get('aggregations', {}).get('severity_dist', {}).get('buckets', [])
        }

        first_seen = None
        last_seen = None
        if time_sort['hits']['hits']:
            first_seen = time_sort['hits']['hits'][0]['_source'].get('timestamp')
        if time_sort_desc['hits']['hits']:
            last_seen = time_sort_desc['hits']['hits'][0]['_source'].get('timestamp')

        return IPAnalysisResponse(
            ip=ip_address,
            total_events=total.get('count', 0) if isinstance(total, dict) else 0,
            first_seen=first_seen,
            last_seen=last_seen,
            event_types=event_types,
            severity_distribution=severity_dist,
            geo_info=geo_info,
            reputation=None,  # Simulado
            associated_sessions=honeypot_sessions.get('count', 0) if isinstance(honeypot_sessions, dict) else 0,
            commands_executed=commands[:50]
        )

    except Exception as e:
        from fastapi import HTTPException
        raise HTTPException(
            status_code=500,
            detail=f"Erro na análise do IP: {str(e)}"
        )


@router.get("/correlation")
async def correlate_events(
    ip_address: Optional[str] = Query(None),
    time_window: str = Query("1h", description="Time window for correlation (e.g., 1h, 30m)"),
    current_user: dict = Depends(require_analyst_or_admin)
):
    """Correlaciona eventos para detectar padrões."""
    try:
        query = {
            "bool": {
                "filter": [
                    {"range": {"timestamp": {"gte": f"now-{time_window}"}}}
                ]
            }
        }

        if ip_address:
            query['bool']['filter'].append({"term": {"source_ip": ip_address}})

        response = await es_client.search(
            index="soc_events",
            query=query,
            size=0,
            aggs={
                "correlated_ips": {
                    "terms": {"field": "source_ip", "size": 50}
                },
                "correlated_events": {
                    "terms": {"field": "event_type", "size": 20}
                },
                "timeline": {
                    "date_histogram": {
                        "field": "timestamp",
                        "calendar_interval": "5m"
                    }
                }
            }
        )

        return {
            "query_ip": ip_address,
            "time_window": time_window,
            "correlated_ips": [
                {'ip': b['key'], 'count': b['doc_count']}
                for b in response['aggregations'].get('correlated_ips', {}).get('buckets', [])
            ],
            "correlated_events": [
                {'event_type': b['key'], 'count': b['doc_count']}
                for b in response['aggregations'].get('correlated_events', {}).get('buckets', [])
            ],
            "timeline": [
                {'timestamp': b['key_as_string'], 'count': b['doc_count']}
                for b in response['aggregations'].get('timeline', {}).get('buckets', [])
            ]
        }

    except Exception as e:
        from fastapi import HTTPException
        raise HTTPException(
            status_code=500,
            detail=f"Erro na correlação: {str(e)}"
        )
