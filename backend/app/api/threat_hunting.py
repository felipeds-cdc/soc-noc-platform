"""
Endpoints de threat hunting
"""
from fastapi import APIRouter, Depends, Query, Request
from typing import Optional
import time
import json

from app.models import ThreatHuntQuery, ThreatHuntResult, IPAnalysisResponse
from app.security import get_current_user, require_analyst_or_admin

router = APIRouter(prefix="/api/threat-hunting", tags=["Threat Hunting"])


@router.post("/search", response_model=ThreatHuntResult)
async def search_events(
    search_query: ThreatHuntQuery,
    request: Request,
    current_user: dict = Depends(require_analyst_or_admin)
):
    """Busca eventos customizados para threat hunting."""
    from app.config import get_settings
    from fastapi import HTTPException

    es_client = request.app.state.es_client
    start_time = time.time()

    try:
        if search_query.query.startswith('{'):
            try:
                query_body = json.loads(search_query.query)
            except json.JSONDecodeError as e:
                raise HTTPException(status_code=400, detail=f"Query DSL inválida: {str(e)}")
        else:
            query_body = {"query_string": {"query": search_query.query, "default_field": "*"}}

        if search_query.filters:
            if 'bool' not in query_body:
                existing_query = query_body.get("query", query_body)
                query_body = {"bool": {"must": [existing_query] if existing_query != {"match_all": {}} else [], "filter": []}}
            elif 'must' not in query_body.get('bool', {}):
                query_body['bool']['must'] = []
                query_body['bool']['filter'] = []

            for key, value in search_query.filters.items():
                query_body['bool']['filter'].append({"term": {key: value}})

        if search_query.time_range:
            if search_query.time_range.endswith('h'):
                gte = f"now-{search_query.time_range}"
            elif search_query.time_range.endswith('d'):
                gte = f"now-{search_query.time_range}"
            else:
                gte = f"now-{search_query.time_range}"

            if 'bool' in query_body:
                query_body['bool']['filter'].append({"range": {"timestamp": {"gte": gte}}})
            else:
                query_body = {"bool": {"filter": [{"range": {"timestamp": {"gte": gte}}}]}}

        response = await es_client.search(index=search_query.index or "soc_events", query=query_body, size=1000)
        results = []
        for hit in response['hits']['hits']:
            result = hit['_source']
            result['_id'] = hit['_id']
            result['_score'] = hit.get('_score')
            results.append(result)

        return ThreatHuntResult(
            query=search_query.query,
            total_hits=response['hits']['total']['value'],
            results=results,
            execution_time_ms=(time.time() - start_time) * 1000
        )

    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Erro na busca: {str(e)}")


@router.get("/ip-analysis/{ip_address}", response_model=IPAnalysisResponse)
async def analyze_ip(ip_address: str, request: Request, current_user: dict = Depends(require_analyst_or_admin)):
    """Analisa IP em detalhe."""
    from fastapi import HTTPException
    es_client = request.app.state.es_client
    try:
        total = await es_client.count(index="soc_events", query={"term": {"source_ip": ip_address}})
        type_agg = await es_client.search(index="soc_events", size=0, query={"term": {"source_ip": ip_address}},
            aggs={"event_types": {"terms": {"field": "event_type", "size": 20}}, "severity_dist": {"terms": {"field": "severity", "size": 10}}})
        time_sort = await es_client.search(index="soc_events", size=1, query={"term": {"source_ip": ip_address}}, sort=[{"timestamp": {"order": "asc"}}])
        time_sort_desc = await es_client.search(index="soc_events", size=1, query={"term": {"source_ip": ip_address}}, sort=[{"timestamp": {"order": "desc"}}])

        geo_info = None
        if time_sort['hits']['hits']:
            first_event = time_sort['hits']['hits'][0]['_source']
            if first_event.get('geo_country'):
                geo_info = {'country': first_event.get('geo_country'), 'city': first_event.get('geo_city'),
                    'latitude': first_event.get('geo_latitude'), 'longitude': first_event.get('geo_longitude'), 'asn': first_event.get('asn')}

        honeypot_sessions = await es_client.count(index="honeypot_sessions", query={"term": {"source_ip": ip_address}})
        commands_session = await es_client.search(index="honeypot_sessions", size=100, query={"term": {"source_ip": ip_address}})

        commands = []
        for session in commands_session['hits']['hits']:
            cmds = session['_source'].get('commands_executed', [])
            if isinstance(cmds, str):
                try: cmds = json.loads(cmds)
                except: cmds = []
            for cmd in cmds:
                commands.append(cmd.get('command', '') if isinstance(cmd, dict) else cmd)

        aggs = type_agg.get('aggregations', {})
        return IPAnalysisResponse(
            ip=ip_address,
            total_events=total.get('count', 0) if isinstance(total, dict) else 0,
            first_seen=time_sort['hits']['hits'][0]['_source'].get('timestamp') if time_sort['hits']['hits'] else None,
            last_seen=time_sort_desc['hits']['hits'][0]['_source'].get('timestamp') if time_sort_desc['hits']['hits'] else None,
            event_types={b['key']: b['doc_count'] for b in aggs.get('event_types', {}).get('buckets', [])},
            severity_distribution={b['key']: b['doc_count'] for b in aggs.get('severity_dist', {}).get('buckets', [])},
            geo_info=geo_info, reputation=None,
            associated_sessions=honeypot_sessions.get('count', 0) if isinstance(honeypot_sessions, dict) else 0,
            commands_executed=commands[:50]
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Erro na análise do IP: {str(e)}")


@router.get("/correlation")
async def correlate_events(
    request: Request,
    ip_address: Optional[str] = Query(None),
    time_window: str = Query("1h"),
    current_user: dict = Depends(require_analyst_or_admin)
):
    """Correlaciona eventos para detectar padrões."""
    from fastapi import HTTPException
    es_client = request.app.state.es_client
    try:
        query = {"bool": {"filter": [{"range": {"timestamp": {"gte": f"now-{time_window}"}}}]}}
        if ip_address:
            query['bool']['filter'].append({"term": {"source_ip": ip_address}})

        response = await es_client.search(index="soc_events", query=query, size=0,
            aggs={"correlated_ips": {"terms": {"field": "source_ip", "size": 50}},
                  "correlated_events": {"terms": {"field": "event_type", "size": 20}},
                  "timeline": {"date_histogram": {"field": "timestamp", "calendar_interval": "5m"}}})

        return {
            "query_ip": ip_address, "time_window": time_window,
            "correlated_ips": [{'ip': b['key'], 'count': b['doc_count']} for b in response['aggregations'].get('correlated_ips', {}).get('buckets', [])],
            "correlated_events": [{'event_type': b['key'], 'count': b['doc_count']} for b in response['aggregations'].get('correlated_events', {}).get('buckets', [])],
            "timeline": [{'timestamp': b['key_as_string'], 'count': b['doc_count']} for b in response['aggregations'].get('timeline', {}).get('buckets', [])]
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Erro na correlação: {str(e)}")
