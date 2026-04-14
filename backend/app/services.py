"""
Serviços de autenticação e usuários
"""
import uuid
from datetime import datetime
from typing import Optional, List

import asyncpg
from fastapi import HTTPException, status

from app.config import get_settings
from app.security import get_password_hash, verify_password, create_access_token


class AuthService:
    """Serviço de autenticação."""
    
    def __init__(self, db_pool):
        self.db_pool = db_pool
        
    async def authenticate(self, username: str, password: str) -> dict:
        """Autentica usuário e retorna token."""
        async with self.db_pool.acquire() as conn:
            row = await conn.fetchrow(
                "SELECT id, username, password_hash, role, is_active FROM users WHERE username = $1",
                username
            )
            
            if not row:
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Credenciais inválidas"
                )
                
            if not row['is_active']:
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail="Usuário desativado"
                )
                
            if not verify_password(password, row['password_hash']):
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Credenciais inválidas"
                )
                
            # Gera token
            token_data = {
                "sub": str(row['id']),
                "username": row['username'],
                "role": row['role']
            }
            access_token = create_access_token(token_data)
            
            return {
                "access_token": access_token,
                "token_type": "bearer",
                "user_id": str(row['id']),
                "username": row['username'],
                "role": row['role']
            }
            
    async def get_user(self, user_id: str) -> Optional[dict]:
        """Obtém usuário por ID."""
        async with self.db_pool.acquire() as conn:
            row = await conn.fetchrow(
                "SELECT id, username, email, role, is_active, created_at FROM users WHERE id = $1",
                uuid.UUID(user_id)
            )
            return dict(row) if row else None
            
    async def get_user_by_username(self, username: str) -> Optional[dict]:
        """Obtém usuário por username."""
        async with self.db_pool.acquire() as conn:
            row = await conn.fetchrow(
                "SELECT id, username, email, role, is_active, created_at FROM users WHERE username = $1",
                username
            )
            return dict(row) if row else None
            
    async def list_users(self, active_only: bool = True) -> List[dict]:
        """Lista todos os usuários."""
        query = "SELECT id, username, email, role, is_active, created_at FROM users"
        if active_only:
            query += " WHERE is_active = true"
        query += " ORDER BY created_at DESC"
        
        async with self.db_pool.acquire() as conn:
            rows = await conn.fetch(query)
            return [dict(row) for row in rows]
            
    async def create_user(self, username: str, password: str, email: str, role: str) -> dict:
        """Cria novo usuário."""
        password_hash = get_password_hash(password)
        user_id = str(uuid.uuid4())
        
        async with self.db_pool.acquire() as conn:
            try:
                row = await conn.fetchrow(
                    """
                    INSERT INTO users (id, username, password_hash, email, role)
                    VALUES ($1, $2, $3, $4, $5)
                    RETURNING id, username, email, role, is_active, created_at
                    """,
                    uuid.UUID(user_id), username, password_hash, email, role
                )
                return dict(row)
            except Exception as e:
                if "unique" in str(e).lower():
                    raise HTTPException(
                        status_code=status.HTTP_400_BAD_REQUEST,
                        detail="Usuário já existe"
                    )
                raise
                
    async def update_user(self, user_id: str, **kwargs) -> Optional[dict]:
        """Atualiza usuário."""
        allowed_fields = {'email', 'role', 'is_active'}
        updates = {k: v for k, v in kwargs.items() if k in allowed_fields}
        
        if not updates:
            return await self.get_user(user_id)
            
        set_clause = ", ".join(f"{k} = ${i+1}" for i, k in enumerate(updates.keys()))
        values = list(updates.values()) + [uuid.UUID(user_id)]
        
        async with self.db_pool.acquire() as conn:
            row = await conn.fetchrow(
                f"UPDATE users SET {set_clause} WHERE id = ${len(values)} RETURNING id, username, email, role, is_active, created_at",
                *values
            )
            return dict(row) if row else None
            
    async def change_password(self, user_id: str, current_password: str, new_password: str) -> bool:
        """Altera senha do usuário."""
        async with self.db_pool.acquire() as conn:
            row = await conn.fetchrow(
                "SELECT password_hash FROM users WHERE id = $1",
                uuid.UUID(user_id)
            )
            
            if not row or not verify_password(current_password, row['password_hash']):
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="Senha atual incorreta"
                )
                
            new_hash = get_password_hash(new_password)
            await conn.execute(
                "UPDATE users SET password_hash = $1, updated_at = NOW() WHERE id = $2",
                new_hash, uuid.UUID(user_id)
            )
            return True


class EventService:
    """Serviço de eventos de segurança."""
    
    def __init__(self, db_pool, elasticsearch):
        self.db_pool = db_pool
        self.es = elasticsearch
        
    async def query_events(self, filters: dict, page: int = 1, page_size: int = 50) -> dict:
        """Consulta eventos com filtros."""
        # Build Elasticsearch query
        query = {
            "bool": {
                "filter": []
            }
        }
        
        # Time range
        if filters.get('start_time') or filters.get('end_time'):
            time_range = {}
            if filters.get('start_time'):
                time_range['gte'] = filters['start_time'].isoformat()
            if filters.get('end_time'):
                time_range['lte'] = filters['end_time'].isoformat()
            query['bool']['filter'].append({"range": {"timestamp": time_range}})
            
        # Other filters
        field_mapping = {
            'event_type': 'event_type',
            'source': 'source',
            'severity': 'severity',
            'source_ip': 'source_ip',
            'status': 'status',
            'mitre_technique_id': 'mitre_technique_id',
        }
        
        for filter_key, es_field in field_mapping.items():
            if filters.get(filter_key):
                query['bool']['filter'].append({"term": {es_field: filters[filter_key]}})
                
        # Se não há filtros, match all
        if not query['bool']['filter']:
            query = {"match_all": {}}
        else:
            query = {"bool": query['bool']}
            
        # Executa busca
        response = await self.es.search(
            index="soc_events",
            query=query,
            sort=[{"timestamp": {"order": "desc"}}],
            from_=(page - 1) * page_size,
            size=page_size,
        )
        
        # Total count
        total = await self.es.count(
            index="soc_events",
            query={"match_all": {}} if not isinstance(query, dict) or 'match_all' in str(query) else query
        )
        
        events = []
        for hit in response['hits']['hits']:
            event = hit['_source']
            event['id'] = hit['_id']
            events.append(event)
            
        return {
            "events": events,
            "total": total['count'] if isinstance(total, dict) else len(events),
            "page": page,
            "page_size": page_size,
            "has_next": (page * page_size) < (total['count'] if isinstance(total, dict) else len(events))
        }
        
    async def get_event(self, event_id: str) -> Optional[dict]:
        """Obtém evento por ID."""
        try:
            response = await self.es.get(index="soc_events", id=event_id)
            event = response['_source']
            event['id'] = response['_id']
            return event
        except Exception:
            return None
            
    async def update_event_status(self, event_id: str, status: str, analyst_id: str = None, notes: str = None) -> Optional[dict]:
        """Atualiza status do evento."""
        try:
            updates = {"status": status}
            if analyst_id:
                updates['analyst_id'] = analyst_id
            if notes:
                updates['resolution_notes'] = notes
                
            await self.es.update(index="soc_events", id=event_id, doc=updates)
            return await self.get_event(event_id)
        except Exception:
            return None
            
    async def get_db_events(self, page: int = 1, page_size: int = 50) -> dict:
        """Obtém eventos do PostgreSQL (apenas críticos)."""
        offset = (page - 1) * page_size
        
        async with self.db_pool.acquire() as conn:
            rows = await conn.fetch(
                """
                SELECT * FROM events 
                ORDER BY timestamp DESC 
                LIMIT $1 OFFSET $2
                """,
                page_size, offset
            )
            
            total_row = await conn.fetchrow("SELECT COUNT(*) as count FROM events")
            total = total_row['count']
            
            return {
                "events": [dict(row) for row in rows],
                "total": total,
                "page": page,
                "page_size": page_size,
                "has_next": offset + page_size < total
            }


class AlertService:
    """Serviço de alertas."""
    
    def __init__(self, db_pool):
        self.db_pool = db_pool
        
    async def query_alerts(self, status: str = None, severity: str = None, page: int = 1, page_size: int = 50) -> dict:
        """Consulta alertas com filtros."""
        query = "SELECT * FROM alerts WHERE 1=1"
        count_query = "SELECT COUNT(*) FROM alerts WHERE 1=1"
        params = []
        param_count = 1
        
        if status:
            query += f" AND status = ${param_count}"
            count_query += f" AND status = ${param_count}"
            params.append(status)
            param_count += 1
            
        if severity:
            query += f" AND severity = ${param_count}"
            count_query += f" AND severity = ${param_count}"
            params.append(severity)
            param_count += 1
            
        query += f" ORDER BY created_at DESC LIMIT ${param_count} OFFSET ${param_count + 1}"
        params.extend([page_size, (page - 1) * page_size])
        
        async with self.db_pool.acquire() as conn:
            rows = await conn.fetch(query, *params)
            total_row = await conn.fetchrow(count_query, *[p for p in params[:-2]])
            total = total_row['count']
            
            return {
                "alerts": [dict(row) for row in rows],
                "total": total,
                "page": page,
                "page_size": page_size,
                "has_next": (page - 1) * page_size + page_size < total
            }
            
    async def update_alert_status(self, alert_id: str, status: str) -> Optional[dict]:
        """Atualiza status do alerta."""
        async with self.db_pool.acquire() as conn:
            if status == "acknowledged":
                query = """
                    UPDATE alerts SET status = $1, acknowledged_at = NOW()
                    WHERE id = $2
                    RETURNING *
                """
            elif status == "resolved":
                query = """
                    UPDATE alerts SET status = $1, resolved_at = NOW()
                    WHERE id = $2
                    RETURNING *
                """
            else:
                query = """
                    UPDATE alerts SET status = $1
                    WHERE id = $2
                    RETURNING *
                """
            row = await conn.fetchrow(query, status, uuid.UUID(alert_id))
            return dict(row) if row else None

    async def get_alert(self, alert_id: str) -> Optional[dict]:
        """Obtém alerta por ID."""
        async with self.db_pool.acquire() as conn:
            row = await conn.fetchrow(
                "SELECT * FROM alerts WHERE id = $1",
                uuid.UUID(alert_id)
            )
            return dict(row) if row else None


class HoneypotService:
    """Serviço de honeypot."""
    
    def __init__(self, db_pool, elasticsearch):
        self.db_pool = db_pool
        self.es = elasticsearch
        
    async def query_sessions(self, filters: dict, page: int = 1, page_size: int = 50) -> dict:
        """Consulta sessões do honeypot."""
        query = {
            "bool": {
                "filter": []
            }
        }
        
        if filters.get('source_ip'):
            query['bool']['filter'].append({"term": {"source_ip": filters['source_ip']}})
        if filters.get('username'):
            query['bool']['filter'].append({"term": {"username": filters['username']}})
        if filters.get('start_time') or filters.get('end_time'):
            time_range = {}
            if filters.get('start_time'):
                time_range['gte'] = filters['start_time'].isoformat()
            if filters.get('end_time'):
                time_range['lte'] = filters['end_time'].isoformat()
            query['bool']['filter'].append({"range": {"started_at": time_range}})
            
        if not query['bool']['filter']:
            query = {"match_all": {}}
            
        response = await self.es.search(
            index="honeypot_sessions",
            query=query,
            sort=[{"started_at": {"order": "desc"}}],
            from_=(page - 1) * page_size,
            size=page_size,
        )
        
        sessions = []
        for hit in response['hits']['hits']:
            session = hit['_source']
            session['id'] = hit['_id']
            sessions.append(session)
            
        return {
            "sessions": sessions,
            "total": len(sessions),
            "page": page,
            "page_size": page_size,
            "has_next": False
        }
        
    async def get_session(self, session_id: str) -> Optional[dict]:
        """Obtém sessão por ID."""
        try:
            response = await self.es.get(index="honeypot_sessions", id=session_id)
            session = response['_source']
            session['id'] = response['_id']
            return session
        except Exception:
            return None


class DashboardService:
    """Serviço de dashboard e KPIs."""
    
    def __init__(self, elasticsearch):
        self.es = elasticsearch
        
    async def get_kpis(self) -> dict:
        """Obtém KPIs do dashboard."""
        now = datetime.utcnow()
        last_24h = now.timestamp() - 86400
        
        # Total events 24h
        events_24h = await self.es.count(
            index="soc_events",
            query={"range": {"timestamp": {"gte": last_24h}}}
        )
        
        # Alertas críticos e altos
        critical = await self.es.count(
            index="soc_events",
            query={"bool": {"filter": [{"term": {"severity": "critical"}}]}}
        )
        
        high = await self.es.count(
            index="soc_events",
            query={"bool": {"filter": [{"term": {"severity": "high"}}]}}
        )
        
        # Unique IPs
        ip_agg = await self.es.search(
            index="soc_events",
            size=0,
            aggs={
                "unique_ips": {
                    "cardinality": {
                        "field": "source_ip"
                    }
                }
            }
        )
        
        # Honeypot sessions
        honeypot_count = await self.es.count(
            index="honeypot_sessions",
            query={"range": {"started_at": {"gte": last_24h}}}
        )
        
        # Brute force attempts
        brute_force = await self.es.count(
            index="soc_events",
            query={"term": {"event_type": "brute_force"}}
        )
        
        # Port scan attempts
        port_scan = await self.es.count(
            index="soc_events",
            query={"term": {"event_type": "port_scan"}}
        )
        
        # Total alerts (critical + high)
        total_alerts = (critical.get('count', 0) if isinstance(critical, dict) else 0) + \
                       (high.get('count', 0) if isinstance(high, dict) else 0)

        return {
            "total_events_24h": events_24h.get('count', 0) if isinstance(events_24h, dict) else 0,
            "total_alerts_24h": total_alerts,
            "critical_alerts": critical.get('count', 0) if isinstance(critical, dict) else 0,
            "high_alerts": high.get('count', 0) if isinstance(high, dict) else 0,
            "unique_source_ips": ip_agg.get('aggregations', {}).get('unique_ips', {}).get('value', 0),
            "honeypot_sessions_24h": honeypot_count.get('count', 0) if isinstance(honeypot_count, dict) else 0,
            "brute_force_attempts": brute_force.get('count', 0) if isinstance(brute_force, dict) else 0,
            "port_scan_attempts": port_scan.get('count', 0) if isinstance(port_scan, dict) else 0,
        }
        
    async def get_time_series(self, interval: str = "1h") -> dict:
        """Obtém séries temporais para gráficos."""
        # Events over time
        events_response = await self.es.search(
            index="soc_events",
            size=0,
            aggs={
                "events_over_time": {
                    "date_histogram": {
                        "field": "timestamp",
                        "calendar_interval": interval
                    }
                }
            }
        )

        events = []
        for bucket in events_response.get('aggregations', {}).get('events_over_time', {}).get('buckets', []):
            events.append({
                "timestamp": bucket['key_as_string'],
                "count": bucket['doc_count']
            })

        # Alerts over time (placeholder)
        alerts = []

        return {"events": events, "alerts": alerts}
        
    async def get_top_items(self) -> dict:
        """Obtém top itens para dashboard."""
        response = await self.es.search(
            index="soc_events",
            size=0,
            aggs={
                "top_source_ips": {
                    "terms": {"field": "source_ip", "size": 10}
                },
                "top_event_types": {
                    "terms": {"field": "event_type", "size": 10}
                },
                "top_usernames": {
                    "terms": {"field": "username", "size": 10}
                },
                "top_countries": {
                    "terms": {"field": "geo_country", "size": 10}
                }
            }
        )
        
        aggs = response.get('aggregations', {})
        
        def extract_items(agg_key):
            return [
                {"key": bucket['key'], "count": bucket['doc_count']}
                for bucket in aggs.get(agg_key, {}).get('buckets', [])
            ]
            
        return {
            "top_source_ips": extract_items('top_source_ips'),
            "top_event_types": extract_items('top_event_types'),
            "top_usernames": extract_items('top_usernames'),
            "top_countries": extract_items('top_countries'),
        }
