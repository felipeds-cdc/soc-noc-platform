"""
Servicos da aplicacao.
"""

from __future__ import annotations

import logging
from datetime import datetime
from typing import Any, Optional

from fastapi import HTTPException, status

from app.models import AlertStatusEnum, EventStatusEnum, SeverityEnum, UserRoleEnum

logger = logging.getLogger(__name__)


def parse_dt(value: Any) -> datetime:
    if isinstance(value, datetime):
        return value
    if isinstance(value, str):
        try:
            return datetime.fromisoformat(value.replace("Z", "+00:00"))
        except ValueError:
            return datetime.utcnow()
    return datetime.utcnow()


def safe_enum(value: Any, enum_cls, default):
    try:
        return enum_cls(value).value
    except Exception:
        return default


def _keyword_field(field: str) -> str:
    keyword_compatible = {
        "event_type",
        "severity",
        "status",
        "source_ip",
        "mitre_technique_id",
        "username",
        "geo_country",
    }
    return f"{field}.keyword" if field in keyword_compatible else field


def normalize_event(hit: dict) -> dict:
    source = hit.get("_source", {})
    return {
        "id": hit.get("_id"),
        "event_type": source.get("event_type", "unknown"),
        "source": source.get("source", "unknown"),
        "severity": safe_enum(source.get("severity"), SeverityEnum, SeverityEnum.LOW.value),
        "source_ip": source.get("source_ip"),
        "destination_ip": source.get("destination_ip"),
        "source_port": source.get("source_port"),
        "destination_port": source.get("destination_port"),
        "protocol": source.get("protocol"),
        "username": source.get("username"),
        "command": source.get("command"),
        "mitre_technique_id": source.get("mitre_technique_id"),
        "mitre_tactic": source.get("mitre_tactic"),
        "timestamp": parse_dt(source.get("timestamp")),
        "status": safe_enum(source.get("status"), EventStatusEnum, EventStatusEnum.NEW.value),
        "analyst_id": source.get("analyst_id"),
        "resolution_notes": source.get("resolution_notes"),
        "created_at": parse_dt(source.get("created_at") or source.get("timestamp")),
    }


def normalize_alert(row: dict) -> dict:
    return {
        "id": str(row.get("id")),
        "event_id": str(row.get("event_id", "")),
        "rule_id": str(row.get("rule_id", "")),
        "rule_name": row.get("rule_name", ""),
        "severity": safe_enum(row.get("severity"), SeverityEnum, SeverityEnum.LOW.value),
        "status": safe_enum(row.get("status"), AlertStatusEnum, AlertStatusEnum.TRIGGERED.value),
        "description": row.get("description"),
        "notified_channels": row.get("notified_channels") or [],
        "created_at": parse_dt(row.get("created_at")),
        "acknowledged_at": parse_dt(row.get("acknowledged_at")) if row.get("acknowledged_at") else None,
        "resolved_at": parse_dt(row.get("resolved_at")) if row.get("resolved_at") else None,
    }


class AuthService:
    def __init__(self, db_pool):
        self.db_pool = db_pool

    def _ensure_db(self) -> None:
        if self.db_pool is None:
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="Banco de dados indisponivel",
            )

    async def authenticate(self, username: str, password: str) -> dict:
        from app.security import create_access_token, verify_password

        self._ensure_db()

        async with self.db_pool.acquire() as conn:
            row = await conn.fetchrow(
                "SELECT id, username, password_hash, role, is_active FROM users WHERE username = $1",
                username,
            )
            if not row or not verify_password(password, row["password_hash"]):
                raise HTTPException(status_code=401, detail="Credenciais invalidas")
            if not row["is_active"]:
                raise HTTPException(status_code=403, detail="Usuario desativado")

            token = create_access_token(
                {
                    "sub": str(row["id"]),
                    "username": row["username"],
                    "role": row["role"],
                }
            )
            return {
                "access_token": token,
                "token_type": "bearer",
                "user_id": str(row["id"]),
                "username": row["username"],
                "role": row["role"],
            }

    async def create_user(self, username: str, password: str, email: Optional[str], role: UserRoleEnum) -> dict:
        from app.security import get_password_hash

        self._ensure_db()
        async with self.db_pool.acquire() as conn:
            exists = await conn.fetchval("SELECT 1 FROM users WHERE username = $1", username)
            if exists:
                raise HTTPException(status_code=409, detail="Usuario ja existe")

            row = await conn.fetchrow(
                """
                INSERT INTO users (username, password_hash, email, role, is_active, created_at)
                VALUES ($1, $2, $3, $4, TRUE, NOW())
                RETURNING id, username, email, role, is_active, created_at
                """,
                username,
                get_password_hash(password),
                email,
                role.value if isinstance(role, UserRoleEnum) else str(role),
            )
            return dict(row)

    async def get_user(self, user_id: str) -> Optional[dict]:
        self._ensure_db()
        async with self.db_pool.acquire() as conn:
            row = await conn.fetchrow(
                "SELECT id, username, email, role, is_active, created_at FROM users WHERE id = $1",
                user_id,
            )
            return dict(row) if row else None

    async def change_password(self, user_id: str, current_password: str, new_password: str) -> None:
        from app.security import get_password_hash, verify_password

        self._ensure_db()
        async with self.db_pool.acquire() as conn:
            row = await conn.fetchrow("SELECT password_hash FROM users WHERE id = $1", user_id)
            if not row:
                raise HTTPException(status_code=404, detail="Usuario nao encontrado")
            if not verify_password(current_password, row["password_hash"]):
                raise HTTPException(status_code=400, detail="Senha atual invalida")

            await conn.execute(
                "UPDATE users SET password_hash = $1 WHERE id = $2",
                get_password_hash(new_password),
                user_id,
            )

    async def list_users(self) -> list[dict]:
        self._ensure_db()
        async with self.db_pool.acquire() as conn:
            rows = await conn.fetch(
                "SELECT id, username, email, role, is_active, created_at FROM users ORDER BY created_at DESC"
            )
            return [dict(row) for row in rows]


class EventService:
    def __init__(self, db_pool, es):
        self.db_pool = db_pool
        self.es = es

    def _ensure_es(self) -> None:
        if self.es is None:
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="Elasticsearch indisponivel",
            )

    async def query_events(self, filters: dict, page: int = 1, page_size: int = 50) -> dict:
        self._ensure_es()

        es_filters = []
        if filters.get("start_time") or filters.get("end_time"):
            time_range = {}
            if filters.get("start_time"):
                time_range["gte"] = filters["start_time"].isoformat()
            if filters.get("end_time"):
                time_range["lte"] = filters["end_time"].isoformat()
            es_filters.append({"range": {"timestamp": time_range}})

        for field in ("event_type", "severity", "source_ip", "status", "mitre_technique_id"):
            value = filters.get(field)
            if value:
                es_filters.append({"term": {_keyword_field(field): str(value)}})

        query = {"bool": {"filter": es_filters}} if es_filters else {"match_all": {}}
        response = await self.es.search(
            index="soc_events",
            query=query,
            sort=[{"timestamp": {"order": "desc"}}],
            from_=(page - 1) * page_size,
            size=page_size,
        )

        total = response.get("hits", {}).get("total", {}).get("value", 0)
        events = [normalize_event(hit) for hit in response.get("hits", {}).get("hits", [])]
        return {
            "events": events,
            "total": total,
            "page": page,
            "page_size": page_size,
            "has_next": page * page_size < total,
        }

    async def get_event(self, event_id: str) -> Optional[dict]:
        self._ensure_es()
        try:
            res = await self.es.get(index="soc_events", id=event_id)
            return normalize_event(res)
        except Exception:
            return None

    async def update_event_status(self, event_id: str, status_value: Optional[str], analyst_id=None, notes=None) -> Optional[dict]:
        self._ensure_es()
        try:
            update_doc = {}
            if status_value is not None:
                update_doc["status"] = safe_enum(status_value, EventStatusEnum, EventStatusEnum.NEW.value)
            if analyst_id:
                update_doc["analyst_id"] = analyst_id
            if notes is not None:
                update_doc["resolution_notes"] = notes
            if not update_doc:
                return await self.get_event(event_id)
            await self.es.update(index="soc_events", id=event_id, doc=update_doc)
            return await self.get_event(event_id)
        except Exception:
            return None


class AlertService:
    def __init__(self, db_pool):
        self.db_pool = db_pool

    def _ensure_db(self) -> None:
        if self.db_pool is None:
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="Banco de dados indisponivel",
            )

    async def query_alerts(self, status_value=None, severity=None, page=1, page_size=50):
        self._ensure_db()
        where = []
        params = []
        idx = 1

        if status_value:
            where.append(f"status = ${idx}")
            params.append(str(status_value))
            idx += 1
        if severity:
            where.append(f"severity = ${idx}")
            params.append(str(severity))
            idx += 1

        where_clause = f" WHERE {' AND '.join(where)}" if where else ""
        list_query = (
            "SELECT id, event_id, rule_id, rule_name, severity, status, description, "
            "notified_channels, created_at, acknowledged_at, resolved_at "
            f"FROM alerts{where_clause} ORDER BY created_at DESC LIMIT ${idx} OFFSET ${idx + 1}"
        )
        count_query = f"SELECT COUNT(*) FROM alerts{where_clause}"
        params_with_page = [*params, page_size, (page - 1) * page_size]

        async with self.db_pool.acquire() as conn:
            rows = await conn.fetch(list_query, *params_with_page)
            total = await conn.fetchval(count_query, *params)

        alerts = [normalize_alert(dict(r)) for r in rows]
        return {
            "alerts": alerts,
            "total": int(total or 0),
            "page": page,
            "page_size": page_size,
            "has_next": page * page_size < int(total or 0),
        }

    async def get_alert(self, alert_id: str) -> Optional[dict]:
        self._ensure_db()
        async with self.db_pool.acquire() as conn:
            row = await conn.fetchrow(
                """
                SELECT id, event_id, rule_id, rule_name, severity, status, description,
                       notified_channels, created_at, acknowledged_at, resolved_at
                FROM alerts
                WHERE id = $1
                """,
                alert_id,
            )
            return normalize_alert(dict(row)) if row else None

    async def update_alert_status(self, alert_id: str, status_value: str) -> Optional[dict]:
        self._ensure_db()
        normalized_status = safe_enum(status_value, AlertStatusEnum, AlertStatusEnum.TRIGGERED.value)
        async with self.db_pool.acquire() as conn:
            row = await conn.fetchrow(
                """
                UPDATE alerts
                SET status = $1,
                    acknowledged_at = CASE WHEN $1 = 'acknowledged' THEN NOW() ELSE acknowledged_at END,
                    resolved_at = CASE WHEN $1 = 'resolved' THEN NOW() ELSE resolved_at END
                WHERE id = $2
                RETURNING id
                """,
                normalized_status,
                alert_id,
            )
        if not row:
            return None
        return await self.get_alert(alert_id)


class HoneypotService:
    def __init__(self, es):
        self.es = es

    def _ensure_es(self) -> None:
        if self.es is None:
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="Elasticsearch indisponivel",
            )

    async def query_sessions(self, filters: Optional[dict] = None, page=1, page_size=50):
        self._ensure_es()
        filters = filters or {}
        query_filters = []

        if filters.get("source_ip"):
            query_filters.append({"term": {_keyword_field("source_ip"): filters["source_ip"]}})
        if filters.get("username"):
            query_filters.append({"term": {_keyword_field("username"): filters["username"]}})
        if filters.get("start_time") or filters.get("end_time"):
            range_query = {}
            if filters.get("start_time"):
                range_query["gte"] = filters["start_time"].isoformat()
            if filters.get("end_time"):
                range_query["lte"] = filters["end_time"].isoformat()
            query_filters.append({"range": {"started_at": range_query}})

        query = {"bool": {"filter": query_filters}} if query_filters else {"match_all": {}}
        res = await self.es.search(
            index="honeypot_sessions",
            query=query,
            sort=[{"started_at": {"order": "desc"}}],
            from_=(page - 1) * page_size,
            size=page_size,
        )

        sessions = []
        for hit in res.get("hits", {}).get("hits", []):
            source = hit.get("_source", {})
            source["id"] = hit.get("_id")
            source["started_at"] = parse_dt(source.get("started_at"))
            if source.get("ended_at"):
                source["ended_at"] = parse_dt(source["ended_at"])
            source["commands_executed"] = source.get("commands_executed") or []
            sessions.append(source)

        total = res.get("hits", {}).get("total", {}).get("value", 0)
        return {
            "sessions": sessions,
            "total": total,
            "page": page,
            "page_size": page_size,
            "has_next": page * page_size < total,
        }


class DashboardService:
    def __init__(self, elasticsearch):
        self.es = elasticsearch

    def _ensure_es(self) -> None:
        if self.es is None:
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="Elasticsearch indisponivel",
            )

    async def get_kpis(self) -> dict:
        self._ensure_es()
        query_24h = {"range": {"timestamp": {"gte": "now-24h"}}}
        response = await self.es.search(
            index="soc_events",
            size=0,
            query=query_24h,
            aggs={
                "by_severity": {"terms": {"field": _keyword_field("severity"), "size": 10}},
                "unique_source_ips": {"cardinality": {"field": _keyword_field("source_ip")}},
                "by_event_type": {"terms": {"field": _keyword_field("event_type"), "size": 20}},
            },
        )
        honeypot = await self.es.count(
            index="honeypot_sessions",
            query={"range": {"started_at": {"gte": "now-24h"}}},
        )

        total_events = response.get("hits", {}).get("total", {}).get("value", 0)
        severity_buckets = {
            bucket["key"]: bucket["doc_count"]
            for bucket in response.get("aggregations", {}).get("by_severity", {}).get("buckets", [])
        }
        event_type_buckets = {
            bucket["key"]: bucket["doc_count"]
            for bucket in response.get("aggregations", {}).get("by_event_type", {}).get("buckets", [])
        }

        return {
            "total_events_24h": total_events,
            "total_alerts_24h": total_events,
            "critical_alerts": severity_buckets.get(SeverityEnum.CRITICAL.value, 0),
            "high_alerts": severity_buckets.get(SeverityEnum.HIGH.value, 0),
            "unique_source_ips": int(
                response.get("aggregations", {}).get("unique_source_ips", {}).get("value", 0)
            ),
            "honeypot_sessions_24h": honeypot.get("count", 0),
            "brute_force_attempts": event_type_buckets.get("auth_failure", 0),
            "port_scan_attempts": event_type_buckets.get("port_scan", 0),
        }

    async def get_time_series(self, interval: str = "1h") -> dict:
        self._ensure_es()
        try:
            response = await self.es.search(
                index="soc_events",
                size=0,
                query={"range": {"timestamp": {"gte": "now-24h"}}},
                aggs={
                    "events_over_time": {
                        "date_histogram": {
                            "field": "timestamp",
                            "calendar_interval": interval,
                        }
                    }
                },
            )
            buckets = (
                response.get("aggregations", {})
                .get("events_over_time", {})
                .get("buckets", [])
            )
            events = [{"timestamp": parse_dt(b["key_as_string"]), "count": b["doc_count"]} for b in buckets]
            return {"events": events, "alerts": []}
        except Exception as exc:
            logger.exception("Erro em get_time_series: %s", exc)
            return {"events": [], "alerts": []}

    async def get_top_items(self) -> dict:
        self._ensure_es()
        response = await self.es.search(
            index="soc_events",
            size=0,
            query={"range": {"timestamp": {"gte": "now-24h"}}},
            aggs={
                "top_source_ips": {"terms": {"field": _keyword_field("source_ip"), "size": 10}},
                "top_event_types": {"terms": {"field": _keyword_field("event_type"), "size": 10}},
                "top_usernames": {"terms": {"field": _keyword_field("username"), "size": 10}},
                "top_countries": {"terms": {"field": _keyword_field("geo_country"), "size": 10}},
            },
        )
        aggs = response.get("aggregations", {})

        def to_items(name: str):
            return [{"key": b.get("key", ""), "count": b.get("doc_count", 0)} for b in aggs.get(name, {}).get("buckets", [])]

        return {
            "top_source_ips": to_items("top_source_ips"),
            "top_event_types": to_items("top_event_types"),
            "top_usernames": to_items("top_usernames"),
            "top_countries": to_items("top_countries"),
        }
