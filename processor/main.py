"""
Event Processor - SOC/NOC Platform
===================================
Processador de eventos que consome Redis Streams, normaliza, enriquece,
classifica/correlaciona e persiste com resiliencia em Elasticsearch e PostgreSQL.
"""

from __future__ import annotations

import asyncio
import ipaddress
import json
import logging
import os
import random
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any, Callable, Optional

try:
    import redis.asyncio as aioredis
except Exception:  # pragma: no cover - fallback para ambientes sem dependencia
    aioredis = None

try:
    from elasticsearch import AsyncElasticsearch
except Exception:  # pragma: no cover - fallback para ambientes sem dependencia
    AsyncElasticsearch = None

try:
    import asyncpg
except Exception:  # pragma: no cover - fallback para ambientes sem dependencia
    asyncpg = None


logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
)
logger = logging.getLogger("processor")


# Conexoes
REDIS_URL = os.getenv("REDIS_URL", "redis://localhost:6379")
ELASTICSEARCH_URL = os.getenv("ELASTICSEARCH_URL", "http://localhost:9200")
DATABASE_URL = os.getenv(
    "DATABASE_URL",
    "postgresql+asyncpg://soc_user:soc_password123@localhost:5432/soc_noc",
)

# Streams e grupos
STREAM_NAME = os.getenv("PROCESSOR_STREAM", "soc_events")
DLQ_STREAM_NAME = os.getenv("PROCESSOR_DLQ_STREAM", "soc_events_dlq")
DLQ_MAXLEN = int(os.getenv("PROCESSOR_DLQ_MAXLEN", "50000"))
CONSUMER_GROUP = os.getenv("PROCESSOR_CONSUMER_GROUP", "processor_group")
CONSUMER_NAME = os.getenv("PROCESSOR_CONSUMER_NAME", "processor_1")

# Processamento
BATCH_SIZE = int(os.getenv("BATCH_SIZE", "200"))
PROCESS_INTERVAL = float(os.getenv("PROCESS_INTERVAL", "0.2"))
MAX_CONCURRENT_EVENT_TASKS = int(os.getenv("MAX_CONCURRENT_EVENT_TASKS", "25"))

# Retry / startup
STARTUP_MAX_RETRIES = int(os.getenv("STARTUP_MAX_RETRIES", "60"))
STARTUP_RETRY_DELAY = float(os.getenv("STARTUP_RETRY_DELAY", "2"))
STORAGE_RETRY_ATTEMPTS = int(os.getenv("STORAGE_RETRY_ATTEMPTS", "4"))
RETRY_BASE_DELAY = float(os.getenv("RETRY_BASE_DELAY", "0.3"))

# Correlacao
BRUTEFORCE_THRESHOLD = int(os.getenv("BRUTEFORCE_THRESHOLD", "5"))
BRUTEFORCE_WINDOW_SECONDS = int(os.getenv("BRUTEFORCE_WINDOW_SECONDS", "300"))
BRUTEFORCE_COOLDOWN_SECONDS = int(os.getenv("BRUTEFORCE_COOLDOWN_SECONDS", "600"))

# Health
HEARTBEAT_FILE = os.getenv("PROCESSOR_HEARTBEAT_FILE", "/tmp/processor_heartbeat")

# Reputacao de IP (simulado para ambiente lab)
KNOWN_MALICIOUS_RANGES = ["10.0.0.", "192.168.100."]
KNOWN_SAFE_RANGES = ["127.0.0.", "192.168.1."]

SEVERITY_ORDER = ["low", "medium", "high", "critical"]
VALID_SEVERITIES = set(SEVERITY_ORDER)

# Mapeamento basico de deteccao para MITRE ATT&CK
MITRE_MAPPING = {
    "honeypot_login": {"mitre_technique_id": "T1110", "mitre_tactic": "Credential Access"},
    "ssh_bruteforce_detected": {
        "mitre_technique_id": "T1110.001",
        "mitre_tactic": "Credential Access",
    },
    "auth_failure": {"mitre_technique_id": "T1110", "mitre_tactic": "Credential Access"},
    "suspicious_process": {
        "mitre_technique_id": "T1059",
        "mitre_tactic": "Execution",
    },
    "suspicious_connection": {
        "mitre_technique_id": "T1071",
        "mitre_tactic": "Command and Control",
    },
}


class ValidationError(Exception):
    """Erro de validacao de schema/evento."""


class StorageError(Exception):
    """Erro de persistencia."""


@dataclass
class PreparedEvent:
    message_id: str
    raw: dict[str, Any]
    event: dict[str, Any]


class GeoIPEnricher:
    """Simula enriquecimento GeoIP (em producao, usar MaxMind)."""

    SIMULATED_GEO = {
        "10.0.0.": {"country": "Unknown", "city": "Unknown", "lat": 0.0, "lon": 0.0, "asn": 0},
        "192.168.100.": {
            "country": "Lab Network",
            "city": "Internal",
            "lat": -15.7939,
            "lon": -47.8828,
            "asn": 64512,
        },
        "203.0.113.": {"country": "CN", "city": "Beijing", "lat": 39.9042, "lon": 116.4074, "asn": 4808},
        "198.51.100.": {"country": "RU", "city": "Moscow", "lat": 55.7558, "lon": 37.6173, "asn": 12389},
        "172.16.0.": {"country": "US", "city": "New York", "lat": 40.7128, "lon": -74.0060, "asn": 15169},
    }

    @classmethod
    def enrich(cls, ip_address: str) -> dict[str, Any]:
        for prefix, geo_data in cls.SIMULATED_GEO.items():
            if ip_address.startswith(prefix):
                return geo_data

        hash_val = sum(ord(char) for char in ip_address)
        countries = ["US", "BR", "DE", "FR", "GB", "JP", "KR", "IN", "RU", "CN"]
        cities = ["Unknown", "Internal", "Lab", "Test"]
        return {
            "country": countries[hash_val % len(countries)],
            "city": cities[hash_val % len(cities)],
            "lat": float((hash_val % 180) - 90),
            "lon": float((hash_val % 360) - 180),
            "asn": int((hash_val % 65535) + 1000),
        }


class IPReputationChecker:
    """Verifica reputacao de IP (simulado)."""

    @classmethod
    def check_reputation(cls, ip_address: str) -> dict[str, Any]:
        score = 50
        if any(ip_address.startswith(prefix) for prefix in KNOWN_MALICIOUS_RANGES):
            score = 10
            threat_level = "high"
        elif any(ip_address.startswith(prefix) for prefix in KNOWN_SAFE_RANGES):
            score = 90
            threat_level = "low"
        else:
            hash_val = sum(ord(char) for char in ip_address)
            score = hash_val % 100
            threat_level = "low" if score > 70 else ("medium" if score > 40 else "high")

        return {
            "reputation_score": int(score),
            "threat_level": threat_level,
            "is_malicious": score < 30,
            "is_safe": score > 70,
        }


class EventProcessor:
    """Processador principal de eventos."""

    def __init__(
        self,
        redis_client: Any = None,
        elasticsearch_client: Any = None,
        postgres_pool: Any = None,
    ):
        self.redis = redis_client
        self.elasticsearch = elasticsearch_client
        self.postgres_pool = postgres_pool
        self.consumer_group = CONSUMER_GROUP
        self.consumer_name = CONSUMER_NAME
        self._initialized = False
        self._event_semaphore = asyncio.Semaphore(MAX_CONCURRENT_EVENT_TASKS)

    async def _touch_heartbeat(self) -> None:
        with open(HEARTBEAT_FILE, "w", encoding="utf-8") as heartbeat:
            heartbeat.write(datetime.now(UTC).isoformat())

    async def _create_consumer_group(self) -> None:
        try:
            await self.redis.xgroup_create(STREAM_NAME, self.consumer_group, mkstream=True)
        except Exception as exc:
            if "BUSYGROUP" not in str(exc):
                logger.warning("Aviso ao criar consumer group: %s", exc)

    async def _close_connections(self) -> None:
        if self.elasticsearch:
            try:
                await self.elasticsearch.close()
            except Exception:
                pass
            self.elasticsearch = None

        if self.postgres_pool:
            try:
                await self.postgres_pool.close()
            except Exception:
                pass
            self.postgres_pool = None

        if self.redis:
            try:
                await self.redis.aclose()
            except Exception:
                pass
            self.redis = None

    async def _ensure_connections(self) -> None:
        if aioredis is None or AsyncElasticsearch is None or asyncpg is None:
            raise RuntimeError("Dependencias ausentes: redis/elasticsearch/asyncpg")

        await self._close_connections()
        last_error = None

        for attempt in range(1, STARTUP_MAX_RETRIES + 1):
            try:
                self.redis = await aioredis.from_url(REDIS_URL, decode_responses=True)
                await self.redis.ping()
                await self._create_consumer_group()

                self.elasticsearch = AsyncElasticsearch([ELASTICSEARCH_URL])
                health = await self.elasticsearch.cluster.health()
                logger.info("Elasticsearch status: %s", health.get("status", "unknown"))

                pg_url = DATABASE_URL.replace("postgresql+asyncpg://", "postgresql://")
                self.postgres_pool = await asyncpg.create_pool(pg_url)

                await self._ensure_elasticsearch_indices()
                self._initialized = True
                await self._touch_heartbeat()
                logger.info("Processador inicializado com sucesso")
                return
            except Exception as exc:
                last_error = exc
                logger.warning(
                    "Dependencias indisponiveis (%s/%s): %s",
                    attempt,
                    STARTUP_MAX_RETRIES,
                    exc,
                )
                await asyncio.sleep(STARTUP_RETRY_DELAY)

        raise RuntimeError(f"Falha ao conectar dependencias apos retries: {last_error}")

    async def initialize(self) -> None:
        if self.redis and self.elasticsearch and self.postgres_pool:
            self._initialized = True
            return
        await self._ensure_connections()

    async def _ensure_elasticsearch_indices(self) -> None:
        indices = {
            "soc_events": {
                "mappings": {
                    "properties": {
                        "id": {"type": "keyword"},
                        "timestamp": {"type": "date"},
                        "status": {"type": "keyword"},
                        "classification": {"type": "keyword"},
                        "event_type": {"type": "keyword"},
                        "source": {"type": "keyword"},
                        "severity": {"type": "keyword"},
                        "source_ip": {"type": "ip"},
                        "destination_ip": {"type": "ip"},
                        "username": {"type": "keyword"},
                        "mitre_technique_id": {"type": "keyword"},
                        "mitre_tactic": {"type": "keyword"},
                        "raw_log": {"type": "text"},
                        "geo_country": {"type": "keyword"},
                        "geo_city": {"type": "keyword"},
                        "geo_latitude": {"type": "float"},
                        "geo_longitude": {"type": "float"},
                        "asn": {"type": "integer"},
                        "reputation_score": {"type": "integer"},
                        "threat_level": {"type": "keyword"},
                    }
                }
            },
            "honeypot_sessions": {
                "mappings": {
                    "properties": {
                        "id": {"type": "keyword"},
                        "session_id": {"type": "keyword"},
                        "timestamp": {"type": "date"},
                        "status": {"type": "keyword"},
                        "source_ip": {"type": "ip"},
                        "username": {"type": "keyword"},
                        "password": {"type": "keyword"},
                        "started_at": {"type": "date"},
                        "ended_at": {"type": "date"},
                        "commands_executed": {"type": "keyword"},
                        "geo_country": {"type": "keyword"},
                        "geo_latitude": {"type": "float"},
                        "geo_longitude": {"type": "float"},
                    }
                }
            },
        }

        for index_name, mapping in indices.items():
            if not await self.elasticsearch.indices.exists(index=index_name):
                await self.elasticsearch.indices.create(index=index_name, body=mapping)
                logger.info("Indice criado: %s", index_name)

    async def process_events(self) -> None:
        logger.info("Iniciando processamento de eventos...")

        while True:
            try:
                await self._touch_heartbeat()
                response = await self.redis.xreadgroup(
                    self.consumer_group,
                    self.consumer_name,
                    {STREAM_NAME: ">"},
                    count=BATCH_SIZE,
                    block=5000,
                )

                if response:
                    all_messages: list[tuple[str, dict[str, Any]]] = []
                    for _, messages in response:
                        all_messages.extend(messages)

                    ack_ids = await self._process_batch(all_messages)
                    if ack_ids:
                        await self.redis.xack(STREAM_NAME, self.consumer_group, *ack_ids)

                await asyncio.sleep(PROCESS_INTERVAL)
            except asyncio.CancelledError:
                logger.info("Processamento encerrado")
                break
            except Exception as exc:
                logger.error("Erro no loop de processamento: %s", exc)
                self._initialized = False
                await self._ensure_connections()
                await asyncio.sleep(2)

    async def _process_batch(self, messages: list[tuple[str, dict[str, Any]]]) -> list[str]:
        prepared: list[PreparedEvent] = []
        ack_ids: set[str] = set()

        tasks = [self._prepare_message(message_id, message_data) for message_id, message_data in messages]
        results = await asyncio.gather(*tasks)

        for result in results:
            if result is None:
                continue
            if isinstance(result, str):
                ack_ids.add(result)
                continue
            prepared.append(result)

        if not prepared:
            return list(ack_ids)

        try:
            es_failed_ids = await self._store_elasticsearch_bulk(prepared)
        except Exception as exc:
            logger.error("Falha total no bulk do Elasticsearch: %s", exc)
            for item in prepared:
                if await self._send_to_dlq(item.message_id, item.raw, "elasticsearch", str(exc)):
                    ack_ids.add(item.message_id)
            return list(ack_ids)

        es_success = [item for item in prepared if item.message_id not in es_failed_ids]
        for item in prepared:
            if item.message_id in es_failed_ids:
                if await self._send_to_dlq(item.message_id, item.raw, "elasticsearch", "erro em item de bulk"):
                    ack_ids.add(item.message_id)

        if es_success:
            pg_candidates = [item for item in es_success if item.event.get("severity") in {"high", "critical"}]
            if pg_candidates:
                pg_failed_ids = await self._store_postgresql_batch(pg_candidates)
            else:
                pg_failed_ids = set()

            for item in es_success:
                if item.message_id in pg_failed_ids:
                    if await self._send_to_dlq(item.message_id, item.raw, "postgresql", "falha ao persistir evento critico"):
                        ack_ids.add(item.message_id)
                else:
                    ack_ids.add(item.message_id)

        return list(ack_ids)

    async def _prepare_message(
        self,
        message_id: str,
        message_data: dict[str, Any],
    ) -> PreparedEvent | str | None:
        async with self._event_semaphore:
            try:
                normalized = await self._parse_and_normalize(message_id, message_data)
                enriched = await self._enrich_event(normalized)
                classified = self._classify_and_map_event(enriched)
                await self._correlate_bruteforce(classified)
                return PreparedEvent(message_id=message_id, raw=message_data, event=classified)
            except ValidationError as exc:
                logger.warning("Evento invalido %s: %s", message_id, exc)
                if await self._send_to_dlq(message_id, message_data, "validation", str(exc)):
                    return message_id
                return None
            except Exception as exc:
                logger.error("Falha ao preparar evento %s: %s", message_id, exc)
                if await self._send_to_dlq(message_id, message_data, "processing", str(exc)):
                    return message_id
                return None

    async def _parse_and_normalize(self, message_id: str, event_data: dict[str, Any]) -> dict[str, Any]:
        if not isinstance(event_data, dict):
            raise ValidationError("payload nao eh objeto")

        event = dict(event_data)
        event["id"] = str(event.get("id") or message_id)
        event["source"] = str(event.get("source") or "unknown")
        event["status"] = str(event.get("status") or "new").lower()

        event_type = event.get("event_type")
        if not isinstance(event_type, str) or not event_type.strip():
            raise ValidationError("campo obrigatorio ausente: event_type")
        event["event_type"] = event_type.strip().lower()

        event["timestamp_dt"] = self._normalize_timestamp(event.get("timestamp"))
        event["timestamp"] = event["timestamp_dt"].isoformat().replace("+00:00", "Z")

        if isinstance(event.get("data"), str):
            try:
                parsed_data = json.loads(event["data"])
                if isinstance(parsed_data, dict):
                    event["parsed_data"] = parsed_data
                    for key, value in parsed_data.items():
                        event.setdefault(key, value)
                else:
                    event["parsed_data"] = {}
            except json.JSONDecodeError:
                raise ValidationError("campo data contem JSON invalido")
        else:
            event["parsed_data"] = event.get("parsed_data") or {}

        severity = str(event.get("severity") or "low").lower()
        event["severity"] = severity if severity in VALID_SEVERITIES else "low"

        for field in ("source_port", "destination_port", "attempts"):
            if field in event and event[field] not in (None, ""):
                try:
                    event[field] = int(event[field])
                except (TypeError, ValueError):
                    raise ValidationError(f"campo {field} deve ser inteiro")

        for field in ("source_ip", "destination_ip"):
            if field in event and event[field]:
                event[field] = str(event[field]).strip()
                try:
                    ipaddress.ip_address(event[field])
                except ValueError as exc:
                    raise ValidationError(f"campo {field} invalido: {event[field]}") from exc

        return event

    def _normalize_timestamp(self, value: Any) -> datetime:
        if value is None or value == "":
            return datetime.now(UTC)

        if isinstance(value, datetime):
            if value.tzinfo is None:
                return value.replace(tzinfo=UTC)
            return value.astimezone(UTC)

        if isinstance(value, (int, float)):
            epoch = float(value)
            if epoch > 10_000_000_000:
                epoch /= 1000.0
            return datetime.fromtimestamp(epoch, tz=UTC)

        if isinstance(value, str):
            raw = value.strip()
            if raw.endswith("Z"):
                raw = raw[:-1] + "+00:00"
            try:
                parsed = datetime.fromisoformat(raw)
            except ValueError as exc:
                raise ValidationError("timestamp invalido") from exc

            if parsed.tzinfo is None:
                parsed = parsed.replace(tzinfo=UTC)
            return parsed.astimezone(UTC)

        raise ValidationError("timestamp invalido")

    async def _enrich_event(self, event: dict[str, Any]) -> dict[str, Any]:
        source_ip = event.get("source_ip")
        if source_ip:
            geo_data = GeoIPEnricher.enrich(source_ip)
            event.update(
                {
                    "geo_country": geo_data["country"],
                    "geo_city": geo_data["city"],
                    "geo_latitude": geo_data["lat"],
                    "geo_longitude": geo_data["lon"],
                    "asn": geo_data["asn"],
                }
            )
            event.update(IPReputationChecker.check_reputation(source_ip))

        destination_ip = event.get("destination_ip")
        if destination_ip:
            dest_geo = GeoIPEnricher.enrich(destination_ip)
            event["dest_geo_country"] = dest_geo["country"]

        return event

    def _classify_and_map_event(self, event: dict[str, Any]) -> dict[str, Any]:
        event_type = str(event.get("event_type", "")).lower()

        if "auth" in event_type or "login" in event_type:
            event["classification"] = "authentication"
        elif "process" in event_type:
            event["classification"] = "process"
        elif "connection" in event_type or "network" in event_type:
            event["classification"] = "network"
        else:
            event["classification"] = "system"

        if event_type in MITRE_MAPPING:
            event.update(MITRE_MAPPING[event_type])

        severity_from_type = {
            "honeypot_login": "medium",
            "honeypot_command": "low",
            "honeypot_session": "medium",
            "auth_failure": "medium",
            "auth_success": "low",
            "suspicious_process": "high",
            "suspicious_connection": "critical",
            "ssh_bruteforce_detected": "high",
            "system_log": "low",
        }
        if event_type in severity_from_type:
            event["severity"] = severity_from_type[event_type]

        if event.get("is_malicious"):
            current_idx = SEVERITY_ORDER.index(event["severity"])
            event["severity"] = SEVERITY_ORDER[min(current_idx + 1, len(SEVERITY_ORDER) - 1)]

        return event

    async def _correlate_bruteforce(self, event: dict[str, Any]) -> None:
        event_type = str(event.get("event_type", ""))
        source_ip = event.get("source_ip")

        if event_type not in {"honeypot_login", "auth_failure"} or not source_ip:
            return

        counter_key = f"corr:bf:{source_ip}"
        cooldown_key = f"corr:bf:cooldown:{source_ip}"

        attempts = await self.redis.incr(counter_key)
        if attempts == 1:
            await self.redis.expire(counter_key, BRUTEFORCE_WINDOW_SECONDS)

        if attempts < BRUTEFORCE_THRESHOLD:
            return

        if await self.redis.exists(cooldown_key):
            return

        alert_event = {
            "id": f"bf-{source_ip}-{int(datetime.now(UTC).timestamp())}",
            "event_type": "ssh_bruteforce_detected",
            "source": "processor",
            "source_ip": source_ip,
            "attempts": attempts,
            "timestamp": datetime.now(UTC).isoformat().replace("+00:00", "Z"),
            "severity": "high",
            "status": "new",
        }

        await self.redis.xadd(STREAM_NAME, alert_event)
        await self.redis.setex(cooldown_key, BRUTEFORCE_COOLDOWN_SECONDS, "1")

    async def _store_elasticsearch_bulk(self, prepared_events: list[PreparedEvent]) -> set[str]:
        if not prepared_events:
            return set()

        operations: list[dict[str, Any]] = []
        order: list[str] = []
        for item in prepared_events:
            index_name = "honeypot_sessions" if item.event.get("event_type") == "honeypot_session" else "soc_events"
            operations.append({"index": {"_index": index_name, "_id": item.event["id"]}})

            payload = dict(item.event)
            payload.pop("timestamp_dt", None)
            operations.append(payload)
            order.append(item.message_id)

        async def do_bulk() -> dict[str, Any]:
            try:
                return await self.elasticsearch.bulk(operations=operations)
            except TypeError:
                return await self.elasticsearch.bulk(body=operations)

        response = await self._retry_operation(do_bulk, "elasticsearch_bulk")

        failed_ids: set[str] = set()
        if response.get("errors"):
            items = response.get("items") or []
            for idx, item in enumerate(items):
                op_data = item.get("index") or item.get("create") or item.get("update") or item.get("delete") or {}
                status = op_data.get("status", 500)
                if int(status) >= 400 and idx < len(order):
                    failed_ids.add(order[idx])

        return failed_ids

    async def _store_postgresql_batch(self, prepared_events: list[PreparedEvent]) -> set[str]:
        if not prepared_events:
            return set()

        rows = []
        message_ids = []
        for item in prepared_events:
            event = item.event
            rows.append(
                (
                    event.get("timestamp_dt") or datetime.now(UTC),
                    event.get("source", "unknown"),
                    event.get("event_type", "unknown"),
                    event.get("severity", "low"),
                    event.get("source_ip"),
                    event.get("destination_ip"),
                    event.get("source_port"),
                    event.get("destination_port"),
                    event.get("protocol"),
                    event.get("username"),
                    event.get("password"),
                    event.get("command"),
                    json.dumps(event.get("parsed_data", {})),
                    event.get("raw_log"),
                    event.get("mitre_technique_id"),
                    event.get("mitre_tactic"),
                    event.get("status", "new"),
                )
            )
            message_ids.append(item.message_id)

        query = """
            INSERT INTO events (
                timestamp, source, event_type, severity,
                source_ip, destination_ip, source_port, destination_port,
                protocol, username, password, command,
                payload, raw_log, mitre_technique_id, mitre_tactic,
                status
            ) VALUES (
                $1, $2, $3, $4, $5, $6, $7, $8, $9, $10,
                $11, $12, $13, $14, $15, $16, $17
            )
        """

        async def do_batch_insert() -> None:
            async with self.postgres_pool.acquire() as conn:
                await conn.executemany(query, rows)

        try:
            await self._retry_operation(do_batch_insert, "postgres_batch_insert")
            return set()
        except Exception as exc:
            logger.error("Erro no batch PostgreSQL (%s eventos): %s", len(rows), exc)
            return set(message_ids)

    async def _retry_operation(
        self,
        operation_factory: Callable[[], Any],
        operation_name: str,
    ) -> Any:
        last_error = None
        for attempt in range(1, STORAGE_RETRY_ATTEMPTS + 1):
            try:
                return await operation_factory()
            except Exception as exc:
                last_error = exc
                if attempt >= STORAGE_RETRY_ATTEMPTS:
                    break
                delay = min(RETRY_BASE_DELAY * (2 ** (attempt - 1)), 5.0)
                delay += random.uniform(0.0, RETRY_BASE_DELAY)
                logger.warning(
                    "Falha em %s (tentativa %s/%s): %s. Retry em %.2fs",
                    operation_name,
                    attempt,
                    STORAGE_RETRY_ATTEMPTS,
                    exc,
                    delay,
                )
                await asyncio.sleep(delay)

        raise StorageError(f"{operation_name} falhou apos retries: {last_error}")

    async def _send_to_dlq(
        self,
        message_id: str,
        payload: dict[str, Any],
        stage: str,
        error: str,
    ) -> bool:
        try:
            dlq_event = {
                "original_message_id": str(message_id),
                "failed_stage": stage,
                "error": str(error)[:1000],
                "timestamp": datetime.now(UTC).isoformat().replace("+00:00", "Z"),
                "payload": json.dumps(payload, default=str),
            }
            await self.redis.xadd(
                DLQ_STREAM_NAME,
                dlq_event,
                maxlen=DLQ_MAXLEN,
                approximate=False,
            )
            return True
        except Exception as exc:
            logger.error("Falha ao enviar evento %s para DLQ: %s", message_id, exc)
            return False

    async def cleanup(self) -> None:
        await self._close_connections()
        try:
            if os.path.exists(HEARTBEAT_FILE):
                os.remove(HEARTBEAT_FILE)
        except Exception:
            pass
        logger.info("Recursos liberados")


async def main() -> None:
    logger.info("=" * 60)
    logger.info("  SOC/NOC Platform - Processador de Eventos")
    logger.info("=" * 60)

    processor = EventProcessor()
    try:
        await processor.initialize()
        await processor.process_events()
    except KeyboardInterrupt:
        logger.info("Processador encerrado pelo usuario")
    except Exception as exc:
        logger.error("Erro fatal: %s", exc)
        raise
    finally:
        await processor.cleanup()


if __name__ == "__main__":
    asyncio.run(main())
