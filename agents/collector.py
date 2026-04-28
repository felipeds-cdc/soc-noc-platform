"""
Log Collector Agent - SOC/NOC Platform
=======================================
Agente para coleta de logs do sistema (auth.log, syslog), monitoramento
processos e conexoes de rede.

AVISO ETICO: Use apenas em ambientes controlados e autorizados.
"""

from __future__ import annotations

import asyncio
import hashlib
import ipaddress
import json
import logging
import os
import random
import re
import socket
import subprocess
import time
import urllib.error
import urllib.request
import uuid
from collections import deque
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

try:
    import redis.asyncio as aioredis
except ModuleNotFoundError:
    aioredis = None


# Portas comumente usadas em reverse shells para deteccao
REVERSE_SHELL_PORTS = {4444, 4445, 1337, 31337, 9001, 9999, 6666}
SEVERITY_LEVELS = {"low", "medium", "high", "critical"}
SENSITIVE_KEYWORDS = {"password", "passwd", "token", "secret", "authorization", "api_key", "apikey"}


def utc_now_iso() -> str:
    """Retorna timestamp UTC no formato ISO-8601 com sufixo Z."""
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


class JsonFormatter(logging.Formatter):
    """Formatter de logs estruturados JSON."""

    def format(self, record: logging.LogRecord) -> str:
        payload: dict[str, Any] = {
            "timestamp": utc_now_iso(),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
        }

        if record.exc_info:
            payload["exception"] = self.formatException(record.exc_info)

        return json.dumps(payload, ensure_ascii=True)


def setup_logging() -> logging.Logger:
    """Configura logging estruturado."""
    logger = logging.getLogger("agent")
    if logger.handlers:
        return logger

    log_level = os.getenv("LOG_LEVEL", "INFO").upper()
    handler = logging.StreamHandler()
    handler.setFormatter(JsonFormatter())

    logger.setLevel(getattr(logging, log_level, logging.INFO))
    logger.addHandler(handler)
    logger.propagate = False
    return logger


logger = setup_logging()


@dataclass
class AgentConfig:
    """Configuracoes do agente via variaveis de ambiente."""

    backend_transport: str
    backend_url: str
    api_token: Optional[str]
    redis_stream: str
    request_timeout: float
    max_retries: int
    backoff_base: float
    backoff_max: float
    resend_interval: float
    resend_batch_size: int
    buffer_dir: Path
    buffer_max_files: int
    dedup_window_seconds: int
    dedup_max_items: int
    log_files: list[str]
    check_interval: int
    anonymize_logs: bool
    position_state_file: Path

    @classmethod
    def from_env(cls) -> "AgentConfig":
        log_files = [item.strip() for item in os.getenv("LOG_FILES", "/var/log/auth.log,/var/log/syslog").split(",") if item.strip()]
        backend_transport = os.getenv("BACKEND_TRANSPORT", "redis").lower().strip()

        default_redis_url = os.getenv("REDIS_URL", "redis://localhost:6379")
        backend_url = os.getenv("BACKEND_URL", default_redis_url).strip()

        return cls(
            backend_transport=backend_transport,
            backend_url=backend_url,
            api_token=os.getenv("API_TOKEN"),
            redis_stream=os.getenv("REDIS_STREAM", "soc_events").strip(),
            request_timeout=float(os.getenv("REQUEST_TIMEOUT_SECONDS", "5")),
            max_retries=max(1, int(os.getenv("PUBLISH_MAX_RETRIES", "5"))),
            backoff_base=max(0.1, float(os.getenv("BACKOFF_BASE_SECONDS", "0.5"))),
            backoff_max=max(0.5, float(os.getenv("BACKOFF_MAX_SECONDS", "15"))),
            resend_interval=max(1.0, float(os.getenv("RESEND_INTERVAL_SECONDS", "5"))),
            resend_batch_size=max(1, int(os.getenv("RESEND_BATCH_SIZE", "200"))),
            buffer_dir=Path(os.getenv("OFFLINE_BUFFER_DIR", "/tmp/soc_agent_buffer")),
            buffer_max_files=max(100, int(os.getenv("OFFLINE_BUFFER_MAX_FILES", "50000"))),
            dedup_window_seconds=max(1, int(os.getenv("EVENT_DEDUP_WINDOW_SECONDS", "30"))),
            dedup_max_items=max(1000, int(os.getenv("EVENT_DEDUP_MAX_ITEMS", "20000"))),
            log_files=log_files,
            check_interval=max(1, int(os.getenv("CHECK_INTERVAL", "5"))),
            anonymize_logs=os.getenv("ANONYMIZE_LOGS", "false").lower() == "true",
            position_state_file=Path(os.getenv("LOG_POSITION_STATE_FILE", "/tmp/soc_agent_state/log_positions.json")),
        )


class EventDeduplicator:
    """Deduplica eventos em janela de tempo para evitar duplicacao."""

    def __init__(self, window_seconds: int, max_items: int):
        self.window_seconds = window_seconds
        self.max_items = max_items
        self._fingerprints: dict[str, float] = {}
        self._order: deque[tuple[str, float]] = deque()

    def _cleanup(self, now: float) -> None:
        cutoff = now - self.window_seconds
        while self._order and self._order[0][1] < cutoff:
            fingerprint, ts = self._order.popleft()
            if self._fingerprints.get(fingerprint) == ts:
                self._fingerprints.pop(fingerprint, None)

        while len(self._order) > self.max_items:
            fingerprint, ts = self._order.popleft()
            if self._fingerprints.get(fingerprint) == ts:
                self._fingerprints.pop(fingerprint, None)

    @staticmethod
    def _fingerprint(event: dict[str, Any]) -> str:
        comparable = {
            "event_type": event.get("event_type"),
            "source": event.get("source"),
            "source_ip": event.get("source_ip"),
            "severity": event.get("severity"),
            "raw_log": event.get("raw_log"),
            "command": event.get("command"),
            "log_file": event.get("log_file"),
            "remote_address": event.get("remote_address"),
            "pid": event.get("pid"),
        }
        payload = json.dumps(comparable, sort_keys=True, ensure_ascii=True, separators=(",", ":"))
        return hashlib.sha256(payload.encode("utf-8")).hexdigest()

    def is_duplicate(self, event: dict[str, Any]) -> bool:
        now = time.time()
        self._cleanup(now)

        fingerprint = self._fingerprint(event)
        previous_ts = self._fingerprints.get(fingerprint)

        self._fingerprints[fingerprint] = now
        self._order.append((fingerprint, now))

        return previous_ts is not None and (now - previous_ts) <= self.window_seconds


class LocalEventBuffer:
    """Fila local em disco para eventos quando backend estiver indisponivel."""

    def __init__(self, directory: Path, max_files: int):
        self.directory = directory
        self.max_files = max_files
        self.directory.mkdir(parents=True, exist_ok=True)

    def _list_files(self) -> list[Path]:
        return sorted(self.directory.glob("*.json"))

    def size(self) -> int:
        return len(self._list_files())

    async def enqueue(self, event: dict[str, Any]) -> None:
        files = self._list_files()
        if len(files) >= self.max_files:
            overflow = len(files) - self.max_files + 1
            for path in files[:overflow]:
                path.unlink(missing_ok=True)
            logger.warning("Buffer offline lotado; eventos antigos removidos",)

        filename = f"{int(time.time() * 1000):013d}-{uuid.uuid4().hex}.json"
        target = self.directory / filename

        with target.open("w", encoding="utf-8") as file_obj:
            json.dump(event, file_obj, ensure_ascii=True)

    async def flush(self, sender, batch_size: int) -> int:
        sent = 0
        for event_file in self._list_files()[:batch_size]:
            try:
                with event_file.open("r", encoding="utf-8") as file_obj:
                    payload = json.load(file_obj)
            except Exception:
                event_file.unlink(missing_ok=True)
                continue

            delivered = await sender(payload)
            if not delivered:
                break

            event_file.unlink(missing_ok=True)
            sent += 1

        return sent


class FilePositionStore:
    """Persistencia local da posicao de leitura dos arquivos de log."""

    def __init__(self, path: Path):
        self.path = path
        self.path.parent.mkdir(parents=True, exist_ok=True)

    def load(self) -> dict[str, int]:
        if not self.path.exists():
            return {}
        try:
            with self.path.open("r", encoding="utf-8") as file_obj:
                raw = json.load(file_obj)
            if not isinstance(raw, dict):
                return {}
            return {str(key): max(0, int(value)) for key, value in raw.items()}
        except Exception:
            return {}

    def save(self, positions: dict[str, int]) -> None:
        temp_path = self.path.with_suffix(".tmp")
        with temp_path.open("w", encoding="utf-8") as file_obj:
            json.dump(positions, file_obj, ensure_ascii=True)
        temp_path.replace(self.path)


class EventNormalizer:
    """Normaliza e sanitiza eventos para schema consistente."""

    def __init__(self, anonymize_logs: bool):
        self.anonymize_logs = anonymize_logs

    @staticmethod
    def _sanitize_text(value: str) -> str:
        # Remove valores de segredos que possam aparecer no payload
        sensitive_pattern = re.compile(
            r"(?i)(password|passwd|token|secret|authorization|api[_-]?key)\s*[:=]\s*[^\s,;]+"
        )
        return sensitive_pattern.sub(lambda m: f"{m.group(1)}=[REDACTED]", value)

    def _sanitize_value(self, value: Any, key_name: str = "") -> Any:
        key_lower = key_name.lower()
        if key_lower in SENSITIVE_KEYWORDS:
            return "[REDACTED]"

        if isinstance(value, dict):
            return {str(k): self._sanitize_value(v, str(k)) for k, v in value.items()}
        if isinstance(value, list):
            return [self._sanitize_value(item, key_name) for item in value]
        if isinstance(value, tuple):
            return [self._sanitize_value(item, key_name) for item in value]
        if isinstance(value, str):
            return self._sanitize_text(value)
        return value

    def _normalize_ip(self, value: Any) -> str:
        if isinstance(value, str):
            raw = value.strip()
            if raw:
                # Extrai apenas host caso venha no formato "ip:porta"
                if raw.count(":") == 1 and "." in raw:
                    raw = raw.split(":", 1)[0]
                elif raw.startswith("[") and "]" in raw:
                    raw = raw[1:raw.index("]")]

                try:
                    return str(ipaddress.ip_address(raw))
                except ValueError:
                    pass

        return "0.0.0.0"

    @staticmethod
    def _normalize_severity(value: Any) -> str:
        severity = str(value or "low").strip().lower()
        return severity if severity in SEVERITY_LEVELS else "low"

    @staticmethod
    def _normalize_timestamp(value: Any) -> str:
        if isinstance(value, str) and value.strip():
            candidate = value.strip()
            try:
                datetime.fromisoformat(candidate.replace("Z", "+00:00"))
                return candidate
            except ValueError:
                return utc_now_iso()
        return utc_now_iso()

    def _anonymize_ip(self, text: str) -> str:
        if not self.anonymize_logs:
            return text
        ip_pattern = r"\b(\d{1,3}\.\d{1,3}\.\d{1,3})\.\d{1,3}\b"
        return re.sub(ip_pattern, r"\1.xxx", text)

    def normalize(self, raw_event: dict[str, Any]) -> dict[str, Any]:
        sanitized = self._sanitize_value(raw_event)
        if not isinstance(sanitized, dict):
            sanitized = {"raw_event": str(sanitized)}

        event_type = str(sanitized.get("event_type") or "unknown").strip() or "unknown"
        source = str(sanitized.get("source") or "agent").strip() or "agent"

        if "raw_log" in sanitized and isinstance(sanitized["raw_log"], str):
            sanitized["raw_log"] = self._anonymize_ip(sanitized["raw_log"])

        event = {
            **sanitized,
            "event_type": event_type,
            "source": source,
            "timestamp": self._normalize_timestamp(sanitized.get("timestamp")),
            "source_ip": self._normalize_ip(sanitized.get("source_ip")),
            "severity": self._normalize_severity(sanitized.get("severity")),
            "collected_at": utc_now_iso(),
        }

        # Garante JSON serializavel
        normalized: dict[str, Any] = {}
        for key, value in event.items():
            key_name = str(key)
            if value is None:
                continue
            if isinstance(value, (str, int, float, bool, list, dict)):
                normalized[key_name] = value
            else:
                normalized[key_name] = str(value)

        return normalized


class RedisTransport:
    """Transporte de eventos para Redis Streams."""

    def __init__(self, redis_url: str, stream: str, timeout_seconds: float):
        self.redis_url = redis_url
        self.stream = stream
        self.timeout_seconds = timeout_seconds
        self.client: Optional[aioredis.Redis] = None

    async def _connect(self) -> None:
        if aioredis is None:
            raise RuntimeError("Dependencia 'redis' nao instalada para transporte Redis")
        self.client = await aioredis.from_url(
            self.redis_url,
            decode_responses=True,
            socket_connect_timeout=self.timeout_seconds,
            socket_timeout=self.timeout_seconds,
            retry_on_timeout=True,
        )
        await self.client.ping()

    async def send(self, event: dict[str, Any]) -> None:
        if self.client is None:
            await self._connect()

        payload = {}
        for key, value in event.items():
            if isinstance(value, (dict, list)):
                payload[key] = json.dumps(value, ensure_ascii=True)
            else:
                payload[key] = str(value)

        try:
            await self.client.xadd(self.stream, payload)
        except Exception:
            if self.client is not None:
                try:
                    await self.client.aclose()
                except Exception:
                    pass
                self.client = None
            raise

    async def close(self) -> None:
        if self.client is not None:
            await self.client.aclose()
            self.client = None


class HttpTransport:
    """Transporte HTTP para backend de eventos."""

    def __init__(self, url: str, token: Optional[str], timeout_seconds: float):
        self.url = url
        self.token = token
        self.timeout_seconds = timeout_seconds

    async def send(self, event: dict[str, Any]) -> None:
        headers = {
            "Content-Type": "application/json",
            "User-Agent": "soc-agent/1.0",
        }
        if self.token:
            headers["Authorization"] = f"Bearer {self.token}"

        body = json.dumps(event, ensure_ascii=True).encode("utf-8")

        def _post() -> None:
            request = urllib.request.Request(self.url, data=body, headers=headers, method="POST")
            with urllib.request.urlopen(request, timeout=self.timeout_seconds) as response:
                status_code = getattr(response, "status", response.getcode())
                if status_code >= 400:
                    raise RuntimeError(f"HTTP {status_code}")

        try:
            await asyncio.to_thread(_post)
        except urllib.error.URLError as exc:
            raise ConnectionError(str(exc)) from exc

    async def close(self) -> None:
        return


class EventPublisher:
    """Publicador resiliente com retry, backoff e buffer offline."""

    def __init__(self, config: AgentConfig):
        self.config = config
        self.normalizer = EventNormalizer(anonymize_logs=config.anonymize_logs)
        self.buffer = LocalEventBuffer(config.buffer_dir, config.buffer_max_files)
        self.deduplicator = EventDeduplicator(config.dedup_window_seconds, config.dedup_max_items)
        self._lock = asyncio.Lock()
        self._resend_task: Optional[asyncio.Task] = None

        if config.backend_transport == "http":
            self.transport = HttpTransport(config.backend_url, config.api_token, config.request_timeout)
        else:
            self.transport = RedisTransport(config.backend_url, config.redis_stream, config.request_timeout)

    def _should_ignore_event(self, event: dict) -> bool:
        IGNORED_TYPES = ["system_log", "http_request"]
        IGNORED_SOURCES = ["frontend", "backend", "internal"]

        if event.get("event_type") in IGNORED_TYPES:
            return True

        if event.get("source") in IGNORED_SOURCES:
            return True

        return False
    
    async def initialize(self) -> None:
        if self.config.backend_transport == "http" and not self.config.api_token:
            logger.warning("API_TOKEN nao configurado; backend HTTP pode rejeitar autenticacao")

        logger.info(
            "Publicador inicializado",
        )

        self._resend_task = asyncio.create_task(self._resend_loop(), name="event-resend-loop")

    async def _send_with_retry(self, event: dict[str, Any]) -> bool:
        for attempt in range(1, self.config.max_retries + 1):
            try:
                await self.transport.send(event)
                return True
            except Exception as exc:
                if attempt >= self.config.max_retries:
                    logger.error(
                        f"Falha no envio apos {self.config.max_retries} tentativas: {exc}"
                    )
                    return False

                backoff = min(
                    self.config.backoff_base * (2 ** (attempt - 1)) + random.uniform(0, 0.2),
                    self.config.backoff_max,
                )
                logger.warning(
                    f"Falha no envio (tentativa {attempt}/{self.config.max_retries}): {exc}; retry em {backoff:.2f}s"
                )
                await asyncio.sleep(backoff)

        return False

    async def flush_buffer(self) -> int:
        async with self._lock:
            sent = await self.buffer.flush(self._send_with_retry, self.config.resend_batch_size)
            if sent > 0:
                logger.info(f"Eventos reenviados do buffer local: {sent}")
            return sent

    async def publish(self, event: dict):

        # 🚫 FILTRO PRINCIPAL
        if self._should_ignore_event(event):
                logger.debug(f"Evento ignorado: {event.get('event_type')}")
                return

        # normalização
        event = self.normalizer.normalize(event)

        # deduplicação
        if self.deduplicator.is_duplicate(event):
            return

        # envio
        await self.transport.send(event)

    async def _resend_loop(self) -> None:
        while True:
            try:
                if self.buffer.size() > 0:
                    await self.flush_buffer()
            except asyncio.CancelledError:
                raise
            except Exception as exc:
                logger.error(f"Erro no loop de reenvio: {exc}")

            await asyncio.sleep(self.config.resend_interval)

    async def close(self) -> None:
        if self._resend_task is not None:
            self._resend_task.cancel()
            try:
                await self._resend_task
            except asyncio.CancelledError:
                pass

        await self.transport.close()


class LogCollector:
    """Coletor de logs do sistema."""

    def __init__(self, publisher: EventPublisher, config: AgentConfig):
        self.publisher = publisher
        self.config = config
        self.position_store = FilePositionStore(config.position_state_file)
        self.file_positions: dict[str, int] = {}

    def classify_event(self, event: dict[str, Any]) -> str:
        if "ssh" in event.get("message", ""):
            return "auth_attempt"

        if "failed login" in event.get("message", ""):
            return "brute_force"

        return "system_log"

    async def initialize(self) -> None:
        self.file_positions = self.position_store.load()
        logger.info("Coletor de logs inicializado")

    async def _save_position(self, log_file: str, position: int) -> None:
        self.file_positions[log_file] = position
        self.position_store.save(self.file_positions)

    async def publish_log_event(self, log_file: str, line: str, timestamp: str) -> None:
        event = {
            "event_type": self.classify_event(event),
            "source": "agent",
            "timestamp": timestamp,
            "log_file": log_file,
            "raw_log": line,
            "severity": "low",
            "source_ip": "0.0.0.0",
        }

        line_lower = line.lower()
        if "failed password" in line_lower or "authentication failure" in line_lower:
            event["event_type"] = "auth_failure"
            event["severity"] = "medium"
            ip_match = re.search(r"(\d+\.\d+\.\d+\.\d+)", line)
            if ip_match:
                event["source_ip"] = ip_match.group(1)
            user_match = re.search(r"for\s+(?:invalid\s+user\s+)?(\S+)", line)
            if user_match:
                event["username"] = user_match.group(1)

        elif "accepted password" in line_lower or "accepted publickey" in line_lower:
            event["event_type"] = "auth_success"
            event["severity"] = "low"
            ip_match = re.search(r"(\d+\.\d+\.\d+\.\d+)", line)
            if ip_match:
                event["source_ip"] = ip_match.group(1)

        elif "sudo" in line_lower:
            event["event_type"] = "sudo_execution"
            event["severity"] = "medium"
            user_match = re.search(r"(\S+)\s+:", line)
            if user_match:
                event["username"] = user_match.group(1)
            cmd_match = re.search(r"COMMAND=(.+)$", line, re.IGNORECASE)
            if cmd_match:
                event["command"] = cmd_match.group(1)

        elif "invalid user" in line_lower:
            event["event_type"] = "invalid_user_attempt"
            event["severity"] = "low"
            user_match = re.search(r"invalid user\s+(\S+)", line)
            if user_match:
                event["username"] = user_match.group(1)
            ip_match = re.search(r"from\s+(\d+\.\d+\.\d+\.\d+)", line)
            if ip_match:
                event["source_ip"] = ip_match.group(1)

        await self.publisher.publish(event)

    async def read_new_lines(self, log_file: str) -> list[str]:
        log_path = Path(log_file.strip())
        if not log_path.exists():
            logger.warning(f"Arquivo de log nao encontrado: {log_file}")
            return []

        try:
            current_size = log_path.stat().st_size
            last_position = self.file_positions.get(log_file, 0)

            # Arquivo rotacionado
            if current_size < last_position:
                last_position = 0

            if current_size == last_position:
                return []

            lines: list[str] = []
            with log_path.open("r", errors="ignore") as file_obj:
                file_obj.seek(last_position)
                for line in file_obj:
                    cleaned = line.strip()
                    if cleaned:
                        lines.append(cleaned)
                new_position = file_obj.tell()

            await self._save_position(log_file, new_position)
            return lines

        except Exception as exc:
            logger.error(f"Erro ao ler {log_file}: {exc}")
            return []

    async def collect_logs(self) -> None:
        for log_file in self.config.log_files:
            new_lines = await self.read_new_lines(log_file)
            if not new_lines:
                continue

            for line in new_lines:
                timestamp = utc_now_iso()
                await self.publish_log_event(log_file, line, timestamp)

    async def start_collection(self) -> None:
        logger.info("Iniciando coleta continua de logs")
        while True:
            try:
                await self.collect_logs()
            except asyncio.CancelledError:
                raise
            except Exception as exc:
                logger.error(f"Erro na coleta de logs: {exc}")

            await asyncio.sleep(self.config.check_interval)


class ProcessMonitor:
    """Monitor de processos do sistema."""

    def __init__(self, publisher: EventPublisher):
        self.publisher = publisher
        self.known_processes: set[str] = set()
        self.suspicious_commands = [
            "nc ", "ncat", "netcat",
            "nmap", "masscan",
            "hydra", "john", "hashcat",
            "metasploit", "msfconsole",
            "sqlmap", "nikto",
            "dirb", "gobuster",
            "wget http", "curl http",
            "/tmp/",
            "chmod 777", "chmod +x",
            "base64 -d",
            "eval(",
            "bash -i",
            "python -c",
            "perl -e",
            "ruby -e",
            "php -r",
        ]

    async def check_processes(self) -> None:
        try:
            result = subprocess.run(["ps", "aux"], capture_output=True, text=True, timeout=10)
            if result.returncode != 0:
                return

            lines = result.stdout.strip().split("\n")[1:]
            current_processes: set[str] = set()

            for line in lines:
                parts = line.split(None, 10)
                if len(parts) < 11:
                    continue

                pid = parts[1]
                user = parts[0]
                command = parts[10]
                current_processes.add(pid)

                is_suspicious = any(cmd.lower() in command.lower() for cmd in self.suspicious_commands)
                if not is_suspicious:
                    continue

                event = {
                    "event_type": "suspicious_process",
                    "source": "agent",
                    "timestamp": utc_now_iso(),
                    "source_ip": "127.0.0.1",
                    "pid": pid,
                    "user": user,
                    "command": command,
                    "severity": "high",
                    "mitre_technique_id": "T1059",
                    "mitre_tactic": "Execution",
                }
                await self.publisher.publish(event)

            self.known_processes = current_processes

        except Exception as exc:
            logger.error(f"Erro ao verificar processos: {exc}")

    async def start_monitoring(self) -> None:
        logger.info("Iniciando monitoramento de processos")
        while True:
            try:
                await self.check_processes()
            except asyncio.CancelledError:
                raise
            except Exception as exc:
                logger.error(f"Erro no monitoramento de processos: {exc}")

            await asyncio.sleep(10)


class NetworkMonitor:
    """Monitor de conexoes de rede."""

    def __init__(self, publisher: EventPublisher):
        self.publisher = publisher
        self.previous_connections: set[str] = set()

    @staticmethod
    def _parse_port(address: str) -> Optional[int]:
        try:
            return int(address.rsplit(":", 1)[-1])
        except (ValueError, IndexError):
            return None

    @staticmethod
    def _parse_ip(address: str) -> str:
        # Converte "1.2.3.4:80" / "[::1]:80" para IP puro
        candidate = address
        if candidate.startswith("[") and "]" in candidate:
            candidate = candidate[1:candidate.index("]")]
        elif candidate.count(":") == 1 and "." in candidate:
            candidate = candidate.split(":", 1)[0]
        else:
            # IPv6 sem colchetes (pode conter multiplos :)
            candidate = candidate.rsplit(":", 1)[0] if ":" in candidate else candidate

        try:
            return str(ipaddress.ip_address(candidate))
        except ValueError:
            return "0.0.0.0"

    async def check_connections(self) -> None:
        try:
            result = subprocess.run(["ss", "-tunap", "--no-header"], capture_output=True, text=True, timeout=10)
            if result.returncode != 0:
                result = subprocess.run(["netstat", "-tunap"], capture_output=True, text=True, timeout=10)
                lines = result.stdout.strip().split("\n")[2:]
            else:
                lines = result.stdout.strip().split("\n")

            current_connections: set[str] = set()

            for line in lines:
                if not line.strip():
                    continue

                parts = line.split()
                if len(parts) < 6:
                    continue

                if parts[0] in ("tcp", "tcp6", "udp", "udp6"):
                    local_addr = parts[3]
                    remote_addr = parts[4]
                    state = parts[5] if len(parts) > 5 else ""
                    pid_program = parts[6] if len(parts) > 6 else ""
                else:
                    local_addr = parts[4]
                    remote_addr = parts[5]
                    state = parts[1]
                    pid_program = parts[6] if len(parts) > 6 else ""

                conn_key = f"{local_addr}->{remote_addr}"
                current_connections.add(conn_key)

                remote_port = self._parse_port(remote_addr)
                if state not in ("SYN_SENT", "ESTAB", "ESTABLISHED"):
                    continue

                if remote_port not in REVERSE_SHELL_PORTS:
                    continue

                event = {
                    "event_type": "suspicious_connection",
                    "source": "agent",
                    "timestamp": utc_now_iso(),
                    "source_ip": self._parse_ip(remote_addr),
                    "local_address": local_addr,
                    "remote_address": remote_addr,
                    "state": state,
                    "pid_program": pid_program,
                    "severity": "critical",
                    "description": f"Possivel reverse shell detectado (porta {remote_port})",
                    "mitre_technique_id": "T1059",
                    "mitre_tactic": "Command and Control",
                }
                await self.publisher.publish(event)

            self.previous_connections = current_connections

        except FileNotFoundError:
            logger.error("Nem 'ss' nem 'netstat' foram encontrados no sistema")
        except Exception as exc:
            logger.error(f"Erro ao verificar conexoes: {exc}")

    async def start_monitoring(self) -> None:
        logger.info("Iniciando monitoramento de rede")
        while True:
            try:
                await self.check_connections()
            except asyncio.CancelledError:
                raise
            except Exception as exc:
                logger.error(f"Erro no monitoramento de rede: {exc}")

            await asyncio.sleep(15)


async def main() -> None:
    """Funcao principal do agente."""
    config = AgentConfig.from_env()

    logger.info("=" * 60)
    logger.info("SOC/NOC Platform - Agente de Coleta")
    logger.info("=" * 60)

    publisher = EventPublisher(config)
    await publisher.initialize()

    collector = LogCollector(publisher, config)
    await collector.initialize()

    process_monitor = ProcessMonitor(publisher)
    network_monitor = NetworkMonitor(publisher)

    tasks = [
        asyncio.create_task(collector.start_collection(), name="collector-loop"),
        asyncio.create_task(process_monitor.start_monitoring(), name="process-monitor-loop"),
        asyncio.create_task(network_monitor.start_monitoring(), name="network-monitor-loop"),
    ]

    try:
        await asyncio.gather(*tasks)
    except KeyboardInterrupt:
        logger.info("Agente encerrado pelo usuario")
    except Exception as exc:
        logger.error(f"Erro fatal no agente: {exc}")
        raise
    finally:
        for task in tasks:
            task.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)
        await publisher.close()


if __name__ == "__main__":
    asyncio.run(main())
