"""
SSH Honeypot - SOC/NOC Platform
================================
Honeypot SSH para captura de credenciais, comandos e telemetria de ataque.
Destinado exclusivamente para ambientes autorizados e laboratoriais.

⚠️ AVISO ÉTICO: Use apenas em ambientes controlados e autorizados.
"""

import asyncio
import hashlib
import ipaddress
import json
import logging
import os
import random
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional
from urllib import error as urlerror
from urllib import request as urlrequest

import asyncssh
import redis.asyncio as aioredis

try:
    import geoip2.database as geoip2_database
except Exception:
    geoip2_database = None


# Configuração
HONEYPOT_HOST = os.getenv("HONEYPOT_HOST", "0.0.0.0")
HONEYPOT_PORT = int(os.getenv("HONEYPOT_PORT", "2222"))
HONEYPOT_PROTOCOL = os.getenv("HONEYPOT_PROTOCOL", "ssh")
HONEYPOT_LOG_FILE = os.getenv("HONEYPOT_LOG_FILE", "./honeypot.log")
REDIS_URL = os.getenv("REDIS_URL", "redis://localhost:6379")
REDIS_STREAM = os.getenv("REDIS_STREAM", "soc_events")
FAILED_EVENTS_FILE = os.getenv("FAILED_EVENTS_FILE", "./failed_honeypot_events.jsonl")

# Integrações opcionais
ELASTICSEARCH_URL = os.getenv("ELASTICSEARCH_URL", "").rstrip("/")
ELASTICSEARCH_INDEX = os.getenv("ELASTICSEARCH_INDEX", "soc-honeypot-events")
ELASTICSEARCH_API_KEY = os.getenv("ELASTICSEARCH_API_KEY", "")
ELASTICSEARCH_USERNAME = os.getenv("ELASTICSEARCH_USERNAME", "")
ELASTICSEARCH_PASSWORD = os.getenv("ELASTICSEARCH_PASSWORD", "")
BACKEND_EVENTS_URL = os.getenv("BACKEND_EVENTS_URL", "")
BACKEND_TOKEN = os.getenv("BACKEND_TOKEN", "")

# GeoIP
GEOIP_DB_PATH = os.getenv("GEOIP_DB_PATH", "")

# SSH
SSH_BANNER = os.getenv("HONEYPOT_SSH_BANNER", "OpenSSH_8.9p1 Ubuntu-3ubuntu0.6")
SSH_HOST_KEY_PATH = os.getenv("HONEYPOT_SSH_HOST_KEY", "./.honeypot/ssh_host_rsa_key")
MAX_AUTH_ATTEMPTS_PER_CONNECTION = int(os.getenv("MAX_AUTH_ATTEMPTS_PER_CONNECTION", "6"))
SESSION_GROUP_WINDOW_SECONDS = int(os.getenv("SESSION_GROUP_WINDOW_SECONDS", "1800"))

# Credenciais fracas plausíveis que simulam comprometimento real
FAKE_CREDENTIALS = {
    "root": "root",
    "admin": "admin123",
    "ubuntu": "ubuntu",
    "oracle": "oracle",
    "postgres": "postgres",
    "mysql": "mysql",
    "user": "password",
}

# Sistema simulado
SIMULATED_FILESYSTEM = {
    "/": ["bin", "boot", "dev", "etc", "home", "lib", "opt", "root", "tmp", "usr", "var"],
    "/root": [".bash_history", ".ssh", "backup", "install.sh", "notes.txt"],
    "/var/log": ["auth.log", "syslog", "kern.log", "apache2"],
    "/etc": ["passwd", "shadow", "ssh", "hostname", "resolv.conf"],
}

SIMULATED_COMMANDS_EXACT = {
    "whoami": "root",
    "id": "uid=0(root) gid=0(root) groups=0(root)",
    "uname -a": "Linux ip-172-31-21-7 5.15.0-105-generic #115-Ubuntu SMP x86_64 GNU/Linux",
    "cat /etc/passwd": (
        "root:x:0:0:root:/root:/bin/bash\n"
        "daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n"
        "www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin\n"
        "ubuntu:x:1000:1000:Ubuntu:/home/ubuntu:/bin/bash"
    ),
    "cat /etc/shadow": "cat: /etc/shadow: Permission denied",
    "pwd": "/root",
    "hostname": "ip-172-31-21-7",
    "uname -m": "x86_64",
    "help": "Builtins: ls, cd, pwd, cat, whoami, id, uname, ps, netstat, ifconfig, curl, wget, exit",
}

SIMULATED_COMMANDS_PREFIX = {
    "curl": "curl: (6) Could not resolve host",
    "wget": "wget: missing URL",
    "python": "Python 3.10.12",
    "perl": "",
    "nc": "",
    "nmap": "Starting Nmap 7.80 ( https://nmap.org )",
}


logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    handlers=[
        logging.FileHandler(HONEYPOT_LOG_FILE, errors="ignore"),
        logging.StreamHandler(),
    ],
)
logger = logging.getLogger("honeypot")


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def iso_z(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def basic_auth_header(user: str, password: str) -> str:
    token_raw = f"{user}:{password}".encode("utf-8")
    import base64

    return "Basic " + base64.b64encode(token_raw).decode("ascii")


class HoneypotSession:
    """Representa uma sessão SSH autenticada no honeypot."""

    def __init__(self, source_ip: str, source_port: int, username: str):
        now = utc_now()
        self.session_id = str(uuid.uuid4())
        self.source_ip = source_ip
        self.source_port = source_port
        self.username = username
        self.password: Optional[str] = None
        self.login_success = True
        self.commands_executed: list[dict[str, str]] = []
        self.started_at = now
        self.ended_at: Optional[datetime] = None
        self.current_directory = "/root"

    def to_dict(self) -> dict[str, Any]:
        ended_or_now = self.ended_at or utc_now()
        duration = int((ended_or_now - self.started_at).total_seconds())

        return {
            "session_id": self.session_id,
            "source_ip": self.source_ip,
            "source_port": self.source_port,
            "username": self.username,
            "password": self.password,
            "login_success": self.login_success,
            "commands_executed": self.commands_executed,
            "command_count": len(self.commands_executed),
            "session_duration_seconds": duration,
            "started_at": iso_z(self.started_at),
            "ended_at": iso_z(self.ended_at) if self.ended_at else None,
        }


class HoneypotServer:
    """Servidor principal do honeypot SSH."""

    def __init__(self):
        self.redis: Optional[aioredis.Redis] = None
        self.active_sessions: dict[str, HoneypotSession] = {}
        self.geoip_reader: Optional[Any] = None
        self.ip_counters: dict[str, dict[str, int]] = {}

    async def initialize(self):
        """Inicializa conexões e recursos opcionais."""
        try:
            self.redis = await aioredis.from_url(REDIS_URL, decode_responses=True)
            await self.redis.ping()
            logger.info("Redis inicializado em %s", REDIS_URL)
        except Exception as exc:
            self.redis = None
            logger.warning("Redis indisponível (%s). Fallback local ativado.", exc)

        if geoip2_database and GEOIP_DB_PATH and Path(GEOIP_DB_PATH).exists():
            try:
                self.geoip_reader = geoip2_database.Reader(GEOIP_DB_PATH)
                logger.info("GeoIP habilitado: %s", GEOIP_DB_PATH)
            except Exception as exc:
                self.geoip_reader = None
                logger.warning("Falha ao abrir GeoIP DB (%s): %s", GEOIP_DB_PATH, exc)
        else:
            if not geoip2_database:
                logger.info("GeoIP desabilitado: biblioteca geoip2 indisponível")
            else:
                logger.info("GeoIP não configurado (GEOIP_DB_PATH vazio ou inexistente)")

    def _next_counter(self, ip: str, success: bool) -> dict[str, int]:
        counters = self.ip_counters.setdefault(
            ip,
            {
                "attempts": 0,
                "failed_logins": 0,
                "successful_logins": 0,
                "commands_total": 0,
            },
        )
        counters["attempts"] += 1
        if success:
            counters["successful_logins"] += 1
        else:
            counters["failed_logins"] += 1
        return counters

    def _register_command_counter(self, ip: str):
        counters = self.ip_counters.setdefault(
            ip,
            {
                "attempts": 0,
                "failed_logins": 0,
                "successful_logins": 0,
                "commands_total": 0,
            },
        )
        counters["commands_total"] += 1

    def _session_group_id(self, ip: str, moment: Optional[datetime] = None) -> str:
        dt = moment or utc_now()
        bucket = int(dt.timestamp() // SESSION_GROUP_WINDOW_SECONDS)
        raw = f"{ip}:{bucket}".encode("utf-8")
        return hashlib.sha256(raw).hexdigest()[:16]

    def _geoip_data(self, ip: str) -> dict[str, Any]:
        data: dict[str, Any] = {
            "ip": ip,
            "is_private": False,
            "country_iso_code": None,
            "country_name": None,
            "city": None,
            "latitude": None,
            "longitude": None,
            "timezone": None,
        }
        try:
            ip_obj = ipaddress.ip_address(ip)
            if ip_obj.is_private or ip_obj.is_loopback:
                data["is_private"] = True
                return data
        except ValueError:
            return data

        if not self.geoip_reader:
            return data

        try:
            city = self.geoip_reader.city(ip)
            data.update(
                {
                    "country_iso_code": city.country.iso_code,
                    "country_name": city.country.name,
                    "city": city.city.name,
                    "latitude": city.location.latitude,
                    "longitude": city.location.longitude,
                    "timezone": city.location.time_zone,
                }
            )
        except Exception:
            # Mantém campos nulos quando o IP não existe na base
            pass

        return data

    def _build_event(self, event_type: str, payload: dict[str, Any]) -> dict[str, Any]:
        now = utc_now()
        source_ip = payload.get("source_ip", "")

        event = {
            "event_id": str(uuid.uuid4()),
            "event_type": event_type,
            "severity": "high",
            "source": "honeypot",
            "protocol": HONEYPOT_PROTOCOL,
            "timestamp": iso_z(now),
            "@timestamp": iso_z(now),
            "session_group_id": self._session_group_id(source_ip, now) if source_ip else None,
            "geoip": self._geoip_data(source_ip) if source_ip else None,
            **payload,
        }
        return event

    async def _http_post_json(self, url: str, payload: dict[str, Any], headers: Optional[dict[str, str]] = None):
        def do_post():
            body = json.dumps(payload).encode("utf-8")
            req = urlrequest.Request(url, data=body, method="POST")
            req.add_header("Content-Type", "application/json")
            for key, value in (headers or {}).items():
                req.add_header(key, value)
            with urlrequest.urlopen(req, timeout=4) as response:
                return response.status

        return await asyncio.to_thread(do_post)

    async def _write_failed_event(self, event: dict[str, Any], reason: str):
        line = {"reason": reason, "event": event}
        path = Path(FAILED_EVENTS_FILE)
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("a", encoding="utf-8") as f:
            f.write(json.dumps(line, ensure_ascii=True) + "\n")

    async def publish_event(self, event_type: str, payload: dict[str, Any]):
        """Publica evento normalizado em Redis + integrações opcionais."""
        event = self._build_event(event_type, payload)

        failures: list[str] = []

        # Redis Stream
        if self.redis:
            try:
                await self.redis.xadd(
                    REDIS_STREAM,
                    {
                        "event_type": event["event_type"],
                        "severity": event["severity"],
                        "timestamp": event["timestamp"],
                        "source": event["source"],
                        "data": json.dumps(event, ensure_ascii=True),
                    },
                )
            except Exception as exc:
                failures.append(f"redis:{exc}")

        # Elasticsearch
        if ELASTICSEARCH_URL:
            es_url = f"{ELASTICSEARCH_URL}/{ELASTICSEARCH_INDEX}/_doc"
            headers: dict[str, str] = {}
            if ELASTICSEARCH_API_KEY:
                headers["Authorization"] = f"ApiKey {ELASTICSEARCH_API_KEY}"
            elif ELASTICSEARCH_USERNAME and ELASTICSEARCH_PASSWORD:
                headers["Authorization"] = basic_auth_header(
                    ELASTICSEARCH_USERNAME, ELASTICSEARCH_PASSWORD
                )

            try:
                await self._http_post_json(es_url, event, headers=headers)
            except (urlerror.URLError, TimeoutError, OSError) as exc:
                failures.append(f"elasticsearch:{exc}")

        # Backend
        if BACKEND_EVENTS_URL:
            headers = {"Authorization": f"Bearer {BACKEND_TOKEN}"} if BACKEND_TOKEN else {}
            try:
                await self._http_post_json(BACKEND_EVENTS_URL, event, headers=headers)
            except (urlerror.URLError, TimeoutError, OSError) as exc:
                failures.append(f"backend:{exc}")

        # Fallback local quando algo falhar
        if failures:
            await self._write_failed_event(event, "; ".join(failures))
            logger.warning("Evento com falhas de envio (%s): %s", event_type, failures)

    async def publish_session_data(self, session: HoneypotSession):
        session_data = session.to_dict()
        await self.publish_event("honeypot_session", session_data)

    async def register_login_attempt(
        self,
        source_ip: str,
        source_port: int,
        username: str,
        password: str,
        success: bool,
        connection_id: str,
        attempt_number_connection: int,
    ):
        counters = self._next_counter(source_ip, success)
        event_type = "honeypot_login"

        await self.publish_event(
            event_type,
            {
                "event_type": "honeypot_login",  # normalização explícita solicitada
                "session_id": connection_id,
                "connection_id": connection_id,
                "username": username,
                "password": password,
                "source_ip": source_ip,
                "source_port": source_port,
                "success": success,
                "attempt_count_ip": counters["attempts"],
                "failed_attempts_ip": counters["failed_logins"],
                "successful_logins_ip": counters["successful_logins"],
                "attempt_number_connection": attempt_number_connection,
                "mitre_technique_id": "T1110",
                "mitre_tactic": "Credential Access",
            },
        )

        logger.info(
            "Login %s %s:%s from %s:%s (ip_attempts=%s)",
            "SUCCESS" if success else "FAILED",
            username,
            password,
            source_ip,
            source_port,
            counters["attempts"],
        )

    async def handle_command(self, session_id: str, command: str) -> str:
        session = self.active_sessions.get(session_id)
        if not session:
            return "Session not found"

        command_clean = command.strip()
        command_entry = {
            "command": command_clean,
            "timestamp": iso_z(utc_now()),
            "cwd": session.current_directory,
        }
        session.commands_executed.append(command_entry)
        self._register_command_counter(session.source_ip)

        await self.publish_event(
            "honeypot_command",
            {
                "session_id": session_id,
                "connection_id": session_id,
                "command": command_clean,
                "cwd": session.current_directory,
                "source_ip": session.source_ip,
                "source_port": session.source_port,
                "username": session.username,
                "mitre_technique_id": "T1059",
                "mitre_tactic": "Execution",
            },
        )

        logger.info("Comando [%s]: %s", session.source_ip, command_clean)
        return self._simulate_command(session, command_clean)

    def _simulate_command(self, session: HoneypotSession, command: str) -> str:
        if command in ("exit", "logout"):
            return "__DISCONNECT__"

        if command.startswith("cd"):
            return self._handle_cd(session, command)

        if command == "ls" or command.startswith("ls "):
            directory = session.current_directory
            files = SIMULATED_FILESYSTEM.get(directory, ["tmp", "var", "etc"])
            return "  ".join(files)

        if command == "ps aux":
            return (
                "USER       PID %CPU %MEM    VSZ   RSS TTY      STAT START   TIME COMMAND\n"
                "root         1  0.0  0.1  16924  3012 ?        Ss   04:21   0:01 /sbin/init\n"
                "root       402  0.0  0.3  78040  6992 ?        Ss   04:21   0:00 /usr/sbin/sshd -D\n"
                "root      1393  0.1  0.2  21544  5128 pts/0    Ss   04:35   0:00 -bash"
            )

        if command == "netstat -tlnp":
            return (
                "Active Internet connections (only servers)\n"
                "Proto Recv-Q Send-Q Local Address           Foreign Address         State       PID/Program name\n"
                "tcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN      402/sshd\n"
                "tcp        0      0 127.0.0.1:6379          0.0.0.0:*               LISTEN      630/redis-server\n"
                "tcp        0      0 0.0.0.0:80              0.0.0.0:*               LISTEN      801/nginx"
            )

        if command == "ifconfig":
            return (
                "eth0: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500\n"
                "        inet 172.31.21.7  netmask 255.255.240.0  broadcast 172.31.31.255\n"
                "        ether 02:42:ac:11:00:07  txqueuelen 1000  (Ethernet)"
            )

        if command in SIMULATED_COMMANDS_EXACT:
            result = SIMULATED_COMMANDS_EXACT[command]
            if command == "pwd":
                return session.current_directory
            return result

        cmd_base = command.split()[0] if command else ""
        if cmd_base in SIMULATED_COMMANDS_PREFIX:
            return SIMULATED_COMMANDS_PREFIX[cmd_base]

        # Nunca executa comandos reais no host
        return f"bash: {command}: command not found"

    def _handle_cd(self, session: HoneypotSession, command: str) -> str:
        parts = command.split(maxsplit=1)
        if len(parts) == 1 or parts[1].strip() in ("~", "/root"):
            session.current_directory = "/root"
            return ""

        target = parts[1].strip()

        if target == "..":
            if session.current_directory == "/":
                return ""
            parent = str(Path(session.current_directory).parent)
            session.current_directory = parent if parent != "." else "/"
            return ""

        if not target.startswith("/"):
            current = Path(session.current_directory)
            candidate = str((current / target).resolve()).replace("/home/sandbox", "")
        else:
            candidate = target

        if candidate in SIMULATED_FILESYSTEM:
            session.current_directory = candidate
            return ""

        return f"bash: cd: {target}: No such file or directory"

    async def handle_session_end(self, session_id: str):
        session = self.active_sessions.pop(session_id, None)
        if session:
            session.ended_at = utc_now()
            await self.publish_session_data(session)
            logger.info("Sessão finalizada: %s (%s)", session_id, session.source_ip)


class HoneypotSSHServerSession(asyncssh.SSHServer):
    """Handler por conexão SSH do honeypot."""

    def __init__(self, honeypot: HoneypotServer):
        self.honeypot = honeypot
        self.connection_id = str(uuid.uuid4())
        self.session_id: Optional[str] = None
        self.source_ip = "unknown"
        self.source_port = 0
        self.auth_attempts = 0

    def connection_made(self, conn):
        peer = conn.get_extra_info("peername")
        if peer:
            self.source_ip = peer[0]
            self.source_port = peer[1]
        logger.info("Conexão recebida de %s:%s", self.source_ip, self.source_port)

    def connection_lost(self, exc):
        if self.session_id:
            asyncio.create_task(self.honeypot.handle_session_end(self.session_id))
        logger.info("Conexão encerrada de %s", self.source_ip)

    def begin_auth(self, username):
        return True

    def password_auth_supported(self):
        return self.auth_attempts < MAX_AUTH_ATTEMPTS_PER_CONNECTION

    def validate_password(self, username: str, password: str) -> bool:
        # Pequeno jitter para parecer validação real sem impacto operacional alto
        self.auth_attempts += 1
        success = FAKE_CREDENTIALS.get(username) == password

        asyncio.create_task(
            self.honeypot.register_login_attempt(
                source_ip=self.source_ip,
                source_port=self.source_port,
                username=username,
                password=password,
                success=success,
                connection_id=self.connection_id,
                attempt_number_connection=self.auth_attempts,
            )
        )

        if success:
            session = HoneypotSession(self.source_ip, self.source_port, username)
            session.password = password
            self.session_id = session.session_id
            self.honeypot.active_sessions[self.session_id] = session
            return True

        return False

    def validate_public_key(self, username, key):
        # Desabilita caminho de autenticação por chave para focar captura de credenciais por senha
        return False

    def session_requested(self):
        if not self.session_id:
            logger.warning("Session request sem autenticação válida de %s", self.source_ip)
            return False

        logger.info("Sessão iniciada: %s de %s", self.session_id, self.source_ip)
        return HoneypotSSHSession(self.honeypot, self.session_id)

    def connection_requested(self, dest_host, dest_port, orig_host, orig_port):
        # Impede tunelamento/forwarding para evitar abuso do honeypot.
        logger.info(
            "Port forwarding negado de %s:%s para %s:%s",
            orig_host,
            orig_port,
            dest_host,
            dest_port,
        )
        return False

    def server_requested(self, listen_host, listen_port):
        return False


class HoneypotSSHSession(asyncssh.SSHServerSession):
    """Sessão shell interativa simulada."""

    def __init__(self, honeypot: HoneypotServer, session_id: str):
        self.honeypot = honeypot
        self.session_id = session_id
        self._chan = None
        self._input_buffer = ""

    def connection_made(self, chan):
        self._chan = chan
        self._chan.write("\r\n")
        self._chan.write("Welcome to Ubuntu 22.04.4 LTS (GNU/Linux 5.15.0-105-generic x86_64)\r\n")
        self._chan.write("\r\n")
        self._chan.write(
            f"Last login: {utc_now().strftime('%a %b %d %H:%M:%S %Y')} from 172.31.1.23\r\n"
        )
        self._write_prompt()

    def _write_prompt(self):
        session = self.honeypot.active_sessions.get(self.session_id)
        user = session.username if session else "root"
        host = "ip-172-31-21-7"
        cwd = session.current_directory if session else "/root"
        suffix = "#" if user == "root" else "$"
        prompt_dir = "~" if cwd == "/root" else cwd
        self._chan.write(f"{user}@{host}:{prompt_dir}{suffix} ")

    def shell_requested(self):
        return True

    def exec_requested(self, command):
        # Alguns bots usam ssh user@host 'cmd'
        asyncio.create_task(self._handle_command(command))
        return True

    def data_received(self, data, data_type):
        if not self._chan:
            return

        for char in data:
            if char in ("\r", "\n"):
                self._chan.write("\r\n")
                command = self._input_buffer.strip()
                self._input_buffer = ""

                if command:
                    asyncio.create_task(self._handle_command(command))
                else:
                    self._write_prompt()
            elif char == "\x7f":
                if self._input_buffer:
                    self._input_buffer = self._input_buffer[:-1]
                    self._chan.write("\b \b")
            elif char == "\x03":
                self._input_buffer = ""
                self._chan.write("^C\r\n")
                self._write_prompt()
            else:
                self._input_buffer += char
                self._chan.write(char)

    async def _handle_command(self, command: str):
        # jitter curto para reduzir respostas "perfeitas" demais
        await asyncio.sleep(random.uniform(0.03, 0.25))
        response = await self.honeypot.handle_command(self.session_id, command)

        if response == "__DISCONNECT__":
            self._chan.write("logout\r\n")
            self._chan.close()
            return

        if response:
            self._chan.write(response + "\r\n")

        self._write_prompt()

    def connection_lost(self, exc):
        pass


async def ensure_host_key(path: str):
    key_path = Path(path)
    if key_path.exists():
        return

    key_path.parent.mkdir(parents=True, exist_ok=True)
    key = asyncssh.generate_private_key("ssh-rsa", key_size=2048)
    key.write_private_key(str(key_path))
    os.chmod(key_path, 0o600)


async def start_honeypot():
    honeypot = HoneypotServer()
    await honeypot.initialize()
    await ensure_host_key(SSH_HOST_KEY_PATH)

    logger.info("Iniciando honeypot %s em %s:%s", HONEYPOT_PROTOCOL, HONEYPOT_HOST, HONEYPOT_PORT)
    logger.info("Banner SSH emulado: %s", SSH_BANNER)

    try:
        await asyncssh.create_server(
            lambda: HoneypotSSHServerSession(honeypot),
            HONEYPOT_HOST,
            HONEYPOT_PORT,
            server_host_keys=[SSH_HOST_KEY_PATH],
            server_version=SSH_BANNER,
            password_auth=True,
            public_key_auth=False,
            kbdint_auth=False,
            authorized_client_keys=None,
        )
        logger.info("Honeypot SSH ouvindo em %s:%s", HONEYPOT_HOST, HONEYPOT_PORT)
        await asyncio.Event().wait()
    except Exception as exc:
        logger.error("Erro ao iniciar honeypot: %s", exc)
        raise


if __name__ == "__main__":
    try:
        asyncio.run(start_honeypot())
    except KeyboardInterrupt:
        logger.info("Honeypot encerrado pelo usuário")
    except Exception as exc:
        logger.error("Erro fatal: %s", exc)
