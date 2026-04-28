"""
SSH Honeypot - SOC/NOC Platform
================================
Honeypot SSH educacional para captura de credenciais, comandos e análise de ataques.
Destinado exclusivamente para ambientes autorizados e laboratoriais.

⚠️ AVISO ÉTICO: Use apenas em ambientes controlados e autorizados.
"""

import asyncio
import json
import logging
import os
import uuid
from datetime import datetime
from typing import Optional

import asyncssh
import redis.asyncio as aioredis

# Configuração de logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('/var/log/honeypot.log', errors='ignore'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger('honeypot')

# Configurações
HONEYPOT_HOST = os.getenv('HONEYPOT_HOST', '0.0.0.0')
HONEYPOT_PORT = int(os.getenv('HONEYPOT_PORT', '2222'))
REDIS_URL = os.getenv('REDIS_URL', 'redis://localhost:6379')

# Credenciais válidas simuladas (qualquer tentativa é registrada)
VALID_USERNAMES = ['root', 'admin', 'ubuntu', 'deploy', 'user', 'test', 'oracle', 'postgres', 'mysql']
VALID_PASSWORDS = ['root', 'admin', '123456', 'password', 'ubuntu', 'test123', 'P@ssw0rd', 'admin123']

# Comandos simulados e respostas
SIMULATED_COMMANDS = {
    'ls': 'total 48\ndrwxr-xr-x  5 root root  4096 Apr  7 10:00 .\ndrwxr-xr-x 20 root root  4096 Apr  7 09:00 ..\n-rw-r--r--  1 root root  3106 Apr  7 08:00 .bashrc\n-rw-r--r--  1 root root   161 Apr  7 08:00 .profile\ndrwxr-xr-x  2 root root  4096 Apr  7 09:00 documents\ndrwxr-xr-x  3 root root  4096 Apr  7 09:00 .ssh',
    'whoami': 'root',
    'id': 'uid=0(root) gid=0(root) groups=0(root)',
    'uname -a': 'Linux honeypot 5.15.0-91-generic #101-Ubuntu SMP Tue Nov 14 13:30:08 UTC 2023 x86_64 x86_64 x86_64 GNU/Linux',
    'cat /etc/passwd': 'root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\nbin:x:2:2:bin:/bin:/usr/sbin/nologin\nsys:x:3:3:sys:/dev:/usr/sbin/nologin\nsync:x:4:65534:sync:/bin:/bin/sync\nnobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin',
    'cat /etc/shadow': 'Permission denied',
    'ps aux': 'USER       PID %CPU %MEM    VSZ   RSS TTY      STAT START   TIME COMMAND\nroot         1  0.0  0.1  18376  3200 ?        Ss   09:00   0:00 /sbin/init\nroot       100  0.0  0.2  72240  5800 ?        Ss   09:00   0:00 /usr/sbin/sshd\nroot       200  0.0  0.1  12345  2345 ?        S    09:01   0:00 bash',
    'netstat -tlnp': 'Active Internet connections (only servers)\nProto Recv-Q Send-Q Local Address           Foreign Address         State       PID/Program name\ntcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN      100/sshd\ntcp        0      0 127.0.0.1:3306          0.0.0.0:*               LISTEN      300/mysqld\ntcp        0      0 0.0.0.0:80              0.0.0.0:*               LISTEN      400/nginx',
    'ifconfig': 'eth0: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500\n        inet 192.168.1.100  netmask 255.255.255.0  broadcast 192.168.1.255\n        inet6 fe80::1  prefixlen 64  scopeid 0x20<link>\n        ether 00:11:22:33:44:55  txqueuelen 1000  (Ethernet)',
    'wget': 'wget: missing URL',
    'curl': 'curl: try \'curl --help\' or \'curl --manual\' for more information',
    'pwd': '/root',
    'hostname': 'honeypot',
    'uname -m': 'x86_64',
    'cat /proc/cpuinfo': 'processor\t: 0\nvendor_id\t: GenuineIntel\ncpu family\t: 6\nmodel\t\t: 142\nmodel name\t: Intel(R) Core(TM) i7-8550U CPU @ 1.80GHz\nstepping\t: 10\ncpu MHz\t\t: 1800.000\ncache size\t: 8192 KB',
    'cat /proc/meminfo': 'MemTotal:        8167356 kB\nMemFree:         2345678 kB\nMemAvailable:    4567890 kB\nBuffers:          234567 kB\nCached:          1234567 kB',
    'help': 'Available commands: ls, whoami, id, uname, cat, ps, netstat, ifconfig, pwd, hostname, wget, curl, help, exit',
}

# Banner do honeypot
SSH_BANNER = 'OpenSSH_8.9p1 Ubuntu-3ubuntu0.4'


class HoneypotSession:
    """Gerencia uma sessão individual do honeypot."""

    def __init__(self, source_ip: str, source_port: int):
        self.session_id = str(uuid.uuid4())
        self.source_ip = source_ip
        self.source_port = source_port
        self.username = None
        self.password = None
        self.login_success = False
        self.commands_executed = []
        self.started_at = datetime.utcnow()
        self.ended_at = None

    def to_dict(self) -> dict:
        # BUG CORRIGIDO: parêntese errado causava subtração antes do `or`.
        # Antes: (self.ended_at or datetime.utcnow() - self.started_at).total_seconds()
        # Depois: ((self.ended_at or datetime.utcnow()) - self.started_at).total_seconds()
        duration = int(((self.ended_at or datetime.utcnow()) - self.started_at).total_seconds())
        return {
            'session_id': self.session_id,
            'source_ip': self.source_ip,
            'source_port': self.source_port,
            'username': self.username,
            'password': self.password,
            'login_success': self.login_success,
            'commands_executed': self.commands_executed,  # Lista nativa, não string JSON
            'session_duration': duration,
            'started_at': self.started_at.isoformat(),
            'ended_at': self.ended_at.isoformat() if self.ended_at else None,
        }


class HoneypotServer:
    """Servidor principal do honeypot SSH."""

    def __init__(self):
        self.redis: Optional[aioredis.Redis] = None
        self.active_sessions = {}

    async def initialize(self):
        """Inicializa conexões e recursos."""
        self.redis = await aioredis.from_url(REDIS_URL, decode_responses=True)
        logger.info(f"Honeypot SSH inicializado - Redis: {REDIS_URL}")

    async def publish_event(self, event_type: str, data: dict):
        """Publica evento no Redis Streams."""
        event = {
            'event_type': event_type,
            'source': 'honeypot',
            'timestamp': datetime.utcnow().isoformat(),
            'data': json.dumps(data)
        }
        await self.redis.xadd('soc_events', event)
        logger.debug(f"Evento publicado: {event_type}")

    async def publish_session_data(self, session: HoneypotSession):
        """Publica dados da sessão no Redis."""
        event = {
            'event_type': 'honeypot_session',
            'source': 'honeypot',
            'timestamp': datetime.utcnow().isoformat(),
            'data': json.dumps(session.to_dict())
        }
        await self.redis.xadd('soc_events', event)
        logger.info(f"Sessão registrada: {session.session_id} de {session.source_ip}")

    async def handle_command(self, session_id: str, command: str) -> str:
        """Processa comando executado na sessão."""
        session = self.active_sessions.get(session_id)
        if not session:
            return 'Session not found'

        # Registra comando
        command_entry = {
            'command': command,
            'timestamp': datetime.utcnow().isoformat()
        }
        session.commands_executed.append(command_entry)

        # Publica evento de comando
        await self.publish_event('honeypot_command', {
            'session_id': session_id,
            'command': command,
            'source_ip': session.source_ip,
            'username': session.username,
            'mitre_technique_id': 'T1059',
            'mitre_tactic': 'Execution'
        })

        logger.info(f"Comando [{session.source_ip}]: {command}")

        # Retorna resposta simulada
        cmd_base = command.strip().split()[0] if command.strip() else ''
        if command.strip() in SIMULATED_COMMANDS:
            return SIMULATED_COMMANDS[command.strip()]
        elif cmd_base in SIMULATED_COMMANDS:
            return SIMULATED_COMMANDS[cmd_base]
        elif command.strip() in ('exit', 'logout'):
            return '__DISCONNECT__'
        else:
            return f'bash: {command.strip()}: command not found'

    async def handle_session_end(self, session_id: str):
        """Finaliza sessão e publica dados."""
        session = self.active_sessions.pop(session_id, None)
        if session:
            session.ended_at = datetime.utcnow()
            await self.publish_session_data(session)
            logger.info(f"Sessão finalizada: {session_id} ({session.source_ip})")


class HoneypotSSHServerSession(asyncssh.SSHServer):
    """Sessão do servidor SSH do honeypot."""

    def __init__(self, honeypot: HoneypotServer):
        self.honeypot = honeypot
        self.session_id = None
        self.source_ip = None
        self.source_port = None

    def connection_made(self, conn):
        self.source_ip = conn.get_extra_info('peername')[0]
        self.source_port = conn.get_extra_info('peername')[1]
        logger.info(f"Conexão recebida de {self.source_ip}:{self.source_port}")

    def connection_lost(self, exc):
        # BUG CORRIGIDO: session_end agora é chamado APENAS aqui (no nível do
        # servidor SSH), evitando chamada dupla com HoneypotSSHSession.connection_lost.
        if self.session_id:
            asyncio.create_task(self.honeypot.handle_session_end(self.session_id))
        logger.info(f"Conexão encerrada de {self.source_ip}")

    def password_auth_supported(self):
        return True

    def validate_auth_password(self, username: str, password: str) -> bool:
        """Valida credenciais (sempre retorna True para honeypot)."""
        session = HoneypotSession(self.source_ip, self.source_port)
        session.username = username
        session.password = password
        session.login_success = True
        self.session_id = session.session_id
        self.honeypot.active_sessions[session.session_id] = session

        asyncio.ensure_future(self.honeypot.publish_event('honeypot_login', {
            'session_id': session.session_id,
            'username': username,
            'password': password,
            'source_ip': self.source_ip,
            'source_port': self.source_port,
            'success': True,
            'mitre_technique_id': 'T1110',
            'mitre_tactic': 'Credential Access'
        }))

        logger.info(f"Login capturado: {username}:{password} de {self.source_ip}:{self.source_port}")
        return True

    def session_requested(self):
        """Inicia nova sessão interativa."""
        logger.info(f"Sessão iniciada: {self.session_id} de {self.source_ip}")
        # BUG CORRIGIDO: era begin_session() que não existe na API do asyncssh.
        # O método correto é session_requested(), que retorna um SSHServerSession.
        return HoneypotSSHSession(self.honeypot, self.session_id)


class HoneypotSSHSession(asyncssh.SSHServerSession):
    """Sessão interativa do honeypot."""

    def __init__(self, honeypot: HoneypotServer, session_id: str):
        self.honeypot = honeypot
        self.session_id = session_id
        self._chan = None
        self._input_buffer = ''

    def connection_made(self, chan):
        self._chan = chan
        self._chan.write('\r\n')
        self._chan.write('=' * 60 + '\r\n')
        self._chan.write('  ⚠️  AUTHORIZED ACCESS ONLY  ⚠️\r\n')
        self._chan.write('  This system is monitored and all activity is logged.\r\n')
        self._chan.write('  Unauthorized access is prohibited.\r\n')
        self._chan.write('=' * 60 + '\r\n\r\n')
        self._chan.write('Welcome to Ubuntu 22.04.3 LTS\r\n\r\n')
        self._chan.write('Last login: Mon Apr  7 09:00:00 2026 from 192.168.1.1\r\n')
        self._write_prompt()

    def _write_prompt(self):
        self._chan.write('root@honeypot:~# ')

    def shell_requested(self):
        return True

    def data_received(self, data, data_type):
        """
        BUG CORRIGIDO: antes apenas imprimia o prompt sem processar o comando.
        Agora acumula input até receber Enter e executa o comando correspondente.
        """
        if not self._chan:
            return

        for char in data:
            if char in ('\r', '\n'):
                # Eco da quebra de linha
                self._chan.write('\r\n')
                command = self._input_buffer.strip()
                self._input_buffer = ''

                if command:
                    asyncio.create_task(self._handle_command(command))
                else:
                    self._write_prompt()
            elif char == '\x7f':  # Backspace
                if self._input_buffer:
                    self._input_buffer = self._input_buffer[:-1]
                    self._chan.write('\b \b')
            elif char == '\x03':  # Ctrl+C
                self._input_buffer = ''
                self._chan.write('^C\r\n')
                self._write_prompt()
            else:
                self._input_buffer += char
                self._chan.write(char)  # Eco do caractere

    async def _handle_command(self, command: str):
        """Executa o comando no honeypot e escreve a resposta."""
        response = await self.honeypot.handle_command(self.session_id, command)
        if response == '__DISCONNECT__':
            self._chan.write('logout\r\n')
            self._chan.close()
        else:
            self._chan.write(response + '\r\n')
            self._write_prompt()

    def connection_lost(self, exc):
        # BUG CORRIGIDO: session_end removido daqui para evitar chamada dupla.
        # O encerramento da sessão é responsabilidade de HoneypotSSHServerSession.connection_lost.
        pass


async def start_honeypot():
    """Inicia o servidor honeypot."""
    honeypot = HoneypotServer()
    await honeypot.initialize()

    # Gera chaves SSH se não existirem
    if not os.path.exists('/etc/ssh/ssh_host_rsa_key'):
        import subprocess
        os.makedirs('/etc/ssh', exist_ok=True)
        subprocess.run(
            ['ssh-keygen', '-t', 'rsa', '-b', '2048', '-f', '/etc/ssh/ssh_host_rsa_key', '-N', ''],
            check=True, capture_output=True
        )

    logger.info(f"Iniciando honeypot SSH em {HONEYPOT_HOST}:{HONEYPOT_PORT}")
    logger.info("⚠️  AVISO: Este honeypot é destinado APENAS para ambientes laboratoriais!")

    # BUG CORRIGIDO: antes passava process_factory duplicado e com tipo errado.
    # `server_factory` recebe um callable que retorna SSHServer (HoneypotSSHServerSession).
    # Não deve passar process_factory aqui — a sessão é retornada por session_requested().
    try:
        await asyncssh.create_server(
            lambda: HoneypotSSHServerSession(honeypot),
            HONEYPOT_HOST,
            HONEYPOT_PORT,
            server_host_keys=['/etc/ssh/ssh_host_rsa_key'],
            server_version=SSH_BANNER,
            password_auth=True,
            public_key_auth=False,
            kbdint_auth=False,
            authorized_client_keys=None,
        )
        logger.info(f"Honeypot SSH ouvindo em {HONEYPOT_HOST}:{HONEYPOT_PORT}")

        await asyncio.Event().wait()
    except Exception as e:
        logger.error(f"Erro ao iniciar honeypot: {e}")
        raise


if __name__ == '__main__':
    try:
        asyncio.run(start_honeypot())
    except KeyboardInterrupt:
        logger.info("Honeypot encerrado pelo usuário")
    except Exception as e:
        logger.error(f"Erro fatal: {e}")
