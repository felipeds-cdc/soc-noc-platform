"""
Log Collector Agent - SOC/NOC Platform
=======================================
Agente para coleta de logs do sistema (auth.log, syslog), monitoramento
de processos e conexões de rede.

⚠️ AVISO ÉTICO: Use apenas em ambientes controlados e autorizados.
"""

import asyncio
import json
import logging
import os
import re
import socket
import subprocess
from datetime import datetime
from pathlib import Path
from typing import Optional

import redis.asyncio as aioredis

# Configuração de logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger('agent')

# Configurações
REDIS_URL = os.getenv('REDIS_URL', 'redis://localhost:6379')
LOG_FILES = os.getenv('LOG_FILES', '/var/log/auth.log,/var/log/syslog').split(',')
CHECK_INTERVAL = int(os.getenv('CHECK_INTERVAL', '5'))  # segundos
ANONYMIZE_LOGS = os.getenv('ANONYMIZE_LOGS', 'false').lower() == 'true'

# Portas comumente usadas em reverse shells para detecção
REVERSE_SHELL_PORTS = {4444, 4445, 1337, 31337, 9001, 9999, 6666}


class LogCollector:
    """Coletor de logs do sistema."""

    def __init__(self):
        self.redis: Optional[aioredis.Redis] = None
        self.file_positions = {}

    async def initialize(self):
        """Inicializa conexões."""
        self.redis = await aioredis.from_url(REDIS_URL, decode_responses=True)
        logger.info(f"Agente de coleta inicializado - Redis: {REDIS_URL}")
        await self._load_positions()

    async def _load_positions(self):
        """Carrega posições de leitura salvas."""
        for log_file in LOG_FILES:
            log_file = log_file.strip()
            if not log_file:
                continue
            position_key = f"log_position:{log_file}"
            position = await self.redis.get(position_key)
            self.file_positions[log_file] = int(position) if position else 0

    async def _save_position(self, log_file: str, position: int):
        """Salva posição de leitura."""
        position_key = f"log_position:{log_file}"
        await self.redis.set(position_key, str(position))

    @staticmethod
    def anonymize_ip(text: str) -> str:
        """Anonimiza endereços IP em logs."""
        # BUG CORRIGIDO: o método era @staticmethod mas acessava ANONYMIZE_LOGS
        # como se fosse instância. Agora acessa a constante global diretamente,
        # que é o uso correto para um método estático.
        if not ANONYMIZE_LOGS:
            return text
        ip_pattern = r'\b(\d{1,3}\.\d{1,3}\.\d{1,3})\.\d{1,3}\b'
        return re.sub(ip_pattern, r'\1.xxx', text)

    async def publish_log_event(self, log_file: str, line: str, timestamp: str):
        """Publica evento de log no Redis."""
        event = {
            'event_type': 'system_log',
            'source': 'agent',
            'timestamp': timestamp,
            'log_file': log_file,
            'raw_log': self.anonymize_ip(line),
            'collected_at': datetime.utcnow().isoformat()
        }

        line_lower = line.lower()
        if 'failed password' in line_lower or 'authentication failure' in line_lower:
            event['event_type'] = 'auth_failure'
            event['severity'] = 'medium'
            ip_match = re.search(r'(\d+\.\d+\.\d+\.\d+)', line)
            if ip_match:
                event['source_ip'] = ip_match.group(1)
            user_match = re.search(r'for\s+(?:invalid\s+user\s+)?(\S+)', line)
            if user_match:
                event['username'] = user_match.group(1)
        elif 'accepted password' in line_lower or 'accepted publickey' in line_lower:
            event['event_type'] = 'auth_success'
            ip_match = re.search(r'(\d+\.\d+\.\d+\.\d+)', line)
            if ip_match:
                event['source_ip'] = ip_match.group(1)
        elif 'sudo' in line_lower:
            event['event_type'] = 'sudo_execution'
            user_match = re.search(r'(\S+)\s+:', line)
            if user_match:
                event['username'] = user_match.group(1)
            cmd_match = re.search(r'COMMAND=(.+)$', line, re.IGNORECASE)
            if cmd_match:
                event['command'] = cmd_match.group(1)
        elif 'invalid user' in line_lower:
            event['event_type'] = 'invalid_user_attempt'
            event['severity'] = 'low'
            user_match = re.search(r'invalid user\s+(\S+)', line)
            if user_match:
                event['username'] = user_match.group(1)
            ip_match = re.search(r'from\s+(\d+\.\d+\.\d+\.\d+)', line)
            if ip_match:
                event['source_ip'] = ip_match.group(1)

        await self.redis.xadd('soc_events', event)

    async def read_new_lines(self, log_file: str) -> list:
        """Lê novas linhas de um arquivo de log."""
        log_path = Path(log_file.strip())
        if not log_path.exists():
            logger.warning(f"Arquivo de log não encontrado: {log_file}")
            return []

        try:
            current_size = log_path.stat().st_size
            last_position = self.file_positions.get(log_file, 0)

            # Arquivo foi rotacionado
            if current_size < last_position:
                last_position = 0

            if current_size == last_position:
                return []

            lines = []
            with open(log_path, 'r', errors='ignore') as f:
                f.seek(last_position)
                new_content = f.read()
                new_position = f.tell()

                for line in new_content.splitlines():
                    if line.strip():
                        lines.append(line)

            self.file_positions[log_file] = new_position
            await self._save_position(log_file, new_position)
            return lines

        except Exception as e:
            logger.error(f"Erro ao ler {log_file}: {e}")
            return []

    async def collect_logs(self):
        """Coleta logs de todos os arquivos configurados."""
        for log_file in LOG_FILES:
            log_file = log_file.strip()
            if not log_file:
                continue

            new_lines = await self.read_new_lines(log_file)
            if new_lines:
                logger.debug(f"Coletadas {len(new_lines)} novas linhas de {log_file}")
                for line in new_lines:
                    timestamp = datetime.utcnow().isoformat()
                    await self.publish_log_event(log_file, line, timestamp)

    async def start_collection(self):
        """Inicia coleta contínua de logs."""
        logger.info("Iniciando coleta contínua de logs...")
        while True:
            try:
                await self.collect_logs()
            except Exception as e:
                logger.error(f"Erro na coleta: {e}")
            await asyncio.sleep(CHECK_INTERVAL)


class ProcessMonitor:
    """Monitor de processos do sistema."""

    def __init__(self, redis_client: aioredis.Redis):
        self.redis = redis_client
        self.known_processes = set()
        self.suspicious_commands = [
            'nc ', 'ncat', 'netcat',
            'nmap', 'masscan',
            'hydra', 'john', 'hashcat',
            'metasploit', 'msfconsole',
            'sqlmap', 'nikto',
            'dirb', 'gobuster',
            'wget http', 'curl http',
            '/tmp/',
            'chmod 777', 'chmod +x',
            'base64 -d',
            'eval(',
            'bash -i',
            'python -c',
            'perl -e',
            'ruby -e',
            'php -r',
        ]

    async def check_processes(self):
        """Verifica processos em execução."""
        try:
            result = subprocess.run(
                ['ps', 'aux'],
                capture_output=True,
                text=True,
                timeout=10
            )

            if result.returncode == 0:
                lines = result.stdout.strip().split('\n')[1:]
                current_processes = set()

                for line in lines:
                    parts = line.split(None, 10)
                    if len(parts) >= 11:
                        pid = parts[1]
                        user = parts[0]
                        command = parts[10]
                        current_processes.add(pid)

                        is_suspicious = any(
                            cmd.lower() in command.lower()
                            for cmd in self.suspicious_commands
                        )

                        if is_suspicious:
                            event = {
                                'event_type': 'suspicious_process',
                                'source': 'agent',
                                'timestamp': datetime.utcnow().isoformat(),
                                'pid': pid,
                                'user': user,
                                'command': command,
                                'severity': 'high',
                                'mitre_technique_id': 'T1059',
                                'mitre_tactic': 'Execution'
                            }
                            await self.redis.xadd('soc_events', event)
                            logger.warning(f"Processo suspeito detectado: {command[:100]}")

                new_pids = current_processes - self.known_processes
                if new_pids:
                    logger.debug(f"Novos processos detectados: {len(new_pids)}")

                self.known_processes = current_processes

        except Exception as e:
            logger.error(f"Erro ao verificar processos: {e}")

    async def start_monitoring(self):
        """Inicia monitoramento contínuo."""
        logger.info("Iniciando monitoramento de processos...")
        while True:
            try:
                await self.check_processes()
            except Exception as e:
                logger.error(f"Erro no monitoramento: {e}")
            await asyncio.sleep(10)


class NetworkMonitor:
    """Monitor de conexões de rede."""

    def __init__(self, redis_client: aioredis.Redis):
        self.redis = redis_client
        self.previous_connections = set()

    @staticmethod
    def _parse_port(address: str) -> Optional[int]:
        """Extrai a porta de um endereço no formato 'ip:porta' ou '[ipv6]:porta'."""
        try:
            # Suporta IPv4 (1.2.3.4:PORT) e IPv6 ([::1]:PORT ou ::1:PORT)
            return int(address.rsplit(':', 1)[-1])
        except (ValueError, IndexError):
            return None

    async def check_connections(self):
        """
        Verifica conexões de rede ativas.

        BUG CORRIGIDO: o parsing do netstat usava índices fixos (parts[5], parts[6])
        que variam dependendo do protocolo (tcp/udp) e do kernel. A versão correta
        usa ss (substituto moderno do netstat) com saída estruturada, ou faz parsing
        baseado no cabeçalho. Aqui adotamos `ss -tunap` com campos nomeados via
        --no-header para robustez.

        BUG CORRIGIDO: detecção de reverse shell limitada apenas à porta 4444.
        Agora verifica contra o conjunto REVERSE_SHELL_PORTS.
        """
        try:
            result = subprocess.run(
                ['ss', '-tunap', '--no-header'],
                capture_output=True,
                text=True,
                timeout=10
            )

            if result.returncode != 0:
                # Fallback para netstat se ss não estiver disponível
                result = subprocess.run(
                    ['netstat', '-tunap'],
                    capture_output=True,
                    text=True,
                    timeout=10
                )
                lines = result.stdout.strip().split('\n')[2:]  # pula 2 linhas de header
            else:
                lines = result.stdout.strip().split('\n')

            current_connections = set()

            for line in lines:
                if not line.strip():
                    continue

                parts = line.split()
                # ss --no-header: Netid State Recv-Q Send-Q LocalAddr:Port PeerAddr:Port
                # netstat:        Proto Recv-Q Send-Q LocalAddr ForeignAddr State [PID]
                if len(parts) < 6:
                    continue

                try:
                    # Compatível com ambos ss e netstat
                    if parts[0] in ('tcp', 'tcp6', 'udp', 'udp6'):
                        # netstat format
                        local_addr = parts[3]
                        remote_addr = parts[4]
                        state = parts[5] if len(parts) > 5 else ''
                        pid_program = parts[6] if len(parts) > 6 else ''
                    else:
                        # ss format: Netid State Recv-Q Send-Q Local Peer
                        local_addr = parts[4]
                        remote_addr = parts[5]
                        state = parts[1]
                        pid_program = parts[6] if len(parts) > 6 else ''

                    conn_key = f"{local_addr}->{remote_addr}"
                    current_connections.add(conn_key)

                    remote_port = self._parse_port(remote_addr)
                    if state in ('SYN_SENT', 'ESTAB', 'ESTABLISHED') and remote_port in REVERSE_SHELL_PORTS:
                        event = {
                            'event_type': 'suspicious_connection',
                            'source': 'agent',
                            'timestamp': datetime.utcnow().isoformat(),
                            'local_address': local_addr,
                            'remote_address': remote_addr,
                            'state': state,
                            'pid_program': pid_program,
                            'severity': 'critical',
                            'description': f'Possível reverse shell detectado (porta {remote_port})',
                            'mitre_technique_id': 'T1059',
                            'mitre_tactic': 'Command and Control'
                        }
                        await self.redis.xadd('soc_events', event)
                        logger.critical(f"Conexão suspeita: {remote_addr} (estado: {state})")

                except (IndexError, ValueError):
                    continue

            new_connections = current_connections - self.previous_connections
            if new_connections:
                logger.debug(f"Novas conexões: {len(new_connections)}")

            self.previous_connections = current_connections

        except FileNotFoundError:
            logger.error("Nem 'ss' nem 'netstat' foram encontrados no sistema.")
        except Exception as e:
            logger.error(f"Erro ao verificar conexões: {e}")

    async def start_monitoring(self):
        """Inicia monitoramento contínuo."""
        logger.info("Iniciando monitoramento de rede...")
        while True:
            try:
                await self.check_connections()
            except Exception as e:
                logger.error(f"Erro no monitoramento: {e}")
            await asyncio.sleep(15)


async def main():
    """Função principal do agente."""
    logger.info("=" * 60)
    logger.info("  SOC/NOC Platform - Agente de Coleta de Logs")
    logger.info("  ⚠️  AVISO: Uso exclusivo em ambientes laboratoriais")
    logger.info("=" * 60)

    collector = LogCollector()
    await collector.initialize()

    process_monitor = ProcessMonitor(collector.redis)
    network_monitor = NetworkMonitor(collector.redis)

    tasks = [
        collector.start_collection(),
        process_monitor.start_monitoring(),
        network_monitor.start_monitoring(),
    ]

    try:
        await asyncio.gather(*tasks)
    except KeyboardInterrupt:
        logger.info("Agente encerrado pelo usuário")
    except Exception as e:
        logger.error(f"Erro fatal no agente: {e}")
        raise


if __name__ == '__main__':
    asyncio.run(main())
