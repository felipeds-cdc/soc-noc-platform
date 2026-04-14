"""
Event Processor - SOC/NOC Platform
===================================
Processador de eventos que consome do Redis Streams, faz parsing,
normalização, enriquecimento (GeoIP, ASN, reputação) e armazena
no Elasticsearch e PostgreSQL.

⚠️ AVISO ÉTICO: Use apenas em ambientes controlados e autorizados.
"""

import asyncio
import json
import logging
import os
import re
from datetime import datetime
from typing import Optional

import redis.asyncio as aioredis
from elasticsearch import AsyncElasticsearch
import asyncpg

# Configuração de logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger('processor')

# Configurações
REDIS_URL = os.getenv('REDIS_URL', 'redis://localhost:6379')
ELASTICSEARCH_URL = os.getenv('ELASTICSEARCH_URL', 'http://localhost:9200')
DATABASE_URL = os.getenv('DATABASE_URL', 'postgresql+asyncpg://soc_user:soc_password123@localhost:5432/soc_noc')
BATCH_SIZE = int(os.getenv('BATCH_SIZE', '100'))
PROCESS_INTERVAL = float(os.getenv('PROCESS_INTERVAL', '1'))

# Grupos de reputação de IP (simulado para ambiente lab)
KNOWN_MALICIOUS_RANGES = ['10.0.0.', '192.168.100.']  # IPs simulados de ataque
KNOWN_SAFE_RANGES = ['127.0.0.', '192.168.1.']  # IPs locais seguros


class GeoIPEnricher:
    """Simula enriquecimento GeoIP (em produção, usar MaxMind)."""
    
    # Dados simulados para demonstração
    SIMULATED_GEO = {
        '10.0.0.': {'country': 'Unknown', 'city': 'Unknown', 'lat': 0.0, 'lon': 0.0, 'asn': 0},
        '192.168.100.': {'country': 'Lab Network', 'city': 'Internal', 'lat': -15.7939, 'lon': -47.8828, 'asn': 64512},
        '203.0.113.': {'country': 'CN', 'city': 'Beijing', 'lat': 39.9042, 'lon': 116.4074, 'asn': 4808},
        '198.51.100.': {'country': 'RU', 'city': 'Moscow', 'lat': 55.7558, 'lon': 37.6173, 'asn': 12389},
        '172.16.0.': {'country': 'US', 'city': 'New York', 'lat': 40.7128, 'lon': -74.0060, 'asn': 15169},
    }
    
    @classmethod
    def enrich(cls, ip_address: str) -> dict:
        """Enriquece IP com dados geográficos simulados."""
        for prefix, geo_data in cls.SIMULATED_GEO.items():
            if ip_address.startswith(prefix):
                return geo_data
        
        # Gera dados aleatórios baseados no IP para demonstração
        hash_val = sum(ord(c) for c in ip_address)
        countries = ['US', 'BR', 'DE', 'FR', 'GB', 'JP', 'KR', 'IN', 'RU', 'CN']
        cities = ['Unknown', 'Internal', 'Lab', 'Test']
        
        return {
            'country': countries[hash_val % len(countries)],
            'city': cities[hash_val % len(cities)],
            'lat': (hash_val % 180) - 90,
            'lon': (hash_val % 360) - 180,
            'asn': (hash_val % 65535) + 1000
        }


class IPReputationChecker:
    """Verifica reputação de IP (simulado)."""
    
    @classmethod
    def check_reputation(cls, ip_address: str) -> dict:
        """Retorna reputação simulada do IP."""
        score = 50  # Neutro por padrão
        
        if any(ip_address.startswith(range) for range in KNOWN_MALICIOUS_RANGES):
            score = 10  # Malicioso
            threat_level = 'high'
        elif any(ip_address.startswith(range) for range in KNOWN_SAFE_RANGES):
            score = 90  # Seguro
            threat_level = 'low'
        else:
            # Simula baseado em hash do IP
            hash_val = sum(ord(c) for c in ip_address)
            score = hash_val % 100
            threat_level = 'low' if score > 70 else ('medium' if score > 40 else 'high')
            
        return {
            'reputation_score': score,
            'threat_level': threat_level,
            'is_malicious': score < 30,
            'is_safe': score > 70
        }


class EventProcessor:
    """Processador principal de eventos."""
    
    def __init__(self):
        self.redis: Optional[aioredis.Redis] = None
        self.elasticsearch: Optional[AsyncElasticsearch] = None
        self.postgres_pool = None
        self.consumer_group = 'processor_group'
        self.consumer_name = f'processor_1'
        
    async def initialize(self):
        """Inicializa todas as conexões."""
        # Redis
        self.redis = await aioredis.from_url(REDIS_URL, decode_responses=True)
        
        # Cria consumer group se não existir
        try:
            await self.redis.xgroup_create(
                'soc_events',
                self.consumer_group,
                mkstream=True
            )
        except Exception as e:
            if 'BUSYGROUP' not in str(e):
                logger.warning(f"Aviso ao criar consumer group: {e}")
                
        # Elasticsearch
        self.elasticsearch = AsyncElasticsearch([ELASTICSEARCH_URL])
        
        # Verifica conexão com Elasticsearch
        health = await self.elasticsearch.cluster.health()
        logger.info(f"Elasticsearch status: {health.get('status', 'unknown')}")
        
        # PostgreSQL
        pg_url = DATABASE_URL.replace('postgresql+asyncpg://', 'postgresql://')
        self.postgres_pool = await asyncpg.create_pool(pg_url)
        
        # Garante que índices do Elasticsearch existem
        await self._ensure_elasticsearch_indices()
        
        logger.info("Processador inicializado com sucesso")
        
    async def _ensure_elasticsearch_indices(self):
        """Cria índices do Elasticsearch se não existirem."""
        indices = {
            'soc_events': {
                'mappings': {
                    'properties': {
                        'timestamp': {'type': 'date'},
                        'event_type': {'type': 'keyword'},
                        'source': {'type': 'keyword'},
                        'severity': {'type': 'keyword'},
                        'source_ip': {'type': 'ip'},
                        'destination_ip': {'type': 'ip'},
                        'username': {'type': 'keyword'},
                        'mitre_technique_id': {'type': 'keyword'},
                        'mitre_tactic': {'type': 'keyword'},
                        'raw_log': {'type': 'text'},
                        'geo_country': {'type': 'keyword'},
                        'geo_city': {'type': 'keyword'},
                        'geo_latitude': {'type': 'float'},
                        'geo_longitude': {'type': 'float'},
                        'asn': {'type': 'integer'},
                        'reputation_score': {'type': 'integer'},
                        'threat_level': {'type': 'keyword'},
                    }
                }
            },
            'honeypot_sessions': {
                'mappings': {
                    'properties': {
                        'session_id': {'type': 'keyword'},
                        'source_ip': {'type': 'ip'},
                        'username': {'type': 'keyword'},
                        'password': {'type': 'keyword'},
                        'started_at': {'type': 'date'},
                        'ended_at': {'type': 'date'},
                        'commands_executed': {'type': 'keyword'},
                        'geo_country': {'type': 'keyword'},
                        'geo_latitude': {'type': 'float'},
                        'geo_longitude': {'type': 'float'},
                    }
                }
            }
        }
        
        for index_name, mapping in indices.items():
            if not await self.elasticsearch.indices.exists(index=index_name):
                await self.elasticsearch.indices.create(
                    index=index_name,
                    body=mapping
                )
                logger.info(f"Índice criado: {index_name}")
                
    async def process_event(self, event_id: str, event_data: dict):
        """Processa um único evento."""
        try:
            # Parse e normalização
            processed_event = await self._parse_and_normalize(event_data)
            
            # Enriquecimento
            processed_event = await self._enrich_event(processed_event)
            
            # Classificação de severidade
            processed_event = self._classify_severity(processed_event)
            
            # Armazena no Elasticsearch
            await self._store_elasticsearch(processed_event)
            
            # Armazena eventos críticos no PostgreSQL
            if processed_event.get('severity') in ['high', 'critical']:
                await self._store_postgresql(processed_event)
                
            logger.debug(f"Evento processado: {event_id} - {processed_event.get('event_type')}")
            
        except Exception as e:
            logger.error(f"Erro ao processar evento {event_id}: {e}")
            
    async def _parse_and_normalize(self, event_data: dict) -> dict:
        """Faz parsing e normalização do evento."""
        event = event_data.copy()
        
        # Garante timestamp
        if 'timestamp' not in event:
            event['timestamp'] = datetime.utcnow().isoformat()
            
        # Parse de dados JSON se for string
        if isinstance(event.get('data'), str):
            try:
                event['parsed_data'] = json.loads(event['data'])
                # Merge parsed data com evento principal
                for key, value in event['parsed_data'].items():
                    if key not in event:
                        event[key] = value
            except json.JSONDecodeError:
                event['parsed_data'] = {}
                
        # Normaliza campo de severidade
        severity_map = {
            'low': 'low',
            'medium': 'medium',
            'high': 'high',
            'critical': 'critical',
        }
        event['severity'] = severity_map.get(
            event.get('severity', 'low').lower(), 
            'low'
        )
        
        return event
        
    async def _enrich_event(self, event: dict) -> dict:
        """Enriquece evento com dados adicionais."""
        # Enriquecimento de IP de origem
        source_ip = event.get('source_ip')
        if source_ip:
            geo_data = GeoIPEnricher.enrich(source_ip)
            event.update({
                'geo_country': geo_data['country'],
                'geo_city': geo_data['city'],
                'geo_latitude': geo_data['lat'],
                'geo_longitude': geo_data['lon'],
                'asn': geo_data['asn'],
            })
            
            # Verifica reputação
            reputation = IPReputationChecker.check_reputation(source_ip)
            event.update(reputation)
            
        # Enriquecimento de IP de destino
        dest_ip = event.get('destination_ip')
        if dest_ip:
            dest_geo = GeoIPEnricher.enrich(dest_ip)
            event['dest_geo_country'] = dest_geo['country']
            
        return event
        
    def _classify_severity(self, event: dict) -> dict:
        """Classifica/ajusta severidade baseado em regras."""
        event_type = event.get('event_type', '').lower()
        
        # Regras de severidade automática
        if 'honeypot_login' in event_type:
            # Múltiplas tentativas = maior severidade
            event['severity'] = 'medium'
        elif 'honeypot_command' in event_type:
            event['severity'] = 'low'
        elif 'honeypot_session' in event_type:
            event['severity'] = 'medium'
        elif 'auth_failure' in event_type:
            event['severity'] = 'medium'
        elif 'auth_success' in event_type:
            event['severity'] = 'low'
        elif 'suspicious_process' in event_type:
            event['severity'] = 'high'
        elif 'suspicious_connection' in event_type:
            event['severity'] = 'critical'
        elif 'system_log' in event_type:
            event['severity'] = 'low'
            
        # Ajusta baseado em reputação
        if event.get('is_malicious'):
            current_severity = event.get('severity', 'low')
            severity_order = ['low', 'medium', 'high', 'critical']
            current_idx = severity_order.index(current_severity) if current_severity in severity_order else 0
            new_idx = min(current_idx + 1, len(severity_order) - 1)
            event['severity'] = severity_order[new_idx]
            
        return event
        
    async def _store_elasticsearch(self, event: dict):
        """Armazena evento no Elasticsearch."""
        index = 'soc_events'
        
        # Honeypot sessions vão para índice separado
        if event.get('event_type') == 'honeypot_session':
            index = 'honeypot_sessions'
            
        await self.elasticsearch.index(
            index=index,
            document=event,
        )
        
    async def _store_postgresql(self, event: dict):
        """Armazena evento crítico no PostgreSQL."""
        try:
            async with self.postgres_pool.acquire() as conn:
                await conn.execute(
                    """
                    INSERT INTO events (
                        timestamp, source, event_type, severity,
                        source_ip, destination_ip, source_port, destination_port,
                        protocol, username, password, command,
                        payload, raw_log, mitre_technique_id, mitre_tactic,
                        status
                    ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17)
                    """,
                    event.get('timestamp', datetime.utcnow().isoformat()),
                    event.get('source', 'unknown'),
                    event.get('event_type', 'unknown'),
                    event.get('severity', 'low'),
                    event.get('source_ip'),
                    event.get('destination_ip'),
                    event.get('source_port'),
                    event.get('destination_port'),
                    event.get('protocol'),
                    event.get('username'),
                    event.get('password'),
                    event.get('command'),
                    json.dumps(event.get('parsed_data', {})),
                    event.get('raw_log'),
                    event.get('mitre_technique_id'),
                    event.get('mitre_tactic'),
                    'new'
                )
        except Exception as e:
            logger.error(f"Erro ao armazenar no PostgreSQL: {e}")
            
    async def process_events(self):
        """Loop principal de processamento de eventos."""
        logger.info("Iniciando processamento de eventos...")
        
        while True:
            try:
                # Lê eventos do Redis Streams
                response = await self.redis.xreadgroup(
                    self.consumer_group,
                    self.consumer_name,
                    {'soc_events': '>'},
                    count=BATCH_SIZE,
                    block=5000  # 5 segundos timeout
                )
                
                if response:
                    for stream_name, messages in response:
                        for message_id, message_data in messages:
                            # Processa evento
                            await self.process_event(message_id, message_data)
                            
                            # Acknowledge evento processado
                            await self.redis.xack('soc_events', self.consumer_group, message_id)
                            
                await asyncio.sleep(PROCESS_INTERVAL)
                
            except asyncio.CancelledError:
                logger.info("Processamento encerrado")
                break
            except Exception as e:
                logger.error(f"Erro no loop de processamento: {e}")
                await asyncio.sleep(5)  # Espera antes de tentar novamente
                
    async def cleanup(self):
        """Limpa recursos."""
        if self.elasticsearch:
            await self.elasticsearch.close()
        if self.postgres_pool:
            await self.postgres_pool.close()
        if self.redis:
            await self.redis.close()
        logger.info("Recursos liberados")


async def main():
    """Função principal."""
    logger.info("="*60)
    logger.info("  SOC/NOC Platform - Processador de Eventos")
    logger.info("  ⚠️  AVISO: Uso exclusivo em ambientes laboratoriais")
    logger.info("="*60)
    
    processor = EventProcessor()
    
    try:
        await processor.initialize()
        await processor.process_events()
    except KeyboardInterrupt:
        logger.info("Processador encerrado pelo usuário")
    except Exception as e:
        logger.error(f"Erro fatal: {e}")
        raise
    finally:
        await processor.cleanup()


if __name__ == '__main__':
    asyncio.run(main())
