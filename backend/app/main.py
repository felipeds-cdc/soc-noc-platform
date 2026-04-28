"""
SOC/NOC Platform - Backend API
===============================
API REST para consulta e controle de eventos de segurança, alertas,
honeypot, threat hunting e relatórios.

⚠️ AVISO ÉTICO: Use apenas em ambientes controlados e autorizados.
"""
from contextlib import asynccontextmanager
from datetime import datetime
import logging
import os

import asyncio
import asyncpg
import redis.asyncio as aioredis
from elasticsearch import AsyncElasticsearch
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.config import get_settings

settings = get_settings()
logger = logging.getLogger(__name__)

STARTUP_MAX_RETRIES = int(os.getenv("STARTUP_MAX_RETRIES", "60"))
STARTUP_RETRY_DELAY = float(os.getenv("STARTUP_RETRY_DELAY", "2"))

# Global connections
redis_client: aioredis.Redis = None
es_client: AsyncElasticsearch = None
pg_pool = None


async def _connect_redis() -> aioredis.Redis:
    client = aioredis.from_url(settings.REDIS_URL, decode_responses=True)
    await client.ping()
    return client


async def _connect_elasticsearch() -> AsyncElasticsearch:
    client = AsyncElasticsearch([settings.ELASTICSEARCH_URL])
    try:
        health = await client.cluster.health()
        logger.info("Elasticsearch: %s", health.get("status", "unknown"))
        return client
    except Exception:
        await client.close()
        raise


async def _connect_postgres():
    pg_url = settings.DATABASE_URL.replace("postgresql+asyncpg://", "postgresql://")
    return await asyncpg.create_pool(pg_url)


async def _connect_with_retry(name: str, connector):
    for attempt in range(1, STARTUP_MAX_RETRIES + 1):
        try:
            conn = await connector()
            logger.info("%s conectado", name)
            return conn
        except Exception as exc:
            logger.warning(
                "Aguardando %s... (%s/%s): %s",
                name,
                attempt,
                STARTUP_MAX_RETRIES,
                exc,
            )
            await asyncio.sleep(STARTUP_RETRY_DELAY)

    logger.error(
        "%s indisponivel apos %s tentativas. Iniciando em modo degradado.",
        name,
        STARTUP_MAX_RETRIES,
    )
    return None


@asynccontextmanager
async def lifespan(app: FastAPI):
    global redis_client, es_client, pg_pool

    logger.info("=" * 60)
    logger.info("SOC/NOC Platform - Backend API")
    logger.info("=" * 60)

    app.state.redis_client = None
    app.state.es_client = None
    app.state.pg_pool = None

    redis_client = await _connect_with_retry("Redis", _connect_redis)
    es_client = await _connect_with_retry("Elasticsearch", _connect_elasticsearch)
    pg_pool = await _connect_with_retry("PostgreSQL", _connect_postgres)

    app.state.redis_client = redis_client
    app.state.es_client = es_client
    app.state.pg_pool = pg_pool

    if settings.SECRET_KEY == "CHANGE_ME_IN_ENV":
        logger.warning("SECRET_KEY padrao em uso. Configure SECRET_KEY em ambiente seguro.")

    logger.info("Backend iniciado")

    yield  # ← ESSENCIAL

    logger.info("Encerrando conexoes...")

    if redis_client:
        try:
            await redis_client.aclose()
        except Exception:
            pass

    if es_client:
        try:
            await es_client.close()
        except Exception:
            pass

    if pg_pool:
        try:
            await pg_pool.close()
        except Exception:
            pass

    logger.info("Conexoes encerradas")

# Cria aplicação FastAPI
app = FastAPI(
    title=settings.APP_NAME,
    version=settings.APP_VERSION,
    description="API para plataforma SOC/NOC - Monitoramento de Segurança e Operações de Rede",
    lifespan=lifespan
)

# CORS
ALLOWED_ORIGINS = [
    origin.strip()
    for origin in os.getenv(
        "ALLOWED_ORIGINS",
        "http://localhost:3000,http://localhost:5173,http://127.0.0.1:3000,http://127.0.0.1:5173",
    ).split(",")
    if origin.strip()
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=ALLOWED_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# Health check
@app.get("/health")
async def health_check():
    """Verifica saúde do serviço."""
    status = {
        "status": "ok",
        "timestamp": datetime.utcnow().isoformat(),
        "services": {}
    }

    # Redis
    try:
        if redis_client:
            await redis_client.ping()
            status["services"]["redis"] = "connected"
        else:
            status["services"]["redis"] = "not_initialized"
    except Exception:
        status["services"]["redis"] = "disconnected"
        status["status"] = "degraded"

    # Elasticsearch
    try:
        if es_client:
            health = await es_client.cluster.health()
            status["services"]["elasticsearch"] = health.get('status', 'unknown')
        else:
            status["services"]["elasticsearch"] = "not_initialized"
    except Exception:
        status["services"]["elasticsearch"] = "disconnected"
        status["status"] = "degraded"

    # PostgreSQL
    try:
        if pg_pool:
            async with pg_pool.acquire() as conn:
                await conn.fetchval('SELECT 1')
            status["services"]["postgresql"] = "connected"
        else:
            status["services"]["postgresql"] = "not_initialized"
    except Exception:
        status["services"]["postgresql"] = "disconnected"
        status["status"] = "degraded"
        
    return status


# Include routers
from app.api import auth, events, alerts, dashboard, threat_hunting, reports

app.include_router(auth.router)
app.include_router(events.router)
app.include_router(alerts.router)
app.include_router(dashboard.router)
app.include_router(threat_hunting.router)
app.include_router(reports.router)


# Root endpoint
@app.get("/")
async def root():
    """Endpoint raiz."""
    return {
        "name": settings.APP_NAME,
        "version": settings.APP_VERSION,
        "docs": "/docs",
        "warning": "⚠️  Esta plataforma é destinada APENAS para ambientes laboratoriais e autorizados"
    }


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(
        "app.main:app",
        host=settings.BACKEND_HOST,
        port=settings.BACKEND_PORT,
        reload=settings.DEBUG
    )
