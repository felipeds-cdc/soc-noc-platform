"""
SOC/NOC Platform - Backend API
===============================
API REST para consulta e controle de eventos de segurança, alertas,
honeypot, threat hunting e relatórios.

⚠️ AVISO ÉTICO: Use apenas em ambientes controlados e autorizados.
"""
import os
from contextlib import asynccontextmanager
from datetime import datetime

import asyncpg
import redis.asyncio as aioredis
from elasticsearch import AsyncElasticsearch
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.config import get_settings

settings = get_settings()

# Global connections
redis_client: aioredis.Redis = None
es_client: AsyncElasticsearch = None
pg_pool = None


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Gerencia ciclo de vida da aplicação."""
    global redis_client, es_client, pg_pool
    
    # Startup
    print("="*60)
    print("  SOC/NOC Platform - Backend API")
    print("  ⚠️  AVISO: Uso exclusivo em ambientes laboratoriais")
    print("="*60)
    
    # Redis
    redis_client = await aioredis.from_url(settings.REDIS_URL, decode_responses=True)
    await redis_client.ping()
    app.state.redis_client = redis_client
    print(f"✓ Redis conectado: {settings.REDIS_URL}")
    
    # Elasticsearch
    es_client = AsyncElasticsearch([settings.ELASTICSEARCH_URL])
    health = await es_client.cluster.health()
    app.state.es_client = es_client
    print(f"✓ Elasticsearch conectado: {health.get('status', 'unknown')}")
    
    # PostgreSQL
    pg_url = settings.DATABASE_URL.replace('postgresql+asyncpg://', 'postgresql://')
    pg_pool = await asyncpg.create_pool(pg_url)
    app.state.pg_pool = pg_pool
    print(f"✓ PostgreSQL conectado: {settings.DATABASE_URL}")
    
    print("\n🚀 Backend API iniciado!")
    
    yield
    
    # Shutdown
    print("\nEncerrando conexões...")
    if redis_client:
        await redis_client.close()
    if es_client:
        await es_client.close()
    if pg_pool:
        await pg_pool.close()
    print("✓ Conexões encerradas")


# Cria aplicação FastAPI
app = FastAPI(
    title=settings.APP_NAME,
    version=settings.APP_VERSION,
    description="API para plataforma SOC/NOC - Monitoramento de Segurança e Operações de Rede",
    lifespan=lifespan
)

# CORS
ALLOWED_ORIGINS = os.getenv("ALLOWED_ORIGINS", "http://localhost:3000,http://localhost:5173").split(",")
app.add_middleware(
    CORSMiddleware,
    allow_origins=ALLOWED_ORIGINS,
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
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
