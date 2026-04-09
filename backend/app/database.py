"""
Gerenciamento de banco de dados
"""
from typing import AsyncGenerator
from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession, async_sessionmaker
from sqlalchemy.orm import declarative_base

from app.config import get_settings, Settings

Base = declarative_base()


class DatabaseManager:
    """Gerencia conexões com banco de dados."""
    
    def __init__(self, settings: Settings):
        self.engine = create_async_engine(
            settings.DATABASE_URL,
            pool_size=settings.DATABASE_POOL_SIZE,
            max_overflow=settings.DATABASE_MAX_OVERFLOW,
            echo=settings.DEBUG
        )
        self.async_session = async_sessionmaker(
            self.engine,
            class_=AsyncSession,
            expire_on_commit=False
        )
        
    async def get_session(self) -> AsyncGenerator[AsyncSession, None]:
        """Obtém sessão do banco."""
        async with self.async_session() as session:
            try:
                yield session
                await session.commit()
            except Exception:
                await session.rollback()
                raise
            finally:
                await session.close()


# Instância singleton (será inicializada no startup)
db_manager: DatabaseManager = None


async def get_db() -> AsyncGenerator[AsyncSession, None]:
    """Dependency para obter sessão DB."""
    if db_manager is None:
        raise RuntimeError("Database não inicializado")
    async for session in db_manager.get_session():
        yield session
