"""
Endpoints de autenticação
"""
from fastapi import APIRouter, Depends, HTTPException, status

from app.models import LoginRequest, LoginResponse, UserCreate, UserResponse, ChangePasswordRequest
from app.security import get_current_user, require_admin
from app.services import AuthService
from app.main import pg_pool

router = APIRouter(prefix="/api/auth", tags=["Authentication"])


@router.post("/login", response_model=LoginResponse)
async def login(credentials: LoginRequest):
    """Autentica usuário e retorna token JWT."""
    auth_service = AuthService(pg_pool)
    return await auth_service.authenticate(credentials.username, credentials.password)


@router.post("/register", response_model=UserResponse)
async def register(
    user_data: UserCreate,
    current_user: dict = Depends(require_admin)
):
    """Registra novo usuário (apenas admin)."""
    auth_service = AuthService(pg_pool)
    return await auth_service.create_user(
        username=user_data.username,
        password=user_data.password,
        email=user_data.email,
        role=user_data.role
    )


@router.get("/me", response_model=UserResponse)
async def get_current_user_info(
    current_user: dict = Depends(get_current_user)
):
    """Obtém informações do usuário atual."""
    auth_service = AuthService(pg_pool)
    user = await auth_service.get_user(current_user['user_id'])
    if not user:
        raise HTTPException(status_code=404, detail="Usuário não encontrado")
    return user


@router.post("/change-password")
async def change_password(
    password_data: ChangePasswordRequest,
    current_user: dict = Depends(get_current_user)
):
    """Altera senha do usuário."""
    auth_service = AuthService(pg_pool)
    await auth_service.change_password(
        current_user['user_id'],
        password_data.current_password,
        password_data.new_password
    )
    return {"message": "Senha alterada com sucesso"}


@router.get("/users", response_model=list[UserResponse])
async def list_users(
    current_user: dict = Depends(require_admin)
):
    """Lista todos os usuários (apenas admin)."""
    auth_service = AuthService(pg_pool)
    return await auth_service.list_users()
