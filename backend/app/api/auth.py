"""
Endpoints de autenticação
"""
from fastapi import APIRouter, Depends, HTTPException, status

from app.models import LoginRequest, LoginResponse, UserCreate, UserResponse, ChangePasswordRequest
from app.security import get_current_user, require_admin
from app.services import AuthService
from app.database import get_db

router = APIRouter(prefix="/api/auth", tags=["Authentication"])


@router.post("/login", response_model=LoginResponse)
async def login(credentials: LoginRequest, db=Depends(get_db)):
    """Autentica usuário e retorna token JWT."""
    auth_service = AuthService(db.bind)  # Usa o pool de conexões
    return await auth_service.authenticate(credentials.username, credentials.password)


@router.post("/register", response_model=UserResponse)
async def register(
    user_data: UserCreate,
    current_user: dict = Depends(require_admin),
    db=Depends(get_db)
):
    """Registra novo usuário (apenas admin)."""
    auth_service = AuthService(db.bind)
    return await auth_service.create_user(
        username=user_data.username,
        password=user_data.password,
        email=user_data.email,
        role=user_data.role
    )


@router.get("/me", response_model=UserResponse)
async def get_current_user_info(
    current_user: dict = Depends(get_current_user),
    db=Depends(get_db)
):
    """Obtém informações do usuário atual."""
    auth_service = AuthService(db.bind)
    user = await auth_service.get_user(current_user['user_id'])
    if not user:
        raise HTTPException(status_code=404, detail="Usuário não encontrado")
    return user


@router.post("/change-password")
async def change_password(
    password_data: ChangePasswordRequest,
    current_user: dict = Depends(get_current_user),
    db=Depends(get_db)
):
    """Altera senha do usuário."""
    auth_service = AuthService(db.bind)
    await auth_service.change_password(
        current_user['user_id'],
        password_data.current_password,
        password_data.new_password
    )
    return {"message": "Senha alterada com sucesso"}


@router.get("/users", response_model=list[UserResponse])
async def list_users(
    current_user: dict = Depends(require_admin),
    db=Depends(get_db)
):
    """Lista todos os usuários (apenas admin)."""
    auth_service = AuthService(db.bind)
    return await auth_service.list_users()
