# backend/modules/auth.py
from fastapi import APIRouter, Depends, HTTPException
from fastapi.security import OAuth2PasswordRequestForm
from sqlalchemy.orm import Session
from backend.common import get_db, User, AllowedMatricula, UserCreate, Token, create_access_token, pwd_context, get_current_user, PasswordChange

router = APIRouter(tags=["Autenticação"])

@router.post("/token", response_model=Token)
async def login(form_data: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(get_db)):
    """
    Realiza o Login do usuário.
    Aceita tanto E-mail quanto Matrícula no campo 'username'.
    Retorna um Token JWT (Bearer) se as credenciais forem válidas.
    """
    # Busca usuário por e-mail OU matrícula
    user = db.query(User).filter((User.email == form_data.username) | (User.matricula == form_data.username)).first()
    
    # Valida existência e senha (hash)
    if not user or not pwd_context.verify(form_data.password, user.hashed_password):
        raise HTTPException(status_code=401, detail="Credenciais incorretas")
    
    # Gera o token de acesso
    access_token = create_access_token(data={"sub": user.email})
    
    return {
        "access_token": access_token, 
        "token_type": "bearer", 
        "is_admin": user.is_admin, 
        "nome": user.nome, 
        "must_change_password": user.must_change_password
    }

@router.post("/register")
def register(user: UserCreate, db: Session = Depends(get_db)):
    """
    Registra um novo usuário no sistema.
    Lógica 'Inteligente':
    1. Se for o PRIMEIRO usuário do banco -> Torna-se ADMIN automaticamente.
    2. Se não for o primeiro -> Verifica se a matrícula está na Whitelist.
    """
    users_count = db.query(User).count()
    is_admin = (users_count == 0) # True apenas se o banco estiver vazio

    # Validação de Whitelist (apenas para não-admins)
    if not is_admin:
        if not db.query(AllowedMatricula).filter(AllowedMatricula.matricula == user.matricula).first(): 
            raise HTTPException(status_code=403, detail="Matrícula não autorizada pelo administrador.")

    # Verifica se usuário já existe
    if db.query(User).filter((User.email == user.email) | (User.matricula == user.matricula)).first():
        raise HTTPException(status_code=400, detail="Usuário já existe (E-mail ou Matrícula duplicada).")

    # Cria e salva o usuário
    db_user = User(
        nome=user.nome, 
        email=user.email, 
        matricula=user.matricula, 
        hashed_password=pwd_context.hash(user.senha), # Criptografa a senha
        is_admin=is_admin
    )
    db.add(db_user)
    db.commit()
    
    role = "ADMINISTRADOR" if is_admin else "usuário padrão"
    return {"message": f"Cadastro realizado com sucesso! Você foi registrado como {role}."}

@router.post("/users/change-password")
def change_own_password(data: PasswordChange, db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    """
    Permite que o próprio usuário logado altere sua senha.
    Também remove a flag 'must_change_password' se ela estiver ativa.
    """
    current_user.hashed_password = pwd_context.hash(data.new_password)
    current_user.must_change_password = False 
    db.commit()
    return {"message": "Senha alterada com sucesso!"}