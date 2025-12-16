# backend/modules/auth.py
from fastapi import APIRouter, Depends, HTTPException
from fastapi.security import OAuth2PasswordRequestForm
from sqlalchemy.orm import Session
from backend.common import get_db, User, AllowedMatricula, UserCreate, Token, create_access_token, pwd_context, get_current_user, PasswordChange

router = APIRouter(tags=["Autenticação"])

# --- Rota de Login ---
# Recebe user/senha do form, valida e retorna o Token de acesso.
@router.post("/token", response_model=Token)
async def login(form_data: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(get_db)):
    # Aceita tanto E-mail quanto Matrícula no campo de login
    user = db.query(User).filter((User.email == form_data.username) | (User.matricula == form_data.username)).first()
    
    # Verifica se usuário existe e se a senha bate com o hash
    if not user or not pwd_context.verify(form_data.password, user.hashed_password):
        raise HTTPException(status_code=401, detail="Credenciais incorretas")
    
    # Cria o Token JWT
    access_token = create_access_token(data={"sub": user.email})
    return {
        "access_token": access_token, "token_type": "bearer", 
        "is_admin": user.is_admin, "nome": user.nome, "must_change_password": user.must_change_password
    }

# --- Rota de Registro Inteligente ---
@router.post("/register")
def register(user: UserCreate, db: Session = Depends(get_db)):
    # Verifica quantos usuários existem no banco
    users_count = db.query(User).count()
    
    # Se for ZERO, este é o primeiro usuário do sistema -> Vira ADMIN automaticamente.
    is_admin = (users_count == 0)

    if not is_admin:
        # Se NÃO for o primeiro, verifica se a matrícula está na Whitelist
        if not db.query(AllowedMatricula).filter(AllowedMatricula.matricula == user.matricula).first(): 
            raise HTTPException(status_code=403, detail="Matrícula não autorizada pelo administrador.")

    # Verifica duplicidade
    if db.query(User).filter((User.email == user.email) | (User.matricula == user.matricula)).first():
        raise HTTPException(status_code=400, detail="Usuário já existe.")

    # Cria o usuário com a senha criptografada
    db_user = User(
        nome=user.nome, email=user.email, matricula=user.matricula, 
        hashed_password=pwd_context.hash(user.senha), is_admin=is_admin
    )
    db.add(db_user)
    db.commit()
    
    role = "ADMINISTRADOR" if is_admin else "usuário padrão"
    return {"message": f"Cadastro realizado com sucesso! Você foi registrado como {role}."}

# --- Rota de Troca de Senha (Pelo próprio usuário) ---
@router.post("/users/change-password")
def change_own_password(data: PasswordChange, db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    current_user.hashed_password = pwd_context.hash(data.new_password)
    current_user.must_change_password = False # Remove a flag de "Troca Obrigatória"
    db.commit()
    return {"message": "Senha alterada com sucesso!"}