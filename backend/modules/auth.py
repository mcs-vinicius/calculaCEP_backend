from fastapi import APIRouter, Depends, HTTPException
from fastapi.security import OAuth2PasswordRequestForm
from sqlalchemy.orm import Session
from backend.common import get_db, User, AllowedMatricula, UserCreate, Token, create_access_token, pwd_context, get_current_user, PasswordChange

router = APIRouter(tags=["Autenticação"])

@router.post("/token", response_model=Token)
async def login(form_data: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(get_db)):
    user = db.query(User).filter((User.email == form_data.username) | (User.matricula == form_data.username)).first()
    if not user or not pwd_context.verify(form_data.password, user.hashed_password):
        raise HTTPException(status_code=401, detail="Credenciais incorretas")
    
    access_token = create_access_token(data={"sub": user.email})
    return {
        "access_token": access_token, "token_type": "bearer", 
        "is_admin": user.is_admin, "nome": user.nome, "must_change_password": user.must_change_password
    }

@router.post("/register")
def register(user: UserCreate, db: Session = Depends(get_db)):
    users_count = db.query(User).count()
    is_admin = (users_count == 0) # Primeiro usuário é admin

    if not is_admin:
        if not db.query(AllowedMatricula).filter(AllowedMatricula.matricula == user.matricula).first(): 
            raise HTTPException(status_code=403, detail="Matrícula não autorizada.")

    if db.query(User).filter((User.email == user.email) | (User.matricula == user.matricula)).first():
        raise HTTPException(status_code=400, detail="Usuário já existe.")

    db_user = User(
        nome=user.nome, email=user.email, matricula=user.matricula, 
        hashed_password=pwd_context.hash(user.senha), is_admin=is_admin
    )
    db.add(db_user)
    db.commit()
    role = "ADMIN" if is_admin else "usuário"
    return {"message": f"Cadastro realizado como {role}!"}

@router.post("/users/change-password")
def change_own_password(data: PasswordChange, db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    current_user.hashed_password = pwd_context.hash(data.new_password)
    current_user.must_change_password = False
    db.commit()
    return {"message": "Senha alterada!"}