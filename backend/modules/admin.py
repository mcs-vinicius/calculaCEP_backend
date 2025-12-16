import secrets
from typing import List
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from backend.common import get_db, get_current_admin, User, AllowedMatricula, WhitelistItem, WhitelistCreate, UserList, pwd_context

router = APIRouter(prefix="/admin", tags=["Administrativo"])

@router.get("/whitelist", response_model=List[WhitelistItem])
def get_whitelist(db: Session = Depends(get_db), admin=Depends(get_current_admin)):
    return db.query(AllowedMatricula).all()

@router.post("/whitelist")
def add_whitelist(data: WhitelistCreate, db: Session = Depends(get_db), admin=Depends(get_current_admin)):
    if db.query(AllowedMatricula).filter(AllowedMatricula.matricula == data.matricula).first():
        raise HTTPException(status_code=400, detail="Já existe.")
    db.add(AllowedMatricula(matricula=data.matricula))
    db.commit()
    return {"message": "Adicionado."}

@router.delete("/whitelist/{id}")
def del_whitelist(id: int, db: Session = Depends(get_db), admin=Depends(get_current_admin)):
    item = db.query(AllowedMatricula).filter(AllowedMatricula.id == id).first()
    if item: db.delete(item); db.commit()
    return {"message": "Removido."}

@router.get("/users", response_model=List[UserList])
def get_users(db: Session = Depends(get_db), admin=Depends(get_current_admin)):
    return db.query(User).all()

@router.delete("/users/{user_id}")
def del_user(user_id: int, db: Session = Depends(get_db), admin=Depends(get_current_admin)):
    if user_id == admin.id: raise HTTPException(status_code=400, detail="Não pode se excluir.")
    user = db.query(User).filter(User.id == user_id).first()
    if user: db.delete(user); db.commit()
    return {"message": "Excluído."}

@router.post("/users/{user_id}/reset-password")
def reset_pass(user_id: int, db: Session = Depends(get_db), admin=Depends(get_current_admin)):
    user = db.query(User).filter(User.id == user_id).first()
    if not user: raise HTTPException(404, "Não encontrado")
    
    temp = secrets.token_urlsafe(8)
    user.hashed_password = pwd_context.hash(temp)
    user.must_change_password = True
    db.commit()
    return {"message": "Senha resetada", "temp_password": temp}