# backend/modules/admin.py
import secrets
from typing import List
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from backend.common import get_db, get_current_admin, User, AllowedMatricula, WhitelistItem, WhitelistCreate, UserList, pwd_context

# Protege TODAS as rotas deste arquivo exigindo que o usuário seja ADMIN (get_current_admin)
router = APIRouter(prefix="/admin", tags=["Painel Administrativo"])

# --- Gestão da Whitelist (Lista de Espera) ---

@router.get("/whitelist", response_model=List[WhitelistItem])
def get_whitelist(db: Session = Depends(get_db), admin=Depends(get_current_admin)):
    """Retorna todas as matrículas cadastradas na Whitelist."""
    return db.query(AllowedMatricula).all()

@router.post("/whitelist")
def add_whitelist(data: WhitelistCreate, db: Session = Depends(get_db), admin=Depends(get_current_admin)):
    """Adiciona uma nova matrícula à Whitelist, permitindo que essa pessoa se cadastre."""
    if db.query(AllowedMatricula).filter(AllowedMatricula.matricula == data.matricula).first():
        raise HTTPException(status_code=400, detail="Matrícula já existe na lista.")
    
    db.add(AllowedMatricula(matricula=data.matricula))
    db.commit()
    return {"message": "Matrícula adicionada com sucesso."}

@router.delete("/whitelist/{id}")
def del_whitelist(id: int, db: Session = Depends(get_db), admin=Depends(get_current_admin)):
    """Remove uma matrícula da Whitelist."""
    item = db.query(AllowedMatricula).filter(AllowedMatricula.id == id).first()
    if item: 
        db.delete(item)
        db.commit()
    return {"message": "Matrícula removida."}

# --- Gestão de Usuários ---

@router.get("/users", response_model=List[UserList])
def get_users(db: Session = Depends(get_db), admin=Depends(get_current_admin)):
    """Lista todos os usuários registrados no sistema."""
    return db.query(User).all()

@router.delete("/users/{user_id}")
def del_user(user_id: int, db: Session = Depends(get_db), admin=Depends(get_current_admin)):
    """Exclui um usuário permanentemente (Bloqueia exclusão do próprio admin logado)."""
    if user_id == admin.id: 
        raise HTTPException(status_code=400, detail="Você não pode excluir a si mesmo.")
    
    user = db.query(User).filter(User.id == user_id).first()
    if user: 
        db.delete(user)
        db.commit()
    return {"message": "Usuário excluído com sucesso."}

@router.post("/users/{user_id}/reset-password")
def reset_pass(user_id: int, db: Session = Depends(get_db), admin=Depends(get_current_admin)):
    """
    Reseta a senha de um usuário específico.
    Gera uma senha temporária aleatória e ativa a flag 'must_change_password'.
    O admin deve informar a senha temporária gerada ao usuário.
    """
    user = db.query(User).filter(User.id == user_id).first()
    if not user: raise HTTPException(404, "Usuário não encontrado")
    
    # Gera senha segura de 8 caracteres url-safe
    temp_pass = secrets.token_urlsafe(8) 
    
    user.hashed_password = pwd_context.hash(temp_pass)
    user.must_change_password = True # Obriga o usuário a trocar no próximo login
    db.commit()
    
    return {"message": "Senha resetada", "temp_password": temp_pass}