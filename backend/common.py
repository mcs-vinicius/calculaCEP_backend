# backend/common.py
import os
from datetime import datetime, timedelta
from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
from jose import JWTError, jwt
from passlib.context import CryptContext
from pydantic import BaseModel
from sqlalchemy import create_engine, Column, Integer, String, Boolean
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, Session

# --- CONFIGURAÇÕES DE AMBIENTE ---
# Utiliza variáveis de ambiente para segurança (não deixar senhas hardcoded).
SECRET_KEY = os.getenv("SECRET_KEY", "SUA_CHAVE_SECRETA_AQUI")
ALGORITHM = "HS256"
DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///./cardiogeriatria.db")

# Correção para compatibilidade com o Render:
# O Render fornece a URL do banco começando com "postgres://", mas o SQLAlchemy
# atual exige "postgresql://". Esta linha faz a correção automática.
if DATABASE_URL.startswith("postgres://"):
    DATABASE_URL = DATABASE_URL.replace("postgres://", "postgresql://", 1)

# --- CONFIGURAÇÃO DO BANCO DE DADOS (SQLAlchemy) ---
if "sqlite" in DATABASE_URL:
    # check_same_thread=False é necessário apenas para SQLite
    engine = create_engine(DATABASE_URL, connect_args={"check_same_thread": False})
else:
    engine = create_engine(DATABASE_URL)

# SessionLocal cria uma nova sessão do banco para cada requisição
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base() # Classe base para criação dos Modelos (Tabelas)

def get_db():
    """
    Dependency Injection para gestão de conexão com Banco de Dados.
    Cria uma sessão antes da requisição e FECHA a sessão obrigatoriamente depois,
    mesmo que ocorra erro. Isso evita vazamento de conexões.
    """
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

# --- MODELOS ORM (Tabelas) ---

class User(Base):
    """Representa a tabela 'users' no banco de dados."""
    __tablename__ = "users"
    id = Column(Integer, primary_key=True, index=True)
    nome = Column(String)
    email = Column(String, unique=True, index=True)
    matricula = Column(String, unique=True, index=True)
    hashed_password = Column(String) # Armazena apenas o HASH da senha, nunca a senha real
    is_admin = Column(Boolean, default=False)
    must_change_password = Column(Boolean, default=False) # Força troca no primeiro acesso após reset

class AllowedMatricula(Base):
    """Tabela 'whitelist' para controlar quem pode se cadastrar."""
    __tablename__ = "allowed_matriculas"
    id = Column(Integer, primary_key=True, index=True)
    matricula = Column(String, unique=True, index=True)

# Cria as tabelas se não existirem
Base.metadata.create_all(bind=engine)

# --- SCHEMAS PYDANTIC (Validação de Dados) ---
# Estas classes definem o formato esperado de entrada e saída da API.

class UserCreate(BaseModel):
    """Schema para entrada de dados no Registro."""
    nome: str
    matricula: str
    email: str
    senha: str

class Token(BaseModel):
    """Schema da resposta de Login bem sucedido."""
    access_token: str
    token_type: str
    is_admin: bool
    nome: str
    must_change_password: bool

class PasswordChange(BaseModel):
    new_password: str

class WhitelistCreate(BaseModel):
    matricula: str

class WhitelistItem(BaseModel):
    id: int
    matricula: str
    class Config: from_attributes = True

class UserList(BaseModel):
    """Schema para listagem de usuários (oculta a senha)."""
    id: int
    nome: str
    email: str
    matricula: str
    is_admin: bool
    must_change_password: bool
    class Config: from_attributes = True

# --- SEGURANÇA E AUTENTICAÇÃO ---

# Configura o algoritmo de Hashing de senha (bcrypt)
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# Define onde o FastAPI deve procurar o token (header Authorization: Bearer ...)
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

def create_access_token(data: dict):
    """Gera um token JWT assinado com a chave secreta e validade definida."""
    to_encode = data.copy()
    expire = datetime.utcnow() + timedelta(minutes=60 * 24) # Validade: 24 horas
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

async def get_current_user(token: str = Depends(oauth2_scheme), db: Session = Depends(get_db)):
    """
    Verifica se o usuário está logado.
    Decodifica o token JWT e busca o usuário no banco.
    """
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        email: str = payload.get("sub")
        if email is None: raise HTTPException(status_code=401, detail="Token inválido")
    except JWTError:
        raise HTTPException(status_code=401, detail="Token inválido ou expirado")
    
    user = db.query(User).filter(User.email == email).first()
    if user is None: raise HTTPException(status_code=401, detail="Usuário não encontrado")
    return user

async def get_current_admin(current_user: User = Depends(get_current_user)):
    """
    Verifica se o usuário logado possui permissões de Administrador.
    """
    if not current_user.is_admin:
        raise HTTPException(status_code=403, detail="Acesso restrito a administradores")
    return current_user