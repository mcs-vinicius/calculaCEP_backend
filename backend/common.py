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
# Pega a chave secreta e URL do banco das variáveis de ambiente (Render).
# Se não encontrar, usa valores padrão para desenvolvimento local.
SECRET_KEY = os.getenv("SECRET_KEY", "SUA_CHAVE_SECRETA_AQUI")
ALGORITHM = "HS256" # Algoritmo de criptografia do Token
DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///./cardiogeriatria.db")

# Ajuste de compatibilidade: O Render fornece URLs com "postgres://", 
# mas a biblioteca SQLAlchemy exige "postgresql://"
if DATABASE_URL.startswith("postgres://"):
    DATABASE_URL = DATABASE_URL.replace("postgres://", "postgresql://", 1)

# --- CONFIGURAÇÃO DO BANCO DE DADOS (SQLAlchemy) ---
# Cria o "Engine" que gerencia a conexão com o banco (SQLite ou PostgreSQL)
if "sqlite" in DATABASE_URL:
    engine = create_engine(DATABASE_URL, connect_args={"check_same_thread": False})
else:
    engine = create_engine(DATABASE_URL)

# SessionLocal: Fábrica de sessões. Cada requisição criará uma nova sessão do banco.
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base() # Classe base para os modelos (Tabelas)

# Dependência: Função que cria e fecha a conexão com o banco para cada request.
def get_db():
    db = SessionLocal()
    try: yield db
    finally: db.close()

# --- MODELOS DO BANCO (ORM) ---
# Define a estrutura das tabelas no banco de dados.

class User(Base):
    """Tabela de Usuários"""
    __tablename__ = "users"
    id = Column(Integer, primary_key=True, index=True)
    nome = Column(String)
    email = Column(String, unique=True, index=True)
    matricula = Column(String, unique=True, index=True)
    hashed_password = Column(String) # A senha NUNCA é salva em texto puro
    is_admin = Column(Boolean, default=False)
    must_change_password = Column(Boolean, default=False)

class AllowedMatricula(Base):
    """Tabela de Whitelist (Lista de Espera/Permitidos)"""
    __tablename__ = "allowed_matriculas"
    id = Column(Integer, primary_key=True, index=True)
    matricula = Column(String, unique=True, index=True)

# Cria as tabelas no banco se elas não existirem
Base.metadata.create_all(bind=engine)

# --- SCHEMAS (Pydantic) ---
# Definem o formato dos dados que entram e saem da API (Validação).

class UserCreate(BaseModel):
    """Dados necessários para criar um usuário"""
    nome: str
    matricula: str
    email: str
    senha: str

class Token(BaseModel):
    """Formato da resposta de Login (Token JWT)"""
    access_token: str
    token_type: str
    is_admin: bool
    nome: str
    must_change_password: bool

class PasswordChange(BaseModel):
    """Dados para troca de senha"""
    new_password: str

class WhitelistCreate(BaseModel):
    """Dados para adicionar na whitelist"""
    matricula: str

class WhitelistItem(BaseModel):
    """Formato de exibição da whitelist"""
    id: int
    matricula: str
    class Config: from_attributes = True # Permite ler direto do objeto SQLAlchemy

class UserList(BaseModel):
    """Formato de exibição da lista de usuários (sem senha)"""
    id: int
    nome: str
    email: str
    matricula: str
    is_admin: bool
    must_change_password: bool
    class Config: from_attributes = True

# --- SEGURANÇA E AUTENTICAÇÃO ---

# Configura o sistema de hash de senhas (bcrypt)
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
# Configura o esquema de autenticação (OAuth2 com Bearer Token)
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

def create_access_token(data: dict):
    """Gera um Token JWT com validade de 24 horas"""
    to_encode = data.copy()
    expire = datetime.utcnow() + timedelta(minutes=60 * 24)
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

async def get_current_user(token: str = Depends(oauth2_scheme), db: Session = Depends(get_db)):
    """
    Dependência de Proteção:
    1. Lê o token do cabeçalho da requisição.
    2. Decodifica e valida o token.
    3. Busca o usuário no banco.
    4. Se tudo der certo, retorna o usuário atual. Senão, lança erro 401.
    """
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        email: str = payload.get("sub")
        if email is None: raise HTTPException(status_code=401, detail="Token inválido")
    except JWTError: raise HTTPException(status_code=401, detail="Token inválido")
    
    user = db.query(User).filter(User.email == email).first()
    if user is None: raise HTTPException(status_code=401, detail="Usuário não encontrado")
    return user

async def get_current_admin(current_user: User = Depends(get_current_user)):
    """
    Dependência de Proteção Administrativa:
    Verifica se o usuário logado tem a flag 'is_admin' como True.
    """
    if not current_user.is_admin:
        raise HTTPException(status_code=403, detail="Acesso restrito")
    return current_user