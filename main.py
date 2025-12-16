# backend/main.py
import io
import os
import uuid
import secrets
from datetime import datetime, timedelta
from typing import Dict, Any, Optional, List

import pandas as pd
import googlemaps
from googlemaps.exceptions import ApiError, HTTPError, Timeout, TransportError

from fastapi import FastAPI, UploadFile, File, Form, HTTPException, Depends, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, FileResponse
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm

# --- Imports de Segurança e Banco de Dados ---
from sqlalchemy import create_engine, Column, Integer, String, Boolean
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, Session
from passlib.context import CryptContext
from jose import JWTError, jwt
from pydantic import BaseModel

# --- CONFIGURAÇÕES GERAIS ---
app = FastAPI(title="API CardioGeriatria", version="5.2.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

SECRET_KEY = "SUA_CHAVE_SECRETA_MUITO_SEGURA_AQUI"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60 * 24

DATABASE_URL = "sqlite:///./cardiogeriatria.db"
engine = create_engine(DATABASE_URL, connect_args={"check_same_thread": False})
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

# --- MODELOS (Tabelas) ---
class User(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True, index=True)
    nome = Column(String)
    email = Column(String, unique=True, index=True)
    matricula = Column(String, unique=True, index=True)
    hashed_password = Column(String)
    is_admin = Column(Boolean, default=False)
    # NOVO CAMPO: Indica se o usuário é obrigado a trocar a senha
    must_change_password = Column(Boolean, default=False)

class AllowedMatricula(Base):
    __tablename__ = "allowed_matriculas"
    id = Column(Integer, primary_key=True, index=True)
    matricula = Column(String, unique=True, index=True)

Base.metadata.create_all(bind=engine)

# --- SCHEMAS (Pydantic) ---
class UserCreate(BaseModel):
    nome: str
    matricula: str
    email: str
    senha: str

class UserList(BaseModel):
    id: int
    nome: str
    email: str
    matricula: str
    is_admin: bool
    must_change_password: bool # Retorna status na lista
    class Config:
        from_attributes = True

class WhitelistCreate(BaseModel):
    matricula: str

class WhitelistItem(BaseModel):
    id: int
    matricula: str
    class Config:
        from_attributes = True

class Token(BaseModel):
    access_token: str
    token_type: str
    is_admin: bool
    nome: str
    must_change_password: bool # Envia status no login

class PasswordChange(BaseModel):
    new_password: str

# --- DEPENDÊNCIAS ---
def get_db():
    db = SessionLocal()
    try: yield db
    finally: db.close()

def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    to_encode = data.copy()
    expire = datetime.utcnow() + (expires_delta if expires_delta else timedelta(minutes=15))
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

async def get_current_user(token: str = Depends(oauth2_scheme), db: Session = Depends(get_db)):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        email: str = payload.get("sub")
        if email is None: raise HTTPException(status_code=401, detail="Credenciais inválidas")
    except JWTError: raise HTTPException(status_code=401, detail="Credenciais inválidas")
    user = db.query(User).filter(User.email == email).first()
    if user is None: raise HTTPException(status_code=401, detail="Usuário não encontrado")
    return user

async def get_current_admin_user(current_user: User = Depends(get_current_user)):
    if not current_user.is_admin:
        raise HTTPException(status_code=403, detail="Acesso restrito a administradores")
    return current_user

# --- CONFIG GOOGLE MAPS ---
GOOGLE_MAPS_API_KEY = 'AIzaSyB-gfeMDr52mASa39zr3n0QV__9zxS9khk'
gmaps_client = googlemaps.Client(key=GOOGLE_MAPS_API_KEY)
coords_cache: Dict[str, tuple] = {}

def clean_and_pad_cep(cep: Any) -> str:
    if pd.isna(cep) or cep is None: return ""
    s_cep = str(int(float(cep))) if isinstance(cep, (float, int)) else str(cep)
    cep_numerico = "".join(filter(str.isdigit, s_cep))
    return f"0{cep_numerico}" if len(cep_numerico) == 7 else cep_numerico

def get_google_coords(rua, numero, bairro, municipio, cep) -> tuple | None:
    cache_key = f"{rua}-{cep}"
    if cache_key in coords_cache: return coords_cache[cache_key]
    try:
        address_string = f"{rua}, {numero}, {bairro}, {municipio}, {cep}" if numero else f"{rua}, {bairro}, {municipio}, {cep}"
        geocode_result = gmaps_client.geocode(address_string, region='BR')
        if geocode_result:
            location = geocode_result[0]['geometry']['location']
            coords = (location['lat'], location['lng'])
            coords_cache[cache_key] = coords
            return coords
    except Exception as e: print(f"Erro Geo: {e}")
    return None

# --- ROTAS DE AUTENTICAÇÃO ---

@app.on_event("startup")
def create_default_admin():
    db = SessionLocal()
    if not db.query(User).first():
        hashed_pw = pwd_context.hash("admin123")
        # Admin não precisa trocar senha inicial por padrão, mas pode se quiser
        admin = User(nome="Administrador", email="admin@admin.com", matricula="00000", hashed_password=hashed_pw, is_admin=True, must_change_password=False)
        db.add(admin)
        db.commit()
        print("--- ADMIN CRIADO: admin@admin.com / admin123 ---")
    db.close()

@app.post("/token", response_model=Token)
async def login_for_access_token(form_data: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(get_db)):
    user = db.query(User).filter(User.email == form_data.username).first() or \
           db.query(User).filter(User.matricula == form_data.username).first()
    
    if not user or not pwd_context.verify(form_data.password, user.hashed_password):
        raise HTTPException(status_code=401, detail="Credenciais incorretas")
    
    access_token = create_access_token(data={"sub": user.email}, expires_delta=timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES))
    
    # Retorna também se o usuário DEVE trocar a senha
    return {
        "access_token": access_token, 
        "token_type": "bearer", 
        "is_admin": user.is_admin, 
        "nome": user.nome,
        "must_change_password": user.must_change_password 
    }

@app.post("/users/change-password")
def change_own_password(data: PasswordChange, db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    """Rota para o usuário logado trocar sua própria senha"""
    hashed_pw = pwd_context.hash(data.new_password)
    current_user.hashed_password = hashed_pw
    current_user.must_change_password = False # Remove a obrigatoriedade após a troca
    db.commit()
    return {"message": "Senha alterada com sucesso!"}

@app.post("/register")
def register_user(user: UserCreate, db: Session = Depends(get_db)):
    is_allowed = db.query(AllowedMatricula).filter(AllowedMatricula.matricula == user.matricula).first()
    if not is_allowed and user.matricula != "00000": 
        raise HTTPException(status_code=403, detail=f"Matrícula {user.matricula} não autorizada.")

    if db.query(User).filter((User.email == user.email) | (User.matricula == user.matricula)).first():
        raise HTTPException(status_code=400, detail="Usuário já cadastrado.")

    hashed_pw = pwd_context.hash(user.senha)
    db_user = User(nome=user.nome, email=user.email, matricula=user.matricula, hashed_password=hashed_pw)
    db.add(db_user)
    db.commit()
    return {"message": "Cadastro realizado com sucesso!"}

# --- ADMIN ---

@app.get("/admin/whitelist", response_model=List[WhitelistItem])
def get_whitelist(db: Session = Depends(get_db), current_user: User = Depends(get_current_admin_user)):
    return db.query(AllowedMatricula).all()

@app.post("/admin/whitelist")
def add_to_whitelist(data: WhitelistCreate, db: Session = Depends(get_db), current_user: User = Depends(get_current_admin_user)):
    if db.query(AllowedMatricula).filter(AllowedMatricula.matricula == data.matricula).first():
        raise HTTPException(status_code=400, detail="Matrícula já está na lista.")
    new_allowed = AllowedMatricula(matricula=data.matricula)
    db.add(new_allowed)
    db.commit()
    return {"message": f"Matrícula {data.matricula} liberada."}

@app.delete("/admin/whitelist/{id}")
def remove_from_whitelist(id: int, db: Session = Depends(get_db), current_user: User = Depends(get_current_admin_user)):
    item = db.query(AllowedMatricula).filter(AllowedMatricula.id == id).first()
    if item:
        db.delete(item)
        db.commit()
    return {"message": "Removido."}

@app.get("/admin/users", response_model=List[UserList])
def get_all_users(db: Session = Depends(get_db), current_user: User = Depends(get_current_admin_user)):
    return db.query(User).all()

@app.delete("/admin/users/{user_id}")
def delete_user(user_id: int, db: Session = Depends(get_db), current_user: User = Depends(get_current_admin_user)):
    if user_id == current_user.id: raise HTTPException(status_code=400, detail="Não pode se excluir.")
    user = db.query(User).filter(User.id == user_id).first()
    if user:
        db.delete(user)
        db.commit()
    return {"message": "Usuário excluído."}

@app.post("/admin/users/{user_id}/reset-password")
def reset_user_password(user_id: int, db: Session = Depends(get_db), current_user: User = Depends(get_current_admin_user)):
    user = db.query(User).filter(User.id == user_id).first()
    if not user: raise HTTPException(status_code=404, detail="Usuário não encontrado.")
    
    temp_password = secrets.token_urlsafe(8)
    user.hashed_password = pwd_context.hash(temp_password)
    user.must_change_password = True # OBRIGA A TROCA NO PRÓXIMO LOGIN
    db.commit()
    
    return {
        "message": "Senha resetada.", 
        "temp_password": temp_password,
        "detail": "O usuário será obrigado a trocar a senha ao entrar."
    }

# --- CALCULADORA ---
@app.post("/api/calculate-distances/")
async def calculate_distances_from_file(
    base_rua: str = Form(...), base_numero: str = Form(...), base_bairro: str = Form(...), 
    base_municipio: str = Form(...), base_cep: str = Form(...), file: UploadFile = File(...),
    current_user: User = Depends(get_current_user)
):
    # (Mantendo o código da calculadora igual)
    try:
        base_coords = get_google_coords(base_rua, base_numero, base_bairro, base_municipio, clean_and_pad_cep(base_cep))
        if not base_coords: raise HTTPException(status_code=400, detail="Erro base coords")
    except Exception as e: raise HTTPException(status_code=400, detail=f"Erro base: {e}")

    try:
        contents = await file.read()
        df = pd.read_excel(io.BytesIO(contents), dtype={'cep': str}) if file.filename.endswith(('.xls', '.xlsx')) else pd.read_csv(io.BytesIO(contents), encoding='utf-8', dtype={'cep': str})
        df = df.replace({pd.NA: None, float('nan'): None})
    except Exception as e: raise HTTPException(status_code=400, detail=f"Erro arquivo: {e}")

    required = ["id_paciente", "cep", "rua", "municipio"]
    for col in required:
        if col not in df.columns: raise HTTPException(status_code=400, detail=f"Falta coluna {col}")

    success, errors = [], []
    for _, row in df.iterrows():
        d = row.to_dict()
        cep = clean_and_pad_cep(d.get("cep"))
        if not cep: 
            d['motivo'] = 'CEP ruim'
            errors.append(d)
            continue
        
        coords = get_google_coords(d.get("rua"), d.get("numero"), d.get("bairro"), d.get("municipio"), cep)
        if not coords:
            d['motivo'] = 'Endereço não achado'
            errors.append(d)
            continue
        
        res = d.copy()
        res['cep'] = cep
        try:
            r_car = gmaps_client.directions(base_coords, coords, mode="driving")
            res['distancia_rota_carro_km'] = round(r_car[0]['legs'][0]['distance']['value']/1000, 2) if r_car else "N/A"
        except: res['distancia_rota_carro_km'] = "Erro"
        
        try:
            r_pub = gmaps_client.directions(base_coords, coords, mode="transit", departure_time=datetime.now())
            if r_pub:
                res['distancia_transporte_km'] = round(r_pub[0]['legs'][0]['distance']['value']/1000, 2)
                res['tempo_transporte_s'] = r_pub[0]['legs'][0]['duration']['value']
            else: res['distancia_transporte_km'] = "N/A"
        except: res['distancia_transporte_km'] = "Erro"
        success.append(res)

    url = None
    if errors:
        os.makedirs("temp_files", exist_ok=True)
        fname = f"erros_{uuid.uuid4().hex[:6]}.xlsx"
        pd.DataFrame(errors).to_excel(os.path.join("temp_files", fname), index=False)
        url = f"/api/download/{fname}"

    return JSONResponse(content={"success_data": success, "error_file_url": url})

@app.get("/api/download/{filename}")
async def download_error_file(filename: str):
    path = os.path.join("temp_files", filename)
    if os.path.exists(path): return FileResponse(path=path, filename=filename)
    raise HTTPException(status_code=404)