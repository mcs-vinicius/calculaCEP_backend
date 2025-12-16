# backend/modules/tool_cep.py
import io
import os
import uuid
import pandas as pd
import googlemaps
from datetime import datetime
from typing import Dict, Any
from fastapi import APIRouter, UploadFile, File, Form, HTTPException, Depends
from fastapi.responses import JSONResponse
from backend.common import get_current_user, User

# Cria um roteador específico para esta ferramenta
router = APIRouter(prefix="/api/calculate-distances", tags=["Ferramenta: CEP"])

# Inicializa o cliente do Google Maps apenas se a chave existir
GOOGLE_MAPS_API_KEY = os.getenv("GOOGLE_MAPS_API_KEY", "AIzaSyB-gfeMDr52mASa39zr3n0QV__9zxS9khk")
gmaps_client = googlemaps.Client(key=GOOGLE_MAPS_API_KEY) if GOOGLE_MAPS_API_KEY else None

# Cache simples em memória para evitar chamadas repetidas ao Google (economiza dinheiro/quota)
coords_cache: Dict[str, tuple] = {}

def clean_cep(cep):
    """Limpa e formata o CEP para o padrão '00000000'"""
    if pd.isna(cep): return ""
    s = str(int(float(cep))) if isinstance(cep, (float, int)) else str(cep)
    n = "".join(filter(str.isdigit, s))
    return f"0{n}" if len(n) == 7 else n

def format_time(seconds):
    """Converte segundos para formato HH:MM:SS"""
    m, s = divmod(seconds, 60); h, m = divmod(m, 60)
    return f"{int(h):02d}:{int(m):02d}:{int(s):02d}"

def get_coords(rua, numero, bairro, municipio, cep):
    """
    Função que consulta a API do Google Geocoding.
    1. Verifica se o endereço já está no cache.
    2. Se não, chama a API e guarda no cache.
    Returns: Tupla (latitude, longitude) ou None.
    """
    if not gmaps_client: return None
    key = f"{rua}-{cep}" # Chave única para o cache
    if key in coords_cache: return coords_cache[key]
    try:
        # Monta a string de endereço completa
        res = gmaps_client.geocode(f"{rua}, {numero}, {bairro}, {municipio}, {cep}", region='BR')
        if res:
            loc = res[0]['geometry']['location']
            coords_cache[key] = (loc['lat'], loc['lng'])
            return coords_cache[key]
    except: pass
    return None

# --- Rota Principal da Ferramenta ---
@router.post("/")
async def calculate(
    # Recebe os dados do formulário e o arquivo
    base_rua: str = Form(...), base_numero: str = Form(...), base_bairro: str = Form(...), 
    base_municipio: str = Form(...), base_cep: str = Form(...), file: UploadFile = File(...),
    # Garante que apenas usuários logados usem a ferramenta
    current_user: User = Depends(get_current_user)
):
    if not gmaps_client: raise HTTPException(500, "API Maps não configurada.")
    
    # 1. Geolocaliza o Ponto de Partida (Base)
    base_coords = get_coords(base_rua, base_numero, base_bairro, base_municipio, clean_cep(base_cep))
    if not base_coords: raise HTTPException(400, "Endereço base não encontrado.")

    # 2. Lê o arquivo Excel ou CSV enviado pelo usuário
    try:
        contents = await file.read()
        if file.filename.endswith(('.xls', '.xlsx')):
            df = pd.read_excel(io.BytesIO(contents), dtype={'cep': str})
        else:
            df = pd.read_csv(io.BytesIO(contents), dtype={'cep': str})
        # Normaliza nomes das colunas (tudo minúsculo, sem espaços)
        df.columns = [c.lower().strip() for c in df.columns]
    except: raise HTTPException(400, "Erro ao ler arquivo. Verifique se é Excel ou CSV.")

    success, errors = [], []
    
    # 3. Itera sobre cada linha da planilha
    for _, row in df.iterrows():
        d = row.to_dict()
        cep = clean_cep(d.get("cep"))
        # Busca coordenadas do paciente
        coords = get_coords(d.get("rua"), d.get("numero"), d.get("bairro"), d.get("municipio"), cep)
        
        if not cep or not coords:
            d['motivo'] = 'Endereço/CEP inválido ou não encontrado'
            errors.append(d)
            continue

        res = d.copy(); res['cep'] = cep
        
        # 4. Calcula Rota de Carro (Driving)
        try:
            r_car = gmaps_client.directions(base_coords, coords, mode="driving")
            res['distancia_rota_carro_km'] = round(r_car[0]['legs'][0]['distance']['value']/1000, 2) if r_car else "N/A"
        except: res['distancia_rota_carro_km'] = "Erro"

        # 5. Calcula Rota de Transporte Público (Transit)
        try:
            r_pub = gmaps_client.directions(base_coords, coords, mode="transit", departure_time=datetime.now())
            if r_pub:
                res['distancia_transporte_km'] = round(r_pub[0]['legs'][0]['distance']['value']/1000, 2)
                res['tempo_transporte_min'] = format_time(r_pub[0]['legs'][0]['duration']['value'])
            else: res['distancia_transporte_km'] = "Sem transporte"; res['tempo_transporte_min'] = "-"
        except: res['distancia_transporte_km'] = "Erro"; res['tempo_transporte_min'] = "-"
        
        success.append(res)

    # 6. Se houver erros, gera um arquivo Excel para download
    url = None
    if errors:
        os.makedirs("backend/temp_files", exist_ok=True)
        fname = f"erros_{uuid.uuid4().hex[:6]}.xlsx"
        pd.DataFrame(errors).to_excel(os.path.join("backend/temp_files", fname), index=False)
        url = f"/api/download/{fname}"

    return JSONResponse({"success_data": success, "error_file_url": url})