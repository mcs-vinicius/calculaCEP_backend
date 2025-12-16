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

router = APIRouter(prefix="/api/calculate-distances", tags=["Ferramenta: CEP"])

GOOGLE_MAPS_API_KEY = os.getenv("GOOGLE_MAPS_API_KEY", "")
gmaps_client = googlemaps.Client(key=GOOGLE_MAPS_API_KEY) if GOOGLE_MAPS_API_KEY else None
coords_cache: Dict[str, tuple] = {}

def clean_cep(cep):
    if pd.isna(cep): return ""
    s = str(int(float(cep))) if isinstance(cep, (float, int)) else str(cep)
    n = "".join(filter(str.isdigit, s))
    return f"0{n}" if len(n) == 7 else n

def format_time(seconds):
    m, s = divmod(seconds, 60); h, m = divmod(m, 60)
    return f"{int(h):02d}:{int(m):02d}:{int(s):02d}"

def get_coords(rua, numero, bairro, municipio, cep):
    if not gmaps_client: return None
    key = f"{rua}-{cep}"
    if key in coords_cache: return coords_cache[key]
    try:
        res = gmaps_client.geocode(f"{rua}, {numero}, {bairro}, {municipio}, {cep}", region='BR')
        if res:
            loc = res[0]['geometry']['location']
            coords_cache[key] = (loc['lat'], loc['lng'])
            return coords_cache[key]
    except: pass
    return None

@router.post("/")
async def calculate(
    base_rua: str = Form(...), base_numero: str = Form(...), base_bairro: str = Form(...), 
    base_municipio: str = Form(...), base_cep: str = Form(...), file: UploadFile = File(...),
    current_user: User = Depends(get_current_user)
):
    if not gmaps_client: raise HTTPException(500, "API Maps não configurada.")
    
    base_coords = get_coords(base_rua, base_numero, base_bairro, base_municipio, clean_cep(base_cep))
    if not base_coords: raise HTTPException(400, "Endereço base não encontrado.")

    try:
        contents = await file.read()
        df = pd.read_excel(io.BytesIO(contents), dtype={'cep': str}) if file.filename.endswith(('.xls', '.xlsx')) else pd.read_csv(io.BytesIO(contents), dtype={'cep': str})
        df.columns = [c.lower().strip() for c in df.columns]
    except: raise HTTPException(400, "Erro ao ler arquivo.")

    success, errors = [], []
    for _, row in df.iterrows():
        d = row.to_dict()
        cep = clean_cep(d.get("cep"))
        coords = get_coords(d.get("rua"), d.get("numero"), d.get("bairro"), d.get("municipio"), cep)
        
        if not cep or not coords:
            d['motivo'] = 'Endereço/CEP inválido'
            errors.append(d)
            continue

        res = d.copy(); res['cep'] = cep
        try:
            r_car = gmaps_client.directions(base_coords, coords, mode="driving")
            res['distancia_rota_carro_km'] = round(r_car[0]['legs'][0]['distance']['value']/1000, 2) if r_car else "N/A"
        except: res['distancia_rota_carro_km'] = "Erro"

        try:
            r_pub = gmaps_client.directions(base_coords, coords, mode="transit", departure_time=datetime.now())
            if r_pub:
                res['distancia_transporte_km'] = round(r_pub[0]['legs'][0]['distance']['value']/1000, 2)
                res['tempo_transporte_min'] = format_time(r_pub[0]['legs'][0]['duration']['value'])
            else: res['distancia_transporte_km'] = "Sem transporte"; res['tempo_transporte_min'] = "-"
        except: res['distancia_transporte_km'] = "Erro"; res['tempo_transporte_min'] = "-"
        
        success.append(res)

    url = None
    if errors:
        os.makedirs("backend/temp_files", exist_ok=True) # Ajuste de caminho para funcionar local e render
        fname = f"erros_{uuid.uuid4().hex[:6]}.xlsx"
        pd.DataFrame(errors).to_excel(os.path.join("backend/temp_files", fname), index=False)
        url = f"/api/download/{fname}"

    return JSONResponse({"success_data": success, "error_file_url": url})