# backend/modules/tool_cep.py
import io
import os
import uuid
import logging
import pandas as pd
import googlemaps
from datetime import datetime
from typing import Dict, Any
from fastapi import APIRouter, UploadFile, File, Form, HTTPException, Depends
from fastapi.responses import JSONResponse
from backend.common import get_current_user, User

# --- Configuração de Logs ---
# Logger configurado para capturar erros críticos e exibi-los no console do Render.
logger = logging.getLogger("uvicorn.error")

router = APIRouter(prefix="/api/calculate-distances", tags=["Ferramenta: Calculadora CEP"])

# --- Inicialização da API Google Maps ---
# Tenta pegar a chave da variável de ambiente. Se falhar, usa string vazia.
GOOGLE_MAPS_API_KEY = os.getenv("GOOGLE_MAPS_API_KEY", "")
# Instancia o cliente apenas se houver chave configurada
gmaps_client = googlemaps.Client(key=GOOGLE_MAPS_API_KEY) if GOOGLE_MAPS_API_KEY else None

# Cache em memória para armazenar coordenadas (Lat, Long) já consultadas.
# Isso evita custos duplicados e estouro de cota na API do Google.
coords_cache: Dict[str, tuple] = {}

def clean_cep(cep):
    """
    Padroniza o CEP removendo traços e garantindo 8 dígitos.
    Ex: '5403-900' -> '05403900'
    """
    if pd.isna(cep): return ""
    # Converte float/int para string, se necessário
    s = str(int(float(cep))) if isinstance(cep, (float, int)) else str(cep)
    # Mantém apenas números
    n = "".join(filter(str.isdigit, s))
    # Adiciona zero à esquerda se necessário (comum em CEPs de SP começando com 0)
    return f"0{n}" if len(n) == 7 else n

def format_time(seconds):
    """Converte segundos para o formato HH:MM:SS."""
    m, s = divmod(seconds, 60)
    h, m = divmod(m, 60)
    return f"{int(h):02d}:{int(m):02d}:{int(s):02d}"

def get_coords(rua, numero, bairro, municipio, cep):
    """
    Consulta a API Geocoding do Google para transformar endereço em Latitude/Longitude.
    
    Fluxo:
    1. Verifica cache interno.
    2. Se não estiver em cache, chama API do Google.
    3. Trata erros e logs para facilitar debug.
    
    Returns:
        tuple: (latitude, longitude) se sucesso.
        None: se falha ou endereço não encontrado.
    """
    if not gmaps_client:
        logger.error("ERRO CRÍTICO: Cliente Google Maps não inicializado. Verifique a variável GOOGLE_MAPS_API_KEY.")
        return None
        
    key = f"{rua}-{cep}" # Chave composta para unicidade no cache
    if key in coords_cache: return coords_cache[key]
    
    try:
        address_str = f"{rua}, {numero}, {bairro}, {municipio}, {cep}"
        
        # Chamada à API (region='BR' melhora a precisão para endereços brasileiros)
        res = gmaps_client.geocode(address_str, region='BR')
        
        if res:
            loc = res[0]['geometry']['location']
            coords_cache[key] = (loc['lat'], loc['lng'])
            return coords_cache[key]
        else:
            logger.warning(f"Google Maps respondeu, mas não encontrou: {address_str}")
            
    except Exception as e:
        # LOG CRÍTICO: Mostra o motivo real da falha (Faturação, Chave Inválida, etc)
        logger.error(f"FALHA NA API GOOGLE MAPS: {str(e)}")
        
    return None

# --- Rota Principal: Processamento de Arquivo ---
@router.post("/")
async def calculate(
    # Recebe os dados do "Ponto de Partida" via formulário
    base_rua: str = Form(...), base_numero: str = Form(...), base_bairro: str = Form(...), 
    base_municipio: str = Form(...), base_cep: str = Form(...), 
    # Recebe o arquivo Excel/CSV
    file: UploadFile = File(...),
    # Proteção: Apenas usuários logados
    current_user: User = Depends(get_current_user)
):
    """
    Processa uma lista de pacientes para calcular rotas a partir de um ponto base.
    Gera duas rotas: Carro (Driving) e Transporte Público (Transit).
    """
    if not gmaps_client: 
        logger.error("Tentativa de cálculo sem API Key configurada.")
        raise HTTPException(500, "API Maps não configurada no servidor.")
    
    # 1. Geolocaliza o Ponto de Partida (Base)
    base_coords = get_coords(base_rua, base_numero, base_bairro, base_municipio, clean_cep(base_cep))
    
    if not base_coords: 
        raise HTTPException(400, "Endereço base não encontrado pelo Google Maps. Verifique os logs do servidor.")

    # 2. Leitura do Arquivo (Pandas)
    try:
        contents = await file.read()
        if file.filename.endswith(('.xls', '.xlsx')):
            df = pd.read_excel(io.BytesIO(contents), dtype={'cep': str})
        else:
            df = pd.read_csv(io.BytesIO(contents), dtype={'cep': str})
        
        # Normalização de colunas para evitar erros de digitação (remove espaços e põe minúsculo)
        df.columns = [c.lower().strip() for c in df.columns]
    except Exception as e:
        logger.error(f"Erro ao ler arquivo: {str(e)}")
        raise HTTPException(400, "Erro ao ler arquivo. Verifique formato Excel/CSV.")

    success, errors = [], []
    
    # 3. Iteração linha a linha da planilha
    for _, row in df.iterrows():
        d = row.to_dict()
        cep = clean_cep(d.get("cep"))
        
        # Busca coordenadas do destino (paciente)
        coords = get_coords(d.get("rua"), d.get("numero"), d.get("bairro"), d.get("municipio"), cep)
        
        if not cep or not coords:
            d['motivo'] = 'Endereço/CEP inválido ou não encontrado'
            errors.append(d)
            continue

        res = d.copy(); res['cep'] = cep
        
        # 4. Cálculo: Rota de Carro (Driving)
        try:
            r_car = gmaps_client.directions(base_coords, coords, mode="driving")
            if r_car:
                # Distância vem em metros, converte para KM
                res['distancia_rota_carro_km'] = round(r_car[0]['legs'][0]['distance']['value']/1000, 2)
            else:
                res['distancia_rota_carro_km'] = "Rota não encontrada"
        except Exception as e: 
            logger.error(f"Erro rota carro: {str(e)}")
            res['distancia_rota_carro_km'] = "Erro API"

        # 5. Cálculo: Rota Transporte Público (Transit)
        try:
            # departure_time=now é necessário para rotas de transporte público
            r_pub = gmaps_client.directions(base_coords, coords, mode="transit", departure_time=datetime.now())
            if r_pub:
                res['distancia_transporte_km'] = round(r_pub[0]['legs'][0]['distance']['value']/1000, 2)
                res['tempo_transporte_min'] = format_time(r_pub[0]['legs'][0]['duration']['value'])
            else: 
                res['distancia_transporte_km'] = "Sem transporte"
                res['tempo_transporte_min'] = "-"
        except Exception as e:
            logger.error(f"Erro rota transporte: {str(e)}")
            res['distancia_transporte_km'] = "Erro API"
            res['tempo_transporte_min'] = "-"
        
        success.append(res)

    # 6. Geração de Relatório de Erros (se houver)
    url = None
    if errors:
        os.makedirs("backend/temp_files", exist_ok=True)
        fname = f"erros_{uuid.uuid4().hex[:6]}.xlsx"
        # Salva o arquivo de erros temporariamente para download
        pd.DataFrame(errors).to_excel(os.path.join("backend/temp_files", fname), index=False)
        url = f"/api/download/{fname}"

    return JSONResponse({"success_data": success, "error_file_url": url})