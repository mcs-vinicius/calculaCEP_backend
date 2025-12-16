# backend/main.py
import os
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from backend.modules import auth, admin, tool_cep

app = FastAPI(title="Digital Health Tools", version="2.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Conecta os módulos
app.include_router(auth.router)
app.include_router(admin.router)
app.include_router(tool_cep.router)

# Rota global para download de arquivos de erro
@app.get("/api/download/{filename}")
async def download_error_file(filename: str):
    # Procura na pasta temp_files dentro de backend
    path = os.path.join("backend/temp_files", filename)
    if not os.path.exists(path):
        # Tenta caminho alternativo (caso o render rode de outro lugar)
        path = os.path.join("temp_files", filename)
    
    if os.path.exists(path): return FileResponse(path=path, filename=filename)
    raise HTTPException(status_code=404, detail="Arquivo não encontrado.")

@app.get("/")
def read_root():
    return {"message": "Digital Health Tools Online", "docs": "/docs"}