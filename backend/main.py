# backend/main.py
import os
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse

# Importação dos módulos (ferramentas) que compõem o sistema.
from backend.modules import auth, admin, tool_cep, backup

# --- Inicialização da Aplicação ---
# Define o título e versão que aparecerão na documentação automática (/docs)
app = FastAPI(
    title="Digital Health Tools API", 
    description="API para ferramentas de gestão e cálculo de rotas.",
    version="2.0"
)

# --- Configuração de CORS (Cross-Origin Resource Sharing) ---
# O CORS é um mecanismo de segurança que permite (ou bloqueia) que um navegador
# rodando um site em 'domain-a.com' faça requisições para 'domain-b.com'.
# Como seu frontend (Vercel) e backend (Render) estão em domínios diferentes, isso é obrigatório.
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Em produção, idealmente troque "*" pela URL do seu frontend.
    allow_credentials=True,
    allow_methods=["*"],  # Permite todos os métodos (GET, POST, PUT, DELETE, etc.)
    allow_headers=["*"],  # Permite todos os cabeçalhos (Authorization, Content-Type, etc.)
)

# --- Inclusão de Rotas (Roteamento Modular) ---
# Aqui conectamos as rotas definidas nos outros arquivos à aplicação principal.
app.include_router(auth.router)      # Rotas de Autenticação (Login/Registro)
app.include_router(admin.router)     # Rotas Administrativas (Gestão de usuários)
app.include_router(tool_cep.router)  # Rotas da Ferramenta de CEP
app.include_router(backup.router)
# --- Rota Global de Download ---
@app.get("/api/download/{filename}")
async def download_error_file(filename: str):
    """
    Endpoint genérico para download de arquivos temporários gerados pelo sistema.
    
    Args:
        filename (str): O nome do arquivo a ser baixado (ex: erros_123.xlsx).
        
    Returns:
        FileResponse: O arquivo físico se encontrado.
        
    Raises:
        HTTPException (404): Se o arquivo não existir ou tiver expirado.
    """
    # 1. Tenta localizar na estrutura modular (backend/temp_files)
    path = os.path.join("backend/temp_files", filename)
    
    # 2. Fallback: Tenta na raiz se não achar (para compatibilidade de execução local)
    if not os.path.exists(path):
        path = os.path.join("temp_files", filename)
    
    # 3. Entrega o arquivo ao navegador
    if os.path.exists(path): 
        return FileResponse(path=path, filename=filename)
    
    raise HTTPException(status_code=404, detail="Arquivo não encontrado ou expirado.")

# --- Health Check ---
@app.get("/")
def read_root():
    """Rota raiz para verificar se a API está online."""
    return {"message": "Digital Health Tools Online", "docs_url": "/docs"}