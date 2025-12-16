# backend/main.py
import os
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse

# Importação dos módulos (ferramentas) que compõem o sistema.
# Cada módulo é um "mini-app" com suas próprias rotas.
from backend.modules import auth, admin, tool_cep

# Inicializa a aplicação FastAPI com metadados básicos
app = FastAPI(title="Digital Health Tools", version="2.0")

# --- Configuração de CORS (Cross-Origin Resource Sharing) ---
# Isso permite que o Frontend (hospedado na Vercel, por exemplo) converse com este Backend.
# allow_origins=["*"] libera acesso para qualquer site. 
# Em produção, recomenda-se trocar "*" pela URL específica do frontend para maior segurança.
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],  # Permite GET, POST, DELETE, etc.
    allow_headers=["*"],  # Permite enviar Tokens e outros cabeçalhos
)

# --- Inclusão de Rotas (Conectando os módulos) ---
# Aqui "plugamos" as ferramentas na aplicação principal.
app.include_router(auth.router)      # Rotas de Login e Registro
app.include_router(admin.router)     # Rotas do Painel Administrativo
app.include_router(tool_cep.router)  # Rotas da Calculadora de CEP

# --- Rota Global de Download ---
# Esta rota serve para baixar arquivos gerados por QUALQUER ferramenta do sistema.
# Ela procura o arquivo na pasta temporária e o entrega ao navegador.
@app.get("/api/download/{filename}")
async def download_error_file(filename: str):
    """
    Endpoint para baixar arquivos temporários (ex: relatórios de erros).
    Recebe o nome do arquivo e tenta encontrá-lo na pasta 'backend/temp_files' ou 'temp_files'.
    """
    # Tenta localizar o arquivo dentro da estrutura modular (pasta backend/temp_files)
    path = os.path.join("backend/temp_files", filename)
    
    # Fallback: Se não achar, tenta na raiz (caso o servidor rode de forma diferente)
    if not os.path.exists(path):
        path = os.path.join("temp_files", filename)
    
    # Se o arquivo existir, envia para download. Senão, retorna erro 404.
    if os.path.exists(path): 
        return FileResponse(path=path, filename=filename)
    
    raise HTTPException(status_code=404, detail="Arquivo não encontrado ou expirado.")

# --- Rota Raiz ---
# Apenas para verificar se a API está online ao acessar a URL base.
@app.get("/")
def read_root():
    return {"message": "Digital Health Tools Online", "docs": "/docs"}