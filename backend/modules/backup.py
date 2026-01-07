# backend/modules/backup.py
from fastapi import APIRouter, Depends, HTTPException, UploadFile, File
from sqlalchemy.orm import Session
from datetime import datetime
import json

# Importações alinhadas com o seu backend/common.py atual
from backend.common import get_db, User, AllowedMatricula, get_current_admin

# Define o roteador para endpoints de backup
router = APIRouter(prefix="/backup", tags=["Backup & Restore"])

@router.get("/export")
def export_data(db: Session = Depends(get_db), current_user: User = Depends(get_current_admin)):
    """
    Exporta todos os dados do sistema (Usuários e Whitelist) para um JSON.
    Apenas administradores podem realizar esta ação.
    """
    try:
        # 1. Recupera todos os usuários
        # Importante: Exportamos o 'hashed_password' para manter o login funcionando após a restauração
        users = db.query(User).all()
        users_data = [
            {
                "nome": u.nome,
                "email": u.email,
                "matricula": u.matricula,
                "hashed_password": u.hashed_password,
                "is_admin": u.is_admin,
                "must_change_password": u.must_change_password
            } 
            for u in users
        ]

        # 2. Recupera a Whitelist (Lista de Espera)
        whitelist = db.query(AllowedMatricula).all()
        whitelist_data = [{"matricula": w.matricula} for w in whitelist]

        # 3. Monta a estrutura final do arquivo
        backup_payload = {
            "metadata": {
                "version": "2.0",
                "exported_at": datetime.utcnow().isoformat(),
                "exported_by": current_user.email
            },
            "data": {
                "users": users_data,
                "whitelist": whitelist_data
            }
        }

        return backup_payload

    except Exception as e:
        print(f"Erro na exportação: {e}")
        raise HTTPException(status_code=500, detail="Falha ao gerar arquivo de backup.")

@router.post("/import")
async def import_data(
    file: UploadFile = File(...), 
    db: Session = Depends(get_db), 
    current_user: User = Depends(get_current_admin)
):
    """
    Restaura o sistema a partir de um arquivo JSON.
    ATENÇÃO: Apaga todos os dados atuais antes de importar.
    """
    if not file.filename.endswith('.json'):
        raise HTTPException(status_code=400, detail="O arquivo deve ser formato .json")

    try:
        # Lê e decodifica o arquivo enviado
        content = await file.read()
        backup_data = json.loads(content)

        # Validação simples da estrutura
        if "data" not in backup_data or "users" not in backup_data["data"]:
            raise HTTPException(status_code=400, detail="Arquivo de backup inválido ou corrompido.")

        # --- OPERAÇÃO DE RESTAURAÇÃO (Transação Atômica) ---
        # Se algo der errado no meio, o 'rollback' cancela tudo.
        
        # 1. Limpeza: Remove dados existentes
        db.query(AllowedMatricula).delete()
        db.query(User).delete()
        
        # 2. Restauração: Whitelist
        for item in backup_data["data"]["whitelist"]:
            new_allowed = AllowedMatricula(matricula=item["matricula"])
            db.add(new_allowed)

        # 3. Restauração: Usuários
        for item in backup_data["data"]["users"]:
            new_user = User(
                nome=item["nome"],
                email=item["email"],
                matricula=item["matricula"],
                hashed_password=item["hashed_password"], # Mantém a senha original criptografada
                is_admin=item["is_admin"],
                must_change_password=item.get("must_change_password", False)
            )
            db.add(new_user)

        # Confirma as alterações no banco
        db.commit()
        
        return {"message": "Sistema restaurado com sucesso! Por favor, faça login novamente."}

    except Exception as e:
        db.rollback() # Desfaz alterações em caso de erro
        print(f"Erro na importação: {e}")
        raise HTTPException(status_code=500, detail=f"Erro crítico ao restaurar: {str(e)}")