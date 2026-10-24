import re
import io
from fastapi import FastAPI, UploadFile, File
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse
import os
from pypdf import PdfReader

app = FastAPI(title="MaskingVault - Safe File Sharing")

# Permitir pedidos do frontend
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

def sanitizar_texto(texto: str):
    """
    Função responsável por detetar e mascarar dados sensíveis.
    """
    muda_contagem = {"nifs": 0, "emails": 0, "telefones": 0, "cc_documentos": 0}

    # 1. Mascarar E-mails
    def sub_email(match):
        muda_contagem["emails"] += 1
        return f"usuario_anonimo_{muda_contagem['emails']}@mascarado.com"
    
    texto_limpo, _ = re.subn(r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}', sub_email, texto)

    # 2. Mascarar NIFs Portugueses (9 dígitos)
    def sub_nif(match):
        muda_contagem["nifs"] += 1
        return "[NIF MASCARADO]"

    texto_limpo, _ = re.subn(r'\b[1235689]\d{8}\b', sub_nif, texto_limpo)

    # 3. Mascarar Números de Telemóvel (+351 / 91, 92, 93, 96)
    def sub_tel(match):
        muda_contagem["telefones"] += 1
        return "+351 900 000 000"

    texto_limpo, _ = re.subn(r'(?:\+351\s?)?9[1236]\d{7}\b', sub_tel, texto_limpo)

    # 4. Mascarar Números de Cartão de Cidadão / Documentos (ex: 30462660 0ZW7 ou 8 dígitos isolados)
    def sub_cc(match):
        muda_contagem["cc_documentos"] += 1
        return "[Nº DOCUMENTO MASCARADO]"

    texto_limpo, _ = re.subn(r'\b\d{8}(?:\s?[A-Z0-9]{4})?\b', sub_cc, texto_limpo)

    total_alteracoes = sum(muda_contagem.values())
    return texto_limpo, muda_contagem, total_alteracoes

@app.post("/sanitizar")
async def processar_ficheiro(file: UploadFile = File(...)):
    conteudo_bytes = await file.read()
    texto_original = ""

    # Verificar se é um PDF ou texto plano
    if file.filename.endswith(".pdf"):
        try:
            leitor_pdf = PdfReader(io.BytesIO(conteudo_bytes))
            for pagina in leitor_pdf.pages:
                texto_extraido = pagina.extract_text()
                if texto_extraido:
                    texto_original += texto_extraido + "\n"
        except Exception as e:
            texto_original = f"Erro ao ler PDF: {str(e)}"
    else:
        texto_original = conteudo_bytes.decode("utf-8", errors="ignore")

    # Sanitizar o conteúdo obtido
    texto_sanitizado, estatisticas, total = sanitizar_texto(texto_original)

    return {
        "status": "sucesso",
        "nome_ficheiro": file.filename,
        "total_mascarados": total,
        "detalhes": estatisticas,
        "conteudo_sanitizado": texto_sanitizado
    }

# Servir a página Web simples
@app.get("/", response_class=HTMLResponse)
async def home():
    if os.path.exists("index.html"):
        with open("index.html", "r", encoding="utf-8") as f:
            return f.read()
    return "<h1>API MaskingVault Ativa!</h1>"