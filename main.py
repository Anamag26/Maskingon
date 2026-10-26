import os
import re
import uuid
import io
from fastapi import FastAPI, UploadFile, File, Form, HTTPException, Cookie, Response, Request
from fastapi.responses import FileResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from starlette.middleware.sessions import SessionMiddleware
from pypdf import PdfReader
from reportlab.lib.pagesizes import letter
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from authlib.integrations.starlette_client import OAuth
from dotenv import load_dotenv

import database as db

# ==========================================
# 1. CONFIGURAÇÕES E VARIÁVEIS DE AMBIENTE
# ==========================================
# Carrega as variáveis sensíveis do ficheiro .env (chaves do Google OAuth)
load_dotenv()

GOOGLE_CLIENT_ID = os.getenv("GOOGLE_CLIENT_ID")
GOOGLE_CLIENT_SECRET = os.getenv("GOOGLE_CLIENT_SECRET")

# Inicialização da aplicação FastAPI
app = FastAPI()

# Obrigatório para o Authlib/OAuth gerir o estado de sessão temporário durante o login externo
app.add_middleware(SessionMiddleware, secret_key=os.getenv("SESSION_SECRET", "chave_temporaria_segura"))

# Configuração do cliente OAuth para autenticação via Google
oauth = OAuth()
oauth.register(
    name='google',
    client_id=GOOGLE_CLIENT_ID,
    client_secret=GOOGLE_CLIENT_SECRET,
    server_metadata_url='https://accounts.google.com/.well-known/openid-configuration',
    client_kwargs={'scope': 'openid email profile'}
)

# Diretório para guardar os PDFs sanitizados gerados
UPLOAD_DIR = "uploads"
os.makedirs(UPLOAD_DIR, exist_ok=True)

# Montagem da pasta estática para servir HTML, CSS e JS
app.mount("/static", StaticFiles(directory="static"), name="static")

# Inicialização automática da Base de Dados e respetivas tabelas
db.init_db()


# ==========================================
# 2. ROTAS DE NAVEGAÇÃO E PÁGINAS PRINCIPAIS
# ==========================================
@app.get("/")
def landing_page(user_session: str = Cookie(default=None)):
    """Exibe a página inicial (Landing Page). Se o utilizador já tiver sessão ativa, redireciona para a app."""
    if user_session:
        return RedirectResponse(url="/app", status_code=302)
    return FileResponse("static/index.html")

@app.get("/app")
def app_dashboard(user_session: str = Cookie(default=None)):
    """Exibe o painel principal da aplicação. Se não estiver autenticado, manda-o de volta para o início."""
    if not user_session:
        return RedirectResponse(url="/", status_code=302)
    return FileResponse("static/app.html")


# ==========================================
# 3. AUTENTICAÇÃO LOCAL (REGISTO, LOGIN E SESSÃO)
# ==========================================
@app.post("/api/register")
def register(name: str = Form(...), email: str = Form(...), password: str = Form(...), response: Response = None):
    """Regista um novo utilizador na base de dados e inicia sessão automaticamente via cookie."""
    user_id = db.create_user(email, password, name)
    if not user_id:
        raise HTTPException(status_code=400, detail="Este e-mail já se encontra registado.")
    response.set_cookie(key="user_session", value=str(user_id), httponly=True)
    return {"status": "ok", "user": {"id": user_id, "name": name, "email": email}}

@app.post("/api/login")
def login(email: str = Form(...), password: str = Form(...), response: Response = None):
    """Verifica as credenciais do utilizador e define o cookie de sessão se estiverem corretas."""
    user = db.verify_user(email, password)
    if not user:
        raise HTTPException(status_code=401, detail="E-mail ou palavra-passe incorretos.")
    response.set_cookie(key="user_session", value=str(user["id"]), httponly=True)
    return {"status": "ok", "user": user}

@app.post("/api/logout")
def logout(response: Response):
    """Termina a sessão do utilizador apagando o cookie correspondente."""
    response.delete_cookie("user_session")
    return {"status": "ok"}

@app.get("/api/user")
def get_current_user(user_session: str = Cookie(default=None)):
    """Retorna os dados do utilizador atualmente autenticado com base no cookie de sessão."""
    if not user_session:
        raise HTTPException(status_code=401, detail="Não autenticado")
    
    conn = db.sqlite3.connect(db.DB_NAME)
    cursor = conn.cursor()
    cursor.execute("SELECT id, name, email FROM users WHERE id = ?", (user_session,))
    u = cursor.fetchone()
    conn.close()
    
    if not u:
        raise HTTPException(status_code=401, detail="Sessão inválida")
    return {"id": u[0], "name": u[1], "email": u[2]}


# ==========================================
# 4. AUTENTICAÇÃO EXTERNA (GOOGLE OAUTH)
# ==========================================
@app.get('/auth/google')
async def login_google(request: Request):
    """Inicia o processo de login com o Google, forçando a janela de seleção de conta."""
    redirect_uri = request.url_for('auth_google_callback')
    return await oauth.google.authorize_redirect(request, redirect_uri, prompt='select_account')

@app.get('/auth/google/callback')
async def auth_google_callback(request: Request):
    """Recebe o retorno do Google, obtém os dados do utilizador, cria/associa a conta e cria a sessão."""
    try:
        token = await oauth.google.authorize_access_token(request)
        user_info = token.get('userinfo')
        
        if not user_info:
            user_info = await oauth.google.parse_id_token(request, token)
            
        if user_info and 'email' in user_info:
            email = user_info['email']
            name = user_info.get('name', email.split('@')[0])
            google_id = user_info.get('sub', '')
            
            user = db.get_or_create_google_user(email, name, google_id)
            
            res = RedirectResponse(url="/app", status_code=302)
            res.set_cookie(key="user_session", value=str(user["id"]), httponly=True)
            return res
        else:
            return RedirectResponse(url="/?error=google_failed")
            
    except Exception as e:
        print(f"Erro no Callback do Google: {e}")
        return RedirectResponse(url="/?error=google_exception")


# ==========================================
# 5. LÓGICA DE PROCESSAMENTO E SANITIZAÇÃO DE FICHEIROS
# ==========================================
def mascarar_dados(texto: str):
    """Aplica expressões regulares para detetar e mascarar emails, NIFs e números de telemóvel."""
    regex_email = r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}'
    regex_nif = r'\b[1235689]\d{8}\b'
    regex_telefone = r'\b(?:9[1236]\d{7}|2\d{8})\b'

    emails = len(re.findall(regex_email, texto))
    nifs = len(re.findall(regex_nif, texto))
    telefones = len(re.findall(regex_telefone, texto))

    texto_sanitizado = re.sub(regex_email, "[EMAIL OCULTO]", texto)
    texto_sanitizado = re.sub(regex_nif, "[NIF OCULTO]", texto_sanitizado)
    texto_sanitizado = re.sub(regex_telefone, "[TELEMOVEL OCULTO]", texto_sanitizado)

    total = emails + nifs + telefones
    detalhes = {"emails": emails, "nifs": nifs, "telefones": telefones}
    return texto_sanitizado, total, detalhes

def gerar_pdf_reportlab(texto: str, caminho_saida: str):
    """Gera um novo documento PDF estilizado contendo o texto já limpo/sanitizado."""
    doc = SimpleDocTemplate(caminho_saida, pagesize=letter)
    styles = getSampleStyleSheet()
    estilo_corpo = ParagraphStyle(
        'EstiloCorpo', parent=styles['Normal'], fontName='Helvetica', fontSize=10, leading=14, spaceAfter=8
    )
    story = []
    for linha in texto.split('\n'):
        if linha.strip():
            story.append(Paragraph(linha.replace('<', '&lt;').replace('>', '&gt;'), estilo_corpo))
        else:
            story.append(Spacer(1, 10))
    doc.build(story)

@app.post("/sanitizar")
async def sanitizar_ficheiro(file: UploadFile = File(...), user_session: str = Cookie(default=None)):
    """Endpoint que recebe um ficheiro (PDF ou Texto), lê o conteúdo, mascara dados sensíveis e gera o PDF final."""
    if not user_session:
        raise HTTPException(status_code=401, detail="Sessão expirada. Inicie sessão novamente.")

    nome_original = file.filename
    extensao = nome_original.split(".")[-1].lower() if "." in nome_original else ""
    conteudo_texto = ""

    if extensao == "pdf":
        contents = await file.read()
        reader = PdfReader(io.BytesIO(contents))
        for page in reader.pages:
            texto_pagina = page.extract_text()
            if texto_pagina:
                conteudo_texto += texto_pagina + "\n"
    else:
        contents = await file.read()
        try:
            conteudo_texto = contents.decode("utf-8")
        except UnicodeDecodeError:
            conteudo_texto = contents.decode("latin-1")

    conteudo_sanitizado, total, detalhes = mascarar_dados(conteudo_texto)
    nome_pdf_saida = f"sanitized_{uuid.uuid4().hex[:8]}.pdf"
    caminho_pdf = os.path.join(UPLOAD_DIR, nome_pdf_saida)
    gerar_pdf_reportlab(conteudo_sanitizado, caminho_pdf)

    # Guarda o registo da operação no histórico do utilizador logado
    db.save_history(int(user_session), nome_original, nome_pdf_saida, total)

    return {
        "nome_ficheiro": nome_original,
        "total_mascarados": total,
        "detalhes": detalhes,
        "conteudo_sanitizado": conteudo_sanitizado,
        "ficheiro_pdf": nome_pdf_saida
    }


# ==========================================
# 6. HISTÓRICO E DOWNLOAD DE FICHEIROS
# ==========================================
@app.get("/api/history")
def get_history(user_session: str = Cookie(default=None)):
    """Retorna o histórico de ficheiros sanitizados associados ao utilizador atual."""
    if not user_session:
        raise HTTPException(status_code=401, detail="Não autenticado")
    return db.get_user_history(int(user_session))

@app.get("/download/{nome_ficheiro}")
def download_ficheiro(nome_ficheiro: str):
    """Permite efetuar o download do PDF sanitizado guardado no servidor."""
    caminho = os.path.join(UPLOAD_DIR, nome_ficheiro)
    if os.path.exists(caminho):
        return FileResponse(caminho, filename=nome_ficheiro, media_type="application/pdf")
    return {"erro": "Ficheiro não encontrado"}