"""
TaskFlow - versao corrigida da esteira DevSecOps (Modulos 1 a 6).

Aplicacao Flask de lista de tarefas usada na disciplina. Partindo da
versao vulneravel original (app-exemplo/app.py), esta versao corrige as
vulnerabilidades de codigo e mantem a camada de observabilidade do
Modulo 6.

Correcoes de seguranca aplicadas:
  1. SQL Injection (login e busca "q")   -> consultas parametrizadas
  2. XSS armazenado e refletido          -> templates Jinja2 com autoescape
                                            (templates/, sem "| safe"),
                                            incluindo o parametro "q" e a
                                            mensagem de erro do login
  3. SECRET_KEY hardcoded                -> variavel TASKFLOW_SECRET_KEY,
                                            sem fallback
  4. Senhas em texto puro                -> hash (Werkzeug) e senhas
                                            iniciais lidas do ambiente
  5. Endpoint /debug/info exposto        -> removido
  6. debug=True fixo                     -> FLASK_DEBUG, desligado por padrao
  7. app.run em 0.0.0.0 fixo             -> FLASK_RUN_HOST, padrao 127.0.0.1

Observabilidade (Modulo 6):
  - Logs em JSON (um objeto por linha / NDJSON) com um Formatter proprio
    sobre a biblioteca padrao `logging`.
  - `request_id` (UUID v4) gerado no `before_request` e anexado a todos os
    logs da requisicao, para correlacao no Grafana/Loki.
  - Eventos: http_request, login_attempt (sucesso/falha), logout,
    task_created e tasks_list_accessed.
  - Nada sensivel e logado: nunca a senha, o cookie ou o token; da tarefa
    so vai o tamanho da descricao.
  - Saida em stdout e no arquivo logs/taskflow.log (lido pelo Promtail).

Variaveis de ambiente:
  TASKFLOW_SECRET_KEY      obrigatoria - chave de sessao do Flask
  TASKFLOW_ADMIN_PASSWORD  senha inicial do usuario "admin" (opcional)
  TASKFLOW_ALUNO_PASSWORD  senha inicial do usuario "aluno" (opcional)
  FLASK_DEBUG              "true" so em desenvolvimento (padrao: false)
  FLASK_RUN_HOST           interface de escuta do servidor de desenvolvimento
                           (padrao: 127.0.0.1); no container quem escuta e o
                           gunicorn (gunicorn.conf.py)
  DATABASE_URL             se definida, usa PostgreSQL (docker-compose.yml);
                           ex.: postgresql://usuario:senha@db:5432/taskflow
  TASKFLOW_DATABASE        caminho do SQLite quando nao ha DATABASE_URL
                           (padrao: taskflow.db)
  TASKFLOW_LOG_DIR         diretorio dos logs (padrao: logs)

Para rodar localmente:
    pip install -r requirements.txt
    export TASKFLOW_SECRET_KEY="$(openssl rand -hex 32)"
    export TASKFLOW_ADMIN_PASSWORD="<senha>"
    python app.py
"""

import hmac
import json
import logging
import os
import secrets
import sqlite3
import time
import uuid
from datetime import datetime, timezone
from logging.handlers import RotatingFileHandler

from flask import (
    Flask,
    abort,
    g,
    redirect,
    render_template,
    request,
    session,
    url_for,
)
from werkzeug.security import check_password_hash, generate_password_hash


# ---------------------------------------------------------------------------
# 1. Formatter JSON customizado
# ---------------------------------------------------------------------------
#
# Um logging.Formatter padrao produz texto livre, por exemplo:
#   "2026-07-08 10:00:01,123 - taskflow - WARNING - login falhou"
#
# Isso e dificil de filtrar/agregar automaticamente (o que e "usuario"?
# onde comeca a mensagem?). Trocamos por um formatter que sempre emite
# um objeto JSON por linha, com campos previsiveis. Ferramentas como
# Loki, Elasticsearch ou qualquer script de analise conseguem parsear
# isso de forma trivial e confiavel.
class JsonFormatter(logging.Formatter):
    """Formata cada LogRecord como uma linha JSON (JSON Lines / NDJSON)."""

    def format(self, record: logging.LogRecord) -> str:
        # Campos padronizados que TODO log da aplicacao vai ter.
        log_entry = {
            "timestamp": datetime.fromtimestamp(record.created, tz=timezone.utc).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
        }

        # Campos extras "de negocio" (event, user, request_id, etc.)
        # sao passados via `extra={...}` nas chamadas de log e ficam
        # disponiveis como atributos do record. Copiamos apenas os que
        # nao fazem parte do LogRecord padrao, para nao duplicar dados.
        campos_padrao_do_record = logging.LogRecord("", 0, "", 0, "", None, None).__dict__.keys()
        for chave, valor in record.__dict__.items():
            if chave not in campos_padrao_do_record and chave not in log_entry:
                log_entry[chave] = valor

        # Se um traceback de excecao foi capturado, inclui como texto.
        if record.exc_info:
            log_entry["exception"] = self.formatException(record.exc_info)

        return json.dumps(log_entry, ensure_ascii=False)


def configurar_logging() -> logging.Logger:
    """Cria e configura o logger 'taskflow' com saida em JSON.

    Emite para dois handlers:
      - StreamHandler (stdout) -> util para `docker compose logs -f`
      - RotatingFileHandler (logs/taskflow.log) -> lido pelo Promtail
    """
    # Diretorio dos logs configuravel: no container a raiz do sistema de
    # arquivos e somente leitura (--read-only), entao os logs vao para um
    # diretorio gravavel (volume/tmpfs) definido no Dockerfile.
    log_dir = os.environ.get("TASKFLOW_LOG_DIR", "logs")
    os.makedirs(log_dir, exist_ok=True)

    logger = logging.getLogger("taskflow")
    logger.setLevel(logging.INFO)
    logger.propagate = False  # evita log duplicado no root logger

    formatter = JsonFormatter()

    console_handler = logging.StreamHandler()
    console_handler.setFormatter(formatter)

    # RotatingFileHandler evita que o arquivo de log cresca sem limite
    # durante a aula (5 MB por arquivo, mantendo 3 arquivos antigos).
    file_handler = RotatingFileHandler(
        os.path.join(log_dir, "taskflow.log"), maxBytes=5 * 1024 * 1024, backupCount=3
    )
    file_handler.setFormatter(formatter)

    logger.addHandler(console_handler)
    logger.addHandler(file_handler)
    return logger


logger = configurar_logging()

app = Flask(__name__)
# SECRET_KEY lida de variavel de ambiente - nunca hardcoded no codigo.
# Sem fallback: se a variavel nao existir, a aplicacao nao sobe (melhor
# falhar alto do que rodar com uma chave conhecida).
#   export TASKFLOW_SECRET_KEY="$(openssl rand -hex 32)"
_secret_key = os.environ.get("TASKFLOW_SECRET_KEY")
if not _secret_key:
    raise RuntimeError(
        "Variavel de ambiente TASKFLOW_SECRET_KEY nao definida. "
        'Ex: export TASKFLOW_SECRET_KEY="$(openssl rand -hex 32)"'
    )
app.config["SECRET_KEY"] = _secret_key

# Cookie de sessao: inacessivel ao JavaScript e nao enviado em requisicoes
# cross-site (defesa extra contra roubo de sessao e CSRF). Em producao com
# HTTPS, defina tambem TASKFLOW_SECURE_COOKIE=true.
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
app.config["SESSION_COOKIE_SECURE"] = (
    os.environ.get("TASKFLOW_SECURE_COOKIE", "false").lower() == "true"
)

# Banco de dados (Modulo 5 - Docker Compose):
#   - DATABASE_URL definida -> PostgreSQL (servico "db" do docker-compose.yml,
#     isolado na rede "backend", sem porta publicada no host).
#   - DATABASE_URL ausente  -> SQLite em arquivo (desenvolvimento local e o
#     container do DAST no CI). O caminho e configuravel porque no container
#     a raiz e somente leitura e o arquivo fica em /data.
DATABASE_URL = os.environ.get("DATABASE_URL")
DATABASE = os.environ.get("TASKFLOW_DATABASE", "taskflow.db")
USANDO_POSTGRES = bool(DATABASE_URL)


class _PostgresDB:
    """Adaptador minimo para o psycopg ter a mesma interface usada pelo
    app com o sqlite3: db.execute(sql, params) -> cursor e db.commit().

    As queries do app usam o placeholder "?" do sqlite3; aqui ele vira o
    "%s" do psycopg. Os valores continuam indo SEMPRE como parametros
    separados da string SQL (consulta parametrizada), nunca concatenados:
    a protecao contra SQL Injection e a mesma nos dois bancos.
    """

    def __init__(self, url):
        import psycopg
        from psycopg.rows import dict_row

        self._conn = psycopg.connect(url, row_factory=dict_row)

    def execute(self, sql, params=()):
        return self._conn.execute(sql.replace("?", "%s"), params)

    def commit(self):
        self._conn.commit()

    def close(self):
        self._conn.close()


def get_db():
    db = getattr(g, "_database", None)
    if db is None:
        if USANDO_POSTGRES:
            db = g._database = _PostgresDB(DATABASE_URL)
        else:
            db = g._database = sqlite3.connect(DATABASE)
            db.row_factory = sqlite3.Row
    return db


@app.teardown_appcontext
def close_connection(exception):
    db = getattr(g, "_database", None)
    if db is not None:
        db.close()


# Esquema das tabelas. So muda o tipo da chave primaria autoincremental
# (SERIAL no PostgreSQL, INTEGER AUTOINCREMENT no SQLite).
_ESQUEMA_SQLITE = """
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        password TEXT NOT NULL
    );
    CREATE TABLE IF NOT EXISTS tasks (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        title TEXT NOT NULL,
        description TEXT,
        done INTEGER DEFAULT 0,
        FOREIGN KEY (user_id) REFERENCES users (id)
    );
"""
_ESQUEMA_POSTGRES = (
    """
    CREATE TABLE IF NOT EXISTS users (
        id SERIAL PRIMARY KEY,
        username TEXT UNIQUE NOT NULL,
        password TEXT NOT NULL
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS tasks (
        id SERIAL PRIMARY KEY,
        user_id INTEGER NOT NULL REFERENCES users (id),
        title TEXT NOT NULL,
        description TEXT,
        done INTEGER DEFAULT 0
    )
    """,
)


def init_db():
    db = get_db()
    if USANDO_POSTGRES:
        for comando in _ESQUEMA_POSTGRES:
            db.execute(comando)
    else:
        db.executescript(_ESQUEMA_SQLITE)
    db.commit()

    # Usuarios iniciais: as senhas vem de variaveis de ambiente (nunca do
    # codigo) e sao gravadas apenas como hash. Se a variavel de um usuario
    # nao estiver definida, ele simplesmente nao e criado.
    usuarios_iniciais = {
        "admin": os.environ.get("TASKFLOW_ADMIN_PASSWORD"),
        "aluno": os.environ.get("TASKFLOW_ALUNO_PASSWORD"),
    }
    for username, senha in usuarios_iniciais.items():
        if not senha:
            logger.warning(
                "usuario inicial nao criado: senha nao definida no ambiente",
                extra={"event": "seed_user_skipped", "username": username},
            )
            continue
        # "Insere se nao existir": sintaxe padrao SQL (ON CONFLICT), aceita
        # tanto pelo PostgreSQL quanto pelo SQLite 3.24+.
        db.execute(
            "INSERT INTO users (username, password) VALUES (?, ?) "
            "ON CONFLICT (username) DO NOTHING",
            (username, generate_password_hash(senha)),
        )
    db.commit()


# ---------------------------------------------------------------------------
# 2. request_id por requisicao (correlacao de eventos)
# ---------------------------------------------------------------------------
#
# `before_request` roda antes de QUALQUER view function. Geramos um
# identificador unico (UUID v4) e guardamos em `g` (contexto da
# requisicao Flask), junto com o horario de inicio para medirmos a
# duracao no `after_request`. Toda vez que a aplicacao loga algo
# durante essa requisicao, incluimos esse mesmo `request_id` - e assim
# que conseguimos, depois, filtrar no Grafana/Loki TODOS os eventos de
# uma unica requisicao especifica.
@app.before_request
def gerar_request_id():
    g.request_id = str(uuid.uuid4())
    g.start_time = time.time()


# ---------------------------------------------------------------------------
# Protecao CSRF (sem dependencia extra): um token aleatorio por sessao e
# incluido como campo oculto "csrf_token" em todo formulario POST e
# conferido aqui antes de qualquer view. Detectado pelo ZAP (regra 10202).
# ---------------------------------------------------------------------------
def csrf_token():
    if "_csrf_token" not in session:
        session["_csrf_token"] = secrets.token_urlsafe(32)
    return session["_csrf_token"]


app.jinja_env.globals["csrf_token"] = csrf_token


@app.before_request
def validar_csrf():
    if request.method != "POST":
        return
    esperado = session.get("_csrf_token")
    recebido = request.form.get("csrf_token", "")
    if not esperado or not hmac.compare_digest(esperado, recebido):
        logger.warning(
            "token CSRF ausente ou invalido",
            extra={
                "event": "csrf_rejected",
                "path": request.path,
                "ip": request.remote_addr,
                "request_id": g.get("request_id"),
            },
        )
        abort(400)


# ---------------------------------------------------------------------------
# Cabecalhos de seguranca em todas as respostas (achados do ZAP Baseline:
# 10020, 10021, 10036, 10038, 10063 e 90004).
# ---------------------------------------------------------------------------
@app.after_request
def adicionar_cabecalhos_de_seguranca(response):
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; "
        "frame-ancestors 'none'; form-action 'self'; base-uri 'self'; "
        "object-src 'none'"
    )
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["Referrer-Policy"] = "same-origin"
    response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
    response.headers["Cross-Origin-Resource-Policy"] = "same-origin"
    response.headers["Cross-Origin-Opener-Policy"] = "same-origin"
    response.headers["Cross-Origin-Embedder-Policy"] = "require-corp"
    return response


@app.after_request
def logar_fim_da_requisicao(response):
    duracao_ms = round((time.time() - g.get("start_time", time.time())) * 1000, 2)
    logger.info(
        "requisicao finalizada",
        extra={
            "event": "http_request",
            "request_id": g.get("request_id"),
            "method": request.method,
            "path": request.path,
            "status_code": response.status_code,
            "duration_ms": duracao_ms,
            "user": session.get("username"),
            # IP de origem tambem no evento de toda requisicao (nao so no
            # login): permite ver no Grafana o volume de trafego por IP.
            "ip": request.remote_addr,
        },
    )
    # Devolve o request_id ao cliente: quem reporta um erro (ou o time de
    # resposta a incidente) informa esse valor e acha no Loki todos os
    # eventos daquela requisicao: {job="taskflow"} | json | request_id="..."
    # E um UUID aleatorio, sem nenhum dado interno.
    response.headers["X-Request-ID"] = g.get("request_id", "")
    return response


def usuario_atual():
    """Retorna o username da sessao atual, ou None se nao autenticado."""
    return session.get("username")


@app.route("/")
def index():
    if "user_id" not in session:
        return redirect(url_for("login"))
    return redirect(url_for("tasks"))


@app.route("/login", methods=["GET", "POST"])
def login():
    error = None
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]

        # Busca parametrizada so pelo username; a senha e validada contra
        # o hash com check_password_hash() (as senhas nao ficam mais em
        # texto puro no banco, entao nao da para compara-las na query).
        db = get_db()
        cur = db.execute("SELECT * FROM users WHERE username = ?", (username,))
        user = cur.fetchone()
        if user and not check_password_hash(user["password"], password):
            user = None

        # Origem da requisicao (IP) e essencial para investigar padroes
        # de brute-force. Em producao, atras de um proxy/load balancer,
        # o IP real normalmente vem do cabecalho X-Forwarded-For - aqui
        # simplificamos usando request.remote_addr.
        ip_origem = request.remote_addr

        if user:
            session["user_id"] = user["id"]
            session["username"] = user["username"]

            # NUNCA logar a senha, mesmo em caso de sucesso. Logamos
            # apenas o USERNAME (dado necessario para investigacao) e
            # o resultado do evento.
            logger.info(
                "login bem-sucedido",
                extra={
                    "event": "login_attempt",
                    "result": "success",
                    "username": username,
                    "ip": ip_origem,
                    "request_id": g.get("request_id"),
                },
            )
            return redirect(url_for("tasks"))

        error = "Usuario ou senha invalidos."

        # Log de falha de autenticacao - dado critico para detectar
        # brute-force e credential stuffing. Novamente, a senha jamais
        # e incluida no log, nem mesmo mascarada: ela simplesmente nao
        # tem motivo de negocio para existir em um log.
        logger.warning(
            "login falhou",
            extra={
                "event": "login_attempt",
                "result": "failure",
                "username": username,
                "ip": ip_origem,
                "request_id": g.get("request_id"),
            },
        )

    # Template Jinja2 com autoescape: a mensagem de erro nunca e
    # interpretada como HTML (fecha o sink de XSS refletido no login).
    return render_template("login.html", error=error)


@app.route("/logout")
def logout():
    logger.info(
        "logout realizado",
        extra={
            "event": "logout",
            "username": usuario_atual(),
            "request_id": g.get("request_id"),
        },
    )
    session.clear()
    return redirect(url_for("login"))


@app.route("/tasks", methods=["GET"])
def tasks():
    if "user_id" not in session:
        return redirect(url_for("login"))

    search = request.args.get("q", "")
    db = get_db()

    if search:
        # Consulta parametrizada: o termo de busca vai como parametro, nunca
        # concatenado na string SQL (evita SQL Injection pelo parametro "q").
        # LOWER(...) nos dois lados: busca sem diferenciar maiusculas, igual
        # nos dois bancos (o LIKE do PostgreSQL diferencia, o do SQLite nao).
        rows = db.execute(
            "SELECT * FROM tasks WHERE user_id = ? AND LOWER(title) LIKE LOWER(?)",
            (session["user_id"], f"%{search}%"),
        ).fetchall()
    else:
        rows = db.execute("SELECT * FROM tasks WHERE user_id = ?", (session["user_id"],)).fetchall()

    # Acesso a lista de tarefas (recurso "sensivel" do ponto de vista de
    # cada usuario, pois pertence a ele). Logar esse acesso permite,
    # por exemplo, detectar um usuario fazendo varredura de buscas
    # (tentativas de SQLi ou enumeracao) no campo "q".
    logger.info(
        "lista de tarefas acessada",
        extra={
            "event": "tasks_list_accessed",
            "username": usuario_atual(),
            "search_term": search or None,
            "results_count": len(rows),
            "request_id": g.get("request_id"),
        },
    )

    # Template Jinja2 com autoescape (sem "| safe"): titulo, descricao,
    # username e o termo de busca "q" sao escapados automaticamente,
    # fechando o XSS armazenado e o refletido pelo parametro de busca.
    return render_template(
        "tasks.html",
        tasks=rows,
        username=session["username"],
        search=search,
    )


@app.route("/tasks/new", methods=["GET", "POST"])
def new_task():
    if "user_id" not in session:
        return redirect(url_for("login"))

    if request.method == "POST":
        title = request.form["title"]
        description = request.form["description"]
        db = get_db()
        db.execute(
            "INSERT INTO tasks (user_id, title, description) VALUES (?, ?, ?)",
            (session["user_id"], title, description),
        )
        db.commit()

        # Evento de negocio simples: criacao de tarefa. Note que NAO
        # logamos o conteudo completo da descricao (poderia conter
        # dado sensivel digitado pelo usuario) - apenas metadados
        # (titulo, que e um identificador de negocio de baixo risco,
        # e o tamanho da descricao).
        logger.info(
            "tarefa criada",
            extra={
                "event": "task_created",
                "username": usuario_atual(),
                "title": title,
                "description_length": len(description or ""),
                "request_id": g.get("request_id"),
            },
        )
        return redirect(url_for("tasks"))

    return render_template("new_task.html")


# O endpoint /debug/info foi REMOVIDO (Modulo 4): ele expunha, sem
# autenticacao, detalhes do ambiente (e, na versao original, a SECRET_KEY).
# Se for preciso um health check, crie uma rota que devolva apenas
# {"status": "ok"}, sem nenhum dado interno.


if __name__ == "__main__":
    with app.app_context():
        init_db()
    logger.info(
        "aplicacao TaskFlow (instrumentada) iniciando",
        extra={"event": "app_startup"},
    )
    # debug controlado por variavel de ambiente e DESLIGADO por padrao: o
    # debugger interativo do Werkzeug permite executar codigo no servidor.
    #   export FLASK_DEBUG=true   # apenas em desenvolvimento local
    debug_mode = os.environ.get("FLASK_DEBUG", "false").lower() in ("1", "true", "yes")
    # Host padrao 127.0.0.1 (so a propria maquina). Dentro de um container
    # e preciso escutar em todas as interfaces: defina FLASK_RUN_HOST no
    # Dockerfile/compose. Em producao, use gunicorn em vez de app.run().
    host = os.environ.get("FLASK_RUN_HOST", "127.0.0.1")
    # O servidor de desenvolvimento do Werkzeug sempre anuncia a propria
    # versao e a do Python no header "Server" (ZAP 10036). Escondemos.
    from werkzeug.serving import WSGIRequestHandler

    WSGIRequestHandler.server_version = "TaskFlow"
    WSGIRequestHandler.sys_version = ""
    app.run(host=host, port=5000, debug=debug_mode)
