"""
TaskFlow - Versao INSTRUMENTADA com logging estruturado (Modulo 6).

Esta e a mesma aplicacao TaskFlow usada no restante do curso
(ver app-exemplo/app.py), com uma camada de observabilidade adicionada
por cima. As vulnerabilidades propositais da versao original (SQL
Injection, XSS, senha em texto puro, segredo hardcoded, endpoint de
debug exposto) foram MANTIDAS de proposito - o objetivo deste modulo
NAO e corrigi-las, e sim demonstrar como enxergar sintomas desses
problemas (e de tentativas de exploracao) atraves de logs estruturados.

O que foi adicionado nesta versao:
  1. Configuracao de logging em formato JSON (um objeto JSON por linha,
     tambem chamado de "JSON Lines" ou NDJSON), usando APENAS a
     biblioteca padrao `logging` do Python + um Formatter customizado.

     Por que nao usamos a lib `python-json-logger` aqui?
     Ela e uma otima opcao de mercado (mais concisa, com suporte a
     campos extra "de fabrica"), e fica registrada como alternativa em
     `requirements-observabilidade.txt` (comentada) para quem quiser
     experimentar. Optamos por escrever nosso proprio Formatter neste
     exemplo para os alunos verem exatamente o que acontece por baixo
     dos panos: como cada registro de log vira um dicionario e depois
     um JSON - isso e didaticamente mais valioso no primeiro contato
     com logging estruturado do que importar uma lib pronta.

  2. Um `request_id` (UUID v4) gerado a cada requisicao HTTP, no hook
     `before_request` do Flask, e anexado a TODOS os logs emitidos
     durante aquela requisicao. Isso permite correlacionar, em uma
     stack de observabilidade (Grafana/Loki), todos os eventos de log
     pertencentes a uma unica jornada de requisicao - essencial para
     investigar incidentes.

  3. Eventos de negocio/seguranca logados explicitamente:
       - login_attempt (sucesso ou falha, SEM logar a senha)
       - task_created
       - tasks_list_accessed

  4. Cuidado deliberado para NAO logar dados sensiveis em claro:
     a senha nunca aparece nos logs; quando precisamos de algum tipo
     de "pista" sobre um dado sensivel (ex.: para debugar duplicidade
     de usuario), preferimos logar um hash curto em vez do valor.

Para rodar:
    pip install -r requirements-observabilidade.txt
    python app_instrumented.py

A aplicacao grava logs em dois lugares ao mesmo tempo:
  - stdout (para quem quiser rodar via `docker compose logs`)
  - arquivo `logs/taskflow.log` (para o Promtail ler e enviar ao Loki)
"""

import json
import logging
import os
import sqlite3
import time
import uuid
from datetime import datetime, timezone
from logging.handlers import RotatingFileHandler

from flask import Flask, g, redirect, render_template, request, session, url_for
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
            "timestamp": datetime.fromtimestamp(
                record.created, tz=timezone.utc
            ).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
        }

        # Campos extras "de negocio" (event, user, request_id, etc.)
        # sao passados via `extra={...}` nas chamadas de log e ficam
        # disponiveis como atributos do record. Copiamos apenas os que
        # nao fazem parte do LogRecord padrao, para nao duplicar dados.
        campos_padrao_do_record = logging.LogRecord(
            "", 0, "", 0, "", None, None
        ).__dict__.keys()
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
    os.makedirs("logs", exist_ok=True)

    logger = logging.getLogger("taskflow")
    logger.setLevel(logging.INFO)
    logger.propagate = False  # evita log duplicado no root logger

    formatter = JsonFormatter()

    console_handler = logging.StreamHandler()
    console_handler.setFormatter(formatter)

    # RotatingFileHandler evita que o arquivo de log cresca sem limite
    # durante a aula (5 MB por arquivo, mantendo 3 arquivos antigos).
    file_handler = RotatingFileHandler(
        "logs/taskflow.log", maxBytes=5 * 1024 * 1024, backupCount=3
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
        "Ex: export TASKFLOW_SECRET_KEY=\"$(openssl rand -hex 32)\""
    )
app.config["SECRET_KEY"] = _secret_key

DATABASE = "taskflow.db"


def get_db():
    db = getattr(g, "_database", None)
    if db is None:
        db = g._database = sqlite3.connect(DATABASE)
        db.row_factory = sqlite3.Row
    return db


@app.teardown_appcontext
def close_connection(exception):
    db = getattr(g, "_database", None)
    if db is not None:
        db.close()


def init_db():
    db = get_db()
    db.executescript(
        """
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
    )
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
        db.execute(
            "INSERT OR IGNORE INTO users (username, password) VALUES (?, ?)",
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
        },
    )
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
        rows = db.execute(
            "SELECT * FROM tasks WHERE user_id = ? AND title LIKE ?",
            (session["user_id"], f"%{search}%"),
        ).fetchall()
    else:
        rows = db.execute(
            "SELECT * FROM tasks WHERE user_id = ?", (session["user_id"],)
        ).fetchall()

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


@app.route("/debug/info")
def debug_info():
    # Vulnerabilidade mantida de proposito - endpoint de debug exposto
    # sem autenticacao (ver app-exemplo/app.py). Logamos o acesso a ele
    # com nivel WARNING, pois e um recurso sensivel que nunca deveria
    # ser publico.
    import platform
    import sys

    logger.warning(
        "acesso ao endpoint de debug",
        extra={
            "event": "sensitive_endpoint_accessed",
            "path": "/debug/info",
            "ip": request.remote_addr,
            "request_id": g.get("request_id"),
        },
    )

    return {
        "python_version": sys.version,
        "platform": platform.platform(),
    }


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
    app.run(host=host, port=5000, debug=debug_mode)