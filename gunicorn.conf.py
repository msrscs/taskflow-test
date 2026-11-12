# Configuracao do gunicorn, o servidor WSGI de producao da TaskFlow no
# container (correcao das FALHAS 5 e 6 do Dockerfile: nada de servidor de
# desenvolvimento do Flask nem debugger interativo do Werkzeug).
#
# O gunicorn le este arquivo automaticamente (./gunicorn.conf.py no
# diretorio de trabalho). Valores podem ser sobrescritos por variaveis
# de ambiente: GUNICORN_WORKERS.

import os

# Escuta em todas as interfaces DENTRO do container; quem decide o que
# fica exposto no host e o "-p" do docker run (ex.: -p 127.0.0.1:5000:5000).
bind = "0.0.0.0:5000"
workers = int(os.environ.get("GUNICORN_WORKERS", "2"))
timeout = 30

# Socket de controle do gunicorn (comandos administrativos em tempo de
# execucao, novidade das versoes recentes) desligado: nao usamos, e menos
# interface exposta e menor superficie de ataque. Ele tambem tentaria
# criar o arquivo no HOME do usuario, que nao existe (raiz somente leitura).
control_socket_disable = True

# Logs de acesso do gunicorn desligados: a propria aplicacao ja registra
# cada requisicao em JSON (evento http_request, com request_id). Erros do
# servidor continuam indo para stderr.
accesslog = None
errorlog = "-"

# Heartbeat dos workers: com a raiz somente leitura (--read-only),
# o gunicorn precisa de um diretorio gravavel; no docker run
# seguro /tmp e um tmpfs gravavel.
worker_tmp_dir = "/tmp"  # noqa: S108 - tmpfs dedicado no container


def on_starting(server):
    """Cria as tabelas e os usuarios iniciais UMA vez, no processo mestre,
    antes de criar os workers (com "python app.py" isso era feito no
    bloco __main__, que o gunicorn nao executa)."""
    from app import app, init_db

    with app.app_context():
        init_db()
