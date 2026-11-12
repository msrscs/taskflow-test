# Dockerfile HARDENED da TaskFlow (Modulo 2).
#
# Cada bloco "CORRIGIDO (FALHA N)" corresponde a uma falha do Dockerfile
# inseguro original (app-exemplo/Dockerfile):
#   FALHA 1 - imagem base "latest"            -> tag + digest fixos, slim
#   FALHA 2 - container rodando como root     -> usuario dedicado nao-root
#   FALHA 3 - dependencias sem integridade    -> pip --require-hashes
#   FALHA 4 - segredo em ENV/ARG              -> nenhum segredo na imagem
#   FALHA 5 - servidor de desenvolvimento     -> gunicorn
#   FALHA 6 - debug ligado e root             -> FLASK_DEBUG=false + USER
#
# Executar com as flags de runtime seguras: ver scripts/docker-run-seguro.sh.

# ---------------------------------------------------------------------------
# CORRIGIDO (FALHA 1): tag fixa (3.12-slim, imagem minima) E digest SHA-256.
# A tag pode ser republicada com outro conteudo; o digest nao. O Dependabot
# (ecossistema docker) abre PR quando sai um digest novo da mesma tag.
# O FROM e escrito por extenso nos dois estagios (em vez de um ARG) porque
# o Dependabot e o Checkov (CKV_DOCKER_7) nao resolvem "FROM ${ARG}".
# Ao atualizar, troque o digest nos DOIS FROM.
# ---------------------------------------------------------------------------

# ===========================================================================
# Estagio 1: build - instala as dependencias num virtualenv isolado.
# Nada deste estagio (cache do pip, arquivos temporarios) vai para a
# imagem final, so o /opt/venv pronto.
# ===========================================================================
FROM python:3.15-slim@sha256:65a65fc7b30b06cb6df4930fd4650697cb23f4c2698ab81fc87e4b031bc36928 AS build

ENV PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

RUN python -m venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

COPY requirements.txt .

# CORRIGIDO (FALHA 3): o requirements.txt e gerado pelo pip-compile com o
# hash SHA-256 de cada pacote (ver requirements.in). Com --require-hashes,
# qualquer pacote adulterado ou diferente do registrado aborta o build.
RUN pip install --require-hashes --no-deps -r requirements.txt

# ===========================================================================
# Estagio 2: runtime - imagem final minima.
# ===========================================================================
FROM python:3.15-slim@sha256:65a65fc7b30b06cb6df4930fd4650697cb23f4c2698ab81fc87e4b031bc36928 AS runtime

# CORRIGIDO (FALHA 6): debug desligado explicitamente (o app.py ja usa
# false como padrao) e bytecode/buffer do Python ajustados para container.
# TASKFLOW_DATABASE e TASKFLOW_LOG_DIR apontam para /data, o unico lugar
# gravavel quando o container roda com --read-only.
# CORRIGIDO (FALHA 4): NENHUM segredo aqui. TASKFLOW_SECRET_KEY e as senhas
# iniciais sao injetadas em tempo de execucao (docker run -e / secrets do
# GitHub / .env do compose), pois ENV/ARG ficam gravados nas camadas e
# aparecem no "docker history".
ENV PATH="/opt/venv/bin:$PATH" \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    FLASK_DEBUG=false \
    TASKFLOW_DATABASE=/data/taskflow.db \
    TASKFLOW_LOG_DIR=/data/logs

# Atualizacoes de seguranca dos pacotes do Debian da imagem base. Mesmo a
# versao mais recente da python:3.12-slim pode sair com CVEs ja corrigidas
# no Debian (ex.: zlib1g, CVE-2026-76844 e CVE-2026-85091, HIGH, em
# 12/11/2026), e o trivy-image reprova a imagem. Trade-off: o build deixa
# de ser 100% reprodutivel (o resultado do upgrade depende do dia), em troca
# de nao publicar uma imagem com CVE conhecida e corrigivel. O cache do apt
# e apagado na mesma camada para nao inflar a imagem.
RUN apt-get update \
    && apt-get upgrade -y --no-install-recommends \
    && rm -rf /var/lib/apt/lists/*

# CORRIGIDO (FALHA 2): usuario e grupo dedicados, sem shell e sem home
# gravavel, com UID/GID fixos (10001) para facilitar permissoes de volume
# e tmpfs (ex.: --tmpfs /data:uid=10001,gid=10001).
RUN groupadd --system --gid 10001 taskflow \
    && useradd --system --uid 10001 --gid taskflow \
       --home-dir /nonexistent --no-create-home --shell /usr/sbin/nologin taskflow \
    && mkdir -p /data/logs \
    && chown -R taskflow:taskflow /data

COPY --from=build /opt/venv /opt/venv

WORKDIR /app

# So o necessario para rodar (o .dockerignore tambem barra .env, *.db, .git,
# logs/ etc.). Os arquivos ficam de propriedade do root e somente leitura
# para o usuario da aplicacao: um invasor nao consegue alterar o codigo.
COPY app.py gunicorn.conf.py ./
COPY templates/ templates/

USER taskflow

# CORRIGIDO (FALHA 5): EXPOSE so documenta a porta; quem atende e o
# gunicorn (servidor WSGI de producao), nao o servidor de desenvolvimento.
EXPOSE 5000

# Health check sem instalar curl na imagem: usa o proprio Python.
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD ["python", "-c", "import urllib.request; urllib.request.urlopen('http://127.0.0.1:5000/login', timeout=4)"]

# CORRIGIDO (FALHAS 5 e 6): gunicorn com a configuracao de gunicorn.conf.py
# (bind 0.0.0.0:5000, 2 workers, cria o banco no on_starting).
CMD ["gunicorn", "app:app"]
