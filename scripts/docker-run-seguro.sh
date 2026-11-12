#!/usr/bin/env bash
# Sobe a TaskFlow com as flags de runtime seguras do Modulo 2.
#
# Uso:
#   docker build -t taskflow:local .
#   ./scripts/docker-run-seguro.sh [imagem]      # padrao: taskflow:local
#
# Os segredos sao gerados na hora (nunca escritos no script nem na imagem).
# Para fixar uma senha do admin: export TASKFLOW_ADMIN_PASSWORD=... antes.
set -euo pipefail

IMAGE="${1:-taskflow:local}"
NAME="taskflow"

docker rm -f "$NAME" >/dev/null 2>&1 || true

# --read-only            raiz do container somente leitura (codigo imutavel)
# --tmpfs /data, /tmp    unicos diretorios gravaveis, em memoria, com dono
#                        = usuario da imagem (UID 10001); noexec/nosuid
# --cap-drop=ALL         remove todas as capabilities do Linux
# --security-opt=no-new-privileges  impede escalar privilegio (setuid etc.)
# --memory/--cpus/--pids-limit      limites contra abuso de recursos / DoS
# -p 127.0.0.1:...       porta publicada so no localhost do host
docker run -d --name "$NAME" \
  --read-only \
  --tmpfs /data:rw,noexec,nosuid,size=64m,uid=10001,gid=10001,mode=0700 \
  --tmpfs /tmp:rw,noexec,nosuid,size=16m,uid=10001,gid=10001,mode=0700 \
  --cap-drop=ALL \
  --security-opt=no-new-privileges \
  --memory=256m --cpus=0.5 --pids-limit=100 \
  -p 127.0.0.1:5000:5000 \
  -e TASKFLOW_SECRET_KEY="$(openssl rand -hex 32)" \
  -e TASKFLOW_ADMIN_PASSWORD="${TASKFLOW_ADMIN_PASSWORD:-$(openssl rand -hex 16)}" \
  "$IMAGE"

# Evidencias para o relatorio:
echo "--- flags aplicadas (ReadonlyRootfs CapDrop SecurityOpt)"
docker inspect "$NAME" --format '{{.HostConfig.ReadonlyRootfs}} {{.HostConfig.CapDrop}} {{.HostConfig.SecurityOpt}}'
echo "--- usuario do processo (uid deve ser 10001, nao 0)"
docker exec "$NAME" id
echo "--- tentativa de escrita na raiz (deve falhar: Read-only file system)"
docker exec "$NAME" touch /app/x 2>&1 || true
