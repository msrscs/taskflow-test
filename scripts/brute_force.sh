#!/bin/sh
# Simulacao de FORCA BRUTA no login da TaskFlow (Modulo 6).
#
# USO SOMENTE NO LAB, contra a sua propria instancia local.
#
#   ./scripts/brute_force.sh [URL] [USUARIO] [TENTATIVAS] [PAUSA_SEG]
#   ./scripts/brute_force.sh http://localhost:5000 admin 50 0.2
#
# Como "atacante" com IP proprio (diferente do seu navegador), rodando num
# container na rede frontend do Compose:
#
#   docker run --rm --network taskflow_frontend -v "$PWD/scripts":/s:ro \
#     curlimages/curl:8.17.0 sh /s/brute_force.sh http://app:5000 admin 50 0.2
#
# O /login exige token CSRF: o script busca o token (e o cookie de sessao)
# antes de cada tentativa, como faria uma ferramenta automatizada. Sem
# isso, toda tentativa voltaria 400 (csrf_rejected) e nao geraria o evento
# login_attempt que o alerta e o runbook usam.
#
# As senhas testadas sao "tentativa1", "tentativa2"... Depois da simulacao,
# confira que NENHUMA delas aparece nos logs:  {job="taskflow"} |= "tentativa"
#
# Escrito em sh POSIX (sem bash) para rodar tambem na imagem curlimages/curl.

set -eu

TARGET="${1:-http://localhost:5000}"
ALVO="${2:-admin}"
N="${3:-50}"
PAUSA="${4:-0.2}"

JAR="$(mktemp)"
trap 'rm -f "$JAR"' EXIT

echo "Forca bruta simulada: $N tentativas contra '$ALVO' em $TARGET"
echo "Inicio: $(date -u +%Y-%m-%dT%H:%M:%SZ)"

ok=0
falha=0
i=1
while [ "$i" -le "$N" ]; do
  token="$(curl -s -c "$JAR" -b "$JAR" "$TARGET/login" \
    | sed -n 's/.*name="csrf_token" value="\([^"]*\)".*/\1/p')"
  code="$(curl -s -o /dev/null -w "%{http_code}" -c "$JAR" -b "$JAR" \
    -X POST "$TARGET/login" \
    --data-urlencode "csrf_token=$token" \
    --data-urlencode "username=$ALVO" \
    --data-urlencode "password=tentativa$i")"
  # 302 = redirecionou para /tasks (senha certa); 200 = continua no login.
  if [ "$code" = "302" ]; then ok=$((ok + 1)); else falha=$((falha + 1)); fi
  echo "tentativa $i -> HTTP $code"
  i=$((i + 1))
  sleep "$PAUSA"
done

echo "Fim: $(date -u +%Y-%m-%dT%H:%M:%SZ)  falhas=$falha  sucessos=$ok"
