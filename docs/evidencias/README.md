# Evidências — antes × depois

Saídas reais das ferramentas da esteira, rodadas em **12/11/2026** contra as duas
versões da TaskFlow:

- **antes**: `app-exemplo/` original da disciplina (código vulnerável +
  Dockerfile com as FALHAS 1 a 6), imagem `taskflow:antes`.
- **depois**: a `main` deste repositório (merge do PR #12), imagem
  `taskflow:depois`, construída a partir do `Dockerfile` da raiz.

Versões usadas, as mesmas fixadas nos workflows: Semgrep 1.185.0, Trivy 0.70.0,
Gitleaks 8.30.1, pip-audit 2.10.1 e ZAP Baseline (`ghcr.io/zaproxy/zaproxy:stable`)
com o mesmo `.zap/rules.tsv` nas duas versões.

## Resumo

| Ferramenta | Antes | Depois | Arquivos |
|---|---|---|---|
| **Semgrep** (`p/python`, `p/flask`, `p/security-audit`) | **10 achados bloqueantes**: SECRET_KEY hardcoded, SQLi no login e na busca, XSS (HTML montado com f-string), `debug=True`, `host="0.0.0.0"` | **0 achados** | `*/semgrep.txt` |
| **pip-audit** | **51 vulnerabilidades em 5 pacotes** (werkzeug 19, requests 10, flask 8, jinja2 8, pyyaml 6) | **0** (`--strict`) | `*/pip-audit.txt` |
| **Trivy image** (HIGH/CRITICAL) | **451** (SO: 421 HIGH + 15 CRITICAL; pacotes Python: 12 HIGH + 3 CRITICAL) | **47 HIGH, todas sem correção** no Debian; **0 com correção** | `*/trivy-image.txt` |
| **Trivy image** `--ignore-unfixed` (o gate do `container.yml`) | **51** (36 SO + 15 Python) | **0** | `*/trivy-image-ignore-unfixed.txt` |
| **Trivy config** (Dockerfile) | **4 falhas**: DS-0031 CRITICAL (segredo em ENV), DS-0002 HIGH (root), DS-0001 MEDIUM (sem tag), DS-0026 LOW (sem HEALTHCHECK) | **0** | `*/trivy-config.txt` |
| **`docker history`** | `ENV ADMIN_PASSWORD=admin123` gravado na camada da imagem | Nenhum segredo; `USER taskflow`; `CMD gunicorn` | `*/docker-history.txt` |
| **`docker inspect`** | `User=""` (root), `ADMIN_PASSWORD` no ambiente, `CMD python app.py` | `User="taskflow"`, `FLASK_DEBUG=false`, `CMD gunicorn app:app` | `*/docker-inspect.txt` |
| **ZAP Baseline** | **6 WARN** (gate reprovaria): 10020 anti-clickjacking, 10021 nosniff, 10036 Server com versão, 10038 sem CSP, 10063 sem Permissions-Policy, 90004 COEP | **0 FAIL / 0 WARN** (65 PASS, 6 IGNORE justificados) | `*/zap-baseline.{html,md}`, `*/zap-baseline-resumo.txt` |
| **Testes manuais** (curl) | SQLi `admin' --` **entra sem senha**; XSS armazenado **executa**; `/debug/info` abre o **Werkzeug Debugger** | SQLi recusado (200, fica no login); XSS **escapado**; `/debug/info` = **404** | `testes-manuais-sqli-xss-debug.txt`, `antes/debug-info-werkzeug-debugger.txt` |
| **Gitleaks** | no leaks found (ver observação) | no leaks found | `*/gitleaks.txt` |

## Observações (importantes para a apresentação)

- **O ZAP Baseline é passivo.** Ele analisa respostas e cabeçalhos, mas não
  tenta SQL Injection nem XSS. Por isso os testes manuais em
  `testes-manuais-sqli-xss-debug.txt` complementam o DAST: no "antes" o login
  com `admin' --` redireciona para `/tasks` e a tarefa com título
  `<script>alert(1)</script>` volta crua no HTML; no "depois" o login falha e o
  payload aparece como `&lt;script&gt;`.
- **FALHA 1 na prática.** O Dockerfile original usa `FROM python:latest`, que
  hoje resolve para Python 3.15. O Flask 0.12.2 não roda nessa versão
  (`AttributeError: module 'pkgutil' has no attribute 'get_loader'`, ver
  `antes/falha1-python-latest-quebrado.txt`). O mesmo Dockerfile que funcionava
  quando o material foi escrito hoje gera uma imagem que nem sobe. As
  evidências de Trivy e `docker history` usam essa imagem original. Para
  conseguir **rodar** o app antigo no ZAP e nos testes manuais, foi preciso
  uma cópia temporária com `FROM python:3.7`, porque o Werkzeug 0.15.4 não roda
  nem no 3.11. Essa cópia não foi versionada, já que o Checkov e o Trivy
  reprovariam um Dockerfile inseguro no repositório.
- **`debug=True` é pior do que vazar a chave.** Na versão antiga, `/debug/info`
  quebra com um `TypeError` e devolve a página interativa do Werkzeug
  Debugger, que permite executar código Python no servidor (OWASP A02
  Security Misconfiguration / A10 Mishandling of Exceptional Conditions).
- **Gitleaks não acusa os segredos didáticos.** `s3gr3d0-super-secreto-...` e
  `admin123` têm entropia baixa e não casam com as regras padrão do Gitleaks
  8.30.1. Quem acusa o segredo é o **Semgrep**
  (`avoid_hardcoded_config_SECRET_KEY`) e o **Trivy config** (DS-0031,
  `ADMIN_PASSWORD` em ENV). Isso mostra por que a esteira usa camadas
  sobrepostas: nenhuma ferramenta pega tudo sozinha.
- **As 47 HIGH restantes no Trivy sem filtro** são pacotes do Debian 13 da
  imagem base **sem correção publicada** (46 com `Status: affected` e 1
  `fix_deferred`, conferido no JSON do Trivy). Não há versão
  para onde atualizar; por isso o gate usa `ignore-unfixed` (decisão
  documentada no README principal). As que tinham correção (zlib1g) foram
  eliminadas com o `apt-get upgrade` no Dockerfile.
- **Valor mascarado.** Em `depois/docker-history.txt` e
  `depois/docker-inspect.txt`, o `GPG_KEY` herdado da imagem oficial `python`
  foi substituído por um texto. É o fingerprint da chave **pública** de
  assinatura do Python (não é segredo), mas o Gitleaks o acusa como
  `generic-api-key`. Mascarar evita um falso positivo no gate sem precisar de
  allowlist.

## Como reproduzir

```bash
# "antes": copiar app.py, Dockerfile e requirements.txt do app-exemplo para uma pasta fora do repo
docker build -t taskflow:antes <pasta-antes>
# "depois": a raiz deste repositório
docker build -t taskflow:depois .

semgrep scan --config=p/python --config=p/flask --config=p/security-audit <pasta>
pip-audit -r <pasta>/requirements.txt
trivy image --severity HIGH,CRITICAL [--ignore-unfixed] taskflow:<versao>
trivy config <pasta>
docker history --no-trunc --format '{{.CreatedBy}}' taskflow:<versao>
gitleaks dir <pasta> -v

# ZAP (a app precisa estar rodando; o "depois" com scripts/docker-run-seguro.sh)
docker run --rm --network host -v "$PWD/.zap":/zap/wrk:rw ghcr.io/zaproxy/zaproxy:stable \
  zap-baseline.py -t http://localhost:5000 -c rules.tsv -a -r zap.html
```
