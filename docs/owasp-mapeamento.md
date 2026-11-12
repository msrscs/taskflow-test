# Mapeamento dos achados para o OWASP Top 10:2025

Cada achado das ferramentas da esteira, na versão original da TaskFlow
("antes") e na corrigida ("depois"), ligado a uma categoria do **OWASP Top
10:2025**. Todos os números vêm das saídas reais em
[`docs/evidencias/`](evidencias/README.md), geradas em 12/11/2026.

Categorias do OWASP Top 10:2025 usadas aqui:

| ID | Categoria |
|---|---|
| A01 | Broken Access Control |
| A02 | Security Misconfiguration |
| A03 | Software Supply Chain Failures |
| A04 | Cryptographic Failures |
| A05 | Injection |
| A06 | Insecure Design |
| A07 | Authentication Failures |
| A08 | Software or Data Integrity Failures |
| A09 | Security Logging and Alerting Failures |
| A10 | Mishandling of Exceptional Conditions |

---

## 1. DAST: alertas do ZAP Baseline

Fonte: `evidencias/antes/zap-baseline.md` e `evidencias/depois/zap-baseline.md`
(mesmo `.zap/rules.tsv` nas duas execuções). "Antes" e "Depois" mostram o
resultado do gate e o número de ocorrências.

### 1.1 Alertas que reprovavam o gate (corrigidos)

| Alerta ZAP | ID | CWE | Risco | OWASP Top 10:2025 | Antes | Depois | Correção |
|---|---|---|---|---|---|---|---|
| Content Security Policy (CSP) Header Not Set | 10038 | 693 | Médio | A02 Security Misconfiguration (a CSP também limita o impacto de A05 Injection/XSS) | **WARN** ×3 | PASS | `Content-Security-Policy: default-src 'self'; frame-ancestors 'none'; form-action 'self'; base-uri 'self'; object-src 'none'`, sem `unsafe-inline` |
| Missing Anti-clickjacking Header | 10020 | 1021 | Médio | A02 Security Misconfiguration | **WARN** ×3 | PASS | `frame-ancestors 'none'` na CSP e `X-Frame-Options: DENY` (ver 1.4) |
| X-Content-Type-Options Header Missing | 10021 | 693 | Baixo | A02 Security Misconfiguration | **WARN** ×3 | PASS | `X-Content-Type-Options: nosniff` |
| Server Leaks Version Information via "Server" | 10036 | 497 | Baixo | A02 Security Misconfiguration | **WARN** ×5 (`Werkzeug/0.15.4 Python/3.7.17`) | PASS (`Server: gunicorn`, sem versão) | gunicorn no lugar do servidor de desenvolvimento; no `app.run()` local, `server_version = "TaskFlow"` |
| Permissions Policy Header Not Set | 10063 | 693 | Baixo | A02 Security Misconfiguration | **WARN** ×5 | PASS | `Permissions-Policy: camera=(), microphone=(), geolocation=()` |
| Insufficient Site Isolation Against Spectre (COEP, COOP e CORP) | 90004 | 693 | Baixo | A02 Security Misconfiguration | **WARN** ×9 (3 de cada header) | PASS | `Cross-Origin-Embedder-Policy: require-corp`, `Cross-Origin-Opener-Policy: same-origin`, `Cross-Origin-Resource-Policy: same-origin` |

**Resultado do gate:** antes **6 WARN-NEW** (o job `zap-baseline` reprovaria);
depois **0 FAIL / 0 WARN, 65 PASS**.

Todos os headers são aplicados num único `@app.after_request`
(`adicionar_cabecalhos_de_seguranca` em `app.py`), então valem para todas as
respostas, inclusive erros e redirects.

### 1.2 Alertas informativos rebaixados para IGNORE (com justificativa)

Estão em `.zap/rules.tsv`, cada um com o motivo. Qualquer alerta **fora** dessa
lista reprova o job.

| Alerta ZAP | ID | CWE | Risco | OWASP Top 10:2025 | Antes | Depois | Por que não é vulnerabilidade |
|---|---|---|---|---|---|---|---|
| Non-Storable / Storable and Cacheable Content | 10049 | 524 | Info | (A02, se fosse cache de página com sessão) | IGNORE ×6 | IGNORE ×6 | Só informa a política de cache; páginas com sessão não devem ir para cache compartilhado |
| Authentication Request Identified | 10111 | – | Info | – | IGNORE ×1 | IGNORE ×1 | O ZAP só identificou o formulário de login |
| Sec-Fetch-Dest/Mode/Site/User Header is Missing | 90005 | 352 | Info | – | IGNORE ×16 | IGNORE ×16 | Verifica headers da **requisição** que o próprio ZAP envia, não da resposta do servidor |
| Base64 Disclosure | 10094 | 319 | Info | (A04, se fosse dado sensível) | – | IGNORE ×3 | O Base64 é o token CSRF aleatório e o cookie de sessão **assinado** do Flask. Aparece só no "depois" porque o CSRF e a sessão foram adicionados |
| Session Management Response Identified | 10112 | – | Info | – | – | IGNORE ×3 | O ZAP só identificou o cookie de sessão (agora `HttpOnly` + `SameSite=Lax`) |
| User Controllable HTML Element Attribute (Potential XSS) | 10031 | 20 | Info | (A05 Injection, se não houvesse escape) | – | IGNORE ×1 | O `q` da busca volta no `value` do campo, mas passa pelo autoescape do Jinja2 (`"` vira `&#34;`). O teste manual de XSS refletido confirma que não há injeção |

### 1.3 O que o ZAP Baseline não testa

O Baseline é **passivo**: lê respostas e headers e não envia payloads. Por
isso ele dá **PASS** na versão antiga para coisas como SQL Injection e XSS
armazenado, que existiam. Esses achados vêm do SAST e dos testes manuais da
seção 2.

### 1.4 Defesa em profundidade comprovada: clickjacking

Na demo de shift-left foi testado remover só o `X-Frame-Options`. O ZAP
**continua verde** (10020 PASS), porque o `frame-ancestors 'none'` da CSP já
protege. O `X-Frame-Options` fica como camada extra para navegadores antigos.
Evidência: `evidencias/demo-shift-left.txt`.

---

## 2. Achados das outras ferramentas (SAST, SCA, container, IaC e testes manuais)

| Vulnerabilidade (versão original) | Detectado por | Evidência | OWASP Top 10:2025 | Antes | Depois | Correção |
|---|---|---|---|---|---|---|
| SQL Injection no login (`admin' --` entra sem senha) e na busca | Semgrep (`tainted-sql-string`) + teste manual | `*/semgrep.txt`, `testes-manuais-sqli-xss-debug.txt` | **A05** Injection | Login sem senha | Recusado (200, fica no login) | Consultas parametrizadas (`?` / `%s`) |
| XSS armazenado e refletido (HTML montado com f-string) | Semgrep (`raw-html-format`, `directly-returned-format-string`) + teste manual | `*/semgrep.txt`, `testes-manuais-sqli-xss-debug.txt` | **A05** Injection | `<script>` executa | Volta como `&lt;script&gt;` | Templates Jinja2 com autoescape, sem `\| safe`; CSP sem `unsafe-inline` |
| `SECRET_KEY` hardcoded | Semgrep (`avoid_hardcoded_config_SECRET_KEY`) | `antes/semgrep.txt` | **A04** Cryptographic Failures | Chave no código | 0 achados | `TASKFLOW_SECRET_KEY` do ambiente, sem fallback |
| `ADMIN_PASSWORD=admin123` no `ENV` do Dockerfile | Trivy config (DS-0031, CRITICAL) + `docker history` | `*/trivy-config.txt`, `*/docker-history.txt` | **A04** Cryptographic Failures / **A07** Authentication Failures | Senha gravada na camada da imagem | Nenhum segredo na imagem | Senhas só via `.env`/runtime, guardadas como hash |
| Senhas em texto puro no banco | Revisão de código | `app.py` original | **A04** Cryptographic Failures / **A07** Authentication Failures | Texto puro | Hash Werkzeug (scrypt) | `generate_password_hash` / `check_password_hash` |
| `debug=True` + `/debug/info` (Werkzeug Debugger com execução de código) | Semgrep (`debug-enabled`) + teste manual | `antes/debug-info-werkzeug-debugger.txt` | **A02** Security Misconfiguration / **A10** Mishandling of Exceptional Conditions | Debugger interativo exposto | `/debug/info` = 404 | Rota removida; `FLASK_DEBUG` desligado por padrão; gunicorn |
| `app.run(host="0.0.0.0")` | Semgrep (`avoid_app_run_with_bad_host`) | `antes/semgrep.txt` | **A02** Security Misconfiguration | Escuta em todas as interfaces | 0 achados | `FLASK_RUN_HOST` (padrão `127.0.0.1`); gunicorn no container |
| Sem proteção CSRF | Revisão de código + teste do `brute_force.sh` | `app.py` (`validar_csrf`) | **A01** Broken Access Control | POST aceito de qualquer origem | POST sem token → 400 `csrf_rejected` | Token por sessão em todo formulário + `SameSite=Lax` |
| 51 CVEs em 5 dependências (werkzeug, requests, flask, jinja2, pyyaml) | pip-audit | `*/pip-audit.txt` | **A03** Software Supply Chain Failures | 51 | 0 (`--strict`) | Versões atualizadas; Dependabot |
| 451 CVEs HIGH/CRITICAL na imagem (51 com correção) | Trivy image | `*/trivy-image*.txt` | **A03** Software Supply Chain Failures | 51 corrigíveis | 0 corrigíveis (gate `ignore-unfixed`) | `python:3.12-slim` + `apt-get upgrade` |
| `FROM python:latest` (sem versão; hoje nem sobe) | Trivy config (DS-0001) | `antes/trivy-config.txt`, `antes/falha1-python-latest-quebrado.txt` | **A08** Software or Data Integrity Failures / **A03** | Imagem muda a cada build | 0 | Imagem base fixada por **digest**; `--require-hashes`; actions por SHA |
| Container rodando como root | Trivy config (DS-0002, HIGH) + `docker inspect` | `*/trivy-config.txt`, `*/docker-inspect.txt` | **A02** Security Misconfiguration | `User=""` (root) | `User=taskflow` (10001) | `USER` não-root; raiz somente leitura; `cap-drop ALL` |
| Sem `HEALTHCHECK` | Trivy config (DS-0026) | `*/trivy-config.txt` | **A02** Security Misconfiguration | Falha | 0 | `HEALTHCHECK` no Dockerfile e no Compose |
| Infra AWS insegura (bucket público, sem criptografia, SG aberto a `0.0.0.0/0`) | Checkov + Trivy config | Workflow `iac-scan.yml` | **A02** Security Misconfiguration / **A01** Broken Access Control | `main.insecure.tf` do material da disciplina (não versionado). Durante o trabalho, o Trivy ainda reprovou o egress `0.0.0.0/0` (AWS-0104, CRITICAL) | Checkov 55 passed / 0 failed / 6 skips justificados; Trivy config 0 | KMS, Public Access Block, HTTPS-only, SG e egress por variável |
| Ausência de logs e de alerta | Revisão + exercício de força bruta | `evidencias/observabilidade/` | **A09** Security Logging and Alerting Failures | Sem logs estruturados | Logs JSON + Loki + alerta em < 1 min | `JsonFormatter`, `X-Request-ID`, Grafana com alerta por IP |

---

## 3. Cobertura por categoria

| OWASP Top 10:2025 | Coberto por | Risco residual |
|---|---|---|
| A01 Broken Access Control | CSRF; checagem de sessão em toda rota protegida; tarefas filtradas por `user_id` da sessão; Checkov no Terraform | – |
| A02 Security Misconfiguration | ZAP (gate), Trivy config, Checkov, Dockerfile endurecido | 47 CVEs HIGH do Debian **sem correção** publicada (monitoradas pelo Trivy) |
| A03 Software Supply Chain Failures | pip-audit `--strict`, Trivy image, Dependabot, actions por SHA | – |
| A04 Cryptographic Failures | Semgrep, Trivy config (DS-0031), Gitleaks, hash de senha | `SESSION_COOKIE_SECURE` só vale atrás de HTTPS (lab roda em HTTP) |
| A05 Injection | Semgrep (SQLi e XSS), autoescape, CSP | ZAP Baseline não testa injeção ativamente |
| A06 Insecure Design | Exercício de força bruta e runbook | **`/login` sem limite de tentativas** (ação preventiva no runbook) |
| A07 Authentication Failures | Hash de senha, senhas do ambiente, alerta de força bruta | Sem rate limit, bloqueio de conta e MFA (runbook, seção 4) |
| A08 Software or Data Integrity Failures | Digest da imagem, `--require-hashes`, SHA das actions | – |
| A09 Security Logging and Alerting Failures | Logs JSON sem senha, Loki, alerta no Grafana | Alerta sem ponto de contato (só aparece na interface) |
| A10 Mishandling of Exceptional Conditions | Debug desligado: erro vira 500 genérico, sem stack trace na resposta; a exceção vai só para o log JSON | – |

---

## 4. Como reproduzir

Os comandos estão em [`evidencias/README.md`](evidencias/README.md#como-reproduzir).
O ensaio da demo de shift-left (uma falha por vez, com o gate ficando
vermelho) está em [`demo-shift-left.md`](demo-shift-left.md).
