# Roteiro da apresentação

**Formato:** ~20 minutos, mostrando o **repositório e o GitHub Actions ao
vivo**, sem slides. O Mauro opera a tela durante toda a apresentação. Cada
integrante narra a sua parte e diz quando trocar de aba.

| # | Parte | Quem fala | Tempo | Acumulado |
|---|---|---|---|---|
| 1 | Contexto, equipe e arquitetura | Artur | 2 min | 2 min |
| 2 | A esteira e a **demo do PR bloqueado** (ao vivo) | Mauro | 4 min | 6 min |
| 3 | SAST, segredos, SCA e container: antes × depois | Eduardo | 3 min | 9 min |
| 4 | DAST: o ZAP acusando e a correção | Gabriel | 2,5 min | 11,5 min |
| 5 | IaC (Checkov e Trivy) e hardening do host (Lynis) | Silvio | 2,5 min | 14 min |
| 6 | **Incidente ao vivo**: força bruta → Grafana → runbook | Gabriel e Mauro | 4 min | 18 min |
| 7 | Uma decisão técnica e um trade-off | Eduardo | 1,5 min | 19,5 min |
| 8 | O aprendizado mais impactante e fechamento | Artur e Silvio | 1 min | 20,5 min |

A divisão é uma sugestão: troquem os nomes à vontade, mas mantenham
**todos falando** (exigência da rubrica).

---

## Preparação (30 minutos antes, na máquina do Mauro)

As duas demos ao vivo dependem disto. Sem a preparação, elas não cabem no
tempo.

```bash
cd ~/taskflow-test && git switch main && git pull
eval "$(ssh-agent -s)" && ssh-add ~/.ssh/id_ed25519   # passphrase AGORA, não durante a demo
gh auth status                     # logado como msrscs

# Stack com observabilidade (o .env é criado na hora e apagado no fim)
cp .env.example .env
sed -i "s/^TASKFLOW_SECRET_KEY=.*/TASKFLOW_SECRET_KEY=$(openssl rand -hex 32)/" .env
sed -i "s/^POSTGRES_PASSWORD=.*/POSTGRES_PASSWORD=$(openssl rand -hex 24)/" .env
sed -i "s/^TASKFLOW_ADMIN_PASSWORD=.*/TASKFLOW_ADMIN_PASSWORD=$(openssl rand -hex 12)/" .env
sed -i "s/^GRAFANA_ADMIN_PASSWORD=.*/GRAFANA_ADMIN_PASSWORD=$(openssl rand -hex 16)/" .env
docker compose --profile observabilidade up -d --build
docker pull curlimages/curl:8.17.0  # imagem do "atacante" já baixada
grep GRAFANA_ADMIN_PASSWORD .env    # anotar para logar no Grafana
```

**PR da demo aberto ANTES** (o ZAP leva ~1,5 min, então ao vivo só se mostra o
resultado e a correção):

```bash
git switch -c demo/shift-left
sed -i "s/{{ task\['title'\] }}/{{ task['title'] | safe }}/" templates/tasks.html
git commit -am "demo: desliga o autoescape do titulo (deve ser bloqueado)"
git push -u origin demo/shift-left
gh pr create --base main --title "demo: shift-left (NAO FAZER MERGE)" --body "PR de demonstracao."
```

Peça para um code owner **aprovar** esse PR antes da apresentação. É isso que
mostra que nem a aprovação libera o merge.

**Abas abertas no navegador, nesta ordem:**
1. README do repositório (`github.com/msrscs/taskflow-test`)
2. O PR da demo, aba **Conversation**
3. **Actions** do repositório
4. Settings → Rules → ruleset **main**
5. `docs/evidencias/README.md` no GitHub
6. `docs/owasp-mapeamento.md`
7. Grafana (`http://127.0.0.1:3000`) já logado, no dashboard *TaskFlow - Seguranca*
8. `docs/runbook-forca-bruta.md`

**Plano B:** se a internet, o Actions ou o Docker falharem, cada demo tem
prints em `docs/evidencias/` (lista no fim deste roteiro).

---

## 1. Contexto, equipe e arquitetura (Artur, 2 min)

**Tela:** README, seção *Identificação*, e depois os dois diagramas Mermaid.

- Apresentar a equipe e os professores (seção *Identificação*).
- **A TaskFlow** é um gerenciador de tarefas em Flask que recebemos
  **propositalmente vulnerável**: SQL Injection, XSS, chave secreta no código,
  `debug=True` e um Dockerfile com 6 falhas.
- **O objetivo** foi corrigir a aplicação e, principalmente, montar uma
  **esteira que impede** que esses erros voltem.
- **Diagrama S-SDLC:** cada fase tem uma ferramenta, e cada ferramenta é um
  **gate** que pode barrar o merge.
- **Diagrama de arquitetura:**
  - a app fica na rede `frontend`;
  - o PostgreSQL fica na rede `backend` (`internal`, sem internet e sem porta
    no host);
  - a observabilidade (Promtail → Loki → Grafana) fica numa rede própria;
  - só o Grafana é exposto, e apenas em `127.0.0.1`.

> **Frase-chave:** "O código corrigido é metade do trabalho. A outra metade é
> garantir que ninguém consiga colocar a falha de volta."

## 2. A esteira e a demo do PR bloqueado (Mauro, 4 min)

**Tela:** README, tabela *A esteira*; depois a aba Rules; depois o PR da demo.

1. **A tabela da esteira:** 6 workflows com **9 jobs**, e cada job é um
   *required check*. Todos com `permissions: contents: read` e actions
   **pinadas por SHA**.
2. **Ruleset da `main`** (aba Settings → Rules):
   - os 9 checks obrigatórios;
   - aprovação de 1 code owner;
   - aprovação antiga cai quando entra commit novo;
   - branch atualizada antes do merge;
   - force push bloqueado;
   - **nenhuma exceção**, nem para o dono do repo.
3. **O PR da demo:** "este PR coloca de volta o `| safe` no template, ou seja,
   reabre o XSS."
   - Mostrar que ele está **aprovado por um code owner**.
   - Mostrar o `SAST - Semgrep` em vermelho, marcado como **Required**.
   - Mostrar o botão de merge **desabilitado**.
   - Abrir o log do job: regra `template-unescaped-with-safe`, linha 39.
4. **Corrigir ao vivo:**
   ```bash
   git revert --no-edit HEAD && git push
   gh pr checks --watch
   ```
   Enquanto os checks rodam (~1,5 min), o Eduardo começa a parte 3. Volta-se ao
   PR no fim da parte 3 para mostrar **tudo verde**. A aprovação antiga terá
   caído (*Dismiss stale approvals*), e isso também vale mostrar.
5. Depois da apresentação: `gh pr close demo/shift-left --delete-branch`.

> **Frase-chave:** "Nem aprovação humana passa por cima do gate. Quem decide é
> o check."

## 3. SAST, segredos, SCA e container: antes × depois (Eduardo, 3 min)

**Tela:** `docs/evidencias/README.md`, tabela *Resumo*.

| Ferramenta | Antes | Depois |
|---|---|---|
| Semgrep | **10 achados**: SQLi, XSS, `SECRET_KEY` no código, `debug=True` | **0** |
| pip-audit | **51 CVEs** em 5 pacotes | **0** (`--strict`) |
| Trivy image (o gate, `ignore-unfixed`) | **51** corrigíveis | **0** |
| Trivy config (Dockerfile) | 4 falhas, uma **CRITICAL**: senha no `ENV` | **0** |
| `docker history` | `ADMIN_PASSWORD=admin123` gravado na camada | nenhum segredo, `USER taskflow` |

- **Testes manuais** (`testes-manuais-sqli-xss-debug.txt`):
  - antes, `admin' --` entrava **sem senha**; depois, é recusado;
  - antes, o `<script>` executava; depois, volta escapado como `&lt;script&gt;`.
- **Ponto interessante:** o **Gitleaks não pegou** os segredos didáticos
  (`admin123` tem entropia baixa). Quem pegou foram o **Semgrep** e o
  **Trivy config**. Por isso a esteira tem camadas sobrepostas.
- **FALHA 1 na prática:** o `FROM python:latest` original hoje resolve para
  Python 3.15, e a app antiga **nem sobe**. Por isso fixamos a imagem base por
  **digest**.

> No fim: "voltando ao PR..." e mostrar os 9 checks verdes.

## 4. DAST: o ZAP acusando e a correção (Gabriel, 2,5 min)

**Tela:** `docs/owasp-mapeamento.md`, seção 1; depois o `.zap/rules.tsv`.

- O ZAP roda **dentro do CI**:
  - o job builda a imagem e sobe a app no runner com as mesmas flags de
    produção (`--read-only`, `--cap-drop=ALL`);
  - espera o `/login` responder;
  - só então roda o scan.
- **Antes:** 6 alertas que reprovariam o gate. São headers ausentes (CSP,
  anti-clickjacking, `nosniff`, Permissions-Policy, COEP/COOP/CORP) e o header
  `Server` vazando `Werkzeug/0.15.4 Python/3.7.17`.
- **Depois:** **0 FAIL, 0 WARN, 65 PASS**. Cada IGNORE no `rules.tsv` tem uma
  justificativa escrita, e qualquer alerta novo reprova o job.
- **Mapeamento OWASP Top 10:2025:** cada alerta tem ID, CWE, risco e categoria
  (A02 Security Misconfiguration, A05 Injection...).
- **Descoberta no ensaio:** remover o `X-Frame-Options` **não** deixa o ZAP
  vermelho, porque a CSP com `frame-ancestors 'none'` já protege. É defesa em
  profundidade comprovada.
- **Limite honesto:** o ZAP Baseline é **passivo**. Ele não testa SQL
  Injection. Isso é coberto pelo Semgrep e pelos testes manuais.

## 5. IaC e hardening do host (Silvio, 2,5 min)

**Tela:** `infra/main.tf` e `docker-compose.yml`; depois `docs/lynis.md`.

- **Terraform** (`infra/`):
  - bucket S3 com KMS, bloqueio de acesso público, versionamento, logging e
    política só-HTTPS;
  - Security Group sem `0.0.0.0/0`, com a faixa permitida vinda de variável.
- **Checkov:** 55 passed, **0 failed**, 6 skips. Cada skip está **justificado
  no próprio código**.
- **Achado real durante o trabalho:**
  - o Trivy reprovou o nosso **próprio** Terraform: o egress estava aberto
    para `0.0.0.0/0` (AWS-0104, **CRITICAL**);
  - corrigimos com `var.cidr_saida`;
  - é o gate funcionando com a gente, não só com o código do professor.
- **Docker Compose:**
  - o Postgres não tem porta no host e a rede `backend` é `internal`;
  - todos os containers com `read_only`, `cap_drop: ALL`, usuário não-root e
    limites de CPU, memória e processos.
- **Lynis no host:** hardening index **66 → 68**. O único **warning** (glibc
  vulnerável) foi eliminado, mais 2 correções de autenticação e permissão:
  umask 027 e validade de senha.

## 6. Incidente ao vivo: força bruta (Gabriel narra, Mauro opera, 4 min)

**Tela:** terminal ao lado do Grafana; depois o runbook.

1. **Detecção (Gabriel explica, Mauro roda):**
   ```bash
   docker run --rm --network taskflow_frontend -v "$PWD/scripts":/s:ro \
     curlimages/curl:8.17.0 sh /s/brute_force.sh http://app:5000 admin 50 0.2
   ```
   O "atacante" é um container com IP próprio, que faz 50 tentativas em ~16 s.
   Ele busca o token CSRF a cada tentativa, como uma ferramenta de verdade.
2. **Grafana, dashboard:** o painel Q1 mostra o pico do IP atacante acima da
   linha vermelha (limite de 10).
3. **Grafana, alerta** (Alerting → Alert rules → aba *Instances*): em até
   ~1 min, o IP atacante aparece em **Alerting**. A regra está marcada
   *Provisioned*, porque veio do repositório e não foi clicada na interface.
4. **Análise no Explore:**
   - `{job="taskflow"} | json | request_id="<uuid>"`: rastreia uma tentativa;
   - `{job="taskflow"} |= "tentativa"`: dá **No logs found**. **Nenhuma senha
     foi gravada nos logs.**
5. **Runbook** (`docs/runbook-forca-bruta.md`): passar rapidamente pelas **4
   fases do NIST SP 800-61** e mostrar:
   - a condição de disparo;
   - a query de detecção;
   - a contenção (bloquear o IP, trocar a `SECRET_KEY` para derrubar sessões);
   - a erradicação (troca de senha testada);
   - as lições aprendidas (falta rate limit no `/login`).

> **Frase-chave:** "Detectamos o ataque em menos de 1 minuto, sabemos que
> nenhuma conta foi invadida e nenhuma senha vazou para os logs."

Se o alerta demorar, siga para o runbook e volte ao Grafana no fim. Se a demo
falhar, use os prints `grafana-*.png`.

## 7. Uma decisão técnica e um trade-off (Eduardo, 1,5 min)

**Tela:** README, seção *Decisões técnicas e trade-offs*.

Escolham **uma** (sugestão: a primeira):

- **`ignore-unfixed` no Trivy image.**
  - Sem o filtro, a imagem tem 47 CVEs HIGH do Debian **sem correção
    publicada**, e o gate travaria todo PR sem que houvesse o que fazer.
  - Com o filtro, o gate barra o que **tem** correção.
  - Trade-off: aceitamos risco conhecido e monitorado em troca de uma esteira
    que funciona.
- **`apt-get upgrade` no Dockerfile.** Zera as CVEs com correção, mas o build
  deixa de ser 100% reprodutível.
- **Promtail**, que foi descontinuado em 2026. Ele é mais simples e é o que o
  material usa. O substituto natural seria o Grafana Alloy.
- **Repositório público.** O PDF pedia privado, mas branch protection em repo
  privado exige plano pago.

## 8. Aprendizado mais impactante e fechamento (Artur e Silvio, 1 min)

Cada um diz **uma frase**. Sugestões:

- "Nenhuma ferramenta pega tudo sozinha: o Gitleaks não viu o `admin123`, mas o
  Semgrep e o Trivy viram."
- "`latest` não é versão: o mesmo Dockerfile que funcionava quando o material
  foi escrito hoje gera uma imagem que nem sobe."
- "Um log bem feito vale mais que muito log: com `request_id`, IP e resultado,
  e sem senha, a investigação levou minutos."

Encerrar com: **"Perguntas?"**

---

## Perguntas prováveis da banca

| Pergunta | Resposta curta | Onde mostrar |
|---|---|---|
| Por que o índice do Lynis subiu só 2 pontos? | Ele pondera 245 testes, e boa parte não se aplica ao WSL2 (kernel, boot e disco são do Windows). O único warning foi eliminado | `docs/lynis.md` |
| E as 47 CVEs que sobraram na imagem? | Não têm correção publicada no Debian. O Trivy continua listando, e quando sair a correção o gate passa a barrar | README, decisões |
| Como um segredo commitado seria pego? | Gitleaks no **histórico completo** (`fetch-depth: 0`) em todo PR, e o push protection do GitHub está ligado | `sast.yml` |
| Por que pinar actions por SHA? | Uma tag (`@v4`) pode ser movida para outro código; o SHA não. É uma proteção da cadeia de suprimentos (A03) | qualquer workflow |
| O que acontece se renomearem um job? | O required check antigo nunca roda e a `main` trava. O README avisa | README, proteção |
| E se o atacante usar muitos IPs? | O alerta por IP não pega. O runbook prevê um alerta por **usuário**, e o painel Q4 já mostra isso | runbook, seção 4 |
| Por que não há rate limit no `/login`? | É a principal lição aprendida do incidente e está registrada como ação preventiva | runbook, seção 4 |

## Plano B: prints por demo

| Demo | Prints em `docs/evidencias/` |
|---|---|
| PR bloqueado | `demo-checks-vermelhos.png`, `demo-merge-bloqueado.png`, `demo-checks-verdes.png` |
| Incidente | `grafana-forca-bruta.png`, `grafana-alerta.png`, `grafana-explore-request-id.png`, `grafana-explore-sem-senha.png` |

## Depois da apresentação

```bash
gh pr close demo/shift-left --delete-branch
docker compose --profile observabilidade down -v
rm -f .env
```
