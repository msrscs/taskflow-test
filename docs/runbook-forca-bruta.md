# Runbook: força bruta no login da TaskFlow

Baseado no ciclo de resposta a incidentes do **NIST SP 800-61**: Preparação →
Detecção e Análise → Contenção, Erradicação e Recuperação → Pós-incidente.

Este runbook foi **exercitado** em 12/11/2026, com um ataque simulado na
stack local. Os números das seções 2 a 4 são os dados reais desse exercício
(evidências em [`docs/evidencias/observabilidade/`](evidencias/observabilidade/)).

## Condição de disparo

> **Mais de 10 eventos `login_attempt` com `result="failure"` vindos do mesmo
> IP em 5 minutos.**

É a regra de alerta **"Forca bruta no login (> 10 falhas/IP em 5 min)"** do
Grafana (pasta *TaskFlow*), avaliada a cada 1 minuto. Ela está versionada em
`observabilidade/grafana/provisioning/alerting/forca-bruta.yml`.

## Query de detecção (LogQL)

```logql
sum by (ip) (count_over_time({job="taskflow", event="login_attempt"} | json | result="failure" [5m]))
```

É a mesma query do alerta e do painel **"[Q1] Falhas de login por IP"** do
dashboard *TaskFlow - Seguranca*.

---

## 1. Preparação

O que precisa estar pronto **antes** de um incidente, e como conferir:

| Item | Onde / como conferir |
|---|---|
| Logs estruturados em JSON com `request_id`, `ip`, `username`, `result` e sem senha, token ou cookie | `app.py` (`JsonFormatter`); `{job="taskflow"} \|= "<senha>"` deve voltar vazio |
| Stack no ar: app → Promtail → Loki → Grafana | `docker compose --profile observabilidade ps` (app, db e grafana `healthy`) |
| Alerta provisionado e saudável | Grafana → Alerting → Alert rules → regra em *Normal*, health *ok* |
| Dashboard de detecção | Grafana → Dashboards → TaskFlow → *TaskFlow - Seguranca* |
| `X-Request-ID` em toda resposta, para o usuário informar ao suporte | `curl -sI http://127.0.0.1:5000/login \| grep -i x-request-id` |
| Acesso ao Grafana só com senha forte do `.env` e só pelo `localhost` | `GRAFANA_ADMIN_PASSWORD`; porta `127.0.0.1:3000` |
| Responsáveis | Detecção e análise: responsável pela observabilidade. Contenção e erradicação: responsável pela infraestrutura. Comunicação: líder do grupo. Contato: canal do grupo |

## 2. Detecção e Análise

**Passo a passo:**

1. O alerta dispara (ou alguém vê o pico no painel Q1). Anote o `ip` do
   rótulo do alerta e o horário.
2. Rode a **query de detecção** em *Explore* (datasource Loki), na janela do
   alerta, para confirmar o IP e o volume.
3. Descubra **quais usuários** foram alvo:
   ```logql
   topk(5, sum by (username) (count_over_time({job="taskflow", event="login_attempt"} | json | result="failure" | ip="<IP>" [15m])))
   ```
4. **Houve comprometimento?** Procure login com **sucesso** do mesmo IP
   depois das falhas. Se houver, o incidente passa a ser de conta
   comprometida (severidade maior):
   ```logql
   {job="taskflow", event="login_attempt"} | json | result="success" | ip="<IP>"
   ```
5. Delimite a **janela do ataque** (primeiro e último evento do IP) e o
   ritmo das tentativas:
   ```logql
   {job="taskflow", event="login_attempt"} | json | ip="<IP>"
   ```
6. Para qualquer evento suspeito, use o `request_id` para ver tudo daquela
   requisição:
   ```logql
   {job="taskflow"} | json | request_id="<uuid>"
   ```
7. Confirme que **nenhuma senha** vazou para os logs durante o ataque:
   `{job="taskflow"} |= "tentativa"` (ou parte da senha testada) → vazio.

**Resultado no exercício de 12/11/2026:**

| Pergunta | Resposta (dados reais) |
|---|---|
| Alerta disparou? | Sim. Instância `ip=172.22.0.4` em **Alerting desde 15:05:50Z** |
| IP atacante | **172.22.0.4** (container na rede `frontend`) |
| Volume | **50 falhas** na janela de 5 min (limite: 10) |
| Janela do ataque | **15:05:27Z → 15:05:41Z**: 50 tentativas em ~15 s (≈ 3,3 por segundo, ritmo de ferramenta automatizada) |
| Usuário-alvo | `admin` (52 falhas no total: 50 do atacante + 2 do usuário legítimo) |
| Tempo até a detecção | 9 s depois da última tentativa, 23 s depois da primeira (alerta avaliado a cada 1 min) |
| Houve sucesso do IP atacante? | **Não.** O único `result=success` no período é do IP legítimo `172.22.0.1`, às 15:05:23Z, **antes** do ataque |
| Falso positivo? | Não: o IP legítimo teve 2 erros de senha e ficou em *Normal* |
| Senha nos logs? | Não. `{job="taskflow"} \|= "tentativa"` → 0 linhas |
| `request_id` da 1ª tentativa | `5510bd72-4467-4600-8766-644ae4dc9d34` |

Os comandos das seções 2 e 3 (queries, troca de senha e troca da chave)
foram executados de verdade no exercício: a senha antiga passou a ser
recusada e a nova aceita.

**Classificação:** tentativa de força bruta **sem comprometimento** de conta.
Severidade **média**: houve ataque ativo contra a conta administrativa, mas
ela não foi acessada.

## 3. Contenção, Erradicação e Recuperação

**Contenção (imediata, minutos):**

1. **Bloquear o IP de origem.**
   - No lab, o atacante é um container: tire-o da rede.
     ```bash
     docker network disconnect taskflow_frontend <container-do-atacante>
     ```
   - Num host real, bloqueie no firewall antes do tráfego chegar à app:
     ```bash
     sudo iptables -I DOCKER-USER -s <IP> -j DROP
     ```
   - Em produção, faça o bloqueio no WAF ou no load balancer.
2. **Se houve login com sucesso do IP atacante**, encerre todas as sessões
   invalidando a chave que assina os cookies. Troque `TASKFLOW_SECRET_KEY` no
   `.env` (`openssl rand -hex 32`) e reinicie a app:
   ```bash
   docker compose up -d app
   ```
   No exercício **não foi necessário**, porque não houve sucesso. O comando
   foi testado à parte: uma sessão válida (`/tasks` → 200) passou a ser
   mandada de volta ao login (302) depois da troca da chave.

**Erradicação (horas):**

3. **Trocar a senha da conta-alvo** (`admin`). Ela é obrigatória se houve
   sucesso e recomendada mesmo sem sucesso, porque o atacante pode ter uma
   lista de senhas vazadas:
   ```bash
   NOVA=$(openssl rand -hex 16)
   docker compose exec -T -e NOVA_SENHA="$NOVA" app python -c "import os, psycopg; \
   from werkzeug.security import generate_password_hash as g; \
   c = psycopg.connect(os.environ['DATABASE_URL']); \
   c.execute('UPDATE users SET password = %s WHERE username = %s', (g(os.environ['NOVA_SENHA']), 'admin')); \
   c.commit(); print('senha trocada')"
   ```
   A nova senha entra por variável de ambiente e o UPDATE é parametrizado. Ela
   não aparece na linha de comando do processo nem em nenhuma string SQL, e o
   banco guarda só o hash. Entregue a nova senha ao dono da conta por um canal
   seguro.
4. **Revisar o que a conta fez**, caso tenha havido acesso:
   ```logql
   {job="taskflow"} | json | user="admin"
   ```
   Procure tarefas criadas e buscas feitas no período.

**Recuperação:**

5. Acompanhar o painel Q1 por pelo menos 24 h. O alerta deve voltar a
   *Normal* e não podem aparecer novos IPs com o mesmo padrão: um ataque
   distribuído mostra muitos IPs, cada um com poucas falhas, mas o painel Q4
   (por usuário) continua subindo.
6. Remover o bloqueio temporário só depois da janela de observação, se o
   IP for de uma faixa dinâmica.

## 4. Pós-incidente (lições aprendidas)

**Linha do tempo (12/11/2026, UTC):**

| Horário | Evento |
|---|---|
| 15:05:22–15:05:23 | Usuário legítimo (172.22.0.1) erra a senha 2 vezes e entra |
| 15:05:27 | Primeira tentativa do atacante (172.22.0.4) contra `admin` |
| 15:05:41 | 50ª e última tentativa; nenhuma com sucesso |
| 15:05:50 | Alerta *Forca bruta no login* passa a **Alerting** para 172.22.0.4 |
| depois | Análise com Q1, Q4 e Q5 + `request_id`; classificação sem comprometimento |

**Causa raiz:** o endpoint `/login` aceita tentativas ilimitadas. O CSRF não
impede o ataque, porque a ferramenta busca o token a cada tentativa. Não há
limitação de taxa nem bloqueio temporário de conta.

**O que funcionou:**
- Os logs JSON tinham tudo o que a investigação precisava (IP, usuário,
  resultado, `request_id`) e nenhuma senha.
- A detecção levou menos de 1 minuto.
- O alerta por IP não confundiu o usuário legítimo com o atacante.

**O que melhorar (ações preventivas, viram issues ou PRs):**

| Ação | Tipo |
|---|---|
| Limitar a taxa no `/login` (ex.: Flask-Limiter, 5 tentativas/min por IP) | Prevenção |
| Bloquear temporariamente a conta após N falhas, com aviso ao dono | Prevenção |
| Configurar um ponto de contato no Grafana (e-mail ou chat do plantão); hoje o alerta só aparece na interface | Detecção |
| Alerta complementar por **usuário** (ataque distribuído: muitos IPs contra a mesma conta) | Detecção |
| Atrás de um proxy reverso, logar o IP real (`X-Forwarded-For` só de proxy confiável, via `ProxyFix`) | Detecção |
| MFA para a conta `admin` | Prevenção |
