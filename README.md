# TaskFlow (App de Exemplo) — Disciplina DevSecOps

Esta é a aplicação de laboratório usada em **todos os encontros práticos** da
disciplina. É um gerenciador de tarefas (to-do list) simples em Python/Flask,
propositalmente vulnerável, que evolui ao longo do curso:

- Módulos 1–2: usada para discutir arquitetura, pipeline e hardening.
- Módulo 3: alvo de SAST (Semgrep) e SCA (pip-audit / Trivy) — os alunos
  encontram SQLi, XSS, segredo hardcoded e dependências vulneráveis.
- Módulo 4: alvo de DAST (OWASP ZAP) rodando contra a aplicação em execução.
- Módulo 5: containerizada com Docker e provisionada via Docker Compose,
  usada para praticar scanning de IaC.
- Módulo 6: instrumentada com logging estruturado para observabilidade.
- Módulo 7: base do projeto final — os alunos entregam a versão corrigida
  com a esteira DevSecOps completa.

## ⚠️ Aviso importante

Este código contém vulnerabilidades **intencionais** para fins didáticos
(ver comentários `# FALHA` e docstring no topo de `app.py`). Nunca:

- Use este código como referência de boas práticas.
- Implante esta aplicação em ambiente de produção ou exposto à internet.
- Reutilize o padrão de código (concatenação de SQL, senhas em texto puro,
  segredo hardcoded) em projetos reais.

## Como executar localmente

```bash
python3 -m venv .venv
source .venv/bin/activate          # Windows: .venv\Scripts\activate
pip install -r requirements.txt

# Segredos vem do ambiente - nunca do codigo
export TASKFLOW_SECRET_KEY="$(openssl rand -hex 32)"
export TASKFLOW_ADMIN_PASSWORD="<escolha-uma-senha>"
export TASKFLOW_ALUNO_PASSWORD="<escolha-outra-senha>"
python app.py
```

A aplicação sobe em `http://localhost:5000`. Na primeira execução, os
usuários `admin` e `aluno` são criados no banco SQLite (`taskflow.db`)
com as senhas definidas nas variáveis acima, armazenadas apenas como
hash. Se uma das variáveis não estiver definida, aquele usuário não é
criado. Sem `TASKFLOW_SECRET_KEY` a aplicação não sobe.

## Como executar com Docker

```bash
cd app-exemplo
docker build -t taskflow:vuln .
docker run -p 5000:5000 \
  -e TASKFLOW_SECRET_KEY="$(openssl rand -hex 32)" \
  -e TASKFLOW_ADMIN_PASSWORD="<escolha-uma-senha>" \
  -e TASKFLOW_ALUNO_PASSWORD="<escolha-outra-senha>" \
  taskflow:vuln
```

## Estrutura

```
app-exemplo/
├── app.py              # Aplicação Flask (versão vulnerável, linha de base)
├── requirements.txt    # Dependências com CVEs conhecidas (uso proposital)
├── Dockerfile           # Dockerfile inseguro (uso no Módulo 2 - Hardening)
└── README.md            # Este arquivo
```

Cada módulo cria, dentro da sua própria pasta `codigo/`, uma cópia ou um
patch desta aplicação demonstrando o "antes" (vulnerável) e o "depois"
(corrigido) referente ao tema daquele encontro.

## Teste de proteção do branch

Mudança de teste.

Teste 3 - A hora de morrer