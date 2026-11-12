# Demo de shift-left: o gate barrando uma falha no PR

Roteiro da demonstração ao vivo. A ideia é mostrar que uma falha de segurança
**não chega à `main`**: o PR fica vermelho, o merge fica bloqueado pela branch
protection e, depois da correção, tudo volta a verde.

Os dois cenários abaixo foram **ensaiados localmente em 12/11/2026**, com as
mesmas versões e opções dos workflows. As saídas reais estão em
[`evidencias/demo-shift-left.txt`](evidencias/demo-shift-left.txt).

| Cenário | Falha introduzida | Check que fica vermelho | OWASP Top 10:2025 |
|---|---|---|---|
| 1 | `\| safe` no título da tarefa (XSS) | `SAST - Semgrep` (`template-unescaped-with-safe`) | A05 Injection |
| 2 | Remover o header `X-Content-Type-Options` | `zap-baseline` (WARN-NEW 10021) | A02 Security Misconfiguration |

> **Não use `X-Frame-Options` no cenário 2.** O ensaio mostrou que o ZAP
> continua verde sem ele, porque o `frame-ancestors 'none'` da CSP já protege
> contra clickjacking. É um bom exemplo de defesa em profundidade para comentar,
> mas não deixa o gate vermelho.

## Antes da apresentação

- A `main` tem que estar verde e com a branch protection ativa (required
  checks + 1 aprovação de code owner).
- O ZAP leva alguns minutos no CI (build da imagem + scan). Se o tempo for
  curto, abra o PR **antes** da apresentação e mostre o resultado já pronto.
  Ao vivo, mostre só a correção ficando verde.

## Passo a passo

```bash
git switch main && git pull
git switch -c demo/shift-left
```

**Cenário 1: XSS (Semgrep)**

```bash
sed -i "s/{{ task\['title'\] }}/{{ task['title'] | safe }}/" templates/tasks.html
git diff                      # mostra a única linha alterada
git commit -am "demo: desliga o autoescape do titulo (deve ser bloqueado)"
```

**Cenário 2: header removido (ZAP)**

```bash
sed -i '/response.headers\["X-Content-Type-Options"\] = "nosniff"/d' app.py
git diff
git commit -am "demo: remove o header nosniff (deve ser bloqueado)"
```

Pode usar os dois no mesmo PR (dois checks vermelhos) ou só um deles.

**Abrir o PR e mostrar o bloqueio**

```bash
git push -u origin demo/shift-left
gh pr create --base main --title "demo: shift-left (NAO FAZER MERGE)" \
  --body "PR de demonstracao: introduz falhas para mostrar o gate."
gh pr checks --watch
```

O que mostrar na tela:
1. Aba **Checks** do PR: `SAST - Semgrep` e/ou `zap-baseline` em vermelho.
   Abra o log do job e mostre a linha do achado: regra do Semgrep na linha 39
   do template, ou `WARN-NEW: X-Content-Type-Options Header Missing [10021]`.
2. O botão de merge **bloqueado** ("Required statuses must pass").
3. (Opcional) `gh pr merge --merge` é recusado pela proteção.

**Corrigir e ficar verde**

```bash
git revert --no-edit HEAD     # repita uma vez para cada commit de falha
git push
gh pr checks --watch          # todos os checks verdes
```

Depois da demo, **feche o PR sem merge** e apague a branch:

```bash
gh pr close demo/shift-left --delete-branch
```

## Prints para guardar

Salve em `docs/evidencias/`:
- `demo-checks-vermelhos.png`: aba Checks com o job vermelho;
- `demo-merge-bloqueado.png`: botão de merge bloqueado;
- `demo-checks-verdes.png`: checks verdes depois do revert.

## Ensaio local (sem push)

Para conferir antes, sem abrir PR:

```bash
# Cenário 1
docker run --rm -v "$PWD":/src:ro -w /src semgrep/semgrep:1.185.0 \
  semgrep scan --config=p/python --config=p/flask --config=p/security-audit --error --metrics=off
# exit 1 = bloqueado

# Cenário 2 (a app precisa estar rodando na porta 5000)
docker build -t taskflow:demo . && ./scripts/docker-run-seguro.sh taskflow:demo
docker run --rm --network host -v "$PWD/.zap":/zap/wrk:rw ghcr.io/zaproxy/zaproxy:stable \
  zap-baseline.py -t http://localhost:5000 -c rules.tsv -a
# exit 2 = WARN-NEW = bloqueado
docker rm -f taskflow

git checkout -- templates/tasks.html app.py   # desfaz as falhas
```
