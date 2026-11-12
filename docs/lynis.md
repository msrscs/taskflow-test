# Auditoria do host com Lynis

O Lynis audita o **host** onde a esteira roda localmente (a máquina que builda
as imagens e sobe a stack do Compose). É o complemento do hardening do
container: o Trivy e o Checkov olham a imagem e o `Dockerfile`, e o Lynis
olha o sistema operacional por baixo deles.

| | |
|---|---|
| Ferramenta | Lynis 3.1.6 (`sudo lynis audit system --quick`) |
| Host | Ubuntu 26.04 LTS no WSL2 (estação de desenvolvimento) |
| Data | 12/11/2026 |
| Testes executados | 245 |
| **Hardening index antes** | **66 / 100** |
| **Hardening index depois** | **68 / 100** |
| Avisos (warnings) | 1 (`PKGS-7392`) → **0** |
| Sugestões | 39 → **35** |
| Pacotes vulneráveis | 4 → **0** |

## Resultado

| Teste | Antes | Depois | Conferido em |
|---|---|---|---|
| `PKGS-7392` | **warning**: 4 pacotes vulneráveis | 0 warnings, `vulnerable_packages_found=0` | `libc6` em `2.43-2ubuntu2.7` |
| `AUTH-9328` | sugestão: umask não definido (022) | sugestão sumiu | `UMASK 027` no `/etc/login.defs` |
| `AUTH-9286` | 2 sugestões: validade mínima e máxima | as duas sumiram | `PASS_MAX_DAYS 90`, `PASS_MIN_DAYS 1` |

O índice subiu só 2 pontos (66 → 68) porque o Lynis pondera centenas de
testes, e a maior parte do que falta não se aplica a um WSL2 (ver
"Achados conhecidos e não corrigidos"). O que importa é que o **único
warning** foi eliminado e os 3 achados escolhidos saíram do relatório.

## Os 3 achados corrigidos

Critério de escolha: o único **warning** do relatório, mais duas sugestões
ligadas a **autenticação** e **permissões de arquivo**, que são as mesmas
classes de problema tratadas na aplicação (OWASP A07 e A02).

### 1. PKGS-7392: pacotes com vulnerabilidade conhecida (warning)

| | |
|---|---|
| Achado | `Found one or more vulnerable packages`: `libc6`, `libc-bin`, `libc-gconv-modules-extra` e `locales` na versão `2.43-2ubuntu2.4` |
| Risco | A glibc é usada por praticamente todo processo do sistema. Uma CVE nela afeta tudo o que roda no host, inclusive o Docker |
| Correção | Aplicar as atualizações de segurança já publicadas (`2.43-2ubuntu2.7`, repositório `resolute-security`) |
| Comando | `sudo apt update && sudo apt upgrade -y` |
| Relação com o projeto | É a mesma decisão do `apt-get upgrade` no `Dockerfile`: aplicar as correções que já existem em vez de esperar a próxima imagem base |

### 2. AUTH-9328: umask padrão permissivo (022)

| | |
|---|---|
| Achado | `Default umask in /etc/login.defs could not be found and defaults usually to 022` |
| Risco | Com umask 022, todo arquivo novo é **legível por qualquer usuário** do sistema (`rw-r--r--`). Um `.env` ou uma chave criada sem cuidado fica exposta a outras contas e processos |
| Correção | `UMASK 027` no `/etc/login.defs`: arquivos novos saem `rw-r-----` e diretórios `rwxr-x---`, sem acesso para "outros" |
| Comando | `echo 'UMASK 027' \| sudo tee -a /etc/login.defs` |
| Relação com o projeto | O `.env` guarda a `TASKFLOW_SECRET_KEY` e as senhas do banco e do Grafana. Com 027 ele já nasce fechado para outros usuários |

### 3. AUTH-9286: senhas locais sem prazo de validade

| | |
|---|---|
| Achado | `Configure minimum/maximum password age in /etc/login.defs` (`PASS_MAX_DAYS 99999`, `PASS_MIN_DAYS 0`) |
| Risco | Uma senha local vazada continua válida para sempre. Com mínimo 0, quem descobre a senha pode trocá-la várias vezes seguidas e voltar à antiga, burlando o histórico |
| Correção | `PASS_MAX_DAYS 90` e `PASS_MIN_DAYS 1` |
| Comando | `sudo sed -i 's/^PASS_MAX_DAYS.*/PASS_MAX_DAYS\t90/; s/^PASS_MIN_DAYS.*/PASS_MIN_DAYS\t1/' /etc/login.defs` |
| Relação com o projeto | Mesma classe do incidente de força bruta (OWASP A07 Authentication Failures): limitar o tempo de vida de uma credencial reduz o estrago quando ela vaza |

O `login.defs` vale para **contas criadas depois** da mudança. Para aplicar
numa conta existente: `sudo chage -M 90 -m 1 <usuario>`.

## Achados conhecidos e não corrigidos (justificativa)

| Teste | Por que não foi corrigido |
|---|---|
| `KRNL-5788` (`/vmlinuz` ausente), `BOOT-5180`, `BOOT-5264` | No WSL2 o kernel e o boot são do Windows, não do Ubuntu. Não se aplicam |
| `FILE-6310` (`/home` e `/var` em partições separadas) | O disco do WSL2 é um único VHDX. Faz sentido num servidor, não na estação |
| `USB-1000`, `NETW-3200` (protocolos `dccp`, `sctp` etc.) | Controlados pelo kernel do WSL2, fora do alcance do Ubuntu convidado |
| `DEB-0880` (fail2ban) | O host não expõe SSH nem outro serviço de login. A proteção contra força bruta que importa aqui é na aplicação (ver `runbook-forca-bruta.md`) |
| `HRDN-7230` (antimalware), `FINT-4350` (integridade de arquivos), `ACCT-9628` (auditd) | Relevantes para um servidor de produção. Ficam como próximos passos |

## Como reproduzir

```bash
sudo apt install -y lynis
sudo lynis audit system --quick | tee lynis-saida.txt
sudo grep -E '^(hardening_index|warning\[\]|suggestion\[\])=' /var/log/lynis-report.dat
```

As saídas completas do Lynis não foram versionadas, porque descrevem o host
de um integrante: pacotes instalados, contas e configuração de rede.
