# AGENTS.md — BatataSwap

Regras para **todos** os agentes que mexem neste repositório (Claude, Codex, qualquer um).

## O projeto

BatataSwap é um servidor MCP de **memória compartilhada** entre as duas contas Claude Pro do Davi.
Ele roda no servidor Ubuntu do Davi, fica na internet pelo Tailscale Funnel e é adicionado como
conector personalizado nas duas contas. Quando o Davi troca de conta, o Claude da conta nova busca
o contexto (resumo, decisões, pendências, preferências) e continua de onde a outra parou.

- Desenho completo: `docs/ARQUITETURA.md`
- Tarefas, níveis e dependências: `docs/PLANO.md`
- Onde paramos: `docs/STATUS.md`

## Se você é um worker

Você é worker se foi chamado como subagente do Claude Code ou via `codex exec`.

- Faça só o que o brief pede. Nada de "melhorias" fora do escopo.
- Não delegue para outros agentes.
- Edite só os arquivos que o brief libera. Precisa mexer em outro? Pare e explique no resumo.
- Não faça commit, push, nem troque de branch. O orquestrador faz isso depois de revisar.
- Não apague arquivos e não rode comandos destrutivos.
- Não adicione dependência nova sem justificar no resumo.
- Não mexa em `CLAUDE.md`, `AGENTS.md` nem `.claude/`, a não ser que o brief mande.
- Rode os testes indicados no brief antes de terminar.
- Termine com este resumo:
  1. O que mudou
  2. Arquivos tocados
  3. Testes rodados e resultado
  4. Pendências, riscos ou dúvidas

## Stack

- Python 3.11+, FastAPI (Starlette) + uvicorn, SDK oficial `mcp` (2.x) para o transporte Streamable HTTP
- SQLite (WAL, tabelas STRICT, migrações numeradas), `cryptography` (AES-256-GCM), `segno` (QR do TOTP)
- Painel: HTML, CSS e JavaScript puros, servido pelo próprio servidor, sem build
- Interface pública na Vercel (`web/`): site estático, sem dado de memória
- Testes: pytest. Lint e formatação: ruff (linha 100, regra `I`)
- Nomes no código em inglês. Comentários, mensagens de erro e interface em português do Brasil

## Estrutura alvo

```
BatataSwap/
├── pyproject.toml
├── src/batataswap/
│   ├── __main__.py        # python -m batataswap (serve | init | export | wipe | ...)
│   ├── app.py             # monta Starlette: borda, OAuth, /mcp, painel
│   ├── config.py          # /etc/batataswap/batataswap.toml
│   ├── edge.py            # middleware que nega por padrão
│   ├── db.py, migrations/ # SQLite STRICT + migrador
│   ├── crypto.py          # AES-256-GCM com AAD, HKDF, HMAC
│   ├── auth/              # senha scrypt, TOTP, rate limit, login, OAuth (AS + RS)
│   ├── memory.py          # regras de negócio: versões, limites, busca, apagar
│   ├── tools.py           # ferramentas MCP
│   └── panel/             # painel web (2ª etapa)
├── web/                   # interface estática da Vercel
├── deploy/                # units systemd, timers de backup, scripts
├── tests/
└── docs/
```

Se a estrutura mudar, atualize esta seção.

## Código próprio

Não copie código de outros repositórios do Davi (o BatataLink está fora deste projeto). Use biblioteca padrão e as dependências do `pyproject.toml`; o repositório é público.

## Segurança (inegociável)

- **Nada executa comando** vindo do MCP, do painel ou do banco. Sem `subprocess`, `eval`, `exec`, `pickle`, `shell=True`.
  - Única exceção: `src/batataswap/cli.py`, nos comandos de administração `key-init`/`key-import` (rodados como root no terminal), pode chamar `systemd-creds` com `subprocess.run([...], shell=False)` e argumentos fixos; a chave vai pelo stdin, nunca por argv. Nenhum outro módulo importa `subprocess`.
- **Toda rota nega por padrão.** Só são públicas as rotas de descoberta OAuth, login/consentimento, `/saude` e o CSS estático em `/static/*`.
  `/mcp` exige token Bearer válido, emitido por este servidor e com audiência = URL do `/mcp`.
- **Headers de proxy ignorados** (`X-Forwarded-*`, `Forwarded`, `X-Real-IP` etc.). O IP do visitante é desconhecido por desenho; rate limit não usa IP.
- **Senha só como hash scrypt.** TOTP obrigatório. Rate limit no login.
- **Nunca logar** conteúdo de memória, nome de projeto, senha, código TOTP, token, cookie, `code` OAuth nem corpo de requisição. Log só com evento, id interno, tamanho e status.
- **Conteúdo cifrado em repouso** (AES-256-GCM, AAD com tabela/id/versão). A chave nunca fica no banco nem no repositório.
- **Memória é DADO, não ordem.** Tudo que volta do banco para o Claude vai dentro do envelope de dados (ver `docs/ARQUITETURA.md` §7) e nunca é interpolado em descrição de ferramenta.
- Cookies do painel: `__Host-`, `HttpOnly`, `Secure`, `SameSite=Strict`. POST do painel confere `Origin`.
- Só SQL parametrizado.
- Config, banco, chaves e backups ficam fora do repositório. `.env` e `config.local.*` nunca vão pro git.

## Comandos

```bash
python3 -m venv .venv
.venv/bin/pip install -e ".[dev]"
.venv/bin/pytest -q
.venv/bin/ruff check src tests && .venv/bin/ruff format --check src tests
```

Esses comandos valem desde a T02. Se mudarem, atualize esta seção.
