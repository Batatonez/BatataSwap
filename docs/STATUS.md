# STATUS — onde paramos

Arquivo de passagem entre sessões e contas. O orquestrador atualiza depois de cada tarefa.
Numa sessão nova (qualquer conta): branch `claude/gallant-ride-wi4aea`, leia `CLAUDE.md`, este arquivo, `docs/ARQUITETURA.md` e `docs/DELEGATION_LOG.md`.

Última atualização: 2026-10-17

## Pronto

- T15: interface da Vercel em `web/` (modo demo; `API_ORIGIN_AQUI` em `config.js` e no CSP do `vercel.json` a trocar pela origem real). Revisada pelo gpt-6.1-sol, correções aplicadas.
- T02: esqueleto (`pyproject.toml`, `python -m batataswap --version`, CI, `requirements.lock` com hash, `NOTICE.md`).
- Codex logado; luna, sol e astra respondem.
- `docs/ARQUITETURA.md` v2 e `docs/PLANO.md` (T01–T18).
- CLAUDE.md / AGENTS.md / workers (`.claude/agents/`) com as regras de orquestrador.
- `docs/ARQUITETURA.md` v1 (pesquisa da doc oficial feita: Streamable HTTP + OAuth com PKCE e CIMD; Funnel atende na porta 8443).

## Em andamento

- Plano **aprovado** pelo Davi ("vai fazendo", 2026-10-17).
- T01: arquitetura **v3.1** (achados das duas passadas do gpt-6-astra aplicados, ver §16 e §16.1). Considero T01 concluída: nenhum crítico aberto, importantes todos endereçados no texto. A conferência final do desenho fica na revisão de nível 4 (T16).
- T03: código pronto e revisado (`spike/`); falta rodar no servidor com o Davi.
- T03 na prática depende do Davi: Tailscale instalado no `batatarp` e a 2ª instância (plano A).

## Decisões do Davi (2026-10-17)

- Vercel: site + status ao vivo + painel **só de status e conexões** (Conta 1/Conta 2 conectadas, última atividade, revogar). Conteúdo das memórias nunca passa pela Vercel.
- "Logar com a conta do Claude" = o Claude se conecta ao BatataSwap pelo conector (OAuth). Não existe "Entrar com Claude" pra terceiros e usar o OAuth da assinatura fora do Claude viola os termos.
- GitHub fora do login (o Claude web já tem conector do GitHub). Login: senha scrypt + TOTP obrigatório, página no servidor.
- Spike com Funnel liberado ("faz o que precisar"), servidor descartável sem dado.
- Orquestrador (pós-revisão): hostname próprio pro BatataSwap via 2ª instância do tailscaled (nó `batataswap`, plano A); 8443 no `batatarp` é plano B. `apagar` do MCP só manda pra lixeira.
- Claude Code local (loopback) desligado: o Davi só usa web/app.
- **Novo requisito:** sync de mensagens entre contas (`anexar_mensagens` / `ler_conversa`, ARQUITETURA §7.1). Limitação explicada ao Davi: o Claude reescreve as mensagens na chamada; não é cópia fiel.

## Próximo passo

1. Aplicar as correções da revisão T01 no `ARQUITETURA.md`.
2. Com o plano aprovado: T02 (esqueleto, worker-haiku), depois T03 (spike).

## Servidor do Davi

- Hostname `batatarp`, usuário `batatonez`. Ubuntu 24.04.4 LTS, systemd 255 (tem `systemd-creds`), Python 3.12.3.
- Tailscale **não instalado** (2026-10-17). Passo 1 enviado: instalar e `tailscale up`.

## Pendências

- Teste comportamental do JS do painel (PKCE, callback, expiração, demo sem rede) — sugestão da revisão; fazer junto com a T11.

- **BLOQUEIO (pergunta pro Davi):** o repo BatataSwap é **público** e o BatataLink é **privado**. Copiar código do BatataLink (db, secretbox, totp, ratelimit, middleware) pra cá publicaria esse código. Opções: (a) deixar o BatataSwap privado (Vercel Hobby funciona com repo privado; o servidor clona com deploy key só leitura); (b) aceitar publicar esses módulos; (c) reescrever sem copiar. T04–T07 esperando a resposta. T03 (spike) e T15 (Vercel) seguem, porque não copiam nada.

- Aprovação do plano pelo Davi.
