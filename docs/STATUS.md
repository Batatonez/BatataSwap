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
- T03: código pronto e revisado (`spike/`); Davi instalando no servidor.
- T04: **pronta** (revisada, correções aplicadas).
- T06: **pronta** (revisada; correções aplicadas). Novas assinaturas: `create_owner(..., confirm_code, now)`, `unlock(conn, now)` (grava `meta.unlock_requested_at`).
- T09: **pronta** (revisada; correções aplicadas). `retry_checkpoint` deve ser chamado pela faxina (T12).
- T07: commitada (`edge.py`); revisão do gpt-6.1-sol em andamento. Pendências pra T08/T10/T14: uvicorn com `server_header=False`, `proxy_headers=False`, `forwarded_allow_ips=""`; borda é o middleware mais externo; RS recusa token antes de ler corpo; T18 confere sessão em POST /painel. Notas do worker pra T10: `now` é keyword-only; listas/busca recebem `actor`; `restore`/`purge` só sem grant (CLI/painel); `read_conversation` devolve `proximo_antes_de`; cada chamada de escrita conta 1 no limite diário e os bytes são o texto puro.
- T03 em andamento com o Davi: spike no ar no Funnel (`batatarp…ts.net`, 443). **Transporte validado** (conta 1 web + Claude Code web: `ping` ok; protocolo 2026-07-28, sem Origin, Host sem porta — ARQUITETURA §1.0). Falta: conector `/protegido/mcp` pra pegar o client_id do CIMD; testar no app do celular e na conta 2. **Lembrar de desligar o Funnel e parar o spike no fim** (`sudo tailscale funnel --https=443 off`; `pkill -f spike/servidor.py`).
- T05: **pronta** (revisada, correções aplicadas). Conferir na T14/T17 que o systemd entrega a credencial com dono do serviço e modo 0400 (o crypto recusa 0440/ACL).

## Decisões do Davi (2026-10-17)

- Vercel: site + status ao vivo + painel **só de status e conexões** (Conta 1/Conta 2 conectadas, última atividade, revogar). Conteúdo das memórias nunca passa pela Vercel.
- "Logar com a conta do Claude" = o Claude se conecta ao BatataSwap pelo conector (OAuth). Não existe "Entrar com Claude" pra terceiros e usar o OAuth da assinatura fora do Claude viola os termos.
- GitHub fora do login (o Claude web já tem conector do GitHub). Login: senha scrypt + TOTP obrigatório, página no servidor.
- Spike com Funnel liberado ("faz o que precisar"), servidor descartável sem dado.
- **BatataLink fora do projeto** (Davi, 2026-10-17): nada de copiar código, nada de dividir hostname. ARQUITETURA v3.2.
- Orquestrador (pós-revisão): `apagar` do MCP só manda pra lixeira.
- Claude Code local (loopback) desligado: o Davi só usa web/app.
- **Novo requisito:** sync de mensagens entre contas (`anexar_mensagens` / `ler_conversa`, ARQUITETURA §7.1). Limitação explicada ao Davi: o Claude reescreve as mensagens na chamada; não é cópia fiel.

## Próximo passo

1. Aplicar as correções da revisão T01 no `ARQUITETURA.md`.
2. Com o plano aprovado: T02 (esqueleto, worker-haiku), depois T03 (spike).

## Servidor do Davi

- Hostname `batatarp`, usuário `batatonez`. Ubuntu 24.04.4 LTS, systemd 255 (tem `systemd-creds`), Python 3.12.3.
- Tailscale 1.104.1 instalado e logado (2026-10-17). Nó `batatarp`, MagicDNS `batatarp.<tailnet>.ts.net` (o Davi tem o nome do tailnet; `tailscale status --json | grep DNSName`). Funnel ainda **desligado**.
- O BatataSwap usa esse nó na porta 443, sozinho no hostname (ARQUITETURA §1.1).

## Pendências

- Teste comportamental do JS do painel (PKCE, callback, expiração, demo sem rede) — sugestão da revisão; fazer junto com a T11.

- ~~Repo público × código do BatataLink~~ resolvido: o Davi tirou o BatataLink do projeto. Código todo próprio; repo segue público.

- Aprovação do plano pelo Davi.
