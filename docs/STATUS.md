# STATUS — onde paramos

Arquivo de passagem entre sessões e contas. O orquestrador atualiza depois de cada tarefa.
Numa sessão nova (qualquer conta): branch `claude/gallant-ride-wi4aea`, leia `CLAUDE.md`, este arquivo, `docs/ARQUITETURA.md` e `docs/DELEGATION_LOG.md`.

Última atualização: 2026-10-17

## Pronto

- CLAUDE.md / AGENTS.md / workers (`.claude/agents/`) com as regras de orquestrador.
- `docs/ARQUITETURA.md` v1 (pesquisa da doc oficial feita: Streamable HTTP + OAuth com PKCE e CIMD; Funnel atende na porta 8443).

## Em andamento

- Login do Codex (`codex login --device-auth`) esperando o Davi aprovar. Numa sessão nova, refazer.
- `docs/PLANO.md` (tarefas T01…) ainda não escrito.

## Decisões do Davi (2026-10-17)

- Vercel: site + status ao vivo + painel **só de status e conexões** (Conta 1/Conta 2 conectadas, última atividade, revogar). Conteúdo das memórias nunca passa pela Vercel.
- "Logar com a conta do Claude" = o Claude se conecta ao BatataSwap pelo conector (OAuth). Não existe "Entrar com Claude" pra terceiros e usar o OAuth da assinatura fora do Claude viola os termos.
- GitHub fora do login (o Claude web já tem conector do GitHub). Login: senha scrypt + TOTP obrigatório, página no servidor.
- Spike com Funnel liberado ("faz o que precisar"), servidor descartável sem dado.
- Claude Code local (loopback) desligado: o Davi só usa web/app.
- **Novo requisito:** sync de mensagens entre contas. Ferramentas `anexar_mensagens(conversa, mensagens)` e `ler_conversa(conversa)`, formato `Claude 1: … / Usuário: … / Claude 2: …`. Limitação explicada ao Davi: o Claude reescreve as mensagens na chamada; não é cópia fiel. Falta pôr na ARQUITETURA.md.

## Próximo passo

1. Testar luna/sol/astra no Codex.
2. Atualizar ARQUITETURA.md (sync de mensagens, painel Vercel com login PKCE, GitHub fora) e escrever `docs/PLANO.md`.
3. Apresentar o plano e esperar aprovação do Davi.

## Pendências

- Versão do Ubuntu do Davi (comando pedido: `lsb_release -ds; systemctl --version | head -1; python3 --version; tailscale version | head -1`).
