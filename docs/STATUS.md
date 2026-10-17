# STATUS — onde paramos

Arquivo de passagem entre sessões e contas. O orquestrador atualiza depois de cada tarefa.
Numa sessão nova (qualquer conta): branch `claude/gallant-ride-wi4aea`, leia `CLAUDE.md`, este arquivo, `docs/ARQUITETURA.md` e `docs/DELEGATION_LOG.md`.

Última atualização: 2026-10-17

## Pronto

- Codex logado; luna, sol e astra respondem.
- `docs/ARQUITETURA.md` v2 e `docs/PLANO.md` (T01–T18).
- CLAUDE.md / AGENTS.md / workers (`.claude/agents/`) com as regras de orquestrador.
- `docs/ARQUITETURA.md` v1 (pesquisa da doc oficial feita: Streamable HTTP + OAuth com PKCE e CIMD; Funnel atende na porta 8443).

## Em andamento

- T01: revisão da `ARQUITETURA.md` v2 pelo gpt-6-astra (brief em `.orchestrator/briefs/001-revisao-arquitetura.md`, que não vai pro git). Se a sessão cair, rodar de novo.
- Plano (`docs/PLANO.md`) apresentado ao Davi. **Esperando aprovação antes de construir.**

## Decisões do Davi (2026-10-17)

- Vercel: site + status ao vivo + painel **só de status e conexões** (Conta 1/Conta 2 conectadas, última atividade, revogar). Conteúdo das memórias nunca passa pela Vercel.
- "Logar com a conta do Claude" = o Claude se conecta ao BatataSwap pelo conector (OAuth). Não existe "Entrar com Claude" pra terceiros e usar o OAuth da assinatura fora do Claude viola os termos.
- GitHub fora do login (o Claude web já tem conector do GitHub). Login: senha scrypt + TOTP obrigatório, página no servidor.
- Spike com Funnel liberado ("faz o que precisar"), servidor descartável sem dado.
- Claude Code local (loopback) desligado: o Davi só usa web/app.
- **Novo requisito:** sync de mensagens entre contas (`anexar_mensagens` / `ler_conversa`, ARQUITETURA §7.1). Limitação explicada ao Davi: o Claude reescreve as mensagens na chamada; não é cópia fiel.

## Próximo passo

1. Aplicar as correções da revisão T01 no `ARQUITETURA.md`.
2. Com o plano aprovado: T02 (esqueleto, worker-haiku), depois T03 (spike).

## Servidor do Davi

- Hostname `batatarp`, usuário `batatonez`. Ubuntu 24.04.4 LTS, systemd 255 (tem `systemd-creds`), Python 3.12.3.
- Tailscale **não instalado** (2026-10-17). Passo 1 enviado: instalar e `tailscale up`.

## Pendências

- Aprovação do plano pelo Davi.
