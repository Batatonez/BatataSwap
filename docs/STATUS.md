# STATUS — onde paramos

Arquivo de passagem entre sessões e contas. O orquestrador atualiza depois de cada tarefa.
Numa sessão nova (qualquer conta): branch `claude/gallant-ride-wi4aea`, leia `CLAUDE.md`, este arquivo, `docs/ARQUITETURA.md` e `docs/DELEGATION_LOG.md`.

Última atualização: 2026-10-17

## Pronto

- T10: ferramentas MCP + app.py (painel plugado), revisado e corrigido. 670 testes.
- T14 com o Davi: instalado (fb1d8ac), `public_origin` configurado, key-init feito (**a chave mestra apareceu no chat; o Davi recusou gerar outra — risco aceito por ele**), init feito (senha + TOTP), `batataswap.service` ativo e `/saude` ok localmente. Próximo: atualizar pro SHA 768645325810610f89aa2478fab2e88c0fe1dbbb e ensaio T13b (Funnel temporário, só conta-1). T16 (revisão nível 4) iniciada sobre esse SHA.
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
- T07: **pronta** (revisada; correções aplicadas). Pra T10: borda é o middleware mais externo; chamar `RoutePolicy.default().check_against(app.routes)` na montagem; `/mcp` como `Route` (Mount é recusado); desligar `/docs` e `/openapi.json`; uvicorn com `server_header=False`, `proxy_headers=False`, `forwarded_allow_ips=""`.
- T08: **pronta** (revisada pelo gpt-6-astra; correções aplicadas; migração 0002 com scope por token). Conferir na T13b, com navegador real, que o login funciona (Origin com meta referrer same-origin).
- T03: **concluída**. Medições em ARQUITETURA §1.0 (protocolo 2026-07-28 no MCP, 2025-11-25 na descoberta, sem Origin, client_id `https://claude.ai/oauth/mcp-oauth-client-metadata`). Funnel **desligado** e spike parado (conferido de fora em 2026-10-17); conectores de teste removidos. Pasta `spike/` apagada na T16.
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

- **Decisões do Davi pedidas pela T16:** (I10) recriar chave mestra, senha e TOTP depois do ensaio (a chave apareceu no chat) — recomendado; (I8) aceitar por escrito o risco residual de preferência envenenada por injeção; (I9) aceitar ou não ligar o painel da Vercel (`vercel_origin`) sabendo do risco de phishing.

- **T16: gpt-6-astra deu 'não expor'** (6 importantes, ver DELEGATION_LOG). Funnel só para o ensaio T13b; desligar depois até as correções + 2ª passada. Correções das duas partes aplicadas (722 testes). 2ª passada (astra + opus) em andamento. Pendência: pior caso de escape com caracteres de controle no limite de resposta (fator 4 assume só `\\`).

- T14: correções aplicadas (init em 2 etapas, lock de build com hash, wrapper com sandbox, deploy por SHA, alertas). Pra T16: `_check_key_file` no caso root/ACL aceita bit de escrita no grupo — endurecer pra aceitar só até 0440; `requirements-build.lock` gerado offline (conferir hashes contra o PyPI na T16). **Contrato da CLI pra T12**: serve, key-init [--substituir] (root direto), key-import (root direto), init (wrapper, pty), migrate, key-export (pty), backup, restore <arq em /var/backups>, restore-test, export --out - (stdout), wipe [--incluir-backups] (pty), grants, revoke <rótulo>, unlock, cleanup. Deploy instala por SHA, não por branch. T14 precisa de 2ª revisão depois da T12.

- Teste comportamental do JS do painel (PKCE, callback, expiração, demo sem rede) — sugestão da revisão; fazer junto com a T11.

- ~~Repo público × código do BatataLink~~ resolvido: o Davi tirou o BatataLink do projeto. Código todo próprio; repo segue público.

- Aprovação do plano pelo Davi.
