# BatataSwap — Plano de tarefas

Ordem de construção. Nível e modelos seguem a tabela do `CLAUDE.md`. "Revisão" é sempre de outra família (quem escreve não revisa).
Status de cada tarefa: `docs/STATUS.md`. Desenho: `docs/ARQUITETURA.md` (§ citados abaixo).

| ID | Tarefa | Nível | Escreve | Revisa | Arquivos | Critério de aceite | Depende de |
|---|---|---|---|---|---|---|---|
| T01 | Revisão da arquitetura | 4 | — | gpt-6-astra | `docs/ARQUITETURA.md` (só leitura) | Nenhum crítico/importante aberto; correções aplicadas no doc | — |
| T02 | Esqueleto do projeto | 1 | worker-haiku | orquestrador | `pyproject.toml`, `src/batataswap/__init__.py`, `__main__.py`, `tests/`, `NOTICE.md`, `requirements.lock`, `.github/workflows/ci.yml` | `pip install -e ".[dev]"`, `pytest` e `ruff` passam; CI verde | T01 |
| T03 | Spike de compatibilidade (descartável) | 2 | worker-sonnet | orquestrador | `spike/` (apagado depois) | Nas 2 contas, web e app: conector conecta na porta 8443 e chama `ping`; log registra `client_id` do CIMD, `Origin`, `Host` e versão do protocolo. Nenhum dado real | T02 |
| T04 | Config, banco, migrador e esquema `0001` | 3 | gpt-6.1-sol | worker-opus | `config.py`, `db.py`, `migrations/0001_inicial.sql` | Esquema do §5; pastas 0700; WAL/STRICT/`secure_delete`; testes de migração | T02 |
| T05 | Cripto (`crypto.py`) | 3 | worker-opus | gpt-6.1-sol | `crypto.py`, testes | Envelope + AAD + HKDF do §6; chave de `$CREDENTIALS_DIRECTORY` ou arquivo 0400; trocar AAD falha | T02 |
| T06 | Senha, TOTP, rate limit, vaga de scrypt, `init` | 3 | gpt-6.1-sol | worker-opus | `auth/passwords.py`, `auth/totp.py`, `auth/ratelimit.py`, `auth/scryptslots.py`, `auth/data/` | §9; código copiado com cabeçalho de origem; anti-replay do TOTP; trancamento e `unlock` testados | T04, T05 |
| T07 | Borda HTTP (`edge.py`) | 3 | worker-opus | gpt-6.1-sol | `edge.py`, testes | §8 com os valores reais do spike; headers de proxy somem; Host/Origin/corpo testados | T02, T03 |
| T08 | OAuth (AS + RS) | 3 | worker-opus | gpt-6-astra | `auth/oauth.py`, `auth/cimd.py`, `auth/pages/` (login, consentimento) | §3, §4: PRM, metadata, authorize com login senha + TOTP, consentimento com rótulo, token, refresh rotativo com reuso, revoke, CIMD em lista fechada, client `painel-vercel` com CORS | T03, T06, T07 |
| T09 | Núcleo da memória | 2 | worker-sonnet | gpt-6.1-sol | `memory.py`, `conversations.py`, testes | §5, §7, §7.1: versões, busca, preferências, conversas, apagar em 2 passos, limites diários | T04, T05 |
| T10 | Ferramentas MCP + envelope DADO | 3 | gpt-6.1-sol | worker-opus | `tools.py`, `app.py` | 8 ferramentas do §7 com descrições fixas e anotações; `/mcp` stateless com Bearer; envelope com nonce; teste com texto malicioso que tenta fechar o bloco | T08, T09 |
| T11 | API do painel e `/saude` | 2 | worker-sonnet | gpt-6-luna | `panel_api.py`, testes | §12: conexões, atividade, revogar com TOTP; zero conteúdo; CORS exato | T08 |
| T12 | CLI e logs seguros | 2 | gpt-6-luna | worker-sonnet | `cli.py`, `logging.py`, testes | Comandos do §6, §7, §11; teste que procura valores marcados nos logs | T09, T10 |
| T13 | Testes ponta a ponta | 2 | worker-sonnet | gpt-6.1-sol | `tests/e2e/` | Cliente MCP do SDK faz OAuth completo e usa todas as ferramentas; testes negativos (sem token, token de outra audiência, refresh reusado, Host/Origin errados) | T10, T11, T12 |
| T14 | Deploy no Ubuntu | 3 | worker-opus | gpt-6.1-sol | `deploy/`, `docs/DEPLOY.md` | §10, §11: units e timers com hardening, credencial, Funnel 8443, backup e teste de restauração; passo a passo pro Davi | T12 e versão do Ubuntu |
| T15 | Interface na Vercel | 2 | worker-sonnet | gpt-6.1-sol | `web/`, `vercel.json` | §12: página, status, painel de conexões com PKCE e token só em memória; CSP rígida; visual sem cara de IA | começa depois de T02 com API simulada; integra depois de T11 |
| T16 | Revisão de segurança antes do Funnel | 4 | — | worker-opus + gpt-6-astra | tudo (só leitura) | **Nenhum crítico ou importante aberto** | T01–T15 |
| T17 | Ligar o Funnel e validar de verdade | 3 | Davi executa | worker-opus acompanha | checklist em `docs/DEPLOY.md` | 2 contas × web + app + celular; headers forjados ignorados; sem token = 401; login errado tranca; reboot e `kill -9` voltam sozinhos; backup restaurado de verdade | T14, T16 |
| T18 | Painel de memórias no servidor (opcional) | 2–3 | worker-sonnet | gpt-6.1-sol, depois revisão nível 4 | `panel/` | Ver, editar (nova versão) e apagar memórias; cookie `__Host-`, `SameSite=Strict`; só `textContent` | T17 |

**Primeiro marco utilizável:** T01–T17, com memória + sync de mensagens funcionando nas duas contas.

Paralelismo possível: T04 ∥ T05; T09 ∥ T07; T15 roda em paralelo com quase tudo; T11 ∥ T10.

## Quem faz o quê

**Davi:**
- Rodar os comandos no Ubuntu, um passo por vez (o orquestrador manda cada um e espera o resultado).
- Ligar e desligar o Funnel quando pedido (spike T03 e T17).
- Adicionar o conector nas duas contas (Personalizar → Conectores) e fazer o login com senha + TOTP.
- Ter um app autenticador no celular e guardar a chave mestra e a senha no gerenciador de senhas.
- Criar o projeto na Vercel ligado a este repositório (Root Directory = `web`).
- Colar a frase do §12 nas preferências pessoais de cada conta Claude.
- Aprovar decisões irreversíveis.

**Orquestrador:** escrever os briefs, delegar, revisar diff e testes, fazer commit e push, manter `STATUS.md` e `DELEGATION_LOG.md`, preparar os comandos do Ubuntu.
