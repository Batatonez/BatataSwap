# Log de delegação

O orquestrador adiciona uma linha por tarefa. Serve para o Davi ver qual modelo fez o quê e quais funcionam melhor.

## Ambiente

| Item | Resultado |
|---|---|
| Codex instalado | ✅ codex-cli 0.163.0 (2026-10-17). Rede liberada para auth.openai.com, api.openai.com e chatgpt.com. Login `--device-auth` (ChatGPT) ok. Vale só para este container: numa sessão nova, repetir |
| `gpt-6-luna` | ✅ respondeu OK (2026-10-17) |
| `gpt-6.1-sol` | ✅ respondeu OK (2026-10-17) |
| `gpt-6-astra` | ✅ respondeu OK (2026-10-17) |
| Fable | proibido (`availableModels` em `.claude/settings.json`) |

## Tarefas

| Data | Tarefa | Nível | Modelo | Resultado |
|---|---|---|---|---|
| 2026-10-17 | Pesquisa da doc atual (conectores claude.ai, spec MCP 2025-11-25 e 2026-07-28, Funnel, SDK mcp 2.x) | 3 | orquestrador (Opus 5.5) | ok |
| 2026-10-17 | CLAUDE.md, AGENTS.md, workers, docs/ARQUITETURA.md v1 | 3 | orquestrador (Opus 5.5) | ok; falta revisão do gpt-6-astra (quem escreve não revisa) |
| 2026-10-17 | ARQUITETURA.md v2 (sync de mensagens, painel Vercel, decisões do Davi) e PLANO.md | 3 | orquestrador (Opus 5.5) | ok |
| 2026-10-17 | T01 Revisão da arquitetura v2 | 4 | gpt-6-astra (Codex) | ok: aprovar com correções (2 críticos, 13 importantes, 3 sugestões), achados excelentes |
| 2026-10-17 | ARQUITETURA.md v3 aplicando os 18 achados | 3 | orquestrador (Opus 5.5) | ok |
| 2026-10-17 | T01 2ª passada (v3) | 4 | gpt-6-astra (Codex) | ok: críticos resolvidos; 8 importantes + 3 sugestões novos (reproduziu bug de NOT NULL no SQLite) |
| 2026-10-17 | ARQUITETURA.md v3.1 aplicando I1–I8, S1–S3; PLANO com T13b | 3 | orquestrador (Opus 5.5) | ok |
| 2026-10-17 | T02 Esqueleto (pyproject, CI, lock com hash, NOTICE) | 1 | worker-haiku | ok de primeira; revisado pelo orquestrador |
| 2026-10-17 | T03 Spike (código) | 2 | gpt-6.1-sol (Codex) | ok de primeira: 16 testes; revisado pelo orquestrador; revisão cruzada com o T15 |
| 2026-10-17 | T15 Interface Vercel (modo demo) | 2 | worker-sonnet | ok; 1 ajuste de ruff |
| 2026-10-17 | Revisão cruzada T03 + T15 | 3 | gpt-6.1-sol (Codex) | aprovar com correções: 0 críticos, 2 importantes (CSP com curinga; spike sem prazo de leitura), 3 sugestões |
| 2026-10-17 | Correções da revisão (web / spike) | 2 | worker-sonnet / gpt-6.1-sol | ok; teste comportamental de JS (sugestão 3) fica pendente |
| 2026-10-17 | T04 Config, banco, migrador, esquema 0001 | 3 | gpt-6.1-sol (Codex) | ok |
| 2026-10-17 | Revisão T04 | 3 | worker-opus | aprovar com correções: 0 crítico, 3 importantes (origem canônica, dono dos arquivos, testes), 15 sugestões |
| 2026-10-17 | Correções T04 (todas as sugestões aceitas) | 3 | gpt-6.1-sol (Codex) | ok (199 testes no total) |
| 2026-10-17 | T05 Cripto | 3 | worker-opus | ok (66 testes) |
| 2026-10-17 | Revisão T05 | 3 | gpt-6.1-sol (Codex) | aprovar com correções: 0 crítico, 1 importante (FIFO trava abertura da chave), 4 sugestões |
| 2026-10-17 | Correções T05 | 3 | worker-opus | ok (78 testes) |
| 2026-10-17 | T06 Senha, TOTP, rate limit, dono | 3 | gpt-6.1-sol (Codex) | ok (vetores RFC 6238, TOTP atômico) |
| 2026-10-17 | Revisão T06 | 3 | worker-opus | aprovar com correções: 0 crítico, 5 importantes (unlock entre processos, corrida no TOTP-only, init sem confirmar TOTP, penalidade eterna, lista fraca), 7 sugestões |
| 2026-10-17 | Correções T06 (12 itens) | 3 | gpt-6.1-sol (Codex) | ok (51 testes da T06) |
| 2026-10-17 | T09 Núcleo da memória e conversas | 2 | worker-sonnet | ok (48 testes) |
| 2026-10-17 | Revisão T09 | 3 | gpt-6.1-sol (Codex) | 0 crítico, 4 importantes (checkpoint silencioso, teto do banco, export sem snapshot, origem no export), 2 sugestões |
| 2026-10-17 | Correções T09 | 2 | worker-sonnet | ok (todas; testes concorrentes reais) |
| 2026-10-17 | T07 Borda HTTP | 3 | worker-opus | ok (105 testes) |
| 2026-10-17 | Revisão T07 | 3 | gpt-6.1-sol (Codex) | 0 crítico, 2 importantes (overflow e exceção com resposta em streaming), 2 sugestões |
| 2026-10-17 | Correções T07 | 3 | worker-opus | ok (127 testes; check_against pra T10) |
| 2026-10-17/18 | T08 OAuth AS+RS, CIMD, páginas | 3 | worker-opus | ok (591 testes no total); parou 1× no limite de uso da conta e foi retomado |
| 2026-10-18 | Revisão T08 | 4 | gpt-6-astra (Codex) | 0 crítico, 2 importantes (reuso de código revogava antes de validar PKCE; CIMD sem deadline global), 2 sugestões |
| 2026-10-18 | Correções T08 (I1, I2, S3 com migração 0002, S4 parcial) | 3 | worker-opus | ok (634 testes); teste de navegador real do Origin fica pra T13b |
| 2026-10-17 | T03 Spike no servidor real | 2 | Davi + orquestrador | ok: transporte (web + Claude Code web) e descoberta OAuth até o authorize; client_id medido |
| 2026-10-17 | T14 Deploy (units, timers, admin, instalar/atualizar, DEPLOY.md) | 3 | gpt-6.1-sol (Codex) | estrutura ok (12 testes, systemd-analyze verify) |
| 2026-10-17 | Revisão T14 | 3 | worker-opus | **2 críticos** (init deixava banco com dono root; build sem hash como root), 7 importantes; precisa 2ª revisão depois da T12 |
| 2026-10-17 | Correções T14 (C1, C2, I1–I7, sugestões) | 3 | gpt-6.1-sol (Codex) | ok (99 testes deploy+cripto) |
| 2026-10-18 | T11 API do painel | 2 | worker-sonnet | ok (23 testes, contrato do web/painel.js) |
| 2026-10-18 | Revisão T11 | 2 | gpt-6-luna (Codex) | 0 crítico, 1 importante (ultima_escrita contava lixeira); corrigido pelo worker-sonnet |
| 2026-10-18 | T10 Ferramentas MCP + app | 3 | gpt-6.1-sol (Codex) | ok (suíte passa; só 12 testes próprios — cobertura fina) |
| 2026-10-18 | Revisão T10 | 3 | worker-opus | 0 crítico, 5 importantes (marcador do envelope forjável via U+2028; anotações faltando; painel não plugado; doc; tools/call moderno sem teste), 7 sugestões |
| 2026-10-18 | Correções T10 (envelope à prova de U+2028, anotações, painel plugado, DNS rebinding, testes) | 3 | gpt-6.1-sol (Codex) + worker-haiku (1 teste) | ok (670 testes) |
| 2026-10-18 | Redesign da interface web (creme, serifada, selo) | 2 | worker-sonnet | ok (pedido do Davi: visual anterior 'muito feio') |
| 2026-10-18 | T12 CLI, backup/restore, logs JSON | 3 | gpt-6.1-sol (Codex) | ok (641 testes rodados pelo orquestrador; o sandbox do Codex trava em cliente HTTP); |
| 2026-10-18 | Revisão T12 | 3 | worker-opus | 0 crítico, 9 importantes (WAL órfão no restore, erros escondidos, init desiste no 1º TOTP, export em disco, wipe incompleto, eventos de segurança fora do journal, testes), 9 sugestões |
| 2026-10-18 | Correções T12 | 3 | gpt-6.1-sol (Codex) + worker-haiku (actor no log, evento limite) | ok (694 testes) |
| 2026-10-18 | T16 Revisão nível 4 (parte OpenAI) | 4 | gpt-6-astra (Codex) | **não expor**: 0 crítico, 6 importantes (DoS por corpo incompleto, cotas operacionais, bloqueio do authorize, lixeira sem restauração, lote em texto puro, limite de resposta), 3 sugestões; correções com gpt-6.1-sol; parte Claude (worker-opus) em andamento |
| 2026-10-18 | Correções T16 (parte astra): prazos de corpo, cotas/retenção, orçamento por aparelho, lixeira na CLI, HMAC do lote, tamanho real da resposta, migração 0003 | 3 | gpt-6.1-sol (Codex) + worker-haiku (teto 140k) | ok (710 testes) |
| 2026-10-18 | T16 Revisão nível 4 (parte Claude) | 4 | worker-opus | aprovar com correções: 0 crítico, 10 importantes (DoS ainda aberto, bloqueio do authorize, refresh sem tolerância, lixeira, cotas, resposta, lote, envenenamento de preferências, phishing via Vercel, chave vazada), 10 sugestões; hashes dos locks conferidos no PyPI (todos batem); correções com gpt-6.1-sol |
| 2026-10-18 | Correções T16 (parte Claude): Bearer antes do corpo, semáforo sem credencial, h11, authorize, janela de refresh, CLI preferencias/expurgar, avisos anti-phishing, spike apagado, migração 0004 | 3 | gpt-6.1-sol (Codex) + worker-sonnet (3 testes desatualizados) | ok (722 testes) |
| 2026-10-18 | Bug em produção: serviço não subia (TOML antigo com tool_response_chars=100000; erro de config escondido) → ConfigError visível + `check-config` no atualizar.sh | 1 | worker-haiku | ok (726 testes); Davi corrigiu o TOML no servidor |
| 2026-10-18 | T16 2ª passada (OpenAI) | 4 | gpt-6-astra (Codex) | não expor: 0 crítico, 3 importantes residuais (pool anônimo bloqueia OAuth; audit em replay de refresh revogado; contexto gravável mas ilegível); correções com gpt-6.1-sol |
| 2026-10-18 | T16 2ª passada (Claude) | 4 | worker-opus | aprovar com correções: 0 crítico; confidencialidade/integridade ok para Funnel permanente; 3 importantes novos (N1 pool anônimo trava refresh; N2 Bearer lixo caro; N3 CLI imprime controle de terminal vindo de preferência), 6 sugestões; fila: brief 026 depois do 025 |
| 2026-10-18 | Correções dos residuais (pools anônimos, refresh revogado sem escrita, tamanho validado na gravação) | 3 | gpt-6.1-sol (Codex) + worker-sonnet (2 testes desatualizados) | ok (729 testes) |
