# Log de delegação

O orquestrador adiciona uma linha por tarefa. Serve para o Davi ver qual modelo fez o quê e quais funcionam melhor.

## Ambiente

| Item | Resultado |
|---|---|
| Codex instalado | ✅ codex-cli 0.163.0 (2026-10-17). Rede liberada para auth.openai.com, api.openai.com e chatgpt.com. Login `--device-auth` aguardando aprovação do Davi |
| `gpt-6-luna` | a testar |
| `gpt-6.1-sol` | a testar |
| `gpt-6-astra` | a testar |
| Fable | proibido (`availableModels` em `.claude/settings.json`) |

## Tarefas

| Data | Tarefa | Nível | Modelo | Resultado |
|---|---|---|---|---|
| 2026-10-17 | Pesquisa da doc atual (conectores claude.ai, spec MCP 2025-11-25 e 2026-07-28, Funnel, SDK mcp 2.x) | 3 | orquestrador (Opus 5.5) | ok |
| 2026-10-17 | CLAUDE.md, AGENTS.md, workers, docs/ARQUITETURA.md v1 | 3 | orquestrador (Opus 5.5) | ok; falta revisão do gpt-6-astra (quem escreve não revisa) |
