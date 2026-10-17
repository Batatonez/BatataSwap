# Spike descartável do BatataSwap (T03)

Servidor sem dados, banco, arquivos persistidos ou tokens emitidos. Serve apenas para observar
como o Claude acessa um MCP remoto. **É descartável**: use por poucos minutos e desligue o
Funnel ao terminar. A rota MCP aberta e a proteção de DNS rebinding desligada são exclusivas
deste experimento; não use este servidor em produção.

## Rodar localmente

Na raiz do repositório, com Python 3.12:

```bash
python3.12 -m venv spike/.venv
. spike/.venv/bin/activate
pip install -r spike/requirements.txt pytest httpx
SPIKE_PUBLIC_ORIGIN=https://batataswap.tail1234.ts.net python spike/servidor.py
```

Substitua a origem pelo hostname HTTPS real, sem caminho nem barra final. Ela é obrigatória e
não vem do header Host. `SPIKE_PORT` é opcional (padrão `8780`); o bind é sempre `127.0.0.1`.
Headers de proxy são ignorados. O servidor não configura nem liga o Funnel.

O SDK 2.2 usa `mcp.server.mcpserver.MCPServer`; `stateless_http`, `json_response` e
`transport_security` são argumentos de `streamable_http_app()`, não do construtor.

## Testar com curl

Com o processo rodando em outro terminal:

```bash
curl -i http://127.0.0.1:8780/aberto/mcp \
  -H 'Content-Type: application/json' \
  -H 'Accept: application/json, text/event-stream' \
  -d '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-11-25","capabilities":{},"clientInfo":{"name":"curl-spike","version":"1"}}}'

curl -i http://127.0.0.1:8780/aberto/mcp \
  -H 'Content-Type: application/json' \
  -H 'Accept: application/json, text/event-stream' \
  -H 'MCP-Protocol-Version: 2025-11-25' \
  -d '{"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}'

curl -i http://127.0.0.1:8780/aberto/mcp \
  -H 'Content-Type: application/json' \
  -H 'Accept: application/json, text/event-stream' \
  -H 'MCP-Protocol-Version: 2025-11-25' \
  -d '{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"ping","arguments":{}}}'

curl -i http://127.0.0.1:8780/protegido/mcp
curl -i http://127.0.0.1:8780/.well-known/oauth-protected-resource/protegido/mcp
curl -i http://127.0.0.1:8780/.well-known/oauth-authorization-server
curl -i 'http://127.0.0.1:8780/oauth/authorize?client_id=teste&state=nao-logar&code_challenge=nao-logar'
curl -i -X POST http://127.0.0.1:8780/oauth/token
```

Use a versão negociada no `initialize` nos pedidos seguintes. O modo é stateless e não exige
ID de sessão. Os resultados esperados são: `pong <UTC ISO>`, 401 com `resource_metadata`,
metadados JSON, HTML 200 sem redirect e `invalid_grant` 400, respectivamente.

Para os testes automatizados:

```bash
SPIKE_PUBLIC_ORIGIN=https://exemplo.ts.net python -m pytest -q spike/test_spike.py
```

## Observar o Claude pelo Funnel

Teste primeiro o plano A: nó separado `batataswap`, segunda instância userspace do
`tailscaled`, Funnel 443 apontando para `127.0.0.1:8780`. Se não funcionar, registre a falha
antes de testar o plano B (hostname existente, porta pública 8443). Ajuste
`SPIKE_PUBLIC_ORIGIN` à origem usada, incluindo `:8443` no plano B.

Em cada uma das duas contas, na web e no app, adicione primeiro
`<origem>/aberto/mcp`, liste as ferramentas e peça `ping`. Depois adicione
`<origem>/protegido/mcp`: o fluxo deve descobrir OAuth e abrir a página que informa que a
autorização está desativada. Nenhum login ou consentimento real acontece.

O stdout contém uma linha JSON com prefixo `SPIKE ` por requisição: headers selecionados,
status e método JSON-RPC. O `initialize` inclui a versão e `clientInfo`; o authorize inclui
o `client_id` CIMD e os parâmetros permitidos. Authorization e ID de sessão aparecem só
como `sim`/`não`, assim como `state` e `code_challenge`. Não há log de cookies, query inteira
ou corpo inteiro. O access log do uvicorn está desligado. Corpos acima de 64 KiB recebem 413.
Não envie dados reais para o spike; os campos de observação são dados fornecidos pelo cliente.

Anote os valores observados de Host, Origin, versão, clientInfo e client_id e o resultado
por conta/interface. A compatibilidade real com Claude e Funnel só fica validada após esse
teste manual. Ao terminar, desligue o Funnel e encerre o servidor com Ctrl+C.
