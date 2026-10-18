# BatataSwap: interface estática (Vercel)

Site público, status ao vivo e painel de conexões. É só HTML, CSS e JS puros: sem build, sem dependência, sem CDN.
O conteúdo das memórias nunca passa por aqui.

## Publicar na Vercel

1. Importe o repositório na Vercel.
2. Em Settings, General, defina **Root Directory = `web`**.
3. Framework Preset: **Other**. Build Command e Output Directory: vazios (sem build).
4. Edite `config.js` e preencha `API_ORIGIN` com a origem do servidor (ex.: `https://servidor.tailnet.ts.net`, sem barra no fim). Vazio = modo demonstração.
5. No servidor, o cliente OAuth `painel-vercel` precisa ter como redirect exato `https://<projeto>.vercel.app/callback`.

`vercel.json` já traz `cleanUrls`, o rewrite de `/callback` e os headers de segurança (CSP, HSTS e outros).

**Origem da API em dois lugares:** o mesmo valor (ex.: `https://servidor.tailnet.ts.net`, sem barra no fim) vai em `config.js` (`API_ORIGIN`) e na CSP do `vercel.json`, no lugar do marcador `https://API_ORIGIN_AQUI` do `connect-src`. Sem curinga: a CSP só libera o servidor exato. Enquanto o marcador estiver lá, o login real e o status não funcionam (o modo demo funciona).

## Como o token passa do callback para o painel

`/callback` é reescrito para `painel.html`: o callback e o painel são a mesma página. O token fica numa variável JS e nunca toca em nenhum storage. Recarregou a página ou passaram 15 min, entra de novo.
Em servidor local simples (`http.server`) não há rewrite, então o login real só funciona na Vercel (ou com `vercel dev`).

## Testar o modo demonstração

```bash
python3 -m http.server -d web 8000
```

Abra `http://localhost:8000/?demo=1` e `http://localhost:8000/painel.html?demo=1`. A tarja listrada no topo avisa que os dados são de mentira.

## Teste automático

```bash
python3 -m pytest -q tests/test_web.py
```
