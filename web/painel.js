// Painel de conexões. Esta mesma página atende /painel e /callback (a Vercel
// reescreve /callback para ela), então o token nunca precisa passar por storage.
"use strict";

let accessToken = null; // só em memória
let expireTimer = null;
let revokeTarget = null;
let session = 0; // muda a cada login/saída/expiração; descarta respostas atrasadas

const $ = (id) => document.getElementById(id);

function showMsg(text) {
  const m = $("msg");
  m.textContent = text;
  m.hidden = !text;
}

function showLogin(message) {
  session++;
  accessToken = null;
  clearTimeout(expireTimer);
  $("painel").hidden = true;
  $("sair").hidden = true;
  $("login").hidden = false;
  showMsg(message || "");
}

function setToken(token, expiresInSec) {
  session++;
  accessToken = token;
  const ms = Math.min(Number(expiresInSec) || 900, 900) * 1000;
  clearTimeout(expireTimer);
  expireTimer = setTimeout(() => showLogin("A sessão de 15 minutos acabou. Entre de novo."), ms);
}

// ---------- API ----------
class Expired extends Error {}

async function api(path, options) {
  const opts = Object.assign({ credentials: "omit", cache: "no-store" }, options);
  opts.headers = Object.assign({ Authorization: "Bearer " + accessToken }, opts.headers);
  const r = await fetch(API_BASE + path, opts);
  if (r.status === 401) throw new Expired();
  return r;
}

async function getJson(path) {
  const r = await api(path);
  if (!r.ok) throw new Error("Erro " + r.status + " ao ler o servidor.");
  return r.json();
}

// ---------- callback ----------
async function handleCallback() {
  const q = new URLSearchParams(location.search);
  const code = q.get("code");
  const state = q.get("state");
  const iss = q.get("iss");
  const err = q.get("error");
  const tx = takeTransaction(); // já apaga do sessionStorage
  history.replaceState(null, "", "/painel"); // tira code/state/iss antes de trocar

  if (!tx) return showLogin("Login expirado ou não iniciado aqui. Entre de novo.");
  if (!state || state !== tx.state) return showLogin("Resposta de login inválida (state).");
  if (iss !== API_BASE) return showLogin("Resposta de login inválida (emissor).");
  // Só depois de validar a resposta: o texto do erro recebido nunca é mostrado.
  if (err || !code) return showLogin("O servidor recusou o login. Tente de novo.");

  const body = new URLSearchParams({
    grant_type: "authorization_code",
    code: code,
    redirect_uri: REDIRECT_URI,
    client_id: CLIENT_ID,
    code_verifier: tx.code_verifier,
    resource: RESOURCE,
  });
  try {
    const r = await fetch(API_BASE + "/oauth/token", {
      method: "POST",
      credentials: "omit",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: body.toString(),
    });
    if (!r.ok) return showLogin("O servidor não aceitou o código de login.");
    const j = await r.json();
    if (!j || typeof j.access_token !== "string") return showLogin("Resposta de token inválida.");
    setToken(j.access_token, j.expires_in);
    await load();
  } catch (e) {
    showLogin("Não consegui falar com o servidor.");
  }
}

// ---------- render ----------
function stat(label, value) {
  return el("div", { class: "stat" }, [el("dt", { text: label }), el("dd", null, [value])]);
}

function renderCards(conexoes, atividade) {
  const box = $("cartoes");
  clear(box);
  if (!conexoes.length) {
    box.append(el("p", { class: "muted", text: "Nenhuma conta conectada ainda." }));
    return;
  }
  for (const c of conexoes) {
    const a = atividade.find((x) => x.rotulo === c.rotulo) || {};
    const card = el("article", { class: "card" });
    const head = el("header", null, [
      el("h3", { class: "mono", text: String(c.rotulo) }),
      el("span", { class: "tag " + (c.ativo ? "on" : "off"), text: c.ativo ? "ativo" : "revogado" }),
    ]);
    const dl = el("dl", { class: "stats" }, [
      stat("Conectado", timeEl(c.conectado_desde)),
      stat("Último uso", timeEl(c.ultimo_uso)),
      stat("Contextos", document.createTextNode(String(a.contextos ?? 0))),
      stat("Mensagens", document.createTextNode(String(a.mensagens ?? 0))),
      stat("Preferências", document.createTextNode(String(a.preferencias ?? 0))),
      stat("Última escrita", timeEl(a.ultima_escrita)),
    ]);
    card.append(head, dl);
    if (c.ativo) {
      const b = el("button", { type: "button", class: "btn danger", text: "Desconectar" });
      b.addEventListener("click", () => openRevoke(String(c.rotulo)));
      card.append(el("footer", null, [b]));
    }
    box.append(card);
  }
}

function meter(label, used, max, fmt) {
  const pct = max > 0 ? Math.min(100, Math.round((used / max) * 100)) : 0;
  const bar = el("progress", { max: "100", value: String(pct), "aria-label": label });
  return el("div", { class: "limit" }, [
    el("div", { class: "limit-head" }, [
      el("span", { text: label }),
      el("span", { class: "mono", text: fmt(used) + " de " + fmt(max) + " (" + pct + "%)" }),
    ]),
    bar,
  ]);
}

function renderLimits(l) {
  const box = $("limites");
  clear(box);
  const n = (v) => String(v);
  box.append(
    meter("Escritas hoje", l.escritas_hoje, l.escritas_max, n),
    meter("Bytes gravados hoje", l.bytes_hoje, l.bytes_max, formatBytes),
    meter("Total guardado", l.total_bytes, l.total_max, formatBytes),
  );
}

async function load() {
  const mine = session;
  try {
    const [con, ati] = await Promise.all([
      getJson("/api/painel/conexoes"),
      getJson("/api/painel/atividade"),
    ]);
    if (mine !== session) return; // saiu ou expirou enquanto carregava
    renderCards(con.conexoes || [], ati.por_conta || []);
    renderLimits(ati.limites || {});
    $("login").hidden = true;
    $("painel").hidden = false;
    $("sair").hidden = false;
    showMsg("");
  } catch (e) {
    if (mine !== session) return;
    if (e instanceof Expired) showLogin("Sessão expirada. Entre de novo.");
    else if (e instanceof TypeError) showLogin("Não consegui falar com o servidor.");
    else showLogin(e && e.message ? e.message : "Não consegui carregar os dados do servidor.");
  }
}

// ---------- revogar ----------
function openRevoke(rotulo) {
  revokeTarget = rotulo;
  $("dlg-texto").textContent =
    "Isso derruba a conexão de " + rotulo + ". Para voltar, essa conta precisa conectar de novo.";
  $("totp").value = "";
  $("dlg-erro").hidden = true;
  $("dlg").showModal();
  $("totp").focus();
}

async function submitRevoke(ev) {
  ev.preventDefault();
  const code = $("totp").value.trim();
  const erro = $("dlg-erro");
  if (!/^[0-9]{6}$/.test(code)) {
    erro.textContent = "Digite os 6 números do autenticador.";
    erro.hidden = false;
    return;
  }
  $("dlg-ok").disabled = true;
  try {
    const r = await api("/api/painel/revogar", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ rotulo: revokeTarget, totp: code }),
    });
    if (r.status === 403) {
      erro.textContent = "Código inválido. Tente o próximo código do autenticador.";
      erro.hidden = false;
      return;
    }
    if (r.status !== 204) {
      erro.textContent = "O servidor respondeu " + r.status + ".";
      erro.hidden = false;
      return;
    }
    $("dlg").close();
    await load();
  } catch (e) {
    if (e instanceof Expired) {
      $("dlg").close();
      showLogin("Sessão expirada. Entre de novo.");
    } else {
      erro.textContent = "Não consegui falar com o servidor.";
      erro.hidden = false;
    }
  } finally {
    $("dlg-ok").disabled = false;
  }
}

// ---------- início ----------
loginClick($("entrar"));
$("sair").addEventListener("click", () => showLogin("Você saiu."));
$("dlg-cancelar").addEventListener("click", () => $("dlg").close());
$("dlg-form").addEventListener("submit", submitRevoke);

if (NOT_CONFIGURED) {
  showLogin("Servidor não configurado.");
  $("entrar").disabled = true;
} else if (location.pathname.replace(/\/+$/, "").endsWith("/callback")) handleCallback();
else showLogin("");
