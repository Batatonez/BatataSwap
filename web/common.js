// Funções compartilhadas entre a página pública e o painel.
// Regra: nenhum dado vira HTML. Tudo é montado com createElement + textContent.
"use strict";

const NOT_CONFIGURED = API_ORIGIN === "";
const API_BASE = API_ORIGIN.replace(/\/+$/, "");
const RESOURCE = API_BASE + "/api/painel";
const TX_KEY = "batataswap_tx";
const TX_TTL_MS = 10 * 60 * 1000;

function el(tag, props, children) {
  const node = document.createElement(tag);
  if (props) {
    for (const [k, v] of Object.entries(props)) {
      if (k === "text") node.textContent = v;
      else if (k === "class") node.className = v;
      else node.setAttribute(k, v);
    }
  }
  for (const c of children || []) node.append(c);
  return node;
}

function clear(node) {
  while (node.firstChild) node.removeChild(node.firstChild);
}

// ---------- datas ----------
function formatAbs(iso) {
  const d = new Date(iso);
  if (isNaN(d)) return "";
  return d.toLocaleString("pt-BR", { dateStyle: "short", timeStyle: "short" });
}

function formatRel(iso) {
  if (!iso) return "nunca";
  const d = new Date(iso);
  if (isNaN(d)) return "nunca";
  const s = Math.round((Date.now() - d.getTime()) / 1000);
  if (s < 45) return "agora há pouco";
  const m = Math.round(s / 60);
  if (m < 60) return "há " + m + " min";
  const h = Math.round(m / 60);
  if (h < 24) return "há " + h + " h";
  const dias = Math.round(h / 24);
  if (dias < 30) return "há " + dias + (dias === 1 ? " dia" : " dias");
  const meses = Math.round(dias / 30);
  if (meses < 12) return "há " + meses + (meses === 1 ? " mês" : " meses");
  const anos = Math.round(dias / 365);
  return "há " + anos + (anos === 1 ? " ano" : " anos");
}

function timeEl(iso) {
  const t = el("time", { text: formatRel(iso) });
  if (iso) {
    t.setAttribute("datetime", iso);
    t.setAttribute("title", formatAbs(iso));
  }
  return t;
}

function formatBytes(n) {
  if (n < 1024) return n + " B";
  if (n < 1024 * 1024) return (n / 1024).toFixed(1).replace(".", ",") + " KiB";
  return (n / 1024 / 1024).toFixed(1).replace(".", ",") + " MiB";
}

// ---------- status ----------
async function fetchSaude() {
  if (NOT_CONFIGURED) return { online: false, naoConfigurado: true };
  const ctl = new AbortController();
  const timer = setTimeout(() => ctl.abort(), 5000);
  try {
    const r = await fetch(API_BASE + "/saude", {
      credentials: "omit",
      cache: "no-store",
      signal: ctl.signal,
    });
    if (!r.ok) return { online: false };
    const j = await r.json();
    if (j && j.ok === true) return { online: true, versao: String(j.versao || "") };
    return { online: false };
  } catch (e) {
    return { online: false };
  } finally {
    clearTimeout(timer);
  }
}

// ---------- PKCE ----------
function b64url(bytes) {
  let s = "";
  for (const b of bytes) s += String.fromCharCode(b);
  return btoa(s).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

function randomB64url(n) {
  const a = new Uint8Array(n);
  crypto.getRandomValues(a);
  return b64url(a);
}

async function startLogin() {
  const verifier = randomB64url(32);
  const state = randomB64url(16);
  const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(verifier));
  const challenge = b64url(new Uint8Array(digest));
  sessionStorage.setItem(
    TX_KEY,
    JSON.stringify({ state: state, code_verifier: verifier, criado_em: Date.now() }),
  );
  const q = new URLSearchParams({
    response_type: "code",
    client_id: CLIENT_ID,
    redirect_uri: REDIRECT_URI,
    scope: "painel",
    resource: RESOURCE,
    state: state,
    code_challenge: challenge,
    code_challenge_method: "S256",
  });
  location.assign(API_BASE + "/oauth/authorize?" + q.toString());
}

// Lê e apaga a transação. Devolve null se não existe, venceu ou está corrompida.
function takeTransaction() {
  let raw = null;
  try {
    raw = sessionStorage.getItem(TX_KEY);
    sessionStorage.removeItem(TX_KEY);
  } catch (e) {
    return null;
  }
  if (!raw) return null;
  try {
    const tx = JSON.parse(raw);
    if (typeof tx.state !== "string" || typeof tx.code_verifier !== "string") return null;
    if (typeof tx.criado_em !== "number" || Date.now() - tx.criado_em > TX_TTL_MS) return null;
    return tx;
  } catch (e) {
    return null;
  }
}

function loginClick(btn) {
  btn.addEventListener("click", () => {
    if (NOT_CONFIGURED) return;
    btn.disabled = true;
    startLogin().catch(() => {
      btn.disabled = false;
    });
  });
}
