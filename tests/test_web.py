"""Checagens estáticas da interface em web/ (CSP estrita, sem XSS óbvio)."""

import json
import re
from pathlib import Path

WEB = Path(__file__).resolve().parent.parent / "web"
TEXT_EXT = {".html", ".js", ".css", ".json", ".md", ".svg"}


def _files():
    return [p for p in WEB.rglob("*") if p.is_file() and p.suffix in TEXT_EXT]


def _html():
    return [p for p in _files() if p.suffix == ".html"]


def test_web_tem_arquivos():
    assert (WEB / "index.html").exists()
    assert (WEB / "painel.html").exists()
    assert (WEB / "vercel.json").exists()


def test_html_sem_script_inline():
    for p in _html():
        for m in re.finditer(r"<script\b([^>]*)>", p.read_text(encoding="utf-8"), re.IGNORECASE):
            assert re.search(r"\bsrc\s*=", m.group(1), re.IGNORECASE), f"{p.name}: script inline"


def test_html_sem_handlers_e_style_inline():
    for p in _html():
        txt = p.read_text(encoding="utf-8")
        assert not re.search(r"<[^>]+\son[a-z]+\s*=", txt, re.IGNORECASE), (
            f"{p.name}: atributo on*="
        )
        assert not re.search(r"<[^>]+\sstyle\s*=", txt, re.IGNORECASE), f"{p.name}: style inline"


def test_sem_apis_perigosas():
    proibidos = [
        "innerHTML",
        "outerHTML",
        "insertAdjacentHTML",
        "document.write",
        "localStorage",
        "eval(",
        "new Function",
    ]
    for p in _files():
        txt = p.read_text(encoding="utf-8")
        for termo in proibidos:
            assert termo not in txt, f"{p.name}: contém {termo}"


def test_sem_recurso_externo():
    for p in _html():
        txt = p.read_text(encoding="utf-8")
        for m in re.finditer(r"\b(?:src|href)\s*=\s*[\"']([^\"']*)[\"']", txt, re.IGNORECASE):
            url = m.group(1).strip().lower()
            assert not url.startswith(("http:", "https:", "//")), f"{p.name}: {url}"


def test_vercel_json():
    cfg = json.loads((WEB / "vercel.json").read_text(encoding="utf-8"))
    headers = {h["key"]: h["value"] for r in cfg["headers"] for h in r["headers"]}
    csp = headers["Content-Security-Policy"]
    assert "script-src 'self'" in csp
    assert "frame-ancestors 'none'" in csp
    assert headers["Referrer-Policy"] == "no-referrer"
