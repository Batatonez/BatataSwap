"""Páginas HTML do login e do consentimento (sem JavaScript, sem estilo inline).

Todo texto variável passa por ``html.escape``. O CSS fica em ``auth/static/oauth.css``.
O ``<meta name="referrer" content="same-origin">`` é necessário: com ``Referrer-Policy:
no-referrer`` (header da borda) o navegador manda ``Origin: null`` no POST do formulário
(Fetch, "append a request Origin header"), e a borda exige ``Origin`` igual ao ``<api>``.
"""

from html import escape
from importlib.resources import files

STATIC_PATH = "/static/oauth.css"

_SCOPES = {
    "memoria": "Ler e salvar as memórias do BatataSwap (contextos, preferências e conversas).",
    "offline_access": "Continuar conectado sem pedir login de novo (até 180 dias).",
    "painel": "Ver as conexões e a atividade, sem nenhum conteúdo de memória.",
}


def stylesheet() -> bytes:
    return files("batataswap.auth").joinpath("static/oauth.css").read_bytes()


def _page(title: str, body: str) -> str:
    return (
        "<!doctype html>\n"
        '<html lang="pt-BR">\n<head>\n<meta charset="utf-8">\n'
        '<meta name="viewport" content="width=device-width, initial-scale=1">\n'
        '<meta name="referrer" content="same-origin">\n'
        '<meta name="robots" content="noindex">\n'
        f"<title>{escape(title)} · BatataSwap</title>\n"
        f'<link rel="stylesheet" href="{STATIC_PATH}">\n'
        "</head>\n<body>\n<main>\n"
        '<p class="marca">BatataSwap</p>\n'
        f"{body}\n</main>\n</body>\n</html>\n"
    )


def _who(client_name: str, host: str) -> str:
    return (
        '<p class="quem">Pedido de <strong>'
        f"{escape(client_name)}</strong>, que vai receber o acesso em "
        f"<strong>{escape(host)}</strong>.</p>"
    )


def _hidden(tx_id: str, csrf: str) -> str:
    return (
        f'<input type="hidden" name="tx" value="{escape(tx_id)}">\n'
        f'<input type="hidden" name="csrf" value="{escape(csrf)}">'
    )


def _message(message: str | None) -> str:
    if not message:
        return ""
    return f'<p class="aviso" role="alert">{escape(message)}</p>'


def login_page(client_name: str, host: str, tx_id: str, csrf: str, message=None) -> str:
    body = (
        "<h1>Entrar</h1>\n"
        '<p class="aviso">Só continue se você acabou de pedir esta conexão no Claude. '
        "A senha só se digita neste endereço.</p>\n"
        f"{_who(client_name, host)}\n"
        f"{_message(message)}\n"
        '<form method="post" action="/oauth/login">\n'
        f"{_hidden(tx_id, csrf)}\n"
        '<label for="senha">Senha</label>\n'
        '<input id="senha" name="senha" type="password" autocomplete="current-password" '
        'required maxlength="1024">\n'
        '<label for="codigo">Código do autenticador</label>\n'
        '<input id="codigo" name="codigo" type="text" inputmode="numeric" '
        'autocomplete="one-time-code" pattern="[0-9 ]{6,7}" maxlength="7" required>\n'
        '<label class="opcao"><input type="checkbox" name="lembrar" value="sim"> '
        "Lembrar este aparelho por 180 dias</label>\n"
        '<button type="submit">Entrar</button>\n'
        "</form>"
    )
    return _page("Entrar", body)


def _scopes(scope: str) -> str:
    items = "".join(f"<li>{escape(_SCOPES[s])}</li>" for s in scope.split(" ") if s in _SCOPES)
    return f'<ul class="permissoes">{items}</ul>'


def _cancel(tx_id: str, csrf: str) -> str:
    return (
        '<form method="post" action="/oauth/consent" class="cancelar">\n'
        f"{_hidden(tx_id, csrf)}\n"
        '<button type="submit" name="acao" value="cancelar" class="secundario">'
        "Cancelar</button>\n</form>"
    )


def consent_page(
    client_name: str,
    host: str,
    scope: str,
    tx_id: str,
    csrf: str,
    labels: tuple[str, ...] | None,
    active: dict[str, str],
    message: str | None = None,
) -> str:
    """Consentimento. ``labels`` None = painel (sem rótulo)."""
    if labels is None:
        choose = ""
        seen = ""
    else:
        options = []
        for i, label in enumerate(labels):
            note = ' <span class="nota">(já conectada)</span>' if label in active else ""
            options.append(
                f'<label class="opcao"><input type="radio" name="rotulo" '
                f'value="{escape(label)}"{" checked" if i == 0 else ""}> '
                f"{escape(label)}{note}</label>"
            )
        choose = (
            "<fieldset>\n<legend>Qual conta está conectando?</legend>\n"
            + "\n".join(options)
            + "\n</fieldset>\n"
        )
        seen = (
            '<input type="hidden" name="vistos" value="'
            f'{escape(",".join(sorted(active.values())))}">\n'
        )
    body = (
        "<h1>Autorizar acesso</h1>\n"
        '<p class="aviso">Só continue se você acabou de pedir esta conexão no Claude. '
        "A senha só se digita neste endereço.</p>\n"
        f"{_who(client_name, host)}\n"
        f"{_message(message)}\n"
        f"{_scopes(scope)}\n"
        '<form method="post" action="/oauth/consent">\n'
        f"{_hidden(tx_id, csrf)}\n{seen}{choose}"
        '<button type="submit" name="acao" value="autorizar">Autorizar</button>\n'
        "</form>\n"
        f"{_cancel(tx_id, csrf)}"
    )
    return _page("Autorizar acesso", body)


def replace_page(
    client_name: str, host: str, label: str, old_grant: str, tx_id: str, csrf: str
) -> str:
    body = (
        "<h1>Substituir a conexão antiga?</h1>\n"
        '<p class="aviso">Só continue se você acabou de pedir esta conexão no Claude. '
        "A senha só se digita neste endereço.</p>\n"
        f"{_who(client_name, host)}\n"
        f"<p>Já existe uma conexão ativa como <strong>{escape(label)}</strong>. "
        "Se continuar, a conexão antiga é desligada e esta passa a valer no lugar dela.</p>\n"
        '<form method="post" action="/oauth/consent">\n'
        f"{_hidden(tx_id, csrf)}\n"
        f'<input type="hidden" name="rotulo" value="{escape(label)}">\n'
        f'<input type="hidden" name="substituir" value="{escape(old_grant)}">\n'
        '<button type="submit" name="acao" value="autorizar">Substituir e autorizar</button>\n'
        "</form>\n"
        f"{_cancel(tx_id, csrf)}"
    )
    return _page("Substituir conexão", body)


def message_page(title: str, message: str, link: tuple[str, str] | None = None) -> str:
    """Página simples. ``link`` = (texto, caminho relativo do próprio servidor)."""
    extra = ""
    if link is not None:
        extra = f'\n<p><a href="{escape(link[1])}">{escape(link[0])}</a></p>'
    return _page(title, f"<h1>{escape(title)}</h1>\n<p>{escape(message)}</p>{extra}")
