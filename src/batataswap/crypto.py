"""Criptografia do BatataSwap (ARQUITETURA §6).

O que este módulo oferece:

- chave mestra: leitura de ``$CREDENTIALS_DIRECTORY/batataswap-master``, geração, export e
  import em base32 com checksum;
- subchaves por HKDF-SHA256 (``Keyring``), uma por uso;
- AEAD AES-256-GCM com envelope ``versão || key_id || nonce || ciphertext+tag``;
- AAD canônico ``bsw1|<tipo>|<campos…>`` e helpers para cada tipo de linha cifrada;
- HMAC-SHA256 por domínio e normalização de nomes;
- hash de tokens e geração de tokens e ``public_id``.

Regra: nenhuma função daqui loga, imprime ou coloca em exceção chave, texto claro, nonce ou tag.
"""

from __future__ import annotations

import base64
import errno
import hashlib
import hmac
import os
import re
import secrets
import stat
import unicodedata
from pathlib import Path
from typing import Literal

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

__all__ = [
    "MASTER_KEY_NAME",
    "AeadPurpose",
    "CryptoError",
    "Keyring",
    "MacPurpose",
    "aad_context",
    "aad_conversation_name",
    "aad_message",
    "aad_owner_totp",
    "aad_preference",
    "aad_project_name",
    "build_aad",
    "export_key",
    "generate_master_key",
    "import_key",
    "load_master_key",
    "new_public_id",
    "new_token",
    "normalize_name",
    "token_hash",
]


class CryptoError(Exception):
    """Erro de criptografia. A mensagem nunca carrega material secreto."""


# ---------------------------------------------------------------------------
# Constantes
# ---------------------------------------------------------------------------

MASTER_KEY_NAME = "batataswap-master"
MASTER_KEY_SIZE = 32

ENVELOPE_VERSION = 1
KEY_ID = 1
NONCE_SIZE = 12
TAG_SIZE = 16
_HEADER_SIZE = 2
_MIN_BLOB_SIZE = _HEADER_SIZE + NONCE_SIZE + TAG_SIZE

_HKDF_SALT = b"batataswap/v1"

AeadPurpose = Literal["conteudo", "totp"]
MacPurpose = Literal["projeto", "conversa", "lote", "csrf", "cursor"]

_AEAD_INFO: dict[str, bytes] = {
    "conteudo": b"aead-conteudo",
    "totp": b"aead-totp",
}
_MAC_INFO: dict[str, bytes] = {
    "projeto": b"mac-projeto",
    "conversa": b"mac-conversa",
    "lote": b"mac-lote",
    "csrf": b"csrf",
    "cursor": b"cursor",
}

_INVALID_BLOB = "dado cifrado inválido"


# ---------------------------------------------------------------------------
# Chave mestra
# ---------------------------------------------------------------------------


def load_master_key(credentials_dir: Path | None = None) -> bytes:
    """Lê a chave mestra binária (32 bytes) de ``<dir>/batataswap-master``.

    ``dir`` é o argumento ou, se ele faltar, ``$CREDENTIALS_DIRECTORY`` (systemd
    ``LoadCredentialEncrypted=``). Recusa link simbólico, arquivo que não seja regular (FIFO,
    diretório…), tamanho diferente de 32 bytes e, no POSIX, arquivo acessível por grupo ou outros
    ou com dono diferente do usuário atual ou do root. O systemd entrega a credencial com modo
    0400 e dono do serviço, o que passa.
    """
    if credentials_dir is None:
        env = os.environ.get("CREDENTIALS_DIRECTORY")
        if not env:
            raise CryptoError(
                "CREDENTIALS_DIRECTORY não está definida: a chave mestra precisa vir da "
                "credencial do systemd (LoadCredentialEncrypted=batataswap-master)"
            )
        credentials_dir = Path(env)

    path = Path(credentials_dir) / MASTER_KEY_NAME
    try:
        if path.is_symlink():
            raise CryptoError(f"a chave mestra não pode ser link simbólico: {path}")
    except OSError:
        raise CryptoError(f"não foi possível ler a chave mestra: {path}") from None

    # O_NONBLOCK: abrir um FIFO sem escritor não trava. O_NOFOLLOW: um link criado depois da
    # checagem acima falha com ELOOP. Flags ausentes no Windows viram 0.
    flags = os.O_RDONLY
    for name in ("O_BINARY", "O_NOFOLLOW", "O_NONBLOCK", "O_CLOEXEC"):
        flags |= getattr(os, name, 0)
    try:
        fd = os.open(path, flags)
    except FileNotFoundError:
        raise CryptoError(f"arquivo da chave mestra não encontrado: {path}") from None
    except OSError as exc:
        if exc.errno == errno.ELOOP:
            raise CryptoError(f"a chave mestra não pode ser link simbólico: {path}") from None
        raise CryptoError(f"não foi possível ler a chave mestra: {path}") from None

    try:
        _check_key_file(os.fstat(fd), path)
        data = b""
        while len(data) <= MASTER_KEY_SIZE:
            chunk = os.read(fd, MASTER_KEY_SIZE + 1 - len(data))
            if not chunk:
                break
            data += chunk
    except OSError:
        raise CryptoError(f"não foi possível ler a chave mestra: {path}") from None
    finally:
        os.close(fd)

    if len(data) != MASTER_KEY_SIZE:
        raise CryptoError(f"a chave mestra precisa ter exatamente {MASTER_KEY_SIZE} bytes: {path}")
    return data


def _check_key_file(st: os.stat_result, path: Path) -> None:
    """Confere, pelo descritor já aberto, tipo, tamanho e (no POSIX) dono e permissões."""
    if not stat.S_ISREG(st.st_mode):
        raise CryptoError(f"a chave mestra precisa ser um arquivo comum: {path}")
    if st.st_size != MASTER_KEY_SIZE:
        raise CryptoError(f"a chave mestra precisa ter exatamente {MASTER_KEY_SIZE} bytes: {path}")
    if os.name == "posix":
        if st.st_mode & 0o077:
            raise CryptoError(
                f"a chave mestra não pode ser acessível por grupo ou outros (use 0400): {path}"
            )
        if st.st_uid not in (os.geteuid(), 0):
            raise CryptoError(f"a chave mestra precisa pertencer ao usuário do serviço: {path}")


def generate_master_key() -> bytes:
    """Gera uma chave mestra nova de 32 bytes."""
    return secrets.token_bytes(MASTER_KEY_SIZE)


_B32_KEY_LEN = 52  # 32 bytes em base32, sem padding
_CHECKSUM_LEN = 4
_B32_ALPHABET = frozenset("ABCDEFGHIJKLMNOPQRSTUVWXYZ234567")


def _key_checksum(key: bytes) -> str:
    digest = hashlib.sha256(key).digest()
    return base64.b32encode(digest[:5]).decode("ascii")[:_CHECKSUM_LEN]


def export_key(key: bytes) -> str:
    """Converte a chave mestra em texto para o gerenciador de senhas.

    Formato: base32 sem padding + 4 caracteres de checksum (início do SHA-256 da chave, em
    base32), em blocos de 4 separados por hífen. São 14 blocos.
    """
    if not isinstance(key, bytes) or len(key) != MASTER_KEY_SIZE:
        raise CryptoError(f"a chave mestra precisa ter {MASTER_KEY_SIZE} bytes")
    body = base64.b32encode(key).decode("ascii").rstrip("=")
    text = body + _key_checksum(key)
    return "-".join(text[i : i + 4] for i in range(0, len(text), 4))


def import_key(text: str) -> bytes:
    """Lê o texto gerado por ``export_key`` e devolve a chave de 32 bytes.

    Aceita maiúsculas ou minúsculas, espaços e hífens. Confere o checksum.
    """
    if not isinstance(text, str):
        raise CryptoError("chave em formato inválido")
    cleaned = "".join(ch for ch in text if not ch.isspace() and ch != "-").upper()
    if len(cleaned) != _B32_KEY_LEN + _CHECKSUM_LEN or not set(cleaned) <= _B32_ALPHABET:
        raise CryptoError("chave em formato inválido: confira se copiou o texto inteiro")
    body, checksum = cleaned[:_B32_KEY_LEN], cleaned[_B32_KEY_LEN:]
    try:
        key = base64.b32decode(body + "====")
    except ValueError:
        raise CryptoError("chave em formato inválido") from None
    # Recusa formas não canônicas (bits de sobra no último caractere).
    if len(key) != MASTER_KEY_SIZE or base64.b32encode(key).decode("ascii")[:52] != body:
        raise CryptoError("chave em formato inválido")
    if not hmac.compare_digest(_key_checksum(key), checksum):
        raise CryptoError("checksum da chave não confere: confira se digitou certo")
    return key


# ---------------------------------------------------------------------------
# Subchaves, AEAD e HMAC
# ---------------------------------------------------------------------------


def _derive(master_key: bytes, info: bytes) -> bytes:
    return HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=_HKDF_SALT,
        info=info,
    ).derive(master_key)


class Keyring:
    """Subchaves derivadas da chave mestra.

    Deriva tudo no construtor e não guarda a chave mestra. Nenhum atributo público expõe
    material de chave, e o ``repr`` não mostra nada secreto.
    """

    __slots__ = ("_aead", "_mac")

    def __init__(self, master_key: bytes) -> None:
        if not isinstance(master_key, bytes) or len(master_key) != MASTER_KEY_SIZE:
            raise CryptoError(f"a chave mestra precisa ter {MASTER_KEY_SIZE} bytes")
        self._aead: dict[str, AESGCM] = {
            purpose: AESGCM(_derive(master_key, info)) for purpose, info in _AEAD_INFO.items()
        }
        self._mac: dict[str, bytes] = {
            purpose: _derive(master_key, info) for purpose, info in _MAC_INFO.items()
        }

    def __repr__(self) -> str:
        return "Keyring(<subchaves ocultas>)"

    __str__ = __repr__

    def _aead_for(self, purpose: str) -> AESGCM:
        try:
            return self._aead[purpose]
        except (KeyError, TypeError):
            raise ValueError("finalidade de cifra desconhecida") from None

    def _mac_key(self, purpose: str) -> bytes:
        try:
            return self._mac[purpose]
        except (KeyError, TypeError):
            raise ValueError("finalidade de HMAC desconhecida") from None

    def seal(self, purpose: AeadPurpose, plaintext: bytes, aad: bytes) -> bytes:
        """Cifra ``plaintext`` com AES-256-GCM e devolve o envelope binário."""
        aead = self._aead_for(purpose)
        if not isinstance(plaintext, bytes) or not isinstance(aad, bytes):
            raise TypeError("plaintext e aad precisam ser bytes")
        nonce = os.urandom(NONCE_SIZE)
        header = bytes((ENVELOPE_VERSION, KEY_ID))
        return header + nonce + aead.encrypt(nonce, plaintext, aad)

    def open(self, purpose: AeadPurpose, blob: bytes, aad: bytes) -> bytes:
        """Abre um envelope de ``seal``. Qualquer problema vira ``CryptoError`` genérico."""
        aead = self._aead_for(purpose)
        if not isinstance(blob, bytes) or not isinstance(aad, bytes):
            raise CryptoError(_INVALID_BLOB)
        if len(blob) < _MIN_BLOB_SIZE or blob[0] != ENVELOPE_VERSION or blob[1] != KEY_ID:
            raise CryptoError(_INVALID_BLOB)
        nonce = blob[_HEADER_SIZE : _HEADER_SIZE + NONCE_SIZE]
        try:
            return aead.decrypt(nonce, blob[_HEADER_SIZE + NONCE_SIZE :], aad)
        except InvalidTag:
            raise CryptoError(_INVALID_BLOB) from None

    def mac(self, purpose: MacPurpose, data: bytes) -> bytes:
        """HMAC-SHA256 de ``data`` com a subchave do domínio ``purpose``."""
        key = self._mac_key(purpose)
        if not isinstance(data, bytes):
            raise TypeError("data precisa ser bytes")
        return hmac.new(key, data, hashlib.sha256).digest()

    def verify_mac(self, purpose: MacPurpose, data: bytes, tag: bytes) -> bool:
        """Confere um HMAC em tempo constante."""
        if not isinstance(tag, bytes):
            return False
        return hmac.compare_digest(self.mac(purpose, data), tag)


# ---------------------------------------------------------------------------
# AAD canônico (§6)
# ---------------------------------------------------------------------------

AAD_PREFIX = "bsw1"
_AAD_FIELD_MAX = 200
_KIND_RE = re.compile(r"[a-z]+")
_B32_ID = r"[a-z2-7]{16}"
_PUBLIC_ID_RE = {
    prefix: re.compile(rf"{prefix}_{_B32_ID}")
    for prefix in ("proj", "pref", "conv", "lote", "grant")
}
ORIGIN_MARKERS = frozenset({"cli", "painel"})
CLAIMED_AUTHORS = frozenset({"usuario", "claude"})


def _check_aad_field(field: str | int) -> str:
    if isinstance(field, bool):
        raise ValueError("campo do AAD não pode ser bool")  # noqa: TRY004 (contrato: ValueError)
    if isinstance(field, int):
        return str(field)
    if not isinstance(field, str):
        raise ValueError("campo do AAD precisa ser str ou int")  # noqa: TRY004 (contrato: ValueError)
    if not field:
        raise ValueError("campo do AAD vazio")
    if len(field) > _AAD_FIELD_MAX:
        raise ValueError(f"campo do AAD maior que {_AAD_FIELD_MAX} caracteres")
    if "|" in field:
        raise ValueError("campo do AAD não pode conter '|'")
    for ch in field:
        # Controle, formatação (bidi, zero-width), surrogates, uso privado e não atribuídos,
        # além de separadores de linha/parágrafo.
        if unicodedata.category(ch)[0] == "C" or unicodedata.category(ch) in ("Zl", "Zp"):
            raise ValueError("campo do AAD com caractere de controle")
    return field


def build_aad(kind: str, *fields: str | int) -> bytes:
    """Monta o AAD canônico ``bsw1|<kind>|<f1>|<f2>…`` em UTF-8.

    ``kind`` só com letras ``a-z``. Cada campo é ``int`` (vira ``str``) ou ``str`` não vazio,
    sem ``|``, sem caracteres de controle e com até 200 caracteres. Violação → ``ValueError``.
    """
    if not isinstance(kind, str) or not _KIND_RE.fullmatch(kind):
        raise ValueError("tipo do AAD inválido")
    parts = [AAD_PREFIX, kind, *(_check_aad_field(f) for f in fields)]
    return "|".join(parts).encode("utf-8")


def _check_public_id(value: str, prefix: str) -> str:
    if not isinstance(value, str) or not _PUBLIC_ID_RE[prefix].fullmatch(value):
        raise ValueError(f"public_id inválido (esperado {prefix}_…)")
    return value


def _check_int(value: int, minimum: int, what: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < minimum:
        raise ValueError(f"{what} inválido")
    return value


def _check_origin(origin: str) -> str:
    if origin in ORIGIN_MARKERS:
        return origin
    return _check_public_id(origin, "grant")


def aad_context(
    project_public_id: str, version: int, origin: str, source_label: str, created_at: int
) -> bytes:
    """AAD de uma versão de contexto: ``bsw1|context|proj_…|<versão>|<origem>|<rótulo>|<data>``.

    ``origin`` é o public_id do grant (``grant_…``) ou o marcador ``cli`` ou ``painel``.
    """
    return build_aad(
        "context",
        _check_public_id(project_public_id, "proj"),
        _check_int(version, 1, "version"),
        _check_origin(origin),
        source_label,
        _check_int(created_at, 0, "created_at"),
    )


def aad_preference(
    public_id: str, version: int, origin: str, source_label: str, created_at: int
) -> bytes:
    """AAD de uma preferência: ``bsw1|preference|pref_…|<versão>|<origem>|<rótulo>|<data>``."""
    return build_aad(
        "preference",
        _check_public_id(public_id, "pref"),
        _check_int(version, 1, "version"),
        _check_origin(origin),
        source_label,
        _check_int(created_at, 0, "created_at"),
    )


def aad_message(
    conv_public_id: str,
    seq: int,
    batch_public_id: str,
    batch_grant_public_id: str,
    claimed_author: str,
    created_at: int,
) -> bytes:
    """AAD de uma mensagem.

    ``bsw1|message|conv_…|<seq>|lote_…|grant_…|<autor alegado>|<data>``. O grant é o do lote
    (quem enviou de verdade); ``claimed_author`` é ``usuario`` ou ``claude``.
    """
    if claimed_author not in CLAIMED_AUTHORS:
        raise ValueError("claimed_author inválido")
    return build_aad(
        "message",
        _check_public_id(conv_public_id, "conv"),
        _check_int(seq, 0, "seq"),
        _check_public_id(batch_public_id, "lote"),
        _check_public_id(batch_grant_public_id, "grant"),
        claimed_author,
        _check_int(created_at, 0, "created_at"),
    )


def aad_project_name(public_id: str) -> bytes:
    """AAD do nome cifrado de um projeto: ``bsw1|project|proj_…``."""
    return build_aad("project", _check_public_id(public_id, "proj"))


def aad_conversation_name(public_id: str) -> bytes:
    """AAD do nome cifrado de uma conversa: ``bsw1|conv|conv_…``."""
    return build_aad("conv", _check_public_id(public_id, "conv"))


def aad_owner_totp() -> bytes:
    """AAD do segredo TOTP do dono: ``bsw1|owner|totp``."""
    return build_aad("owner", "totp")


# ---------------------------------------------------------------------------
# Nomes, tokens e ids
# ---------------------------------------------------------------------------


def normalize_name(name: str) -> str:
    """Normaliza um nome de projeto ou conversa para o ``mac("projeto"/"conversa", …)``.

    NFC, ``casefold``, remove acentos (NFD sem marcas combinantes), colapsa espaços e tira
    espaços das pontas. Validar o formato do nome (1–80 caracteres, caracteres permitidos)
    NÃO é responsabilidade deste módulo: isso fica com quem chama, antes de normalizar.
    """
    text = unicodedata.normalize("NFC", name).casefold()
    text = "".join(
        ch for ch in unicodedata.normalize("NFD", text) if unicodedata.category(ch) != "Mn"
    )
    text = unicodedata.normalize("NFC", text)
    return " ".join(text.split())


def token_hash(token: str) -> bytes:
    """SHA-256 de um token, código ou cookie, para guardar no banco no lugar do valor."""
    return hashlib.sha256(token.encode("utf-8")).digest()


_TOKEN_PREFIX_RE = re.compile(r"[a-z0-9_]*")
_ID_PREFIX_RE = re.compile(r"[a-z]+_")


def new_token(prefix: str) -> str:
    """Token aleatório: ``prefix`` + 32 bytes em base64 url-safe."""
    if not isinstance(prefix, str) or not _TOKEN_PREFIX_RE.fullmatch(prefix):
        raise ValueError("prefixo de token inválido")
    return prefix + secrets.token_urlsafe(32)


def new_public_id(prefix: str) -> str:
    """``public_id``: ``prefix`` (ex.: ``proj_``) + 16 caracteres base32 minúsculos."""
    if not isinstance(prefix, str) or not _ID_PREFIX_RE.fullmatch(prefix):
        raise ValueError("prefixo de public_id inválido (ex.: 'proj_')")
    return prefix + base64.b32encode(secrets.token_bytes(10)).decode("ascii").lower()
