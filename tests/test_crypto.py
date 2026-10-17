import base64
import hashlib
import os
import re
import threading

import pytest
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from batataswap import crypto
from batataswap.crypto import (
    CryptoError,
    Keyring,
    aad_context,
    aad_conversation_name,
    aad_message,
    aad_owner_totp,
    aad_preference,
    aad_project_name,
    build_aad,
    export_key,
    generate_master_key,
    import_key,
    load_master_key,
    new_public_id,
    new_token,
    normalize_name,
    token_hash,
)

MASTER = bytes(range(32))
PROJ = "proj_abcdefghijklmnop"
CONV = "conv_abcdefghijklmnop"
LOTE = "lote_abcdefghijklmnop"
GRANT = "grant_abcdefghijklmnop"
PREF = "pref_abcdefghijklmnop"


@pytest.fixture
def ring():
    return Keyring(MASTER)


# --- AEAD -------------------------------------------------------------------


def test_seal_open_ida_e_volta(ring):
    aad = aad_project_name(PROJ)
    blob = ring.seal("conteudo", b"segredo", aad)
    assert blob[0] == 1 and blob[1] == 1
    assert len(blob) == 2 + 12 + len(b"segredo") + 16
    assert ring.open("conteudo", blob, aad) == b"segredo"


def test_seal_texto_vazio(ring):
    blob = ring.seal("totp", b"", aad_owner_totp())
    assert ring.open("totp", blob, aad_owner_totp()) == b""


def test_aad_diferente_falha(ring):
    blob = ring.seal("conteudo", b"x", aad_project_name(PROJ))
    with pytest.raises(CryptoError, match="^dado cifrado inválido$"):
        ring.open("conteudo", blob, aad_project_name("proj_bbbbbbbbbbbbbbbb"))


@pytest.mark.parametrize("pos", [2, 13, 14, -1])
def test_trocar_um_bit_falha(ring, pos):
    aad = aad_project_name(PROJ)
    blob = bytearray(ring.seal("conteudo", b"conteudo qualquer", aad))
    blob[pos] ^= 0x01
    with pytest.raises(CryptoError, match="^dado cifrado inválido$"):
        ring.open("conteudo", bytes(blob), aad)


def test_versao_e_key_id_desconhecidos_falham(ring):
    aad = aad_project_name(PROJ)
    blob = ring.seal("conteudo", b"x", aad)
    for bad in (b"\x02" + blob[1:], blob[:1] + b"\x02" + blob[2:]):
        with pytest.raises(CryptoError, match="^dado cifrado inválido$"):
            ring.open("conteudo", bad, aad)


def test_blob_curto_falha(ring):
    with pytest.raises(CryptoError, match="^dado cifrado inválido$"):
        ring.open("conteudo", b"\x01\x01" + b"\x00" * 27, b"")


def test_purposes_diferentes_nao_abrem(ring):
    aad = aad_owner_totp()
    blob = ring.seal("totp", b"x", aad)
    with pytest.raises(CryptoError):
        ring.open("conteudo", blob, aad)
    blob2 = ring.seal("conteudo", b"x", aad)
    with pytest.raises(CryptoError):
        ring.open("totp", blob2, aad)


def test_purpose_desconhecido(ring):
    with pytest.raises(ValueError):
        ring.seal("outro", b"x", b"")  # type: ignore[arg-type]


def test_chave_mestra_diferente_nao_abre(ring):
    blob = ring.seal("conteudo", b"x", b"a")
    with pytest.raises(CryptoError):
        Keyring(bytes(32)).open("conteudo", blob, b"a")


def test_dois_seal_geram_blobs_diferentes(ring):
    a = ring.seal("conteudo", b"igual", b"aad")
    b = ring.seal("conteudo", b"igual", b"aad")
    assert a != b
    assert a[2:14] != b[2:14]


# --- HKDF / Keyring -------------------------------------------------------------


def test_subchaves_distintas_e_deterministicas():
    infos = [
        b"aead-conteudo",
        b"aead-totp",
        b"mac-projeto",
        b"mac-conversa",
        b"mac-lote",
        b"csrf",
        b"cursor",
    ]
    keys = [crypto._derive(MASTER, info) for info in infos]
    assert len(set(keys)) == len(keys)
    assert all(len(k) == 32 for k in keys)
    assert keys == [crypto._derive(MASTER, info) for info in infos]
    assert MASTER not in keys


def test_keyring_deterministico():
    a, b = Keyring(MASTER), Keyring(MASTER)
    assert a.mac("projeto", b"n") == b.mac("projeto", b"n")
    assert b.open("conteudo", a.seal("conteudo", b"x", b"y"), b"y") == b"x"


def test_macs_de_dominios_diferentes_diferem(ring):
    tags = {ring.mac(p, b"mesmo") for p in ("projeto", "conversa", "lote", "csrf", "cursor")}
    assert len(tags) == 5


def test_keyring_rejeita_tamanho_errado():
    with pytest.raises(CryptoError):
        Keyring(b"\x00" * 31)


def test_repr_keyring_sem_material_de_chave():
    master = generate_master_key()
    ring = Keyring(master)
    text = repr(ring) + str(ring)
    subkeys = list(ring._mac.values())
    for secret in [master, *subkeys]:
        for form in (secret.hex(), repr(secret), base64.b64encode(secret).decode()):
            assert form not in text
    assert not hasattr(ring, "__dict__")
    assert master not in subkeys


# --- build_aad --------------------------------------------------------------------


def test_build_aad_formato_exato():
    assert build_aad("context", PROJ, 3, "cli", "conta-1", 1700000000) == (
        b"bsw1|context|proj_abcdefghijklmnop|3|cli|conta-1|1700000000"
    )
    assert build_aad("conv", "ção") == "bsw1|conv|ção".encode()


@pytest.mark.parametrize(
    "field",
    [
        "a|b",
        "",
        "x" * 201,
        "a\nb",
        "a\x00b",
        "a\x1fb",
        "a" + chr(0x200B) + "b",
        "a" + chr(0x2028) + "b",
        True,
        1.5,
        None,
    ],
)
def test_build_aad_rejeita_campos(field):
    with pytest.raises(ValueError):
        build_aad("context", field)


def test_build_aad_limite_de_200():
    assert build_aad("x", "a" * 200).endswith(b"a" * 200)


@pytest.mark.parametrize("kind", ["", "Context", "ctx1", "a|b", "ctx\n", "çao", "a b"])
def test_build_aad_rejeita_kind(kind):
    with pytest.raises(ValueError):
        build_aad(kind, "x")


def test_helpers_de_aad():
    assert aad_owner_totp() == b"bsw1|owner|totp"
    assert aad_project_name(PROJ) == f"bsw1|project|{PROJ}".encode()
    assert aad_conversation_name(CONV) == f"bsw1|conv|{CONV}".encode()
    assert aad_context(PROJ, 1, GRANT, "conta-1", 10) == (
        f"bsw1|context|{PROJ}|1|{GRANT}|conta-1|10".encode()
    )
    assert aad_preference(PREF, 2, "painel", "painel", 10) == (
        f"bsw1|preference|{PREF}|2|painel|painel|10".encode()
    )
    assert aad_message(CONV, 0, LOTE, GRANT, "claude", 10) == (
        f"bsw1|message|{CONV}|0|{LOTE}|{GRANT}|claude|10".encode()
    )


def test_helpers_de_aad_validam():
    with pytest.raises(ValueError):
        aad_context(PROJ, 1, "outro", "conta-1", 10)  # origem inválida
    with pytest.raises(ValueError):
        aad_context(CONV, 1, "cli", "conta-1", 10)  # prefixo errado
    with pytest.raises(ValueError):
        aad_context(PROJ, 0, "cli", "conta-1", 10)  # versão começa em 1
    with pytest.raises(ValueError):
        aad_preference(PREF, 1, "cli", "a|b", 10)
    with pytest.raises(ValueError):
        aad_message(CONV, 1, LOTE, GRANT, "sistema", 10)
    with pytest.raises(ValueError):
        aad_message(CONV, 1, LOTE, "cli", "claude", 10)  # lote sempre tem grant
    with pytest.raises(ValueError):
        aad_project_name("proj_ABCDEFGHIJKLMNOP")


def test_metadado_trocado_nao_abre(ring):
    blob = ring.seal("conteudo", b"{}", aad_context(PROJ, 1, GRANT, "conta-1", 10))
    with pytest.raises(CryptoError):
        ring.open("conteudo", blob, aad_context(PROJ, 1, GRANT, "conta-2", 10))
    with pytest.raises(CryptoError):
        ring.open("conteudo", blob, aad_context(PROJ, 2, GRANT, "conta-1", 10))


# --- export / import ----------------------------------------------------------------


def test_export_import_ida_e_volta():
    key = generate_master_key()
    text = export_key(key)
    assert re.fullmatch(r"[A-Z2-7]{4}(-[A-Z2-7]{4}){13}", text)
    assert import_key(text) == key


def test_import_tolerante():
    key = generate_master_key()
    text = export_key(key)
    variant = "  " + text.lower().replace("-", " - ") + "\n"
    assert import_key(variant) == key
    assert import_key(text.replace("-", "")) == key


def test_import_checksum_errado():
    key = MASTER
    text = export_key(key).replace("-", "")
    last = text[-1]
    bad = text[:-1] + ("A" if last != "A" else "B")
    with pytest.raises(CryptoError, match="checksum"):
        import_key(bad)


def test_import_corpo_alterado_falha():
    text = export_key(MASTER).replace("-", "")
    bad = ("B" if text[0] != "B" else "C") + text[1:]
    with pytest.raises(CryptoError):
        import_key(bad)


@pytest.mark.parametrize("text", ["", "ABCD", "1" * 56, "A" * 60])
def test_import_formato_invalido(text):
    with pytest.raises(CryptoError):
        import_key(text)


def test_export_checksum_e_sha256():
    text = export_key(MASTER).replace("-", "")
    expected = base64.b32encode(hashlib.sha256(MASTER).digest()[:5]).decode()[:4]
    assert text[-4:] == expected
    assert base64.b32decode(text[:52] + "====") == MASTER


# --- load_master_key ----------------------------------------------------------------


def _write_key(directory, data):
    path = directory / "batataswap-master"
    path.write_bytes(data)
    path.chmod(0o600)
    return path


def test_load_master_key_ok(tmp_path):
    _write_key(tmp_path, MASTER)
    assert load_master_key(tmp_path) == MASTER


def test_load_master_key_pela_variavel(tmp_path, monkeypatch):
    _write_key(tmp_path, MASTER)
    monkeypatch.setenv("CREDENTIALS_DIRECTORY", str(tmp_path))
    assert load_master_key() == MASTER


def test_load_master_key_sem_variavel(monkeypatch):
    monkeypatch.delenv("CREDENTIALS_DIRECTORY", raising=False)
    with pytest.raises(CryptoError, match="CREDENTIALS_DIRECTORY"):
        load_master_key()


def test_load_master_key_arquivo_faltando(tmp_path):
    with pytest.raises(CryptoError, match="não encontrado"):
        load_master_key(tmp_path)


@pytest.mark.parametrize("size", [0, 31, 33, 64])
def test_load_master_key_tamanho_errado(tmp_path, size):
    secret = (b"SEGREDOX" * 8)[:size]
    _write_key(tmp_path, secret)
    with pytest.raises(CryptoError) as exc:
        load_master_key(tmp_path)
    msg = str(exc.value)
    assert "32 bytes" in msg
    if secret:
        assert "SEGREDO" not in msg
        assert secret.hex() not in msg
        assert repr(secret) not in msg


def test_load_master_key_symlink(tmp_path):
    real = tmp_path / "real"
    real.mkdir()
    target = _write_key(real, MASTER)
    link_dir = tmp_path / "creds"
    link_dir.mkdir()
    try:
        os.symlink(target, link_dir / "batataswap-master")
    except (OSError, NotImplementedError):
        pytest.skip("sistema sem permissão para criar link simbólico")
    with pytest.raises(CryptoError, match="link simbólico") as exc:
        load_master_key(link_dir)
    assert MASTER.hex() not in str(exc.value)


def test_load_master_key_diretorio_no_lugar(tmp_path):
    (tmp_path / "batataswap-master").mkdir()
    with pytest.raises(CryptoError):
        load_master_key(tmp_path)


# --- normalize_name / mac -------------------------------------------------------------


def test_normalize_name():
    a = normalize_name("Site da Escola")
    assert a == "site da escola"
    assert normalize_name("  site   DA escola ") == a
    assert normalize_name("Sité da Escola") == a
    assert normalize_name("Site\tda\nEscola") == a
    assert normalize_name("Ação") == normalize_name("acao") == "acao"
    # NFD já decomposto também normaliza igual
    assert normalize_name("Sité da Escola") == a


def test_mac_e_verify(ring):
    data = normalize_name("Site da Escola").encode()
    tag = ring.mac("projeto", data)
    assert len(tag) == 32
    assert ring.verify_mac("projeto", data, tag)
    assert not ring.verify_mac("conversa", data, tag)
    assert not ring.verify_mac("projeto", data + b"x", tag)
    assert not ring.verify_mac("projeto", data, tag[:-1] + bytes([tag[-1] ^ 1]))
    assert not ring.verify_mac("projeto", data, b"")


def test_mac_purpose_desconhecido(ring):
    with pytest.raises(ValueError):
        ring.mac("conteudo", b"x")  # type: ignore[arg-type]


# --- tokens e ids ----------------------------------------------------------------------


def test_token_hash():
    assert token_hash("abc") == hashlib.sha256(b"abc").digest()
    assert token_hash("abc") != token_hash("abd")


def test_new_token():
    a, b = new_token("bsw_at_"), new_token("bsw_at_")
    assert a.startswith("bsw_at_") and a != b
    assert len(a) == len("bsw_at_") + 43
    with pytest.raises(ValueError):
        new_token("A|")


def test_new_public_id():
    pid = new_public_id("proj_")
    assert re.fullmatch(r"proj_[a-z2-7]{16}", pid)
    assert new_public_id("proj_") != pid
    assert aad_project_name(pid)  # aceito pelos helpers
    for bad in ("proj", "PROJ_", "", "pr|_"):
        with pytest.raises(ValueError):
            new_public_id(bad)


posix_only = pytest.mark.skipif(os.name != "posix", reason="só POSIX")


@posix_only
@pytest.mark.parametrize("mode", [0o400, 0o600])
def test_load_master_key_modo_seguro(tmp_path, mode):
    path = _write_key(tmp_path, MASTER)
    path.chmod(mode)
    assert load_master_key(tmp_path) == MASTER


@posix_only
@pytest.mark.parametrize("mode", [0o640, 0o644, 0o604, 0o440, 0o620])
def test_load_master_key_modo_inseguro(tmp_path, mode):
    path = _write_key(tmp_path, MASTER)
    path.chmod(mode)
    with pytest.raises(CryptoError, match="grupo ou outros"):
        load_master_key(tmp_path)


@posix_only
def test_load_master_key_dono_errado(tmp_path, monkeypatch):
    _write_key(tmp_path, MASTER)
    real_fstat = os.fstat
    other_uid = 54321 if os.geteuid() != 54321 else 54322

    def fake_fstat(fd):
        values = list(real_fstat(fd))
        values[4] = other_uid  # posição de st_uid em os.stat_result
        return os.stat_result(values)

    monkeypatch.setattr(crypto.os, "fstat", fake_fstat)
    with pytest.raises(CryptoError, match="pertencer"):
        load_master_key(tmp_path)


@pytest.mark.skipif(not hasattr(os, "mkfifo"), reason="sem FIFO neste sistema")
def test_load_master_key_fifo_nao_trava(tmp_path):
    os.mkfifo(tmp_path / "batataswap-master", 0o600)
    result = {}

    def run():
        try:
            load_master_key(tmp_path)
        except CryptoError as exc:
            result["err"] = str(exc)

    worker = threading.Thread(target=run, daemon=True)
    worker.start()
    worker.join(timeout=5)
    assert not worker.is_alive(), "load_master_key travou abrindo um FIFO"
    assert "arquivo comum" in result["err"]


@pytest.mark.skipif(not hasattr(os, "O_NOFOLLOW"), reason="sem O_NOFOLLOW")
def test_load_master_key_symlink_trocado_depois_da_checagem(tmp_path, monkeypatch):
    real = tmp_path / "real"
    real.mkdir()
    target = _write_key(real, MASTER)
    link_dir = tmp_path / "creds"
    link_dir.mkdir()
    link = link_dir / "batataswap-master"

    def racing_is_symlink(self):
        # Simula a corrida: o link aparece logo depois da checagem.
        if self == link and not os.path.lexists(link):
            os.symlink(target, link)
        return False

    monkeypatch.setattr(crypto.Path, "is_symlink", racing_is_symlink)
    with pytest.raises(CryptoError, match="link simbólico"):
        load_master_key(link_dir)
    assert os.path.islink(link)  # a corrida aconteceu de fato


def test_hkdf_vetor_independente():
    def expected(info):
        return HKDF(algorithm=hashes.SHA256(), length=32, salt=b"batataswap/v1", info=info).derive(
            MASTER
        )

    ring = Keyring(MASTER)
    for purpose, info in [
        ("projeto", b"mac-projeto"),
        ("conversa", b"mac-conversa"),
        ("lote", b"mac-lote"),
        ("csrf", b"csrf"),
        ("cursor", b"cursor"),
    ]:
        assert ring._mac[purpose] == expected(info)
    for purpose, info in [("conteudo", b"aead-conteudo"), ("totp", b"aead-totp")]:
        nonce = b"\x00" * 12
        ct = AESGCM(expected(info)).encrypt(nonce, b"vetor", b"aad")
        assert ring.open(purpose, b"\x01\x01" + nonce + ct, b"aad") == b"vetor"


def test_import_rejeita_base32_nao_canonico():
    alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"
    text = export_key(MASTER).replace("-", "")
    body, checksum = text[:52], text[52:]
    # O último caractere do corpo carrega 1 bit de dado e 4 de padding: muda só o padding.
    last = alphabet.index(body[-1])
    tweaked = body[:-1] + alphabet[last ^ 0b0001] + checksum
    assert base64.b32decode(tweaked[:52] + "====") == MASTER  # mesmos bytes, mesmo checksum
    with pytest.raises(CryptoError, match="formato"):
        import_key(tweaked)
