"""OAuth secret preparation using temporary keys and synthetic credentials."""

import re
from base64 import urlsafe_b64decode, urlsafe_b64encode
from hashlib import sha256

import pytest
from cryptography.fernet import Fernet
from pydantic import SecretStr

from app.account_oauth_material import (
    InvalidOAuthLoginMaterial,
    create_oauth_login_material,
    hash_oauth_browser_token,
    recover_oauth_pkce_verifier,
)
from app.account_token_encryption import AccountTokenCipher


@pytest.fixture
def key() -> SecretStr:
    return SecretStr(Fernet.generate_key().decode("ascii"))


@pytest.fixture
def cipher(key: SecretStr) -> AccountTokenCipher:
    return AccountTokenCipher(key)


def test_published_s256_vector_and_separate_browser_binding(
    cipher: AccountTokenCipher, monkeypatch: pytest.MonkeyPatch
) -> None:
    # Public interoperability vector: RFC 7636 Appendix B, not a live credential.
    # https://www.rfc-editor.org/rfc/rfc7636.html#appendix-B
    browser_token = "b" * 43
    verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
    values = iter([browser_token, verifier])
    requested_sizes: list[int] = []

    def generate(nbytes: int) -> str:
        requested_sizes.append(nbytes)
        return next(values)

    monkeypatch.setattr("app.account_oauth_material.token_urlsafe", generate)
    material = create_oauth_login_material(cipher)

    assert requested_sizes == [32, 32]
    assert material.code_challenge == "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
    assert material.browser_token.get_secret_value() == browser_token
    assert material.browser_token_hash == sha256(browser_token.encode("ascii")).digest()
    assert material.browser_token_hash != sha256(verifier.encode("ascii")).digest()
    assert cipher.decrypt(material.pkce_verifier_ciphertext).get_secret_value() == verifier


def test_generated_material_fits_pkce_and_database_bounds(cipher: AccountTokenCipher) -> None:
    material = create_oauth_login_material(cipher)
    browser_token = material.browser_token.get_secret_value()
    verifier = cipher.decrypt(material.pkce_verifier_ciphertext).get_secret_value()

    assert re.fullmatch(r"[A-Za-z0-9_-]{43}", browser_token)
    assert re.fullmatch(r"[A-Za-z0-9_-]{43}", verifier)
    assert re.fullmatch(r"[A-Za-z0-9_-]{43}", material.code_challenge)
    assert browser_token != verifier
    assert len(material.browser_token_hash) == 32
    assert material.browser_token_hash == sha256(browser_token.encode("ascii")).digest()
    assert (
        urlsafe_b64decode(material.code_challenge + "=")
        == sha256(verifier.encode("ascii")).digest()
    )
    assert 1 <= len(material.pkce_verifier_ciphertext) <= 1024
    assert verifier.encode("ascii") not in material.pkce_verifier_ciphertext


def test_separate_attempts_receive_fresh_secrets(cipher: AccountTokenCipher) -> None:
    first = create_oauth_login_material(cipher)
    second = create_oauth_login_material(cipher)

    assert first.browser_token != second.browser_token
    assert first.browser_token_hash != second.browser_token_hash
    assert first.code_challenge != second.code_challenge
    assert cipher.decrypt(first.pkce_verifier_ciphertext) != cipher.decrypt(
        second.pkce_verifier_ciphertext
    )


def test_representation_does_not_expose_secrets_or_ciphertext(cipher: AccountTokenCipher) -> None:
    material = create_oauth_login_material(cipher)
    verifier = cipher.decrypt(material.pkce_verifier_ciphertext).get_secret_value()

    for rendered in (str(material), repr(material)):
        assert material.browser_token.get_secret_value() not in rendered
        assert verifier not in rendered
        assert material.pkce_verifier_ciphertext.decode("ascii") not in rendered
        assert "pkce_verifier_ciphertext=" not in rendered
        assert "browser_token_hash=" not in rendered


def test_encryption_failure_returns_no_material(
    cipher: AccountTokenCipher, monkeypatch: pytest.MonkeyPatch
) -> None:
    failure = RuntimeError("Synthetic encryption failure.")

    def reject_encryption(token: SecretStr) -> bytes:
        raise failure

    monkeypatch.setattr(cipher, "encrypt", reject_encryption)

    with pytest.raises(RuntimeError) as caught:
        create_oauth_login_material(cipher)

    assert caught.value is failure


def test_generated_material_can_be_hashed_and_recovered(cipher: AccountTokenCipher) -> None:
    material = create_oauth_login_material(cipher)

    assert hash_oauth_browser_token(material.browser_token.get_secret_value()) == (
        material.browser_token_hash
    )
    verifier = recover_oauth_pkce_verifier(material.pkce_verifier_ciphertext, cipher=cipher)
    assert isinstance(verifier, SecretStr)
    assert verifier == cipher.decrypt(material.pkce_verifier_ciphertext)
    assert verifier.get_secret_value() not in repr(verifier)


@pytest.mark.parametrize(
    "token",
    [
        pytest.param(None, id="missing"),
        pytest.param("", id="empty"),
        pytest.param("a" * 42, id="short"),
        pytest.param("a" * 44, id="long"),
        pytest.param("a" * 10000, id="oversized"),
        pytest.param(" " + "a" * 42, id="leading-space"),
        pytest.param("a" * 42 + " ", id="trailing-space"),
        pytest.param("a" * 42 + "\n", id="newline"),
        pytest.param("a" * 42 + "\N{SNOWMAN}", id="unicode"),
        pytest.param("a" * 42 + "+", id="plus"),
        pytest.param("a" * 42 + "/", id="slash"),
        pytest.param("a" * 42 + "=", id="padding"),
    ],
)
def test_malformed_browser_tokens_are_rejected(token: str | None) -> None:
    with pytest.raises(InvalidOAuthLoginMaterial) as caught:
        hash_oauth_browser_token(token)

    assert str(caught.value) == "Invalid OAuth login material."


def test_urlsafe_browser_token_is_hashed_without_normalization() -> None:
    token = "aB09_-" * 7 + "A"
    assert hash_oauth_browser_token(token) == sha256(token.encode("ascii")).digest()
    assert hash_oauth_browser_token(token) != hash_oauth_browser_token(token.lower())


@pytest.mark.parametrize("ciphertext", [b"", b"x" * 1025], ids=["empty", "oversized"])
def test_ciphertext_bounds_are_checked_before_decryption(
    cipher: AccountTokenCipher,
    monkeypatch: pytest.MonkeyPatch,
    ciphertext: bytes,
) -> None:
    def unexpected_decryption(value: bytes) -> SecretStr:
        raise AssertionError("Out-of-bounds ciphertext must not reach decryption.")

    monkeypatch.setattr(cipher, "decrypt", unexpected_decryption)
    with pytest.raises(InvalidOAuthLoginMaterial) as caught:
        recover_oauth_pkce_verifier(ciphertext, cipher=cipher)

    assert str(caught.value) == "Invalid OAuth login material."


@pytest.mark.parametrize("failure", ["malformed", "wrong-key", "tampered"])
def test_unreadable_ciphertext_uses_generic_error(cipher: AccountTokenCipher, failure: str) -> None:
    ciphertext = cipher.encrypt(SecretStr("v" * 43))
    if failure == "malformed":
        ciphertext = b"not-fernet-ciphertext"
    elif failure == "wrong-key":
        cipher = AccountTokenCipher(SecretStr(Fernet.generate_key().decode("ascii")))
    else:
        damaged = bytearray(urlsafe_b64decode(ciphertext))
        damaged[-1] ^= 1
        ciphertext = urlsafe_b64encode(damaged)

    with pytest.raises(InvalidOAuthLoginMaterial) as caught:
        recover_oauth_pkce_verifier(ciphertext, cipher=cipher)

    assert str(caught.value) == "Invalid OAuth login material."
    assert caught.value.__suppress_context__ is True


@pytest.mark.parametrize(
    "plaintext",
    [
        pytest.param(b"", id="empty"),
        pytest.param(b"v" * 42, id="short"),
        pytest.param(b"v" * 44, id="long"),
        pytest.param(b"v" * 42 + b" ", id="space"),
        pytest.param(b"v" * 42 + b"\n", id="newline"),
        pytest.param(b"v" * 42 + b"=", id="padding"),
        pytest.param(b"v" * 42 + b".", id="outside-generated-format"),
        pytest.param(b"\xff" * 43, id="non-ascii"),
    ],
)
def test_decrypted_verifier_must_match_our_generated_format(
    cipher: AccountTokenCipher, key: SecretStr, plaintext: bytes
) -> None:
    # Valid encryption alone must not make malformed verifier content acceptable.
    ciphertext = Fernet(key.get_secret_value().encode("ascii")).encrypt(plaintext)

    with pytest.raises(InvalidOAuthLoginMaterial) as caught:
        recover_oauth_pkce_verifier(ciphertext, cipher=cipher)

    assert str(caught.value) == "Invalid OAuth login material."
