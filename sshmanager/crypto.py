"""Criptografia de senhas em repouso e de exportações."""

from __future__ import annotations

import base64
import binascii
import hashlib
import os
import sys
from collections.abc import Mapping
from pathlib import Path
from typing import Any

from cryptography.fernet import Fernet, InvalidToken

from .errors import CryptoError
from .utils import restrict_permissions

# Parâmetros do scrypt usados nas exportações protegidas por senha.
SCRYPT_N = 2**15
SCRYPT_R = 8
SCRYPT_P = 1


class SecretCipher:
    """Cifra e decifra textos com Fernet, usando uma chave local."""

    def __init__(self, key_path: Path) -> None:
        self.key_path = Path(key_path)
        self._fernet = Fernet(self._load_or_create_key())

    def _load_or_create_key(self) -> bytes:
        try:
            key = self.key_path.read_bytes().strip()
        except FileNotFoundError:
            key = self._create_key()
        except OSError as exc:
            raise CryptoError(
                f"Não foi possível ler a chave em '{self.key_path}': {exc}"
            ) from exc

        try:
            Fernet(key)  # valida o formato
        except (TypeError, ValueError) as exc:
            raise CryptoError(
                f"Chave inválida em '{self.key_path}'. Restaure o arquivo original "
                "ou remova-o junto com o servidores.json para recomeçar."
            ) from exc
        return key

    def _create_key(self) -> bytes:
        key = Fernet.generate_key()
        try:
            self.key_path.parent.mkdir(parents=True, exist_ok=True)
            fd = os.open(self.key_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(fd, "wb") as handle:
                handle.write(key)
                handle.flush()
                os.fsync(handle.fileno())
        except FileExistsError:
            return self.key_path.read_bytes().strip()
        except OSError as exc:
            raise CryptoError(
                f"Não foi possível criar a chave em '{self.key_path}': {exc}"
            ) from exc

        restrict_permissions(self.key_path)
        print(
            f"Chave de criptografia criada em: {self.key_path}",
            file=sys.stderr,
        )
        return key

    def encrypt(self, value: str) -> str:
        if not value:
            return ""
        try:
            token = self._fernet.encrypt(value.encode("utf-8"))
        except Exception as exc:  # pragma: no cover - falha improvável
            raise CryptoError(f"Falha ao cifrar a senha: {exc}") from exc
        return token.decode("ascii")

    def decrypt(self, token: str) -> str:
        if not token:
            return ""
        try:
            return self._fernet.decrypt(token.encode("ascii")).decode("utf-8")
        except (InvalidToken, ValueError, UnicodeDecodeError) as exc:
            raise CryptoError(
                "Não foi possível decifrar uma senha. O arquivo 'secret.key' "
                "não é o original que cifrou esses dados."
            ) from exc


def derive_key(passphrase: str, salt: bytes, n: int, r: int, p: int) -> bytes:
    """Deriva uma chave Fernet (32 bytes em base64) a partir da senha e do sal."""
    try:
        raw = hashlib.scrypt(
            passphrase.encode("utf-8"),
            salt=salt,
            n=n,
            r=r,
            p=p,
            dklen=32,
            maxmem=256 * 1024 * 1024,
        )
    except (AttributeError, OSError, ValueError) as exc:
        raise CryptoError(f"Falha ao derivar a chave da exportação: {exc}") from exc
    return base64.urlsafe_b64encode(raw)


def create_kdf(passphrase: str) -> tuple[dict[str, Any], bytes]:
    """Cria parâmetros de KDF novos e a chave correspondente."""
    salt = os.urandom(16)
    params: dict[str, Any] = {
        "name": "scrypt",
        "salt": base64.b64encode(salt).decode("ascii"),
        "n": SCRYPT_N,
        "r": SCRYPT_R,
        "p": SCRYPT_P,
    }
    key = derive_key(passphrase, salt, SCRYPT_N, SCRYPT_R, SCRYPT_P)
    return params, key


def key_from_kdf(passphrase: str, kdf: Mapping[str, Any]) -> bytes:
    """Valida os parâmetros recebidos e deriva a chave da exportação."""
    if not isinstance(kdf, Mapping) or kdf.get("name") != "scrypt":
        raise CryptoError("Parâmetros de criptografia ausentes ou não suportados.")
    try:
        salt = base64.b64decode(str(kdf["salt"]), validate=True)
        n = int(kdf["n"])
        r = int(kdf["r"])
        p = int(kdf["p"])
    except (KeyError, TypeError, ValueError, binascii.Error) as exc:
        raise CryptoError("Parâmetros de criptografia inválidos no arquivo.") from exc

    if (
        not 2**12 <= n <= 2**20
        or not 1 <= r <= 16
        or not 1 <= p <= 4
        or not 8 <= len(salt) <= 64
    ):
        raise CryptoError("Parâmetros de criptografia fora dos limites permitidos.")

    return derive_key(passphrase, salt, n, r, p)
