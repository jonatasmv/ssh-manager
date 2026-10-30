"""Utilidades de arquivo, permissões e tempo."""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import tempfile
from collections.abc import Mapping
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from .config import ENV_DATA_DIR
from .errors import StorageError


def utc_now() -> str:
    """Retorna o instante atual em UTC no formato ISO-8601 (ex.: 2026-10-27T12:00:00Z)."""
    return datetime.now(UTC).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def default_data_dir() -> Path:
    """Diretório padrão de dados: %APPDATA%\\SSHManager ou ~/.config/ssh-manager."""
    env = os.environ.get(ENV_DATA_DIR)
    if env:
        return Path(env).expanduser()
    if os.name == "nt":
        base = os.environ.get("APPDATA") or (Path.home() / "AppData" / "Roaming")
        return Path(base) / "SSHManager"
    return Path.home() / ".config" / "ssh-manager"


def restrict_permissions(path: Path) -> None:
    """Restringe o acesso ao arquivo ao usuário atual (melhor esforço)."""
    if os.name != "nt":
        try:
            path.chmod(0o600)
        except OSError:
            pass
        return

    user = os.environ.get("USERNAME")
    if not user:
        return
    try:
        subprocess.run(
            ["icacls", str(path), "/inheritance:r", "/grant:r", f"{user}:F"],
            check=False,
            capture_output=True,
            timeout=10,
        )
    except (OSError, subprocess.SubprocessError):
        # Sem privilégios para ajustar ACL: o arquivo herda a ACL do %APPDATA%,
        # que já é restrita ao usuário na configuração padrão do Windows.
        pass


def backup_path(path: Path) -> Path:
    return path.with_suffix(path.suffix + ".bak")


def atomic_write_bytes(path: Path, data: bytes, *, backup: bool = False) -> None:
    """Grava bytes de forma atômica, opcionalmente com backup da versão anterior."""
    existed = path.exists()
    path.parent.mkdir(parents=True, exist_ok=True)

    fd, tmp_name = tempfile.mkstemp(
        dir=str(path.parent), prefix=f".{path.name}.", suffix=".tmp"
    )
    tmp_path = Path(tmp_name)
    try:
        with os.fdopen(fd, "wb") as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())

        if backup and existed:
            shutil.copy2(path, backup_path(path))
        os.replace(tmp_path, path)
    except OSError as exc:
        raise StorageError(f"Não foi possível gravar '{path}': {exc}") from exc
    finally:
        if tmp_path.exists():
            try:
                tmp_path.unlink()
            except OSError:
                pass

    if not existed:
        restrict_permissions(path)


def atomic_write_json(
    path: Path, payload: Mapping[str, Any], *, backup: bool = True
) -> None:
    """Grava JSON de forma atômica."""
    text = json.dumps(payload, ensure_ascii=False, indent=2) + "\n"
    atomic_write_bytes(path, text.encode("utf-8"), backup=backup)


def atomic_write_text(
    path: Path, text: str, *, encoding: str = "utf-8", backup: bool = False
) -> None:
    """Grava texto de forma atômica."""
    atomic_write_bytes(path, text.encode(encoding), backup=backup)
