"""Persistência local dos servidores."""

from __future__ import annotations

import json
import sys
from collections.abc import Sequence
from pathlib import Path
from typing import Any

from .config import SCHEMA_VERSION
from .crypto import SecretCipher
from .errors import CryptoError, StorageError, ValidationError
from .models import Server
from .utils import atomic_write_json, backup_path


class ServerRepository:
    """Mantém os servidores em memória e persiste em servers.json."""

    def __init__(self, data_dir: Path) -> None:
        self.data_dir = Path(data_dir)
        try:
            self.data_dir.mkdir(parents=True, exist_ok=True)
        except OSError as exc:
            raise StorageError(
                f"Não foi possível criar o diretório de dados '{self.data_dir}': {exc}"
            ) from exc

        self.path = self.data_dir / "servers.json"
        key_path = self.data_dir / "secret.key"
        if self.path.exists() and not key_path.exists():
            raise CryptoError(
                f"O arquivo '{self.path.name}' existe, mas a chave '{key_path.name}' "
                "não foi encontrada. Restaure o secret.key original ou remova os "
                "dados para recomeçar; uma chave nova não decifra as senhas antigas."
            )
        self._cipher = SecretCipher(key_path)
        self._servers: list[Server] = self._load()

    # -- leitura ---------------------------------------------------------
    def all(self) -> list[Server]:
        return list(self._servers)

    def get(self, server_id: str) -> Server | None:
        return next((s for s in self._servers if s.id == server_id), None)

    def name_exists(self, name: str, *, exclude_id: str | None = None) -> bool:
        target = name.strip().casefold()
        return any(
            s.name.strip().casefold() == target and s.id != exclude_id
            for s in self._servers
        )

    def _load(self) -> list[Server]:
        if not self.path.exists():
            return []

        payload = self._read_payload(self.path)
        version = payload.get("version", 1)
        if not isinstance(version, int) or not 1 <= version <= SCHEMA_VERSION:
            raise StorageError(
                f"Versão de dados não suportada ({version}). "
                f"Este programa suporta até a versão {SCHEMA_VERSION}."
            )

        items = payload.get("servers", [])
        if not isinstance(items, list):
            raise StorageError(
                "O arquivo de dados está corrompido: 'servers' não é uma lista."
            )

        return [Server.from_dict(item, self._cipher) for item in items]

    def _read_payload(self, path: Path) -> dict[str, Any]:
        try:
            raw = path.read_text(encoding="utf-8")
            payload = json.loads(raw)
        except (OSError, json.JSONDecodeError) as exc:
            backup = backup_path(self.path)
            if path == self.path and backup.exists():
                print(
                    f"Aviso: '{path}' está corrompido ({exc}). "
                    f"Carregando o backup '{backup.name}'.",
                    file=sys.stderr,
                )
                return self._read_payload(backup)
            raise StorageError(
                f"Não foi possível ler '{path}': {exc}. "
                "Verifique o arquivo ou restaure um backup."
            ) from exc

        if not isinstance(payload, dict):
            raise StorageError(f"Formato inválido em '{path}'.")
        return payload

    # -- escrita ---------------------------------------------------------
    def _save(self) -> None:
        payload = {
            "version": SCHEMA_VERSION,
            "servers": [server.to_dict(self._cipher) for server in self._servers],
        }
        atomic_write_json(self.path, payload)

    def add(self, server: Server) -> None:
        if self.name_exists(server.name):
            raise ValidationError(f"Já existe um servidor com o nome '{server.name}'.")
        self._servers.append(server)
        self._save()

    def update(self, server: Server) -> None:
        if self.name_exists(server.name, exclude_id=server.id):
            raise ValidationError(f"Já existe um servidor com o nome '{server.name}'.")
        for index, current in enumerate(self._servers):
            if current.id == server.id:
                self._servers[index] = server
                self._save()
                return
        raise StorageError("Servidor não encontrado para atualização.")

    def delete(self, server_id: str) -> None:
        remaining = [s for s in self._servers if s.id != server_id]
        if len(remaining) == len(self._servers):
            raise StorageError("Servidor não encontrado para remoção.")
        self._servers = remaining
        self._save()

    def replace_all(self, servers: Sequence[Server]) -> None:
        """Substitui todo o inventário e grava uma única vez (usado na importação)."""
        self._servers = list(servers)
        self._save()
