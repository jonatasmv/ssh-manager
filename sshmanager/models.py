"""Modelo de servidor e validações de domínio."""

from __future__ import annotations

import ipaddress
import re
import uuid
from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import Any

from .crypto import SecretCipher
from .errors import StorageError, ValidationError
from .utils import utc_now

CONTROL_CHARS = re.compile(r"[\x00-\x1f\x7f]")
HOST_LABEL = r"[A-Za-z0-9_](?:[A-Za-z0-9_-]{0,61}[A-Za-z0-9_])?"
HOSTNAME_RE = re.compile(rf"^{HOST_LABEL}(?:\.{HOST_LABEL})*$")


def parse_port(value: Any) -> int:
    """Converte e valida uma porta SSH; vazio usa o padrão 22."""
    if value is None or str(value).strip() == "":
        return 22
    try:
        port = int(str(value).strip())
    except (TypeError, ValueError) as exc:
        raise ValidationError(f"Porta inválida: '{value}'.") from exc
    if not 1 <= port <= 65535:
        raise ValidationError("A porta SSH deve estar entre 1 e 65535.")
    return port


@dataclass
class Server:
    name: str
    group: str = ""
    ip: str = ""
    dns: str = ""
    port: int = 22
    user: str = ""
    user_password: str = ""
    root_user: str = "root"
    root_password: str = ""
    description: str = ""
    ssh_key: str = ""
    id: str = field(default_factory=lambda: uuid.uuid4().hex)
    created_at: str = field(default_factory=utc_now)
    updated_at: str = field(default_factory=utc_now)

    def host(self) -> str:
        """Host usado para conexão: DNS quando informado, senão IP."""
        return self.dns or self.ip

    def to_dict(self, cipher: SecretCipher) -> dict[str, Any]:
        """Serializa o servidor, cifrando as senhas."""
        return {
            "id": self.id,
            "name": self.name,
            "group": self.group,
            "dns": self.dns,
            "ip": self.ip,
            "port": self.port,
            "user": self.user,
            "user_password": cipher.encrypt(self.user_password),
            "root_user": self.root_user,
            "root_password": cipher.encrypt(self.root_password),
            "description": self.description,
            "ssh_key": self.ssh_key,
            "created_at": self.created_at,
            "updated_at": self.updated_at,
        }

    @classmethod
    def from_dict(cls, data: Mapping[str, Any], cipher: SecretCipher) -> Server:
        """Reconstrói o servidor, decifrando as senhas."""
        if not isinstance(data, Mapping):
            raise StorageError("Registro de servidor inválido no arquivo de dados.")

        def text(key: str) -> str:
            value = data.get(key, "")
            if value is None:
                return ""
            if not isinstance(value, str):
                raise StorageError(
                    f"Campo '{key}' inválido no arquivo de dados (esperado texto)."
                )
            return value

        try:
            port = parse_port(data.get("port", 22))
        except ValidationError as exc:
            raise StorageError(
                "Campo 'port' inválido no arquivo de dados (use 1 a 65535)."
            ) from exc

        return cls(
            id=text("id") or uuid.uuid4().hex,
            name=text("name"),
            group=text("group"),
            dns=text("dns"),
            ip=text("ip"),
            port=port,
            user=text("user"),
            user_password=cipher.decrypt(text("user_password")),
            root_user=text("root_user"),
            root_password=cipher.decrypt(text("root_password")),
            description=text("description"),
            ssh_key=text("ssh_key"),
            created_at=text("created_at") or utc_now(),
            updated_at=text("updated_at") or utc_now(),
        )


def _validate_text(value: str, label: str, max_len: int) -> None:
    if len(value) > max_len:
        raise ValidationError(f"{label} deve ter no máximo {max_len} caracteres.")
    if CONTROL_CHARS.search(value):
        raise ValidationError(f"{label} contém caracteres inválidos.")


def validate_username(user: str, label: str = "Usuário") -> None:
    if not user:
        raise ValidationError(f"{label} é obrigatório.")
    if len(user) > 64:
        raise ValidationError(f"{label} deve ter no máximo 64 caracteres.")
    if CONTROL_CHARS.search(user) or re.search(r"\s", user) or user.startswith("-"):
        raise ValidationError(f"{label} inválido (sem espaços e sem iniciar com '-').")


def validate_server(server: Server) -> None:
    """Valida o registro completo antes de qualquer gravação."""
    if not server.name.strip():
        raise ValidationError("O nome é obrigatório.")
    _validate_text(server.name, "Nome", 80)

    _validate_text(server.group, "Grupo", 40)
    if not isinstance(server.port, int) or not 1 <= server.port <= 65535:
        raise ValidationError("A porta SSH deve estar entre 1 e 65535.")

    if not server.dns and not server.ip:
        raise ValidationError("Informe ao menos DNS ou IP.")
    if server.dns:
        dns = server.dns.rstrip(".")
        if len(dns) > 253 or not HOSTNAME_RE.fullmatch(dns):
            raise ValidationError(
                f"DNS inválido: '{server.dns}'. Exemplo: servidor.exemplo.com"
            )
    if server.ip:
        try:
            ipaddress.ip_address(server.ip)
        except ValueError as exc:
            raise ValidationError(f"IP inválido: '{server.ip}'.") from exc

    validate_username(server.user)
    if server.root_user:
        validate_username(server.root_user, "Usuário root")

    _validate_text(server.description, "Descrição", 200)
    _validate_text(server.ssh_key, "Caminho da chave SSH", 1024)
