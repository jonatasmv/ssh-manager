"""Exportação e importação de inventário (núcleo sem prompts)."""

from __future__ import annotations

import csv
import io
import json
import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field, replace
from typing import Any

from cryptography.fernet import Fernet, InvalidToken

from .config import EXPORT_FIELDS, EXPORT_FORMAT, EXPORT_VERSION
from .crypto import create_kdf, key_from_kdf
from .errors import AppError, CryptoError, ValidationError
from .models import Server, parse_port, validate_server
from .utils import utc_now

EXPORT_KEY_ALIASES: dict[str, str] = {
    "name": "name",
    "nome": "name",
    "group": "group",
    "grupo": "group",
    "dns": "dns",
    "host": "dns",
    "hostname": "dns",
    "ip": "ip",
    "endereco_ip": "ip",
    "endereço_ip": "ip",
    "port": "port",
    "porta": "port",
    "user": "user",
    "usuario": "user",
    "usuário": "user",
    "user_password": "user_password",
    "senha": "user_password",
    "senha_usuario": "user_password",
    "senha_do_usuario": "user_password",
    "root_user": "root_user",
    "root": "root_user",
    "root_password": "root_password",
    "senha_root": "root_password",
    "senha_do_root": "root_password",
    "description": "description",
    "descricao": "description",
    "descrição": "description",
    "ssh_key": "ssh_key",
    "chave_ssh": "ssh_key",
    "chave": "ssh_key",
}
IMPORTABLE_FIELDS = frozenset(EXPORT_FIELDS) | {"user_password", "root_password"}


def normalize_import_record(record: Mapping[str, Any]) -> dict[str, Any]:
    """Normaliza chaves (inglês/português) e descarta campos desconhecidos."""
    if not isinstance(record, Mapping):
        raise ValidationError("Registro de importação inválido (esperado objeto).")
    normalized: dict[str, Any] = {}
    for raw_key, value in record.items():
        key = re.sub(r"[\s-]+", "_", str(raw_key).strip().casefold())
        canonical = EXPORT_KEY_ALIASES.get(key)
        if canonical in IMPORTABLE_FIELDS:
            normalized[canonical] = "" if value is None else value
    return normalized


def import_record_to_server(record: Mapping[str, Any]) -> tuple[Server, bool, bool]:
    """Valida um registro importado e devolve (servidor, tem_senha, tem_senha_root)."""
    normalized = normalize_import_record(record)

    def text(key: str, default: str = "") -> str:
        if key not in normalized:
            return default
        value = normalized[key]
        return str(value).strip() if value is not None else ""

    has_user_password = "user_password" in normalized
    has_root_password = "root_password" in normalized
    server = Server(
        name=text("name"),
        group=text("group"),
        dns=text("dns").rstrip("."),
        ip=text("ip"),
        port=parse_port(normalized.get("port")),
        user=text("user"),
        user_password=text("user_password"),
        root_user=text("root_user", "root"),
        root_password=text("root_password"),
        description=text("description"),
        ssh_key=text("ssh_key"),
    )
    validate_server(server)
    return server, has_user_password, has_root_password


def server_to_export_record(
    server: Server, *, include_passwords: bool
) -> dict[str, Any]:
    record: dict[str, Any] = {field: getattr(server, field) for field in EXPORT_FIELDS}
    if include_passwords:
        record["user_password"] = server.user_password
        record["root_password"] = server.root_password
    return record


def build_export_payload(
    servers: Sequence[Server],
    *,
    include_passwords: bool,
    passphrase: str | None = None,
) -> dict[str, Any]:
    """Monta o JSON de exportação; com senhas, cifra o conteúdo com scrypt+Fernet."""
    records = [
        server_to_export_record(server, include_passwords=include_passwords)
        for server in servers
    ]
    payload: dict[str, Any] = {
        "format": EXPORT_FORMAT,
        "version": EXPORT_VERSION,
        "exported_at": utc_now(),
        "encrypted": False,
        "includes_passwords": include_passwords,
        "servers": records,
    }
    if not include_passwords:
        return payload
    if not passphrase:
        raise CryptoError("Informe uma senha para exportar as senhas.")

    kdf, key = create_kdf(passphrase)
    plaintext = json.dumps(
        {"servers": records}, ensure_ascii=False, separators=(",", ":")
    ).encode("utf-8")

    payload["encrypted"] = True
    payload["servers"] = []
    payload["kdf"] = kdf
    payload["data"] = Fernet(key).encrypt(plaintext).decode("ascii")
    return payload


def decrypt_export_payload(
    payload: Mapping[str, Any], passphrase: str
) -> list[dict[str, Any]]:
    """Decifra uma exportação protegida por senha e devolve os registros."""
    kdf = payload.get("kdf")
    if not isinstance(kdf, Mapping) or kdf.get("name") != "scrypt":
        raise CryptoError("Parâmetros de criptografia ausentes ou não suportados.")

    key = key_from_kdf(passphrase, kdf)
    token = payload.get("data")
    if not isinstance(token, str) or not token:
        raise CryptoError("Arquivo de exportação sem conteúdo cifrado.")

    try:
        plaintext = Fernet(key).decrypt(token.encode("ascii"))
        inner = json.loads(plaintext.decode("utf-8"))
    except (InvalidToken, ValueError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise CryptoError(
            "Senha incorreta ou arquivo de exportação corrompido."
        ) from exc

    servers = inner.get("servers") if isinstance(inner, dict) else None
    if not isinstance(servers, list):
        raise CryptoError("Conteúdo da exportação inválido.")
    return servers


def export_csv_text(servers: Sequence[Server]) -> str:
    """Gera CSV sem senhas (seguro para compartilhar)."""
    buffer = io.StringIO()
    writer = csv.DictWriter(
        buffer, fieldnames=list(EXPORT_FIELDS), extrasaction="ignore"
    )
    writer.writeheader()
    for server in servers:
        writer.writerow(server_to_export_record(server, include_passwords=False))
    return buffer.getvalue()


def read_csv_records(text: str) -> list[dict[str, Any]]:
    reader = csv.DictReader(io.StringIO(text))
    if not reader.fieldnames:
        raise AppError("O CSV não possui cabeçalho.")
    return [dict(row) for row in reader]


@dataclass
class ImportResult:
    servers: list[Server]
    added: int = 0
    updated: int = 0
    skipped: int = 0
    errors: list[str] = field(default_factory=list)
    included_passwords: bool = False


def merge_import(
    existing: Sequence[Server],
    records: Sequence[Mapping[str, Any]],
    *,
    overwrite: bool,
) -> ImportResult:
    """Mescla registros importados ao inventário, sem tocar no disco."""
    result = ImportResult(servers=list(existing))
    by_name: dict[str, Server] = {
        server.name.casefold(): server for server in result.servers
    }
    index: dict[str, int] = {
        server.name.casefold(): position
        for position, server in enumerate(result.servers)
    }

    for record in records:
        display_name = "(sem nome)"
        if isinstance(record, Mapping):
            raw_name = record.get("name") or record.get("nome")
            if raw_name:
                display_name = str(raw_name)
        try:
            incoming, has_user_password, has_root_password = import_record_to_server(
                record
            )
        except AppError as exc:
            result.errors.append(f"{display_name}: {exc}")
            result.skipped += 1
            continue

        result.included_passwords = (
            result.included_passwords or has_user_password or has_root_password
        )
        key = incoming.name.casefold()
        current = by_name.get(key)

        if current is None:
            result.servers.append(incoming)
            by_name[key] = incoming
            index[key] = len(result.servers) - 1
            result.added += 1
            continue

        if not overwrite:
            result.skipped += 1
            continue

        try:
            merged = replace(
                current,
                name=incoming.name,
                group=incoming.group,
                dns=incoming.dns,
                ip=incoming.ip,
                port=incoming.port,
                user=incoming.user,
                root_user=incoming.root_user,
                description=incoming.description,
                ssh_key=incoming.ssh_key,
                updated_at=utc_now(),
            )
            if has_user_password:
                merged.user_password = incoming.user_password
            if has_root_password:
                merged.root_password = incoming.root_password
            validate_server(merged)
        except ValidationError as exc:
            result.errors.append(f"{incoming.name}: {exc}")
            result.skipped += 1
            continue

        result.servers[index[key]] = merged
        by_name[key] = merged
        result.updated += 1

    return result
