"""API pública do SSH Manager.

Reexporta os componentes principais para uso em testes, scripts e integrações.
"""

from __future__ import annotations

from .cli import SSHManagerApp, main, parse_args
from .config import APP_NAME, APP_VERSION, EXPORT_FIELDS, EXPORT_FORMAT, SCHEMA_VERSION
from .crypto import SecretCipher
from .errors import AppError, CryptoError, StorageError, ValidationError
from .models import Server, parse_port, validate_server, validate_username
from .presentation import build_ssh_command, mask_secret, print_server_table
from .repository import ServerRepository
from .transfer import (
    ImportResult,
    build_export_payload,
    decrypt_export_payload,
    export_csv_text,
    import_record_to_server,
    merge_import,
    normalize_import_record,
    read_csv_records,
    server_to_export_record,
)

__version__ = APP_VERSION

__all__ = [
    "APP_NAME",
    "APP_VERSION",
    "EXPORT_FIELDS",
    "EXPORT_FORMAT",
    "SCHEMA_VERSION",
    "AppError",
    "CryptoError",
    "ImportResult",
    "SSHManagerApp",
    "SecretCipher",
    "Server",
    "ServerRepository",
    "StorageError",
    "ValidationError",
    "build_export_payload",
    "build_ssh_command",
    "decrypt_export_payload",
    "export_csv_text",
    "import_record_to_server",
    "main",
    "mask_secret",
    "merge_import",
    "normalize_import_record",
    "parse_args",
    "parse_port",
    "print_server_table",
    "read_csv_records",
    "server_to_export_record",
    "validate_server",
    "validate_username",
]
