"""Constantes de configuração do SSH Manager."""

from __future__ import annotations

APP_NAME = "SSH Manager"
APP_VERSION = "1.1.0"

# Versão do formato de servers.json. A versão 2 adicionou grupo e porta.
SCHEMA_VERSION = 2

# Variável de ambiente que sobrescreve o diretório de dados.
ENV_DATA_DIR = "SSH_MANAGER_HOME"

# Formato dos arquivos de exportação/importação.
EXPORT_FORMAT = "ssh-manager-export"
EXPORT_VERSION = 1
EXPORT_FIELDS: tuple[str, ...] = (
    "name",
    "group",
    "dns",
    "ip",
    "port",
    "user",
    "root_user",
    "description",
    "ssh_key",
)
