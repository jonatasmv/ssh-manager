"""Hierarquia de erros esperados da aplicação."""

from __future__ import annotations


class AppError(Exception):
    """Erro esperado, com mensagem amigável para o usuário final."""


class ValidationError(AppError):
    """Dados inválidos informados pelo usuário ou presentes no arquivo."""


class StorageError(AppError):
    """Falha de leitura/gravação do armazenamento local."""


class CryptoError(AppError):
    """Falha ao criar, ler ou usar a chave de criptografia."""
