"""Leitura e validação de dados digitados no terminal."""

from __future__ import annotations

import getpass
import ipaddress
from collections.abc import Sequence
from pathlib import Path

from .errors import ValidationError
from .models import CONTROL_CHARS, HOSTNAME_RE, parse_port, validate_username


def ask_text(
    label: str,
    *,
    default: str | None = None,
    required: bool = False,
    max_len: int = 0,
    clearable: bool = False,
) -> str:
    """Pergunta um texto. Enter usa o padrão; '-' limpa quando permitido."""
    while True:
        suffix = f" [{default}]" if default not in (None, "") else ""
        raw = input(f"{label}{suffix}: ").strip()

        if raw == "":
            if default is not None:
                value = default
            elif required:
                print("  ! Campo obrigatório.")
                continue
            else:
                return ""
        elif raw == "-" and clearable:
            return ""
        else:
            value = raw

        if max_len and len(value) > max_len:
            print(f"  ! Máximo de {max_len} caracteres.")
            continue
        if CONTROL_CHARS.search(value):
            print("  ! O valor contém caracteres inválidos.")
            continue
        return value


def ask_dns(default: str = "", *, clearable: bool = False) -> str:
    while True:
        value = ask_text(
            "DNS (hostname)", default=default or None, max_len=253, clearable=clearable
        )
        if not value:
            return ""
        value = value.rstrip(".")
        if not HOSTNAME_RE.fullmatch(value):
            print("  ! Hostname inválido. Exemplo: servidor.exemplo.com")
            continue
        return value


def ask_ip(default: str = "", *, clearable: bool = False) -> str:
    while True:
        value = ask_text("IP", default=default or None, clearable=clearable)
        if not value:
            return ""
        try:
            return str(ipaddress.ip_address(value))
        except ValueError:
            print("  ! IP inválido. Exemplos: 192.168.0.10 ou 2001:db8::1")


def ask_group(
    default: str = "", *, clearable: bool = False, known: Sequence[str] = ()
) -> str:
    """Pergunta o grupo; grupos existentes são sugeridos."""
    if known:
        print(f"  Grupos existentes: {', '.join(known)}")
    return ask_text(
        "Grupo (Enter sem grupo)",
        default=default or None,
        max_len=40,
        clearable=clearable,
    )


def ask_port(default: int = 22) -> int:
    while True:
        value = ask_text("Porta SSH", default=str(default), max_len=5)
        try:
            return parse_port(value)
        except ValidationError as exc:
            print(f"  ! {exc}")


def ask_username(
    label: str,
    *,
    default: str | None = None,
    required: bool = True,
    clearable: bool = False,
) -> str:
    while True:
        value = ask_text(
            label,
            default=default,
            required=required,
            max_len=64,
            clearable=clearable,
        )
        if not value and not required:
            return ""
        try:
            validate_username(value, label)
        except ValidationError as exc:
            print(f"  ! {exc}")
            continue
        return value


def ask_ssh_key(default: str = "", *, clearable: bool = False) -> str:
    while True:
        value = ask_text(
            "Chave SSH (caminho do arquivo privado)",
            default=default or None,
            max_len=1024,
            clearable=clearable,
        )
        if not value:
            return ""
        path = Path(value).expanduser()
        if path.is_file():
            return str(path.resolve())
        if confirm(
            f"  Arquivo '{path}' não encontrado. Salvar mesmo assim?", default=False
        ):
            return str(path.resolve())
        default = ""


def read_password(label: str) -> str:
    """Lê uma senha oculta, com confirmação. Enter retorna vazio."""
    while True:
        first = getpass.getpass(f"{label}: ")
        if not first:
            return ""
        second = getpass.getpass("Confirme a senha: ")
        if first != second:
            print("  ! As senhas não conferem. Tente novamente.")
            continue
        return first


def read_new_passphrase(label: str = "Senha de proteção do arquivo") -> str:
    """Lê uma senha de exportação com confirmação e mínimo de 8 caracteres."""
    while True:
        first = getpass.getpass(f"{label}: ")
        if len(first) < 8:
            print("  ! Use pelo menos 8 caracteres.")
            continue
        second = getpass.getpass("Confirme a senha: ")
        if first != second:
            print("  ! As senhas não conferem. Tente novamente.")
            continue
        return first


def edit_password(label: str, has_value: bool) -> str | None:
    """Edita uma senha. Retorna None (manter), '' (remover) ou a nova senha."""
    if has_value:
        print(f"{label}: [Enter] manter | [n] nova | [-] remover")
    else:
        print(f"{label}: [Enter] manter vazio | [n] definir")

    while True:
        option = input("  opção: ").strip().lower()
        if option == "":
            return None
        if option == "-" and has_value:
            return ""
        if option == "n":
            return read_password(label)
        print("  ! Digite Enter, 'n' ou '-'.")


def confirm(text: str, *, default: bool = False) -> bool:
    hint = "[S/n]" if default else "[s/N]"
    while True:
        raw = input(f"{text} {hint}: ").strip().lower()
        if not raw:
            return default
        if raw in {"s", "sim", "y", "yes"}:
            return True
        if raw in {"n", "nao", "não", "no"}:
            return False
        print("  ! Responda 's' ou 'n'.")
