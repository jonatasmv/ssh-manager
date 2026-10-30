"""Formatação de tabelas, comandos SSH e área de transferência."""

from __future__ import annotations

import os
import re
import shutil
import subprocess
import sys
from collections.abc import Sequence

from .models import Server

TABLE_COLUMNS: tuple[tuple[str, int], ...] = (
    ("#", 3),
    ("Nome", 18),
    ("Grupo", 13),
    ("Host", 24),
    ("Porta", 5),
    ("Usuário", 12),
    ("Descrição", 20),
)


def _truncate(text: str, width: int) -> str:
    text = text.replace("\n", " ")
    if len(text) <= width:
        return text
    return text[: max(0, width - 3)] + "..."


def print_server_table(servers: Sequence[Server]) -> None:
    headers = [header for header, _ in TABLE_COLUMNS]
    widths = [width for _, width in TABLE_COLUMNS]
    separator = "+" + "+".join("-" * (width + 2) for width in widths) + "+"

    print(separator)
    print("| " + " | ".join(h.ljust(w) for h, w in zip(headers, widths)) + " |")
    print(separator)

    for index, server in enumerate(servers, start=1):
        row = [
            str(index),
            _truncate(server.name, widths[1]),
            _truncate(server.group or "-", widths[2]),
            _truncate(server.host() or "-", widths[3]),
            str(server.port),
            _truncate(server.user or "-", widths[5]),
            _truncate(server.description or "-", widths[6]),
        ]
        print("| " + " | ".join(cell.ljust(w) for cell, w in zip(row, widths)) + " |")
    print(separator)


def mask_secret(value: str) -> str:
    return "******** (definida)" if value else "(vazia)"


def quote_arg(value: str) -> str:
    return f'"{value}"' if re.search(r"\s", value) else value


def build_ssh_command(server: Server) -> str:
    parts = ["ssh"]
    if server.port != 22:
        parts += ["-p", str(server.port)]
    if server.ssh_key:
        parts += ["-i", quote_arg(server.ssh_key)]
    parts.append(f"{server.user}@{server.host()}")
    return " ".join(parts)


def copy_to_clipboard(text: str) -> bool:
    if os.name == "nt":
        command = [
            "powershell",
            "-NoProfile",
            "-NonInteractive",
            "-Command",
            "Set-Clipboard -Value $input",
        ]
        try:
            subprocess.run(
                command,
                input=text,
                text=True,
                check=True,
                timeout=10,
                capture_output=True,
            )
            return True
        except (OSError, subprocess.SubprocessError):
            return False

    if sys.platform == "darwin":
        candidates = [["pbcopy"]]
    else:
        candidates = [
            ["wl-copy"],
            ["xclip", "-selection", "clipboard"],
            ["xsel", "--clipboard", "--input"],
        ]

    for candidate in candidates:
        if shutil.which(candidate[0]) is None:
            continue
        try:
            subprocess.run(
                candidate,
                input=text.encode("utf-8"),
                check=True,
                timeout=10,
                capture_output=True,
            )
            return True
        except (OSError, subprocess.SubprocessError):
            continue
    return False


def configure_console() -> None:
    """Garante acentuação correta no console quando possível."""
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8", errors="replace")  # type: ignore[attr-defined]
        except (AttributeError, OSError):
            pass
