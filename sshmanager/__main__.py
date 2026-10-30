"""Permite executar o pacote com ``python -m sshmanager``."""

from __future__ import annotations

from .cli import main

if __name__ == "__main__":
    raise SystemExit(main())
