#!/usr/bin/env python3
"""Ponto de entrada do SSH Manager.

Uso:
    python ssh_manager.py [--data-dir CAMINHO]
    python ssh_manager.py --list

A implementação está no pacote ``sshmanager``.
"""

from __future__ import annotations

from sshmanager.cli import main

if __name__ == "__main__":
    raise SystemExit(main())
