"""Interface de linha de comando do SSH Manager."""

from __future__ import annotations

import argparse
import getpass
import json
import shutil
import subprocess
import sys
from collections.abc import Callable, Mapping, Sequence
from datetime import datetime
from pathlib import Path
from typing import Any

from .config import APP_NAME, APP_VERSION, EXPORT_FORMAT
from .errors import AppError
from .models import Server, validate_server
from .presentation import (
    build_ssh_command,
    configure_console,
    copy_to_clipboard,
    mask_secret,
    print_server_table,
    quote_arg,
)
from .prompts import (
    ask_dns,
    ask_group,
    ask_ip,
    ask_port,
    ask_ssh_key,
    ask_text,
    ask_username,
    confirm,
    edit_password,
    read_new_passphrase,
    read_password,
)
from .repository import ServerRepository
from .transfer import (
    build_export_payload,
    decrypt_export_payload,
    export_csv_text,
    merge_import,
    read_csv_records,
)
from .utils import atomic_write_json, atomic_write_text, default_data_dir, utc_now


class SSHManagerApp:
    MENU: tuple[tuple[str, str], ...] = (
        ("1", "Listar servidores"),
        ("2", "Cadastrar servidor"),
        ("3", "Editar servidor"),
        ("4", "Remover servidor"),
        ("5", "Buscar"),
        ("6", "Ver detalhes"),
        ("7", "Copiar comando SSH"),
        ("8", "Abrir sessão SSH"),
        ("9", "Listar por grupo"),
        ("10", "Exportar servidores"),
        ("11", "Importar servidores"),
        ("0", "Sair"),
    )

    def __init__(self, repository: ServerRepository) -> None:
        self.repo = repository

    # -- menu ------------------------------------------------------------
    def run(self) -> None:
        actions = self._actions()
        while True:
            self._print_menu()
            try:
                choice = input("Escolha uma opção: ").strip()
            except EOFError:
                print()
                return

            if choice.lower() in {"0", "q", "sair"}:
                print("Até logo.")
                return

            action = actions.get(choice)
            if action is None:
                print("  ! Opção inválida.")
                continue

            try:
                action()
            except AppError as exc:
                print(f"\n  Erro: {exc}")
            except KeyboardInterrupt:
                print("\n  Operação cancelada.")
            except EOFError:
                print()
                return
            print()

    def _actions(self) -> dict[str, Callable[[], None]]:
        return {
            "1": self.list_servers,
            "2": self.add_server,
            "3": self.edit_server,
            "4": self.remove_server,
            "5": self.search_servers,
            "6": self.show_details,
            "7": self.copy_ssh_command,
            "8": self.open_ssh_session,
            "9": self.list_by_group,
            "10": self.export_servers,
            "11": self.import_servers,
        }

    def _print_menu(self) -> None:
        print("=" * 66)
        print(f"  {APP_NAME} {APP_VERSION}")
        print(f"  Dados: {self.repo.data_dir}")
        print("=" * 66)
        for key, label in self.MENU:
            print(f"  {key}  {label}")
        print("=" * 66)

    def _select_server(self, action: str) -> Server | None:
        servers = self.repo.all()
        if not servers:
            print("  Nenhum servidor cadastrado.")
            return None

        print(f"\n--- {action} ---")
        print_server_table(servers)
        while True:
            raw = input("Número ou nome do servidor (Enter cancela): ").strip()
            if not raw:
                return None
            if raw.isdigit():
                index = int(raw) - 1
                if 0 <= index < len(servers):
                    return servers[index]
            target = raw.casefold()
            exact = [s for s in servers if s.name.casefold() == target]
            if len(exact) == 1:
                return exact[0]
            partial = [s for s in servers if target in s.name.casefold()]
            if len(partial) == 1:
                return partial[0]
            print("  ! Servidor não encontrado. Tente o número exibido na tabela.")

    # -- operações -------------------------------------------------------
    def list_servers(self, servers: Sequence[Server] | None = None) -> None:
        data = list(servers) if servers is not None else self.repo.all()
        print()
        if not data:
            print("  Nenhum servidor cadastrado.")
            return
        print(f"  {len(data)} servidor(es):")
        print_server_table(data)

    def add_server(self) -> None:
        print("\n--- Cadastrar servidor ---")
        name = self._ask_unique_name()
        group = self._normalize_group_name(ask_group(known=self._group_names()))
        dns, ip = self._ask_host_pair()
        port = ask_port()

        user = ask_username("Usuário SSH")
        user_password = read_password("Senha do usuário")
        root_user = ask_username("Usuário root", default="root")
        root_password = read_password("Senha do root")
        description = ask_text("Descrição", max_len=200)
        ssh_key = ask_ssh_key()

        server = Server(
            name=name,
            group=group,
            dns=dns,
            ip=ip,
            port=port,
            user=user,
            user_password=user_password,
            root_user=root_user,
            root_password=root_password,
            description=description,
            ssh_key=ssh_key,
        )
        validate_server(server)
        self.repo.add(server)
        print(f"\n  Servidor '{server.name}' cadastrado com sucesso.")

    def edit_server(self) -> None:
        server = self._select_server("Editar servidor")
        if server is None:
            return

        print(f"\n--- Editando '{server.name}' ---")
        print("  Enter mantém o valor atual; '-' limpa campos opcionais.")

        name = self._ask_unique_name(server.name, exclude_id=server.id)
        group = self._normalize_group_name(
            ask_group(
                server.group,
                clearable=True,
                known=self._group_names(),
            )
        )
        dns = ask_dns(server.dns, clearable=True)
        ip = ask_ip(server.ip, clearable=True)
        while not dns and not ip:
            print("  ! Informe ao menos DNS ou IP.")
            dns = ask_dns(dns, clearable=True)
            if not dns:
                ip = ask_ip(ip, clearable=True)

        port = ask_port(server.port)
        user = ask_username("Usuário SSH", default=server.user)
        user_password = edit_password("Senha do usuário", bool(server.user_password))
        root_user = ask_username(
            "Usuário root", default=server.root_user, required=False, clearable=True
        )
        root_password = edit_password("Senha do root", bool(server.root_password))
        description = ask_text(
            "Descrição", default=server.description, max_len=200, clearable=True
        )
        ssh_key = ask_ssh_key(server.ssh_key, clearable=True)

        updated = Server(
            id=server.id,
            name=name,
            group=group,
            dns=dns,
            ip=ip,
            port=port,
            user=user,
            user_password=server.user_password,
            root_user=root_user,
            root_password=server.root_password,
            description=description,
            ssh_key=ssh_key,
            created_at=server.created_at,
            updated_at=utc_now(),
        )
        if user_password is not None:
            updated.user_password = user_password
        if root_password is not None:
            updated.root_password = root_password

        validate_server(updated)
        self.repo.update(updated)
        print("  Servidor atualizado com sucesso.")

    def remove_server(self) -> None:
        server = self._select_server("Remover servidor")
        if server is None:
            return

        print(f"\n  Nome...: {server.name}")
        print(f"  Host...: {server.host()}")
        print(f"  Usuário: {server.user}")
        if not confirm(f"Remover '{server.name}' definitivamente?", default=False):
            print("  Remoção cancelada.")
            return

        self.repo.delete(server.id)
        print(f"  Servidor '{server.name}' removido.")

    def search_servers(self) -> None:
        term = ask_text(
            "Buscar (nome, host, usuário ou descrição)", required=True, max_len=80
        ).casefold()
        matches = []
        for server in self.repo.all():
            haystack = (
                f"{server.name} {server.group} {server.dns} {server.ip} "
                f"{server.port} {server.user} {server.root_user} "
                f"{server.description} {server.ssh_key}"
            ).casefold()
            if term in haystack:
                matches.append(server)
        print(f"\n  {len(matches)} resultado(s) para '{term}':")
        if matches:
            print_server_table(matches)

    def show_details(self) -> None:
        server = self._select_server("Ver detalhes")
        if server is None:
            return

        print(f"\n--- {server.name} ---")
        print(f"  ID..............: {server.id}")
        print(f"  Grupo...........: {server.group or '-'}")
        print(f"  DNS.............: {server.dns or '-'}")
        print(f"  IP..............: {server.ip or '-'}")
        print(f"  Host usado......: {server.host()}")
        print(f"  Porta...........: {server.port}")
        print(f"  Usuário.........: {server.user}")
        print(f"  Senha do usuário: {mask_secret(server.user_password)}")
        print(f"  Usuário root....: {server.root_user or '-'}")
        print(f"  Senha do root...: {mask_secret(server.root_password)}")
        print(f"  Descrição.......: {server.description or '-'}")
        print(f"  Chave SSH.......: {server.ssh_key or '-'}")
        print(f"  Criado em.......: {server.created_at}")
        print(f"  Atualizado em...: {server.updated_at}")
        print(f"  Comando.........: {build_ssh_command(server)}")

        if (server.user_password or server.root_password) and confirm(
            "  Mostrar senhas em texto claro?", default=False
        ):
            print(f"  Senha do usuário: {server.user_password or '(vazia)'}")
            print(f"  Senha do root...: {server.root_password or '(vazia)'}")

    def copy_ssh_command(self) -> None:
        server = self._select_server("Copiar comando SSH")
        if server is None:
            return

        command = build_ssh_command(server)
        print(f"\n  Comando: {command}")
        if copy_to_clipboard(command):
            print("  Comando copiado para a área de transferência.")
        else:
            print("  Não foi possível copiar automaticamente; selecione o texto acima.")

    def open_ssh_session(self) -> None:
        server = self._select_server("Abrir sessão SSH")
        if server is None:
            return

        if shutil.which("ssh") is None:
            raise AppError(
                "Cliente SSH não encontrado no PATH. "
                "No Windows, instale o recurso 'OpenSSH Client'."
            )

        args = ["ssh"]
        if server.port != 22:
            args += ["-p", str(server.port)]
        if server.ssh_key:
            key = Path(server.ssh_key)
            if key.is_file():
                args += ["-i", str(key)]
            else:
                print(f"  ! Chave não encontrada: {key}. Conectando sem '-i'.")
        args.append(f"{server.user}@{server.host()}")

        print(f"\n  Executando: {' '.join(quote_arg(arg) for arg in args)}")
        if server.user_password:
            print(
                "  Observação: a senha salva não é enviada automaticamente; "
                "o ssh solicitará a senha (ou usará a chave)."
            )

        try:
            code = subprocess.call(args)
        except OSError as exc:
            raise AppError(f"Falha ao executar o ssh: {exc}") from exc
        print(f"  Sessão encerrada (código {code}).")

    def list_by_group(self) -> None:
        servers = self.repo.all()
        if not servers:
            print("  Nenhum servidor cadastrado.")
            return

        group = self._ask_group_filter("Filtrar por grupo")
        if group is None:
            selected = servers
            label = "todos"
        else:
            key = group.casefold()
            selected = [
                server
                for server in servers
                if (server.group.casefold() if server.group else "") == key
            ]
            label = group or "(sem grupo)"

        print(f"\n  Grupo: {label} — {len(selected)} servidor(es)")
        if selected:
            print_server_table(selected)
        else:
            print("  Nenhum servidor neste grupo.")

    def export_servers(self) -> None:
        print("\n--- Exportar servidores ---")
        servers = self.repo.all()
        if not servers:
            print("  Nenhum servidor cadastrado.")
            return

        group = self._ask_group_filter("Exportar quais servidores?")
        if group is None:
            selected = servers
        else:
            key = group.casefold()
            selected = [
                server
                for server in servers
                if (server.group.casefold() if server.group else "") == key
            ]
        if not selected:
            print("  Nenhum servidor no grupo selecionado.")
            return

        fmt = self._ask_choice(
            (("1", "JSON (.json)"), ("2", "CSV (.csv)")), default="1"
        )
        include_passwords = False
        passphrase: str | None = None
        if fmt == "1":
            include_passwords = confirm(
                "  Incluir senhas na exportação?", default=False
            )
            if include_passwords:
                passphrase = read_new_passphrase()
        else:
            print("  CSV nunca inclui senhas.")

        extension = "json" if fmt == "1" else "csv"
        stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
        default_path = str(Path.cwd() / f"ssh-servers-{stamp}.{extension}")
        raw_path = ask_text("Arquivo de destino", default=default_path, max_len=1024)
        path = Path(raw_path).expanduser()
        if not path.is_absolute():
            path = Path.cwd() / path
        if path.suffix.lower() != f".{extension}":
            path = path.with_name(path.name + f".{extension}")
        if path.is_dir():
            raise AppError(f"O destino é um diretório: {path}")
        reserved = {
            self.repo.path.resolve(),
            (self.repo.data_dir / "secret.key").resolve(),
        }
        if path.resolve() in reserved:
            raise AppError("O destino não pode ser um arquivo interno do SSH Manager.")
        if path.exists() and not confirm(
            f"  '{path}' já existe. Sobrescrever?", default=False
        ):
            print("  Exportação cancelada.")
            return

        if fmt == "1":
            payload = build_export_payload(
                selected,
                include_passwords=include_passwords,
                passphrase=passphrase,
            )
            atomic_write_json(path, payload, backup=False)
        else:
            atomic_write_text(path, export_csv_text(selected), encoding="utf-8-sig")

        print(f"\n  {len(selected)} servidor(es) exportado(s) para: {path}")
        if include_passwords:
            print(
                "  Senhas incluídas, protegidas pela senha informada. "
                "Guarde-a com segurança."
            )
        else:
            print("  Senhas NÃO foram incluídas.")

    def import_servers(self) -> None:
        print("\n--- Importar servidores ---")
        raw_path = ask_text("Arquivo (.json ou .csv)", required=True, max_len=1024)
        path = Path(raw_path).expanduser()
        if not path.is_absolute():
            path = Path.cwd() / path
        if not path.is_file():
            raise AppError(f"Arquivo não encontrado: {path}")

        records = self._read_import_file(path)
        if not records:
            print("  Nenhum registro encontrado no arquivo.")
            return

        strategy = self._ask_import_strategy()
        if strategy is None:
            print("  Importação cancelada.")
            return

        result = merge_import(
            self.repo.all(), records, overwrite=(strategy == "overwrite")
        )
        if result.added or result.updated:
            self.repo.replace_all(result.servers)

        print(
            f"\n  Importação concluída: {result.added} adicionado(s), "
            f"{result.updated} atualizado(s), {result.skipped} ignorado(s)."
        )
        if result.errors:
            print("  Registros com problema:")
            for error in result.errors[:10]:
                print(f"   - {error}")
            if len(result.errors) > 10:
                print(f"   ... e mais {len(result.errors) - 10}.")
        if result.added and not result.included_passwords:
            print(
                "  Aviso: o arquivo não continha senhas; os novos registros "
                "ficaram sem senha. Edite-os para definir."
            )

    def _read_import_file(self, path: Path) -> list[Mapping[str, Any]]:
        suffix = path.suffix.lower()
        if suffix == ".csv":
            try:
                text = path.read_text(encoding="utf-8-sig")
            except OSError as exc:
                raise AppError(f"Não foi possível ler '{path}': {exc}") from exc
            return read_csv_records(text)

        if suffix != ".json":
            raise AppError("Formato não suportado. Use um arquivo .json ou .csv.")

        try:
            content = path.read_text(encoding="utf-8-sig")
        except OSError as exc:
            raise AppError(f"Não foi possível ler '{path}': {exc}") from exc
        try:
            payload = json.loads(content)
        except json.JSONDecodeError as exc:
            raise AppError(f"JSON inválido em '{path}': {exc}") from exc

        if isinstance(payload, list):
            return payload
        if not isinstance(payload, Mapping):
            raise AppError("O JSON deve conter um objeto ou uma lista de servidores.")

        if payload.get("format") == EXPORT_FORMAT:
            if payload.get("encrypted"):
                passphrase = getpass.getpass("Senha do arquivo exportado: ")
                if not passphrase:
                    raise AppError("Senha obrigatória para importar este arquivo.")
                return decrypt_export_payload(payload, passphrase)
            servers = payload.get("servers")
            if not isinstance(servers, list):
                raise AppError("Exportação sem lista de servidores.")
            return servers

        if "version" in payload and "servers" in payload:
            raise AppError(
                "Este é o arquivo interno do SSH Manager (senhas cifradas com a "
                "chave local). Use a opção Exportar para gerar um arquivo portátil."
            )

        servers = payload.get("servers")
        if isinstance(servers, list):
            return servers
        raise AppError("Formato JSON não reconhecido.")

    def _ask_import_strategy(self) -> str | None:
        print("\n  Servidores com o mesmo nome:")
        print("   1  Ignorar (manter o existente)")
        print("   2  Sobrescrever (usar o arquivo)")
        print("   0  Cancelar")
        while True:
            option = input("  Opção [1]: ").strip() or "1"
            if option == "1":
                return "skip"
            if option == "2":
                return "overwrite"
            if option == "0":
                return None
            print("  ! Opção inválida.")

    @staticmethod
    def _ask_choice(options: Sequence[tuple[str, str]], *, default: str) -> str:
        for key, label in options:
            print(f"   {key}  {label}")
        valid = {key for key, _ in options}
        while True:
            choice = input(f"  Opção [{default}]: ").strip() or default
            if choice in valid:
                return choice
            print("  ! Opção inválida.")

    def _ask_group_filter(self, title: str) -> str | None:
        """Retorna None (todos), '' (sem grupo) ou o nome do grupo escolhido."""
        groups: dict[str, str] = {}
        counts: dict[str, int] = {}
        for server in self.repo.all():
            key = server.group.casefold() if server.group else ""
            groups.setdefault(key, server.group)
            counts[key] = counts.get(key, 0) + 1

        print(f"\n  {title}")
        if groups:
            ordered = sorted(
                groups.items(),
                key=lambda item: (item[0] != "", item[1].casefold()),
            )
            for key, display in ordered:
                print(f"    {display or '(sem grupo)'} ({counts[key]})")

        while True:
            raw = input("  Grupo [Enter = todos, '-' = sem grupo]: ").strip()
            if not raw:
                return None
            if raw == "-":
                return ""
            target = raw.casefold()
            if target in groups:
                return groups[target]
            partial = [key for key in groups if target in key]
            if len(partial) == 1:
                return groups[partial[0]]
            print("  ! Grupo não encontrado. Tente novamente.")

    def _group_names(self) -> list[str]:
        seen: dict[str, str] = {}
        for server in self.repo.all():
            if server.group:
                seen.setdefault(server.group.casefold(), server.group)
        return sorted(seen.values(), key=str.casefold)

    def _normalize_group_name(self, value: str) -> str:
        if not value:
            return ""
        for existing in self._group_names():
            if existing.casefold() == value.casefold():
                return existing
        return value

    # -- auxiliares ------------------------------------------------------
    def _ask_unique_name(
        self, current: str = "", *, exclude_id: str | None = None
    ) -> str:
        while True:
            name = ask_text("Nome", default=current or None, required=True, max_len=80)
            if self.repo.name_exists(name, exclude_id=exclude_id):
                print("  ! Já existe um servidor com esse nome.")
                current = ""
                continue
            return name

    def _ask_host_pair(self, dns: str = "", ip: str = "") -> tuple[str, str]:
        dns = ask_dns(dns)
        ip = ask_ip(ip)
        while not dns and not ip:
            print("  ! Informe ao menos DNS ou IP.")
            dns = ask_dns(dns)
            if not dns:
                ip = ask_ip(ip)
        return dns, ip


def parse_args(argv: Sequence[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="ssh_manager.py",
        description="Gerencia um inventário local de servidores SSH com senhas cifradas.",
    )
    parser.add_argument(
        "--data-dir",
        type=Path,
        help="Diretório de dados (padrão: %%APPDATA%%\\SSHManager).",
    )
    parser.add_argument(
        "--list",
        action="store_true",
        help="Lista os servidores e sai (modo não interativo).",
    )
    parser.add_argument(
        "--version", action="version", version=f"%(prog)s {APP_VERSION}"
    )
    return parser.parse_args(argv)


def main(argv: Sequence[str] | None = None) -> int:
    configure_console()
    args = parse_args(argv)

    data_dir = args.data_dir.expanduser() if args.data_dir else default_data_dir()
    try:
        repository = ServerRepository(data_dir)
    except AppError as exc:
        print(f"Erro: {exc}", file=sys.stderr)
        return 1

    app = SSHManagerApp(repository)
    if args.list:
        app.list_servers()
        return 0

    try:
        app.run()
    except (KeyboardInterrupt, EOFError):
        print("\nAté logo.")
    return 0
