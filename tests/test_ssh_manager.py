"""Testes automatizados do gerenciador de servidores SSH.

Execute com:
    python -m unittest discover -s tests -v
"""

from __future__ import annotations

import json
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import sshmanager as sm


def make_server(**overrides) -> sm.Server:
    data = {
        "name": "Web 01",
        "group": "Produção",
        "port": 22,
        "dns": "web01.example.com",
        "ip": "10.0.0.10",
        "user": "deploy",
        "user_password": "senha-do-deploy",
        "root_user": "root",
        "root_password": "senha-do-root",
        "description": "Servidor de aplicação",
        "ssh_key": r"C:\Users\jonat\.ssh\id_ed25519",
    }
    data.update(overrides)
    return sm.Server(**data)


class ValidationTests(unittest.TestCase):
    def test_valid_server_passes(self) -> None:
        sm.validate_server(make_server())

    def test_name_is_required(self) -> None:
        with self.assertRaises(sm.ValidationError):
            sm.validate_server(make_server(name="   "))

    def test_invalid_ip_is_rejected(self) -> None:
        with self.assertRaises(sm.ValidationError):
            sm.validate_server(make_server(ip="999.999.999.999"))

    def test_ipv6_is_accepted(self) -> None:
        sm.validate_server(make_server(ip="2001:db8::10"))

    def test_host_is_required(self) -> None:
        with self.assertRaises(sm.ValidationError):
            sm.validate_server(make_server(dns="", ip=""))

    def test_invalid_dns_is_rejected(self) -> None:
        with self.assertRaises(sm.ValidationError):
            sm.validate_server(make_server(dns="servidor com espaço"))

    def test_invalid_username_is_rejected(self) -> None:
        with self.assertRaises(sm.ValidationError):
            sm.validate_server(make_server(user="-root"))

    def test_empty_root_user_is_allowed(self) -> None:
        sm.validate_server(make_server(root_user=""))

    def test_description_too_long(self) -> None:
        with self.assertRaises(sm.ValidationError):
            sm.validate_server(make_server(description="x" * 201))

    def test_invalid_port_is_rejected(self) -> None:
        for port in (0, 65536):
            with (
                self.subTest(port=port),
                self.assertRaises(sm.ValidationError),
            ):
                sm.validate_server(make_server(port=port))

    def test_group_too_long_is_rejected(self) -> None:
        with self.assertRaises(sm.ValidationError):
            sm.validate_server(make_server(group="g" * 41))


class CipherTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.base = Path(self.tmp.name)

    def test_roundtrip(self) -> None:
        cipher = sm.SecretCipher(self.base / "secret.key")
        token = cipher.encrypt("s3nh@ secreta")
        self.assertNotEqual(token, "s3nh@ secreta")
        self.assertEqual(cipher.decrypt(token), "s3nh@ secreta")

    def test_empty_values_stay_empty(self) -> None:
        cipher = sm.SecretCipher(self.base / "secret.key")
        self.assertEqual(cipher.encrypt(""), "")
        self.assertEqual(cipher.decrypt(""), "")

    def test_wrong_key_raises_crypto_error(self) -> None:
        cipher_a = sm.SecretCipher(self.base / "a" / "secret.key")
        cipher_b = sm.SecretCipher(self.base / "b" / "secret.key")
        token = cipher_a.encrypt("segredo")
        with self.assertRaises(sm.CryptoError):
            cipher_b.decrypt(token)


class RepositoryTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.data_dir = Path(self.tmp.name) / "data"

    def repository(self) -> sm.ServerRepository:
        return sm.ServerRepository(self.data_dir)

    def test_add_and_persist(self) -> None:
        repo = self.repository()
        server = make_server()
        repo.add(server)

        reloaded = self.repository()
        self.assertEqual(len(reloaded.all()), 1)
        loaded = reloaded.all()[0]
        self.assertEqual(loaded.id, server.id)
        self.assertEqual(loaded.name, server.name)
        self.assertEqual(loaded.user_password, server.user_password)
        self.assertEqual(loaded.root_password, server.root_password)

    def test_passwords_are_not_plaintext_on_disk(self) -> None:
        repo = self.repository()
        repo.add(make_server())
        raw = (self.data_dir / "servers.json").read_text(encoding="utf-8")
        self.assertNotIn("senha-do-deploy", raw)
        self.assertNotIn("senha-do-root", raw)

    def test_update(self) -> None:
        repo = self.repository()
        server = make_server()
        repo.add(server)

        server.name = "Web 02"
        server.user_password = "nova-senha"
        repo.update(server)

        loaded = self.repository().all()[0]
        self.assertEqual(loaded.name, "Web 02")
        self.assertEqual(loaded.user_password, "nova-senha")

    def test_delete(self) -> None:
        repo = self.repository()
        server = make_server()
        repo.add(server)
        repo.delete(server.id)
        self.assertEqual(self.repository().all(), [])

    def test_duplicate_name_is_rejected(self) -> None:
        repo = self.repository()
        repo.add(make_server())
        with self.assertRaises(sm.ValidationError):
            repo.add(make_server(name="web 01"))

    def test_name_exists_ignores_case_and_same_id(self) -> None:
        repo = self.repository()
        server = make_server()
        repo.add(server)
        self.assertTrue(repo.name_exists("WEB 01"))
        self.assertFalse(repo.name_exists("WEB 01", exclude_id=server.id))

    def test_corrupted_file_falls_back_to_backup(self) -> None:
        repo = self.repository()
        repo.add(make_server(name="Primeiro"))
        repo.add(make_server(name="Segundo"))  # gera servers.json.bak com 1 item

        path = self.data_dir / "servers.json"
        path.write_text("{ isto não é json", encoding="utf-8")

        recovered = self.repository()
        names = [server.name for server in recovered.all()]
        self.assertEqual(names, ["Primeiro"])

    def test_group_and_port_persist(self) -> None:
        repo = self.repository()
        repo.add(make_server(group="Homologação", port=2222))

        loaded = self.repository().all()[0]
        self.assertEqual(loaded.group, "Homologação")
        self.assertEqual(loaded.port, 2222)

    def test_v1_data_loads_with_defaults(self) -> None:
        repo = self.repository()
        repo.add(make_server())
        path = self.data_dir / "servers.json"
        payload = json.loads(path.read_text(encoding="utf-8"))
        payload["version"] = 1
        for record in payload["servers"]:
            record.pop("group", None)
            record.pop("port", None)
        path.write_text(json.dumps(payload), encoding="utf-8")

        loaded = self.repository().all()[0]
        self.assertEqual(loaded.group, "")
        self.assertEqual(loaded.port, 22)

    def test_missing_key_with_existing_data_raises(self) -> None:
        repo = self.repository()
        repo.add(make_server())
        (self.data_dir / "secret.key").unlink()

        with self.assertRaises(sm.CryptoError):
            self.repository()

    def test_schema_version_is_checked(self) -> None:
        repo = self.repository()
        repo.add(make_server())
        path = self.data_dir / "servers.json"
        payload = json.loads(path.read_text(encoding="utf-8"))
        payload["version"] = 99
        path.write_text(json.dumps(payload), encoding="utf-8")

        with self.assertRaises(sm.StorageError):
            self.repository()


class CommandTests(unittest.TestCase):
    def test_build_ssh_command_with_key(self) -> None:
        server = make_server(ssh_key="/home/user/.ssh/id_ed25519")
        self.assertEqual(
            sm.build_ssh_command(server),
            "ssh -i /home/user/.ssh/id_ed25519 deploy@web01.example.com",
        )

    def test_build_ssh_command_with_custom_port(self) -> None:
        server = make_server(ssh_key="/home/user/.ssh/id_ed25519", port=2222)
        self.assertEqual(
            sm.build_ssh_command(server),
            "ssh -p 2222 -i /home/user/.ssh/id_ed25519 deploy@web01.example.com",
        )

    def test_build_ssh_command_quotes_paths_with_spaces(self) -> None:
        server = make_server(ssh_key=r"C:\Users\Jonat\Minhas Chaves\id_ed25519")
        self.assertIn(
            '"C:\\Users\\Jonat\\Minhas Chaves\\id_ed25519"',
            sm.build_ssh_command(server),
        )

    def test_build_ssh_command_without_key(self) -> None:
        server = make_server(ssh_key="")
        self.assertEqual(sm.build_ssh_command(server), "ssh deploy@web01.example.com")

    def test_dns_takes_precedence_over_ip(self) -> None:
        server = make_server()
        self.assertEqual(server.host(), "web01.example.com")
        server.dns = ""
        self.assertEqual(server.host(), "10.0.0.10")


class ExportImportTests(unittest.TestCase):
    def setUp(self) -> None:
        self.server = make_server()

    def encrypted_payload(self, passphrase: str = "senha-forte") -> dict:
        return sm.build_export_payload(
            [self.server], include_passwords=True, passphrase=passphrase
        )

    def test_plain_export_omits_passwords(self) -> None:
        payload = sm.build_export_payload([self.server], include_passwords=False)
        self.assertFalse(payload["encrypted"])
        self.assertFalse(payload["includes_passwords"])

        record = payload["servers"][0]
        self.assertEqual(record["group"], "Produção")
        self.assertEqual(record["port"], 22)
        self.assertNotIn("user_password", record)
        self.assertNotIn("root_password", record)

        serialized = json.dumps(payload)
        self.assertNotIn("senha-do-deploy", serialized)
        self.assertNotIn("senha-do-root", serialized)

    def test_encrypted_export_roundtrip(self) -> None:
        payload = self.encrypted_payload()
        self.assertTrue(payload["encrypted"])
        self.assertEqual(payload["servers"], [])
        self.assertEqual(payload["kdf"]["name"], "scrypt")
        self.assertNotIn("senha-do-deploy", json.dumps(payload))

        records = sm.decrypt_export_payload(payload, "senha-forte")
        self.assertEqual(records[0]["name"], "Web 01")
        self.assertEqual(records[0]["group"], "Produção")
        self.assertEqual(records[0]["user_password"], "senha-do-deploy")
        self.assertEqual(records[0]["root_password"], "senha-do-root")

    def test_encrypted_export_requires_passphrase(self) -> None:
        with self.assertRaises(sm.CryptoError):
            sm.build_export_payload([self.server], include_passwords=True)

    def test_wrong_passphrase_is_rejected(self) -> None:
        with self.assertRaises(sm.CryptoError):
            sm.decrypt_export_payload(self.encrypted_payload(), "senha-errada")

    def test_tampered_kdf_is_rejected(self) -> None:
        payload = self.encrypted_payload()
        payload["kdf"]["n"] = 2**30
        with self.assertRaises(sm.CryptoError):
            sm.decrypt_export_payload(payload, "senha-forte")

    def test_csv_omits_passwords_and_keeps_group(self) -> None:
        text = sm.export_csv_text([self.server])
        expected_header = "name,group,dns,ip,port,user,root_user,description,ssh_key"
        self.assertTrue(text.startswith(expected_header))
        self.assertIn("Produção", text)
        self.assertNotIn("senha-do-deploy", text)

        records = sm.read_csv_records(text)
        self.assertEqual(records[0]["name"], "Web 01")
        self.assertEqual(records[0]["group"], "Produção")

    def test_portuguese_headers_are_normalized(self) -> None:
        normalized = sm.normalize_import_record(
            {
                "Nome": "X",
                "Grupo": "G",
                "Porta": "2222",
                "Usuário": "u",
                "Senha": "p",
                "Root": "r",
                "Senha Root": "rp",
                "Descrição": "d",
                "Chave SSH": "k",
            }
        )
        self.assertEqual(normalized["name"], "X")
        self.assertEqual(normalized["group"], "G")
        self.assertEqual(normalized["port"], "2222")
        self.assertEqual(normalized["user"], "u")
        self.assertEqual(normalized["user_password"], "p")
        self.assertEqual(normalized["root_user"], "r")
        self.assertEqual(normalized["root_password"], "rp")
        self.assertEqual(normalized["description"], "d")
        self.assertEqual(normalized["ssh_key"], "k")

    def test_merge_overwrite_preserves_password_when_absent(self) -> None:
        existing = [make_server(name="Web 01")]
        records = [
            {
                "name": "web 01",
                "group": "Homologação",
                "port": 2200,
                "dns": "web01.example.com",
                "user": "deploy",
            }
        ]
        result = sm.merge_import(existing, records, overwrite=True)

        self.assertEqual((result.added, result.updated, result.skipped), (0, 1, 0))
        merged = result.servers[0]
        self.assertEqual(merged.group, "Homologação")
        self.assertEqual(merged.port, 2200)
        self.assertEqual(merged.user_password, "senha-do-deploy")
        self.assertEqual(merged.root_password, "senha-do-root")
        self.assertFalse(result.included_passwords)

    def test_merge_skip_keeps_existing(self) -> None:
        existing = [make_server(name="Web 01")]
        result = sm.merge_import(
            existing, [{"name": "WEB 01", "group": "X"}], overwrite=False
        )
        self.assertEqual(result.skipped, 1)
        self.assertEqual(result.servers[0].group, "Produção")

    def test_merge_adds_new_without_password(self) -> None:
        result = sm.merge_import(
            [],
            [
                {
                    "name": "Novo",
                    "dns": "novo.local",
                    "grupo": "Teste",
                    "porta": "2222",
                    "usuario": "deploy",
                }
            ],
            overwrite=True,
        )
        self.assertEqual(result.added, 1)
        server = result.servers[0]
        self.assertEqual(server.group, "Teste")
        self.assertEqual(server.port, 2222)
        self.assertEqual(server.user_password, "")
        self.assertFalse(result.included_passwords)

    def test_merge_with_passwords_sets_flag(self) -> None:
        result = sm.merge_import(
            [],
            [
                {
                    "name": "Novo",
                    "dns": "n.local",
                    "usuario": "deploy",
                    "senha": "abc",
                    "senha_root": "xyz",
                }
            ],
            overwrite=True,
        )
        self.assertTrue(result.included_passwords)
        self.assertEqual(result.servers[0].user_password, "abc")
        self.assertEqual(result.servers[0].root_password, "xyz")

    def test_merge_invalid_record_is_reported(self) -> None:
        result = sm.merge_import([], [{"name": "Sem host"}], overwrite=True)
        self.assertEqual(result.added, 0)
        self.assertEqual(result.skipped, 1)
        self.assertTrue(result.errors)

    def test_merge_duplicate_names_respects_strategy(self) -> None:
        records = [
            {"name": "A", "dns": "a.local", "user": "deploy", "group": "G1"},
            {"name": "A", "dns": "a.local", "user": "deploy", "group": "G2"},
        ]
        result = sm.merge_import([], records, overwrite=True)
        self.assertEqual(result.added, 1)
        self.assertEqual(result.updated, 1)
        self.assertEqual(result.servers[0].group, "G2")


if __name__ == "__main__":
    unittest.main()
