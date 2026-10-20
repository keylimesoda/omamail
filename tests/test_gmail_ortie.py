"""Synthetic tests; the optional real backend test must run in an isolated keyring."""
import contextlib
import importlib.util
import io
import json
import os
from pathlib import Path
import stat
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parent.parent
SPEC = importlib.util.spec_from_file_location("gmail_ortie", ROOT / "scripts/gmail-ortie.py")
helper = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(helper)
EMAIL = "person@example.org"
SECRET = "synthetic-refresh-secret"


class SetupTests(unittest.TestCase):
    def test_prepare_is_private_and_does_not_replace_existing_config(self):
        with tempfile.TemporaryDirectory() as root:
            path = Path(root) / "setup/ortie.toml"
            helper.prepare(path)
            account, command, secret = helper.load_account(path, "gmail")
            self.assertEqual(account["client-id"], helper.CLIENT)
            self.assertEqual(secret, helper.CLIENT_SECRET)
            self.assertIsInstance(command, list)
            self.assertIn(helper.MAIL, account["scopes"])
            self.assertIn(helper.CALENDAR, account["scopes"])
            self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)
            self.assertEqual(stat.S_IMODE(path.parent.stat().st_mode), 0o700)
            path.write_text(path.read_text() + "\n# user's changes\n")
            before = path.read_bytes()
            helper.prepare(path)
            self.assertEqual(path.read_bytes(), before)

    def test_unsafe_paths_never_modify_their_targets(self):
        with tempfile.TemporaryDirectory() as root:
            root = Path(root)
            outside = root / "outside"
            outside.mkdir()
            target = outside / "credentials.json"
            target.write_bytes(b"sentinel")
            os.chmod(target, 0o600)
            linked = root / "linked"
            linked.symlink_to(outside)
            with self.assertRaises(OSError):
                helper.private_dir(linked)
            fd = helper.private_dir(root / "safe")
            try:
                (root / "safe/credentials.json").symlink_to(target)
                with self.assertRaises(OSError):
                    helper.atomic_write(fd, "credentials.json", b"bad", None)
                (root / "safe/credentials.json").unlink()
                os.link(target, root / "safe/credentials.json")
                with self.assertRaises(helper.Refused):
                    helper.atomic_write(fd, "credentials.json", b"bad", b"sentinel")
                self.assertEqual(target.read_bytes(), b"sentinel")
                (root / "safe/credentials.json").unlink()
                unsafe = root / "safe/credentials.json"
                unsafe.write_bytes(b"unsafe-permissions")
                os.chmod(unsafe, 0o644)
                with self.assertRaises(helper.Refused):
                    helper.atomic_write(fd, "credentials.json", b"bad", b"unsafe-permissions")
                self.assertEqual(unsafe.read_bytes(), b"unsafe-permissions")
                self.assertEqual(stat.S_IMODE(unsafe.stat().st_mode), 0o644)
            finally:
                os.close(fd)

    def test_concurrent_client_write_is_preserved(self):
        with tempfile.TemporaryDirectory() as root:
            fd = helper.private_dir(Path(root))
            try:
                helper.atomic_write(fd, "credentials.json", b"newer", None)
                with self.assertRaises(helper.Refused):
                    helper.atomic_write(fd, "credentials.json", b"stale", None)
                self.assertEqual(helper.read_private(fd, "credentials.json"), b"newer")
            finally:
                os.close(fd)

    def test_import_preserves_other_clients_and_legacy_default(self):
        legacy = {"installed": {"client_id": "old", "client_secret": "old-secret"}}
        got = json.loads(helper.merge_clients(json.dumps(legacy).encode(), EMAIL, "new", "secret"))
        self.assertEqual(got["accounts"][0]["installed"], legacy["installed"])
        again = json.loads(helper.merge_clients(json.dumps(got).encode(), EMAIL.upper(), "second", "secret"))
        self.assertEqual(len(again["accounts"]), 2)
        self.assertEqual(again["accounts"][0], got["accounts"][0])
        for raw in [b"[]", b"{}", b'{"version":3,"accounts":[]}', b'{"accounts":[null]}']:
            with self.assertRaises(helper.Refused):
                helper.merge_clients(raw, EMAIL, "new", "secret")

    def test_account_update_preserves_all_fields_and_active_mailbox(self):
        original = {"version": 1, "activeId": "imap:other@example.org", "accounts": [
            {"provider": "imap", "email": "other@example.org", "signature": "keep"},
            {"provider": "gmail", "email": EMAIL, "senderName": "Keep me"},
        ]}
        before = json.dumps(original)
        with self.assertRaises(helper.Refused):
            helper.merge_registry(original, EMAIL, False)
        result = helper.merge_registry(original, EMAIL, True)
        self.assertEqual(result, original)
        result = helper.merge_registry(original, "new@example.org", False)
        self.assertEqual(result["accounts"][:2], original["accounts"])
        self.assertEqual(result["activeId"], original["activeId"])
        self.assertEqual(json.dumps(original), before)

    def verify(self, *, expected=None, scope=None):
        def google(url, **kwargs):
            if url == "https://oauth2.googleapis.com/token":
                self.assertEqual(kwargs["form"]["refresh_token"], SECRET)
                return {"access_token": "synthetic-access", "scope": scope or helper.MAIL + " " + helper.CALENDAR}
            if url.endswith("/profile"):
                return {"emailAddress": EMAIL}
            return {"items": []}
        with patch.object(helper, "run", return_value=json.dumps({"refresh_token": SECRET}).encode()), \
                patch.object(helper, "google", side_effect=google) as requests:
            result = helper.verify_grant({"client-id": "client"}, ["storage"], "secret", expected)
        return result, requests

    def test_verifies_mailbox_from_google_and_probes_calendar(self):
        result, requests = self.verify(expected=EMAIL.upper())
        self.assertEqual(result, (EMAIL, SECRET))
        self.assertEqual(requests.call_count, 3)

    def test_malformed_refresh_tokens_never_leave_the_storage_boundary(self):
        for token in ["", "bad\n", "bad\r\n", "bad\0", "bad\x7f", "bad token", "bad\u00a0", "x" * 8193]:
            with patch.object(helper, "run", return_value=json.dumps({"refresh_token": token}).encode()), \
                    patch.object(helper, "google") as google:
                with self.assertRaises(helper.Refused):
                    helper.verify_grant({"client-id": "client"}, ["storage"], "secret", None)
                google.assert_not_called()

    def test_wrong_identity_and_incomplete_scope_never_reach_storage(self):
        with patch.object(helper, "Backend") as backend, patch.object(helper, "atomic_write") as write:
            for kwargs in [{"expected": "wrong@example.org"}, {"scope": helper.MAIL}, {"scope": helper.CALENDAR}]:
                with self.assertRaises(helper.Refused):
                    self.verify(**kwargs)
            backend.assert_not_called()
            write.assert_not_called()

    def test_credentials_cannot_choose_a_network_destination_or_header(self):
        with patch.object(helper.urllib.request, "build_opener") as opener:
            with self.assertRaises(helper.Refused):
                helper.google("https://evil.example/token", form={"refresh_token": SECRET})
            with self.assertRaises(helper.Refused):
                helper.google("https://gmail.googleapis.com/gmail/v1/users/me/profile", token="bad\r\nsecret")
            opener.assert_not_called()

    def test_google_errors_expose_only_operation_and_status(self):
        error = helper.urllib.error.HTTPError("https://google.example", 403, SECRET, {}, None)
        with patch.object(helper.urllib.request, "build_opener") as opener:
            opener.return_value.open.side_effect = error
            with self.assertRaises(helper.Refused) as result:
                helper.google("https://gmail.googleapis.com/gmail/v1/users/me/profile", token="synthetic-access")
        self.assertIn("Gmail profile (HTTP 403)", str(result.exception))
        self.assertNotIn(SECRET, str(result.exception))

    def test_redirect_does_not_receive_credentials(self):
        # Use real HTTP redirect handling against two synthetic local servers.
        import http.server
        import threading
        from urllib.error import HTTPError
        from urllib.request import Request, build_opener, ProxyHandler
        received = []
        class Target(http.server.BaseHTTPRequestHandler):
            def do_GET(self):
                received.append(self.headers.get("Authorization"))
                self.send_response(200)
                self.end_headers()
            def log_message(self, *args):
                pass
        target = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Target)
        class Redirect(Target):
            def do_GET(self):
                self.send_response(302)
                self.send_header("Location", f"http://127.0.0.1:{target.server_port}/")
                self.end_headers()
        source = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Redirect)
        threads = [threading.Thread(target=s.serve_forever) for s in (source, target)]
        for thread in threads:
            thread.start()
        try:
            request = Request(f"http://127.0.0.1:{source.server_port}/", headers={"Authorization": SECRET})
            with self.assertRaises(HTTPError) as error:
                build_opener(ProxyHandler({}), helper.NoRedirect()).open(request, timeout=2)
            error.exception.close()
            self.assertEqual(received, [])
        finally:
            for server in (source, target):
                server.shutdown()
                server.server_close()
            for thread in threads:
                thread.join()

    def test_subprocess_secrets_travel_over_stdin_and_stay_out_of_errors(self):
        result = helper.run([sys.executable, "-c", "import sys; sys.stdout.buffer.write(sys.stdin.buffer.read())"], SECRET.encode())
        self.assertEqual(result, SECRET.encode())
        with self.assertRaises(helper.Refused) as error:
            helper.run([sys.executable, "-c", "import sys; print(sys.stdin.read()); sys.exit(1)"], SECRET.encode())
        self.assertNotIn(SECRET, str(error.exception))
        with self.assertRaises(helper.Refused):
            helper.run([sys.executable, "-c", "print('x' * 2000000)"], timeout=2)
        with self.assertRaises(helper.Refused):
            helper.run([sys.executable, "-c", "import time; time.sleep(10)"], timeout=0.05)

    def test_whole_request_deadline_interrupts_a_stalled_operation(self):
        import time
        with self.assertRaises(helper.Refused):
            with helper.network_deadline(0.03):
                time.sleep(10)

    def test_failed_validation_does_not_write_registry_clients_or_keyring(self):
        args = type("Args", (), {"backend": "synthetic", "ortie_config": Path("synthetic"),
                                "account": "gmail", "email": "wrong@example.org", "replace": False})()
        with patch.object(helper, "Backend") as backend, \
                patch.object(helper, "load_account", return_value=({}, [], "")), \
                patch.object(helper, "verify_grant", side_effect=helper.Refused("wrong account")), \
                patch.object(helper, "private_dir") as directory:
            with self.assertRaises(helper.Refused):
                helper.import_grant(args)
            backend.return_value.call.assert_not_called()
            directory.assert_not_called()

    def test_unfinished_manual_login_never_imports_an_old_grant(self):
        class Terminal(io.StringIO):
            def isatty(self):
                return True
        with tempfile.TemporaryDirectory() as root:
            path = Path(root) / "ortie.toml"
            helper.prepare(path)
            error = io.StringIO()
            with patch.object(helper.sys, "argv", ["gmail-ortie.py", "login", "--ortie-config", str(path)]), \
                    patch.object(helper.sys, "stdin", Terminal()), \
                    contextlib.redirect_stdout(Terminal()), contextlib.redirect_stderr(error), \
                    patch.object(helper, "Backend"), patch.object(helper.shutil, "which", return_value="synthetic"), \
                    patch.object(helper, "run", return_value=b"unchanged-synthetic-grant"), \
                    patch.object(helper.subprocess, "run", return_value=SimpleNamespace(returncode=0)), \
                    patch.object(helper, "import_grant") as imported:
                self.assertEqual(helper.main(), 1)
                imported.assert_not_called()
            self.assertIn("auth resume", error.getvalue())

    def test_noninteractive_login_never_starts_ortie(self):
        with patch.object(helper.sys, "argv", ["gmail-ortie.py", "login"]), \
                patch.object(helper.sys, "stdin", io.StringIO()), \
                contextlib.redirect_stderr(io.StringIO()), patch.object(helper, "Backend"), \
                patch.object(helper.subprocess, "run") as command:
            self.assertEqual(helper.main(), 1)
            command.assert_not_called()


@unittest.skipUnless(os.environ.get("OMAMAIL_TEST_BACKEND"), "set OMAMAIL_TEST_BACKEND inside omabox")
class NativeBackendTest(unittest.TestCase):
    def test_real_backend_stores_the_native_grant_and_preserves_accounts(self):
        require_box = os.environ.get("HOME") == "/home/sbx"
        self.assertTrue(require_box, "This test requires an isolated omabox HOME/keyring")
        backend = helper.Backend(Path(os.environ["OMAMAIL_TEST_BACKEND"]))
        snapshot = backend.call("accounts.read", {})
        registry = helper.merge_registry(snapshot["registry"], EMAIL, False)
        args = type("Args", (), {"backend": Path(os.environ["OMAMAIL_TEST_BACKEND"]),
                                "ortie_config": Path("synthetic"), "account": "gmail",
                                "email": EMAIL, "replace": False})()
        with patch.object(helper, "load_account", return_value=({"client-id": helper.CLIENT}, [], "public-secret")), \
                patch.object(helper, "verify_grant", return_value=(EMAIL, SECRET)), \
                contextlib.redirect_stdout(io.StringIO()):
            helper.import_grant(args)
        clients = helper.config_home() / "omamail/credentials.json"
        self.assertNotIn(SECRET, clients.read_text())
        self.assertEqual(stat.S_IMODE(clients.stat().st_mode), 0o600)
        retrieved = backend.call("credentials.get", {"kind": "google-refresh-token", "accountId": EMAIL,
                                "clientId": helper.CLIENT})
        # Assert without printing native-store response contents on failure.
        self.assertTrue(retrieved.get("secret") == SECRET)
        saved = backend.call("accounts.read", {})
        self.assertEqual(saved["registry"], registry)
        # A stale save must neither overwrite nor drop the registered mailbox.
        with self.assertRaises(helper.Refused):
            backend.call("accounts.save", {"registry": snapshot["registry"], "revision": snapshot["revision"]})
        self.assertEqual(backend.call("accounts.read", {})["registry"], registry)
        backend.call("credentials.delete", {"kind": "google-refresh-token", "accountId": EMAIL,
                     "clientId": helper.CLIENT})


@unittest.skipUnless(os.environ.get("ORTIE_TEST_BINARY"), "set ORTIE_TEST_BINARY for the installed Ortie contract")
class NativeOrtieTest(unittest.TestCase):
    def test_ortie_reads_the_generated_config_and_synthetic_storage_response(self):
        with tempfile.TemporaryDirectory() as root:
            path = Path(root) / "ortie.toml"
            helper.prepare(path)
            storage = Path(root) / "storage.py"
            stored = {"access_token": "synthetic-access", "refresh_token": SECRET,
                      "token_type": "Bearer", "expires_in": 3600,
                      "scope": helper.MAIL + " " + helper.CALENDAR}
            storage.write_text("print(" + repr(json.dumps(stored)) + ")\n")
            lines = path.read_text().splitlines()
            path.write_text("\n".join(
                "storage.read.command = " + json.dumps([sys.executable, str(storage)])
                if line.startswith("storage.read.command = ") else line for line in lines) + "\n")
            captured = io.StringIO()
            with contextlib.redirect_stdout(captured):
                result = helper.run([os.environ["ORTIE_TEST_BINARY"], "--json", "-c", str(path),
                                     "-a", "gmail", "token", "inspect"])
            self.assertEqual(captured.getvalue(), "")
            metadata = json.loads(result)
            # Ortie 2.2 prints the full response in JSON mode; newer versions
            # print metadata only. The helper must keep either form private.
            self.assertTrue(metadata.get("with_refresh_token", bool(metadata.get("refresh_token"))))
            self.assertEqual(set(metadata["scope"].split()), {helper.MAIL, helper.CALENDAR})

    def test_ortie_chooses_a_dynamic_loopback_redirect_without_browser_or_consent(self):
        with tempfile.TemporaryDirectory() as root:
            path = Path(root) / "ortie.toml"
            helper.prepare(path)
            result = helper.run([os.environ["ORTIE_TEST_BINARY"], "--json", "-c", str(path),
                                 "-a", "gmail", "auth", "get"])
            # Piped stdout makes this a local authorization-URL generation;
            # Ortie does not open a browser, contact Google, or save a token.
            payload = json.loads(result)
            query = helper.urllib.parse.parse_qs(helper.urllib.parse.urlsplit(payload["authorization_uri"]).query)
            redirect = helper.urllib.parse.urlsplit(query["redirect_uri"][0])
            self.assertEqual((redirect.scheme, redirect.hostname), ("http", "127.0.0.1"))
            self.assertGreaterEqual(redirect.port, 1024)


if __name__ == "__main__":
    unittest.main()
