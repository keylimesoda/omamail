#!/usr/bin/env python3
"""Connect an Ortie Google grant to Omamail without Google Cloud Console."""
import argparse
import contextlib
import copy
import fcntl
import json
import os
from pathlib import Path
import re
import selectors
import shutil
import signal
import stat
import subprocess
import sys
import time
import tomllib
import urllib.error
import urllib.parse
import urllib.request

LIMIT = 1024 * 1024
CLIENT = "406964657835-aq8lmia8j95dhl1a2bvharmfk3t1hgqj.apps.googleusercontent.com"
# Public desktop application credentials documented by Ortie and Thunderbird.
CLIENT_SECRET = "kSmqreRr0qwBWJgbf5Y-PjSU"
MAIL = "https://mail.google.com/"
CALENDAR = "https://www.googleapis.com/auth/calendar"
EMAIL = re.compile(r"[^\s@\x00-\x1f\x7f]+@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)*\.[A-Za-z]{2,}")


class Refused(Exception):
    pass


def require(condition, message):
    if not condition:
        raise Refused(message)


def config_home():
    return Path(os.environ.get("XDG_CONFIG_HOME") or Path.home() / ".config")


def default_config():
    return config_home() / "omamail-gmail-setup/ortie.toml"


def private_dir(path):
    """Open every component without following symlinks; create private leaves."""
    path = Path(os.path.abspath(path))
    fd = os.open("/", os.O_RDONLY | os.O_DIRECTORY)
    try:
        for component in path.parts[1:]:
            try:
                next_fd = os.open(component, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                                  dir_fd=fd)
            except FileNotFoundError:
                os.mkdir(component, 0o700, dir_fd=fd)
                next_fd = os.open(component, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                                  dir_fd=fd)
            os.close(fd)
            fd = next_fd
        info = os.fstat(fd)
        require(info.st_uid == os.getuid() and info.st_mode & 0o077 == 0,
                "Config directory must belong to you and have mode 0700.")
        return fd
    except BaseException:
        os.close(fd)
        raise


def read_private(fd, name):
    try:
        source = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=fd)
    except FileNotFoundError:
        return None
    with os.fdopen(source, "rb") as stream:
        info = os.fstat(stream.fileno())
        require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1
                and info.st_uid == os.getuid() and info.st_mode & 0o077 == 0,
                "Existing config must be an owner-only regular file without links.")
        data = stream.read(LIMIT + 1)
    require(len(data) <= LIMIT, "Config exceeds 1 MiB.")
    return data


def atomic_write(fd, name, data, expected):
    require(read_private(fd, name) == expected,
            "Config changed while setting up. Close Omamail and retry.")
    temporary = ".gmail-setup-" + os.urandom(12).hex()
    try:
        out = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                      0o600, dir_fd=fd)
        with os.fdopen(out, "wb") as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        require(read_private(fd, name) == expected,
                "Config changed while setting up. Close Omamail and retry.")
        if expected is None:
            # Atomic no-clobber creation, even if another writer races us.
            os.link(temporary, name, src_dir_fd=fd, dst_dir_fd=fd, follow_symlinks=False)
        else:
            os.replace(temporary, name, src_dir_fd=fd, dst_dir_fd=fd)
        os.fsync(fd)
    finally:
        with contextlib.suppress(FileNotFoundError):
            os.unlink(temporary, dir_fd=fd)


def prepare(path):
    # Array commands avoid a shell. The write command receives JSON on stdin.
    text = f'''# Public Thunderbird OAuth client; see README for ownership and limits.
[accounts.gmail]
default = true
client-id = "{CLIENT}"
client-secret.raw = "{CLIENT_SECRET}"
grant = "authorization-code"
endpoints.authorization = "https://accounts.google.com/o/oauth2/v2/auth"
endpoints.token = "https://oauth2.googleapis.com/token"
# No fixed redirect: Ortie chooses a free unprivileged loopback port.
scopes = ["{MAIL}", "{CALENDAR}"]
extras.access_type = "offline"
extras.prompt = "consent"
auto-refresh = true
storage.read.command = ["secret-tool", "lookup", "application", "omamail-gmail-setup", "account", "gmail"]
storage.write.command = ["secret-tool", "store", "--label=Omamail Gmail setup (Ortie)", "application", "omamail-gmail-setup", "account", "gmail"]
'''
    fd = private_dir(path.parent)
    try:
        if read_private(fd, path.name) is None:
            atomic_write(fd, path.name, text.encode(), None)
    finally:
        os.close(fd)


def run(argv, data=None, timeout=35):
    # Both the storage output and backend responses can contain credentials.
    # Never include child output or exception strings in diagnostics.
    process = subprocess.Popen(argv, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                               stderr=subprocess.DEVNULL, start_new_session=True)
    body = bytearray()
    pending = memoryview(data or b"")
    deadline = time.monotonic() + timeout
    try:
        with selectors.DefaultSelector() as selector:
            os.set_blocking(process.stdout.fileno(), False)
            selector.register(process.stdout, selectors.EVENT_READ)
            if pending:
                os.set_blocking(process.stdin.fileno(), False)
                selector.register(process.stdin, selectors.EVENT_WRITE)
            else:
                process.stdin.close()
            while selector.get_map():
                left = deadline - time.monotonic()
                require(left > 0, "A required command timed out.")
                for key, _ in selector.select(left):
                    if key.fileobj is process.stdin:
                        written = os.write(process.stdin.fileno(), pending[:4096])
                        pending = pending[written:]
                        if not pending:
                            selector.unregister(process.stdin)
                            process.stdin.close()
                    else:
                        chunk = os.read(process.stdout.fileno(), 65536)
                        if not chunk:
                            selector.unregister(process.stdout)
                        body.extend(chunk)
                        require(len(body) <= LIMIT, "Command output exceeds 1 MiB.")
        code = process.wait(timeout=max(0.01, deadline - time.monotonic()))
        require(code == 0, "A required command failed. Check Ortie, Omamail and your keyring.")
        return bytes(body)
    finally:
        with contextlib.suppress(ProcessLookupError):
            os.killpg(process.pid, signal.SIGKILL)
        process.wait()
        process.stdout.close()
        process.stdin.close()


def load_account(path, name):
    # This is executable user configuration: storage.read.command chooses a
    # program. Only your own, non-writable-by-others config may authorize it.
    with path.open("rb") as stream:
        info = os.fstat(stream.fileno())
        require(info.st_uid == os.getuid() and not info.st_mode & 0o022,
                "Ortie config must belong to you and not be writable by others.")
        body = stream.read(LIMIT + 1)
    require(len(body) <= LIMIT, "Ortie config exceeds 1 MiB.")
    raw = tomllib.loads(body.decode())
    account = raw.get("accounts", {}).get(name)
    require(isinstance(account, dict), "Named Ortie account was not found.")
    require(account.get("endpoints", {}).get("token") == "https://oauth2.googleapis.com/token",
            "Only Google's current token endpoint is supported.")
    require(re.fullmatch(r"[0-9]+-[A-Za-z0-9_]+\.apps\.googleusercontent\.com",
                         account.get("client-id", "")), "Not a Google desktop OAuth client.")
    secret = account.get("client-secret", {}).get("raw", "")
    require(isinstance(secret, str) and secret and not any(ord(c) < 32 or ord(c) == 127 for c in secret),
            "A raw desktop client secret is required (never a Google password).")
    command = account.get("storage", {}).get("read", {}).get("command")
    require(isinstance(command, list) and command and all(isinstance(x, str) and x for x in command),
            "storage.read.command must be an argv array, not a shell string.")
    return account, command, secret


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        return None


@contextlib.contextmanager
def network_deadline(seconds=25):
    """Bound the whole request, including a peer that trickles headers/body."""
    def expired(signum, frame):
        raise Refused("Google request timed out.")
    previous_handler = signal.signal(signal.SIGALRM, expired)
    previous_timer = signal.setitimer(signal.ITIMER_REAL, seconds)
    started = time.monotonic()
    try:
        yield
    finally:
        signal.setitimer(signal.ITIMER_REAL, 0)
        signal.signal(signal.SIGALRM, previous_handler)
        if previous_timer[0]:
            signal.setitimer(signal.ITIMER_REAL,
                            max(0.001, previous_timer[0] - (time.monotonic() - started)),
                            previous_timer[1])


def google(url, *, form=None, token=None):
    require(url in (
        "https://oauth2.googleapis.com/token",
        "https://gmail.googleapis.com/gmail/v1/users/me/profile",
        "https://www.googleapis.com/calendar/v3/users/me/calendarList?maxResults=1",
    ), "Unrecognized Google destination.")
    headers = {"Accept": "application/json"}
    data = None
    if form is not None:
        data = urllib.parse.urlencode(form).encode()
        headers["Content-Type"] = "application/x-www-form-urlencoded"
    if token is not None:
        require(isinstance(token, str) and re.fullmatch(r"[\x21-\x7e]+", token),
                "Invalid access token.")
        headers["Authorization"] = "Bearer " + token
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect())
    try:
        with network_deadline(), opener.open(urllib.request.Request(url, data=data, headers=headers), timeout=20) as response:
            body = response.read(LIMIT + 1)
    except urllib.error.HTTPError as error:
        error.close()
        operation = ("token exchange" if form is not None else
                     "Gmail profile" if url.endswith("/profile") else "calendar access")
        raise Refused(f"Google refused {operation} (HTTP {error.code}). Check the grant, account policy and the client's API availability; no Omamail data was imported.") from None
    except (OSError, urllib.error.URLError):
        raise Refused("Google refused the request or could not be reached. Reauthorize in Ortie; check mail/calendar permissions.") from None
    require(len(body) <= LIMIT, "Google response exceeds 1 MiB.")
    result = json.loads(body)
    require(isinstance(result, dict), "Invalid Google response.")
    return result


def verify_grant(account, command, secret, expected_email):
    stored = json.loads(run(command))
    refresh = stored.get("refresh_token")
    require(isinstance(refresh, str) and len(refresh) <= 8192 and re.fullmatch(r"[\x21-\x7e]+", refresh),
            "Ortie has no valid refresh token. Run its auth get command first.")
    grant = google("https://oauth2.googleapis.com/token", form={
        "client_id": account["client-id"], "client_secret": secret,
        "refresh_token": refresh, "grant_type": "refresh_token",
    })
    scopes = set(grant.get("scope", "").split())
    require(MAIL in scopes or {
        "https://www.googleapis.com/auth/gmail.modify",
        "https://www.googleapis.com/auth/gmail.send",
    } <= scopes, "Grant lacks Omamail's mail permissions. Reauthorize in Ortie.")
    require(CALENDAR in scopes or {
        "https://www.googleapis.com/auth/calendar.events",
        "https://www.googleapis.com/auth/calendar.calendarlist.readonly",
    } <= scopes, "Grant lacks calendar permissions. Reauthorize in Ortie.")
    access = grant.get("access_token")
    require(isinstance(access, str) and access, "Google did not return an access token.")
    profile = google("https://gmail.googleapis.com/gmail/v1/users/me/profile", token=access)
    email = profile.get("emailAddress", "")
    require(isinstance(email, str) and EMAIL.fullmatch(email), "Google returned an invalid mailbox identity.")
    email = email.lower()
    require(not expected_email or email == expected_email.lower(),
            "The Google account differs from --email. Nothing was imported.")
    google("https://www.googleapis.com/calendar/v3/users/me/calendarList?maxResults=1", token=access)
    require(not grant.get("refresh_token") or grant["refresh_token"] == refresh,
            "Google rotated this grant; refresh it with Ortie before importing.")
    return email, refresh


class Backend:
    def __init__(self, path):
        self.path = str(path)
        info = json.loads(run([self.path, "--json", "info"]))
        required = {"credentials.put", "accounts.read", "accounts.save"}
        require(info.get("name") == "omamail" and required <= set(info.get("methods", [])),
                "This Omamail backend lacks the required APIs. Update Omamail first.")

    def call(self, method, params):
        result = json.loads(run([self.path, "--json", "call", method], json.dumps(params).encode()))
        require(result.get("ok") is True, "Omamail refused the operation. Close Omamail and retry.")
        return result["result"]


def merge_clients(raw, email, client, secret):
    email = email.lower()
    if raw is None:
        store = {"version": 2, "accounts": []}
    else:
        store = json.loads(raw)
        require(isinstance(store, dict), "Invalid existing credentials.json; refusing to replace it.")
        if "accounts" not in store:
            require("installed" in store or "clientId" in store or "client_id" in store,
                    "Unknown credentials.json format; refusing to replace it.")
            store = {"version": 2, "accounts": [dict(store, id="")]}
        require(isinstance(store["accounts"], list)
                and all(isinstance(e, dict) for e in store["accounts"]),
                "Invalid client list; refusing to replace it.")
        require(store.get("version", 2) == 2, "Unknown credentials.json version.")
    entry = {"id": email, "installed": {"client_id": client, "client_secret": secret}}
    for index, existing in enumerate(store["accounts"]):
        if str(existing.get("id", "")).lower() == email:
            store["accounts"][index] = entry
            break
    else:
        store["accounts"].append(entry)
    return (json.dumps(store, ensure_ascii=False) + "\n").encode()


def merge_registry(registry, email, replace):
    email = email.lower()
    result = copy.deepcopy(registry)
    require(result.get("version") == 1 and isinstance(result.get("accounts"), list),
            "Unknown Omamail account registry format.")
    for existing in result["accounts"]:
        if (existing.get("provider", "gmail") == "gmail"
                and str(existing.get("email", "")).lower() == email):
            require(replace, "This Gmail mailbox already exists. Use --replace to update its grant.")
            break
    else:
        result["accounts"].append({"id": email, "email": email, "provider": "gmail", "label": ""})
    if not result.get("activeId"):
        result["activeId"] = email
    return result


def backend_for(args):
    backend_path = args.backend or Path(os.environ.get("XDG_DATA_HOME") or Path.home() / ".local/share") / "omamail/bin/omamail"
    return Backend(backend_path)


def import_grant(args, backend=None):
    backend = backend or backend_for(args)
    account, command, secret = load_account(args.ortie_config, args.account)
    email, refresh = verify_grant(account, command, secret, args.email)
    snapshot = backend.call("accounts.read", {})
    registry = merge_registry(snapshot["registry"], email, args.replace)
    fd = private_dir(config_home() / "omamail")
    try:
        lock = os.open(".gmail-setup.lock", os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW | os.O_NONBLOCK,
                       0o600, dir_fd=fd)
        with os.fdopen(lock, "rb") as handle:
            info = os.fstat(handle.fileno())
            require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and info.st_uid == os.getuid(),
                    "Unsafe setup lock.")
            fcntl.flock(handle, fcntl.LOCK_EX | fcntl.LOCK_NB)
            old = read_private(fd, "credentials.json")
            new = merge_clients(old, email, account["client-id"], secret)
            # Account writes use Omamail's own revision/lock protocol. Its UI
            # client-file writer has no shared lock: close Omamail for setup.
            backend.call("credentials.put", {"kind": "google-refresh-token",
                         "accountId": email, "clientId": account["client-id"], "secret": refresh})
            atomic_write(fd, "credentials.json", new, old)
            backend.call("accounts.save", {"registry": registry, "revision": snapshot["revision"]})
    finally:
        os.close(fd)
    print(f"Connected {email} using Omamail's native Gmail provider. Reopen Omamail.")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=["prepare", "login", "import"])
    parser.add_argument("--ortie-config", type=Path, default=default_config())
    parser.add_argument("--account", default="gmail")
    parser.add_argument("--email", help="Refuse import if Google reports a different mailbox")
    parser.add_argument("--backend", type=Path, help="Omamail backend executable")
    parser.add_argument("--replace", action="store_true", help="Replace an existing Gmail grant")
    args = parser.parse_args()
    try:
        require(not args.email or EMAIL.fullmatch(args.email), "--email must be a mailbox address.")
        if args.command == "prepare":
            require(args.account == "gmail", "Generated configuration uses account gmail.")
            prepare(args.ortie_config)
            print(f"Ortie config ready: {args.ortie_config}")
            print("Next: run this script with login. Google will ask for consent in your browser.")
        else:
            backend = backend_for(args)
            if args.command == "login":
                require(sys.stdin.isatty() and sys.stdout.isatty(),
                        "login needs an interactive terminal. For headless setup, complete Ortie's auth get/resume flow, then use import.")
                if not args.ortie_config.exists():
                    require(args.account == "gmail", "Generated configuration uses account gmail.")
                    prepare(args.ortie_config)
                account, command, _ = load_account(args.ortie_config, args.account)
                require(shutil.which("ortie") and shutil.which(command[0]),
                        "Install Ortie and the configured token-storage command first (normally secret-tool).")
                if account["client-id"] == CLIENT:
                    print("Uses Thunderbird's public OAuth client with full mail/calendar permissions; see docs/GMAIL-ORTIE.md.", flush=True)
                print("Close Omamail before continuing. Sign in and allow both mail and calendar access.", flush=True)
                try:
                    previous = run(command)
                except Refused:
                    previous = None
                result = subprocess.run(["ortie", "--log-level", "warn", "-c", str(args.ortie_config), "-a", args.account,
                                         "auth", "get"], check=False)
                require(result.returncode == 0, "Ortie sign-in failed; nothing was imported.")
                require(run(command) != previous,
                        "Ortie did not save a new grant. Complete its printed auth resume command, then run this helper's import command.")
            import_grant(args, backend)
    except KeyboardInterrupt:
        print("\nCancelled.", file=sys.stderr)
        return 130
    except (Refused, OSError, ValueError, KeyError, TypeError, AttributeError, subprocess.TimeoutExpired):
        # Only our own static error messages are safe to print. JSON/TOML and
        # native errors may embed token bytes, config data or response bodies.
        error = sys.exc_info()[1]
        print(f"Setup stopped: {error if isinstance(error, Refused) else 'Invalid data or an unavailable file/command. Check the README.'}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
