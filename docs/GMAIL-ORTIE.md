# Gmail setup through Ortie (Linux)

`scripts/gmail-ortie.py` connects Gmail to Omamail from the terminal without creating a Google Cloud project, configuring a consent screen, or downloading a client JSON file. It uses [Ortie](https://github.com/pimalaya/ortie) for Google's interactive OAuth authorization and imports the resulting grant into Omamail's existing native Gmail provider. Normal Google browser sign-in and consent are still required.

This is an optional alternative to the built-in Gmail setup. Close Omamail during import, then reopen it when the command succeeds. Mail continues to use Omamail's Gmail API implementation; it is not converted to IMAP, and no background broker or hosted relay is installed.

## Requirements

- Linux with Python 3.11 or newer.
- Ortie 2.2 or newer. Follow [Ortie's installation instructions](https://github.com/pimalaya/ortie#installation); the helper does not install dependencies or execute downloaded installers.
- `secret-tool` from libsecret and an unlocked Secret Service keyring. On Arch/Omarchy, the package is `libsecret`.
- An installed Omamail backend implementing `credentials.put`, `accounts.read` and `accounts.save`. The helper checks these methods before reading Ortie's token. The native import contract was tested with Omamail 0.11.1 / API 8.

The default backend is `$XDG_DATA_HOME/omamail/bin/omamail` (normally `~/.local/share/omamail/bin/omamail`), the private executable installed by Omamail's plugin runtime. For a standalone installation or source build, pass `--backend /absolute/path/to/omamail`. This must be the backend executable, not the Qt application launcher. The helper does not download, replace, or start the desktop app.

## First connection

From this checkout:

```sh
python3 scripts/gmail-ortie.py login --email you@gmail.com
```

The command creates a private Ortie configuration at `$XDG_CONFIG_HOME/omamail-gmail-setup/ortie.toml`, starts `ortie auth get`, and waits for you to complete Google's browser consent. Choose the account named by `--email` and allow both mail and calendar access. After consent, the helper verifies the actual mailbox identity through Google's Gmail API and probes Calendar access before it writes any Omamail credentials or accounts. `--email` is optional but recommended: it prevents accidentally importing a different signed-in Google account.

You can inspect the generated configuration before authorizing anything:

```sh
python3 scripts/gmail-ortie.py prepare
```

`prepare` does not start Ortie or open a browser. Existing configurations are preserved.

`login` requires an interactive terminal, and its generated configuration lets Ortie choose a free unprivileged loopback port. If a custom configuration needs manual completion, finish the `ortie auth resume` command Ortie prints and then run this helper's `import` command; the helper refuses to treat an unchanged old token as a completed new login. For a headless host, run Ortie's authorization/resume flow yourself and use `import` afterwards.

## Existing Ortie users

If you already authorized Google in Ortie, import that grant directly:

```sh
python3 scripts/gmail-ortie.py import \
  --ortie-config ~/.config/ortie/config.toml \
  --account gmail \
  --email you@gmail.com
```

The selected account must use Google's current token endpoint, a Google desktop client ID, a `client-secret.raw` value, and an argv array for `storage.read.command`. The helper deliberately does not evaluate shell-string storage commands, secret environment references, command-based client secrets, or merged multi-file Ortie configurations. Use the generated configuration if yours uses one of those forms. Only use configuration files you trust: an Ortie storage command runs a program as your user.

To refresh an existing Omamail account's grant, append `--replace`. The helper preserves the account's signature, display name, settings and active-mailbox selection, and preserves every other account and OAuth client. To add a second Google mailbox, run `login --email second@gmail.com` again and choose that account in Google; each imported refresh token is stored separately in Omamail. Ortie's generated account retains only the most recent authorization, while earlier imports remain in Omamail's keyring.

## Public OAuth client and permissions

The default configuration uses the public Thunderbird Google client that [Ortie explicitly documents](https://github.com/pimalaya/ortie#google), also present in [Thunderbird's provider source](https://github.com/mozilla/releases-comm-central/blob/master/mailnews/base/src/OAuth2Providers.sys.mjs). The client ID and desktop client secret are public application identifiers, not your Google password or a token. Google consent therefore identifies the application as Thunderbird, not Omamail. This helper is independent of Thunderbird and does not imply its endorsement.

The default grant requests `https://mail.google.com/` and `https://www.googleapis.com/auth/calendar`, the existing client's mail and calendar scopes. These are broader than Omamail's normal Gmail setup scopes: the mail scope permits permanent deletion, and the calendar scope includes calendar management. Omamail's features and mutation protections remain the same; the grant itself has these broader permissions. Do not authorize them unless you accept that difference.

Using another project's public client depends on that project's registration, Google API enablement, policies, quotas and continued availability. This does not provide Omamail with an independently verified OAuth application. Google or the client owner can restrict it, and managed accounts may block it. A maintainer-owned, verified Omamail client would remove that dependency. An existing user-owned desktop client is also supported through `--ortie-config`, if its grant includes Omamail's mail and calendar permissions.

Google's documented [Gmail profile endpoint](https://developers.google.com/workspace/gmail/api/reference/rest/v1/users/getProfile) accepts the full mail scope, and the [Calendar list endpoint](https://developers.google.com/workspace/calendar/api/v3/reference/calendarList/list) accepts the full calendar scope. The helper verifies actual access at runtime rather than assuming that public client credentials guarantee it. A rejected grant, missing permission, unavailable API or wrong mailbox stops import.

## Credential storage and recovery

Ortie saves the original token response in Secret Service using its configured storage command. The helper reads that response privately, obtains a fresh Google access token, validates the mailbox and calendar, and sends only the refresh token to Omamail's typed `credentials.put` API over stdin. Imported refresh tokens remain in the OS keyring, bound to mailbox and OAuth client ID. Access tokens and refresh tokens are not written to config files or passed as process arguments by the helper.

Only OAuth client identifiers go into Omamail's `credentials.json` (mode 0600); mailbox metadata goes through Omamail's revision-checked `accounts.save` API. Client-file writes are atomic and refuse symlinks, hardlinks and unsafe permissions. A helper lock prevents overlapping imports, but Omamail's UI client-file writer does not share that lock; close Omamail during setup. Existing configuration directories must be private (0700); unsafe existing permissions are refused instead of changed silently.

Import spans the keyring, client file and account registry, which have no shared transaction. A disk, keyring or account-revision failure can leave a verified grant or client entry saved without a registered mailbox. The command reports failure; fix the reported condition and rerun `import` (with `--replace` if the mailbox already exists). It never deletes other accounts to resolve a conflict. A Google refresh-token rotation is refused rather than leaving Ortie's copy stale.

After import, Omamail refreshes tokens itself and Ortie does not need to stay running. For reauthorization, use this helper's `login --replace` again: Omamail's normal setup screen requests its own narrower scope set and is not the reconnect path for the shared Thunderbird client. Removing the mailbox in Omamail and revoking access in your [Google account connections](https://myaccount.google.com/connections) removes access; a shared-client revocation may also affect Thunderbird or other uses of that same client. The helper's separate Ortie keyring entry remains until you remove it or revoke its grant.

## Validation

Run the synthetic suite without a Google account:

```sh
python3 tests/test_gmail_ortie.py
```

To include the real Omamail credential and registry contract, run against an isolated HOME/keyring. For example, using [omabox](https://github.com/diogochaves/omabox) and an installed backend:

```sh
omabox run --no-shell --net isolated \
  --ro-bind "$HOME/.local/share/omamail/bin:/opt/omamail-test" -- \
  env OMAMAIL_TEST_BACKEND=/opt/omamail-test/omamail \
  python3 tests/test_gmail_ortie.py
```

These tests use synthetic tokens, local HTTP servers and disposable account data. They verify token transport, redirect refusal, private file handling, account preservation and Omamail's actual keyring contract. They do not establish that Google will authorize the public client for every account, or replace a live sign-in test. No real mailbox is needed or modified by the test suite.

The optional `ORTIE_TEST_BINARY=/absolute/path/to/ortie` test checks that a real Ortie executable accepts the generated configuration and storage response, using a synthetic storage command instead of a keyring or Google. Its output is captured privately; do not assume that Ortie's JSON token-inspection output is credential-free across versions.

Validation on 2026-10-20: all 19 helper tests passed in an isolated omabox session, including the native Ortie 2.2.0 configuration/storage contract, dynamic loopback authorization URL generation, and Omamail 0.11.1 / API 8 credential-and-registry contract. Omamail's broader Rust, JavaScript, shell, QML, standalone-composition and QML-lint checks also passed, as did plugin validation and whitespace checks; the desktop-dependent checks ran in omabox with Qt 6.12.0 and Omarchy 4.0.6. **Security: PASS for the exercised local setup boundaries** (private files, fixed destinations, redirect refusal, token stdin transport, error redaction, deadlines and account preservation). **Live Google authorization: NOT VERIFIED**; a fresh-account sign-in remains required before treating this as a release-ready workflow. This scoped result is not a full security audit of Ortie, Thunderbird or Omamail.
