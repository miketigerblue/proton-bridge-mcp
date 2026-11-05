# proton-bridge-mcp

A local Model Context Protocol (MCP) server that lets Claude (or any MCP client) read, search, draft, send, and organise email through your running **Proton Mail Bridge**. Everything stays on your Mac — Claude talks to Bridge over `127.0.0.1` IMAP (1143) and SMTP (1025). Nothing transits the public internet via this server.

## Why this exists

Proton Mail's end-to-end encryption is great for privacy and a problem for automation: there's no public IMAP endpoint and no first-party API. **Proton Mail Bridge** solves that by exposing your decrypted mail over loopback IMAP/SMTP on your own machine. This MCP server wraps that loopback in a small, hardened tool surface that Claude can drive.

## Why this one?

Several other Proton MCP servers exist on GitHub. Most are functional and some have far larger tool surfaces. This one is built for a different priority: **security and supply-chain hygiene over feature count**, on the assumption that the people most likely to want to plug an LLM into their email are also the people who most need a credible threat model and a reproducible install.

| Concern                  | This server                                                                                                                          | Typical alternative                                  |
| ------------------------ | ------------------------------------------------------------------------------------------------------------------------------------ | ---------------------------------------------------- |
| Bridge TLS               | Pinned to Bridge's self-signed cert via TOFU capture, by default; refuses to start without a verified cert unless explicitly downgraded | `CERT_NONE` on loopback, or TLS handling unspecified |
| Credential storage       | macOS Keychain, with `/usr/bin/security` on the trusted-applications ACL so prompts stop after first install                         | `.env` file, plaintext in config, or env-var only    |
| Dependency installation  | `--require-hashes` against a fully resolved `requirements.txt` lock (every transitive sha256 verified at install)                    | `pip install <package>` (floats to latest)           |
| Connection management    | Pooled IMAP + SMTP sessions per process, asyncio locks, auto-reconnect on drops                                                      | New connection per call (login storms)               |
| Read semantics           | `mark_seen=false` is the default; reads never implicitly mark messages read                                                          | Often marks read implicitly                          |
| Threat model             | Documented in the README; explicit prompt-injection caveat for inbound mail content                                                  | Usually absent                                       |
| Troubleshooting coverage | Real-world gotchas captured: Python 3.12+ naive-datetime crash, IMAP `FETCH` UID-spec quirk, macOS Keychain ACL prompt-loop, stale `__pycache__` after Python-version bump | Generic, or absent                                   |

**When this is not the right pick.** If you want the largest possible Proton tool surface (Mail + Pass + Drive + Calendar + VPN), look at [`jorgenclaw/proton-mcp`](https://github.com/jorgenclaw/proton-mcp). If you specifically want a local SQLite + FTS5 search index over your Bridge mail, look at [`dreamc0der-ai/proton-mail-mcp`](https://github.com/dreamc0der-ai/proton-mail-mcp). If you want a hardened, audit-friendly, Mail-only Bridge MCP with hash-pinned dependencies and an opinionated security posture, you're in the right place.

## Tool surface

| Tool                         | Purpose                                                  | Annotations     |
| ---------------------------- | -------------------------------------------------------- | --------------- |
| `proton_list_folders`        | List every mailbox / label                               | read-only       |
| `proton_list_recent`         | N newest messages in a mailbox (headers only)            | read-only       |
| `proton_search_emails`       | IMAP SEARCH (from / to / subject / body / date / flags)  | read-only       |
| `proton_read_email`          | Full headers + text + (optional) HTML + attachments list | read-only       |
| `proton_download_attachment` | Save a specific attachment to disk                       | destructive (writes to disk; requires `acknowledged=true`) |
| `proton_flag_email`          | Mark read/unread, flag/unflag                            | mutate          |
| `proton_move_email`          | Move a message to another mailbox                        | mutate          |
| `proton_delete_email`        | Move to Trash (or permanently expunge)                   | destructive (requires `acknowledged=true`) |
| `proton_send_email`          | Send via Bridge SMTP, optional attachments + Sent copy   | destructive (requires `acknowledged=true`) |
| `proton_create_draft`        | Save a draft for manual review, optional attachments     | destructive when addressed externally (requires `acknowledged=true` for non-self recipients) |

## Hardening highlights

- **Credentials in the macOS Keychain**, never in `claude_desktop_config.json`. The config file only names the Keychain service and account.
- **TLS pinning by default** against Bridge's own self-signed certificate, captured on first run via STARTTLS. The server fails closed if the cert can't be located. Set `PROTON_BRIDGE_TLS_POLICY=best_effort` only if you knowingly need to fall back to `CERT_NONE` on loopback (e.g. first-install diagnostics).
- **Pooled connections**: one long-lived IMAP session and one SMTP session per process, guarded by asyncio locks, with auto-reconnect on drops. No per-call login storms.
- **Non-blocking**: blocking stdlib IMAP/SMTP calls run in `asyncio.to_thread` so the event loop stays responsive.
- **Hash-pinned dependencies** (`requirements.txt`) so the install is reproducible and supply-chain attacks are caught at install time.
- **Reads never implicitly mark messages read** — `mark_seen=false` is the default on `proton_read_email`.
- **Attachments are opt-in and allow-listed**: `proton_send_email` and `proton_create_draft` refuse every local file until `PROTON_BRIDGE_ATTACHMENT_DIRS` names the folders they may come from. Symlinks are resolved before the check.

## Prerequisites

- macOS (Keychain integration is macOS-specific)
- Proton Mail Bridge installed, running, and logged in
- Python 3.10 or later (tested on 3.10, 3.12, and 3.14). **Apple's `/usr/bin/python3` is 3.9 on current macOS and is not supported** — install a newer interpreter via Homebrew (`brew install python@3.12`) or python.org. The bootstrap script auto-detects a Homebrew Python 3.10+ and re-execs under it if you launch it from too old an interpreter, but the manual install path needs you to invoke a 3.10+ `python3` directly.
- Bridge **username** (your email) and **app-password**, copied from Bridge → *Mailbox details*. This is **not** your Proton account password.

## Install

There are two paths. Use **A** unless you want fine control over each step.

### A. One-shot bootstrap

```bash
cd <install-path>/proton-bridge-mcp
python3 bootstrap.py
```

`bootstrap.py` is idempotent and re-runnable. It:

1. Creates `.venv` next to the script.
2. Installs the hash-pinned dependencies from `requirements.txt`.
3. Captures Bridge's TLS certificate via STARTTLS (trust-on-first-use) and saves it to `~/.config/proton-bridge-mcp/cert.pem` with `0600` perms.
4. Prompts once for your Bridge app-password and writes it to the macOS Keychain under service `proton_bridge_mcp`, account = your username, with `/usr/bin/security` on the trusted-applications list (so macOS does not prompt again on every MCP process spawn).
5. Verifies IMAP login end-to-end with the pinned cert.
6. Merges a `proton_bridge` block into `~/Library/Application Support/Claude/claude_desktop_config.json`, preserving any other MCP servers you have configured.

Then **fully quit Claude Desktop (⌘Q) and relaunch**.

### B. Manual four-step install

```bash
cd <install-path>/proton-bridge-mcp

# 1. Create the venv and install hash-pinned dependencies
./install.sh

# 2. Put the Bridge app-password in the macOS Keychain
./setup_keychain.sh you@example.com
# (prompts for the password — paste it; nothing is echoed)

# 3. Capture Bridge's TLS certificate (required: pinned mode is the default
#    and the server fails closed if the cert isn't found and verified).
#    Writes ~/.config/proton-bridge-mcp/cert.pem with 0600 perms.
.venv/bin/python proton_bridge_mcp.py --learn-cert

# 4. Merge the entry from claude_desktop_config.example.json into
#    ~/Library/Application Support/Claude/claude_desktop_config.json,
#    replacing the <INSTALL_PATH> and <YOU> placeholders. No password
#    goes in this file — the Keychain handles that.
```

Then quit and relaunch Claude Desktop.

## Verifying

In a new conversation, ask Claude:

> Using proton_bridge, list my mail folders.

Then something with bite:

> Search proton_bridge for all mail to or from `@example.com` in the last 12 months, in any folder. Read the most recent 10 threads.

## Configuration reference

All configuration is done via the `env` block in `claude_desktop_config.json`. See `claude_desktop_config.example.json` for a starting template.

| Variable                          | Required | Default       | Notes                                                                                  |
| --------------------------------- | -------- | ------------- | -------------------------------------------------------------------------------------- |
| `PROTON_BRIDGE_USER`              | yes      | —             | Your Bridge username (usually your email).                                             |
| `PROTON_BRIDGE_HOST`              | no       | `127.0.0.1`   | Bridge listens on loopback by default — leave alone unless you know why.               |
| `PROTON_BRIDGE_IMAP_PORT`         | no       | `1143`        | Per Bridge → *Advanced settings*.                                                      |
| `PROTON_BRIDGE_SMTP_PORT`         | no       | `1025`        | Per Bridge → *Advanced settings*.                                                      |
| `PROTON_BRIDGE_DEFAULT_FROM`      | no       | = `_USER`     | Used when sending if `from_addr` isn't specified per call.                             |
| `PROTON_BRIDGE_CERT_PATH`         | no       | autoresolve   | Path to Bridge's TLS cert. The bootstrap captures it; otherwise `_locate_bridge_cert` searches well-known locations. |
| `PROTON_BRIDGE_TLS_POLICY`        | no       | `pinned`      | Default: refuse to start unless Bridge's cert is found and verified. Set to `best_effort` to fall back to `CERT_NONE` on loopback (use for first-install diagnostics, not as a long-term posture). |
| `PROTON_BRIDGE_KEYCHAIN_SVC`      | no       | `proton_bridge_mcp` | Keychain service name. Override only if you have multiple Bridge accounts.       |
| `PROTON_BRIDGE_PASS`              | no       | —             | Direct password fallback. Avoid; prefer Keychain. Useful for headless / CI.            |
| `PROTON_BRIDGE_LOG_LEVEL`         | no       | `INFO`        | Standard Python log level.                                                             |
| `PROTON_BRIDGE_ATTACHMENT_DIRS`   | no       | —             | Folders attachments may come from: absolute paths separated by `:`. Unset: every attachment is refused. Anything inside can be mailed out, so name a dedicated folder without secrets. |
| `PROTON_BRIDGE_MAX_ATTACHMENT_MB` | no       | `18`          | Combined attachment size per message, before MIME encoding (which adds about a third). |

## Rotating and revoking

- **Rotate the Bridge app-password**: regenerate in Bridge → *Mailbox details*, then re-run `./setup_keychain.sh you@example.com` (or `bootstrap.py --force-password`).
- **Delete the Keychain entry**: `security delete-generic-password -s proton_bridge_mcp -a you@example.com`.
- **Remove entirely**: delete the `proton_bridge` block from `claude_desktop_config.json`, then delete this folder.

## Troubleshooting

| Symptom                                                                                    | Fix                                                                                                                                                                                                                                                                                                                                                                                              |
| ------------------------------------------------------------------------------------------ | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| `credentials: Proton Bridge password not found`                                            | Run `./setup_keychain.sh you@example.com`, or set `PROTON_BRIDGE_PASS` env var as a temporary fallback. If the password used to load and stopped, see "macOS prompts for Keychain access on every restart" below.                                                                                                                                                                                |
| **macOS prompts for Keychain access on every restart**, even after clicking "Always Allow" | The Keychain item is missing `/usr/bin/security` on its trusted-applications ACL. Re-add the entry with `security add-generic-password -U -s proton_bridge_mcp -a you@example.com -T /usr/bin/security -w '<bridge-app-password>'`. The `bootstrap.py` and updated `setup_keychain.sh` in this repo do this correctly. Older deployments may need this manual fix.                              |
| `tls: PROTON_BRIDGE_TLS_POLICY=best_effort and cert not found; falling back to CERT_NONE`  | Only fires when you've explicitly set `PROTON_BRIDGE_TLS_POLICY=best_effort`. The default (`pinned`) refuses to start in this case. Fix: set `PROTON_BRIDGE_CERT_PATH` to the real Bridge cert location (the bootstrap script saves it to `~/.config/proton-bridge-mcp/cert.pem`), then drop the `best_effort` override so you're back on the secure default.                                    |
| `CERTIFICATE_VERIFY_FAILED`                                                                | Happens with `PROTON_BRIDGE_TLS_POLICY=pinned` when the cert can't be read or doesn't match. Switch to `best_effort` to confirm everything else works, then fix the cert path. Bridge regenerates its cert on some upgrades — re-run `bootstrap.py` to recapture.                                                                                                                                |
| `WRONG_VERSION_NUMBER` (ssl error)                                                         | Wrong port. Check Bridge → *Advanced settings* and confirm IMAP/SMTP ports match `PROTON_BRIDGE_IMAP_PORT` / `PROTON_BRIDGE_SMTP_PORT`.                                                                                                                                                                                                                                                          |
| `[AUTH] LOGIN failed`                                                                      | App-password is wrong or expired. Regenerate in Bridge → *Mailbox details* and re-run `setup_keychain.sh` (or `bootstrap.py --force-password`).                                                                                                                                                                                                                                                  |
| `proton_search_emails` returns `uid: null` for every message                               | Older versions of this server used a FETCH spec that did not include `UID` in the data items list. Pull the latest source — the spec now includes `UID` explicitly.                                                                                                                                                                                                                              |
| `proton_create_draft` or `proton_send_email` fails with `ValueError: date_time must be aware` | Older versions called `imaplib.Time2Internaldate(datetime.now())` with a naive datetime. Python 3.12 deprecated this and 3.14 hard-rejects it. Pull the latest source — both call sites now pass a timezone-aware UTC datetime.                                                                                                                                                                  |
| MCP server fails to start after upgrading Python                                           | `__pycache__/` may contain bytecode compiled for the previous Python version. Delete it: `rm -rf <install-path>/proton-bridge-mcp/__pycache__`. Then restart Claude Desktop.                                                                                                                                                                                                                     |
| Connection drops mid-search                                                                | The pool reconnects automatically; re-issue the tool call. Persistent drops usually mean Bridge has been quit or its TLS cert was regenerated.                                                                                                                                                                                                                                                   |

## Threat model

- **Local-only**: this MCP server runs on your Mac under your user account. Bridge listens only on `127.0.0.1`. Nothing this server does talks to the public internet on your behalf — when Claude invokes a tool, the resulting IMAP/SMTP traffic stays on loopback to Bridge, and Bridge then talks to Proton over its own end-to-end-encrypted channel.
- **Credentials**: the Bridge app-password lives in the macOS Keychain, fetched per-process via `/usr/bin/security`. The Keychain item's ACL trusts the `security` CLI explicitly, so macOS does not gate every read with a prompt; conversely, no other process can read the password without macOS authentication. The password is never written to disk by this server, never logged, and never exposed in tool outputs.
- **TLS**: the connection to Bridge is always STARTTLS-wrapped. The default policy is `pinned` — the server pins to Bridge's specific self-signed certificate (saved to `~/.config/proton-bridge-mcp/cert.pem` on first install) and refuses to start if that cert can't be located. Setting `PROTON_BRIDGE_TLS_POLICY=best_effort` is an explicit downgrade that allows fallback to `CERT_NONE` on loopback only — acceptable for first-install diagnostics because the only thing Bridge listens on is loopback under your own user account, but not the recommended long-term posture.
- **Send / destructive tools**: explicitly annotated. `proton_send_email`, `proton_delete_email`, `proton_move_email`, `proton_flag_email`, and `proton_create_draft` all carry MCP `destructiveHint` / `idempotentHint` annotations the client can use to gate confirmation. Reads default to non-mutating (`mark_seen=false`).
- **Prompt-injection caveat**: an MCP server that reads email is, by construction, a prompt-injection surface. Email bodies you read with `proton_read_email` may contain instructions intended to manipulate the model. Never have Claude execute actions described in inbound email content without your explicit approval. Treat all email content as untrusted input, even from senders you know.

## Development

```bash
# Re-generate the runtime hash-pinned lockfile after editing requirements.in
uv pip compile requirements.in --generate-hashes --python-version 3.10 -o requirements.txt
# (or: pip-compile --generate-hashes --output-file requirements.txt requirements.in)

# Re-generate the dev lockfile (a superset including pytest + transitives).
# Always pass BOTH .in files so the dev lockfile is a complete resolution
# consistent with the runtime lockfile.
uv pip compile requirements.in requirements-dev.in --generate-hashes \
    --python-version 3.10 -o requirements-dev.txt

# Quick syntax check on the two top-level Python files
python3 -m compileall -q proton_bridge_mcp.py bootstrap.py

# Install dev deps (hash-pinned) and run the pytest suite
.venv/bin/pip install --require-hashes -r requirements-dev.txt
.venv/bin/python -m pytest tests/ -v
```

The pytest suite covers the side-effect-free helpers (header decoding,
address parsing, body extraction, IMAP-search criteria construction). IMAP,
SMTP and Keychain paths are intentionally not unit-tested — they need a
running Bridge and integration coverage.

## License

MIT — see `LICENSE`.
