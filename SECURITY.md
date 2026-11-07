# Security Policy

`proton-bridge-mcp` runs on your Mac, holds a Proton Bridge app-password in your
macOS Keychain, and reads inbound email on your behalf. Vulnerabilities here
matter. This document covers how to report them and what guarantees the server
does and does not make.

## Supported versions

| Version  | Supported |
| -------- | --------- |
| `main` (latest commit) | yes |
| Latest tagged release | yes |
| All other tagged releases | no — upgrade |
| Forks                | not by this repo |

There is no LTS branch. Fixes land on `main` and are picked up in the next tag.

## Reporting a vulnerability

**Use GitHub Security Advisories.** This keeps the disclosure private until a
fix is ready.

1. Open <https://github.com/miketigerblue/proton-bridge-mcp/security/advisories/new>.
2. Include: affected versions, reproduction steps, observed vs. expected
   behaviour, and (if known) suggested mitigation.
3. Expect an initial acknowledgement within 5 working days. A coordinated
   disclosure window of up to 90 days is the working default; shorter windows
   are negotiable for actively-exploited issues.

Please do **not** open a public GitHub issue, PR, or discussion for a
security-impacting bug. Public reports get fixed, but the people most likely to
weaponise them get a head start.

If you cannot use GitHub Security Advisories, email
[mike@tigerblue.io](mailto:mike@tigerblue.io) with `[proton-bridge-mcp
security]` in the subject. PGP key is on the keyservers under the same
address; ask if you need it inline.

## Threat model

What this server protects against and what it doesn't.

### In scope

- **Loopback isolation.** Bridge listens only on `127.0.0.1`. The MCP server
  speaks to Bridge over loopback IMAP/SMTP. No traffic crosses your network as
  a result of an MCP tool call. Bridge's own outbound channel to Proton is
  end-to-end encrypted and out of this repo's control.
- **Credential confidentiality at rest.** The Bridge app-password lives in the
  macOS Keychain. The keychain item's ACL trusts only `/usr/bin/security`. The
  password is never written to disk by this server, never logged, and never
  appears in tool outputs.
- **Supply-chain integrity at install.** `requirements.txt` is hash-pinned;
  every transitive dependency is verified against a known-good sha256 at
  install. Tampered wheels on PyPI fail loudly. `bootstrap.py` and
  `install.sh` both pass `--require-hashes`.
- **TLS to Bridge.** STARTTLS is always negotiated. The default policy is
  `pinned`: the connection refuses to start unless Bridge presents the cert
  captured during first-run TOFU. Setting `PROTON_BRIDGE_TLS_POLICY=best_effort`
  is an explicit downgrade that allows fallback to `CERT_NONE` on loopback
  only — useful for first-install diagnostics, not the recommended long-term
  posture.
- **Read semantics.** `proton_read_email` defaults `mark_seen=false`. Reading
  a message never implicitly marks it seen.
- **Mutating tools are annotated.** `proton_send_email`, `proton_delete_email`,
  `proton_move_email`, `proton_flag_email`, and `proton_create_draft` all
  carry MCP `destructiveHint` / `idempotentHint` annotations the client can
  use to gate confirmation. `proton_send_email` and `proton_delete_email`
  carry `destructiveHint: true`.
- **Server-side `acknowledged` requirement on the side-effecting tools.**
  `proton_send_email`, `proton_delete_email`, `proton_create_draft`, and
  `proton_download_attachment` all require an explicit `acknowledged`
  bool argument at the input layer (Pydantic `Field(...)` with no
  default), so a prompt-injection payload that simply names the tool
  and its arguments is rejected before any side effect runs -- the
  model has to *deliberately* set the value, which is the point at
  which a well-instructed model surfaces the action to the operator.
  The body-level enforcement differs by tool:
  - `proton_send_email` and `proton_delete_email` are *always* refused
    on `acknowledged=false`; the tool body returns a structured
    `refused` JSON payload (`reason: "acknowledged_required"`) without
    resolving credentials or touching IMAP/SMTP.
  - `proton_download_attachment` is *always* refused on
    `acknowledged=false`. Writing attachment bytes to a user-supplied
    `save_path` is a side effect outside the model's sandbox; a
    prompt-injection payload could direct the write to a sensitive
    location (LaunchAgent plist, ssh authorized_keys, etc.).
  - `proton_create_draft` is refused on `acknowledged=false` only
    when at least one recipient is *not* the operator's own address.
    Drafts to non-self addresses are an exfil staging channel:
    harvested mail composed into a draft to attacker@evil.com sits in
    Drafts until a future click sends it. Self-only drafts are
    accepted regardless. Self addresses are derived from
    `PROTON_BRIDGE_USER` and `PROTON_BRIDGE_DEFAULT_FROM` (case-
    insensitive) -- aliases not represented in either env var are
    treated as external for this gate, which is the safe default.
- **Local-file attachments are opt-in and allow-listed.** `proton_send_email`
  and `proton_create_draft` refuse every attachment until
  `PROTON_BRIDGE_ATTACHMENT_DIRS` names at least one folder. Paths must be
  absolute and are checked after resolving symlinks, so neither `..` nor a
  symlink leads out of an allowed folder. This check runs before the file is
  touched, so an error does not reveal which paths exist outside those folders.
  The combined size is capped by `PROTON_BRIDGE_MAX_ATTACHMENT_MB`. Attachments
  do not change either tool's `acknowledged` rule, so a self-only draft can copy
  an allowed file into the operator's own Drafts without it.
- **Prompt-injection hardening at the read boundary** (partial — see also
  the out-of-scope section below). Two layered mitigations apply to email
  content returned to the LLM:
  - **Steganographic Unicode is stripped.** Zero-width characters
    (U+200B / U+200C / U+200D / U+FEFF / U+2060–U+2064), bidi-override
    controls (U+202A–U+202E, U+2066–U+2069), soft hyphen, and Unicode
    line / paragraph separators are removed from every header value
    (via `_decode_header`) and from email bodies (via `_extract_body`).
    These carry payloads invisible to a human reader of the same email
    but visible to a model.
  - **Bodies are wrapped in nonce-tagged provenance delimiters.**
    `proton_read_email` returns body text and (optional) HTML wrapped in
    `<UNTRUSTED_EMAIL_BODY_<6-hex-nonce> source="…" subject="…">…
    </UNTRUSTED_EMAIL_BODY_<same-nonce>>` with a one-line preamble
    instructing the model to treat the wrapped content as data rather
    than instructions. The per-call nonce prevents an attacker who
    controls the body from forging a closing tag and convincing the
    model that the trusted scope has resumed.
  - **Sender-authentication results are surfaced in the wrapper.**
    `proton_read_email` parses any RFC 8601 `Authentication-Results`
    header on the message and adds the SPF / DKIM / DMARC outcome
    tokens to the wrapper's provenance attrs (e.g.
    `spf="fail" dkim="pass" dmarc="fail"`). A spoofed `From:` header
    therefore reaches the model alongside the auth verdict that
    Proton's MX recorded, rather than as an unchallenged authority
    claim. The verdict tokens are passed through verbatim
    (`pass` / `fail` / `softfail` / `neutral` / `none` / `temperror` /
    `permerror`); absence of the header is itself a signal.

### Out of scope (intentionally not protected)

- **Compromise of the host machine.** A local attacker with code execution as
  your user can read the keychain and intercept loopback traffic. This is
  outside the threat model — same as for any MCP server, mail client, or
  password manager on the same box.
- **Compromise of Proton Mail Bridge itself.** This server treats Bridge as
  trusted. If Bridge is compromised, Bridge's own threat model applies, not
  ours.
- **Prompt injection from inbound mail content (full prevention).** A real
  risk that cannot be fully eliminated at the server layer alone. We mitigate
  at the read boundary (steganographic-Unicode stripping and provenance
  wrapping — see "In scope" above) but a sufficiently sophisticated injection
  that survives those defences and convinces the model to call a destructive
  tool with plausible arguments is the *operator's* and *client's* problem,
  not ours. Any feature that lets the model take action based on email
  content (auto-reply, auto-forward, rule-based delete) **must** require
  explicit per-action user confirmation in the MCP client. The server
  provides the primitives and the layered defences; the client and the
  operator provide the policy.
- **Read-side exfiltration via the model.** The `acknowledged=true` gate
  on the side-effecting tools and the prompt-injection wrapper protect
  against destructive actions being triggered by inbound mail content.
  They do *not* prevent a sufficiently capable injection from coaxing the
  model into reading additional mail (the read tools have no `acknowledged`
  gate by design — gating them would make the server unusable) and
  surfacing those contents into the conversation, where the attacker
  receives them via the next reply the model composes, or via any other
  channel the model can write to. The read tools are *how the server is
  useful at all*; their natural behaviour is data flowing into the
  model's context. If the operator has the model auto-respond to mail
  or otherwise act on its read context, that path is exfiltration. The
  mitigation is operator policy: do not have the model auto-respond on
  inboxes that may receive injected content; treat the LLM provider as
  having read-access to every email Claude reads via this tool, because
  it does.
- **Files inside the allowed attachment folders.** The allow-list limits which
  files can leave the machine, not whether they do. A model that has been
  convinced to set `acknowledged=true` can mail any file in those folders to
  any recipient. The mitigation is operator policy; see the hardening
  recommendations below.
- **Attacks against Proton's infrastructure or end-to-end-encryption design.**
  Out of this repo's hands.
- **Non-macOS platforms.** Linux and Windows are unsupported. Bridge runs
  there, but the credential-storage and process-spawn assumptions in this
  server are macOS-specific. Don't deploy it elsewhere.

## Security properties to verify

Anyone auditing the server should be able to confirm the following from the
source:

- `requirements.txt` is generated with `--generate-hashes`; nothing else gets
  installed. (`install.sh` and `bootstrap.py` both assert this.)
- The keychain item for `proton_bridge_mcp` has `/usr/bin/security` on its
  trusted-applications ACL. (`setup_keychain.sh` and `bootstrap.py` set this
  with `-T /usr/bin/security`.)
- The MCP server fetches the password by invoking `/usr/bin/security` per
  process; the password is not cached on disk.
- The source defaults `PROTON_BRIDGE_TLS_POLICY` to `pinned` (see
  `proton_bridge_mcp.py`), and the supplied manifests do not override it.
  Running the server without a verified Bridge cert therefore fails closed.
  Setting `PROTON_BRIDGE_TLS_POLICY=best_effort` is the only path that allows
  `CERT_NONE` fallback on loopback.
- The `_strip_invisibles` regex in `proton_bridge_mcp.py` covers, at minimum,
  the zero-width and bidi character ranges enumerated above, and is invoked
  from `_decode_header` and `_extract_body` so every header and body value
  flowing back to the LLM is sanitised. The unit tests in
  `tests/test_helpers.py` (classes `TestStripInvisibles` and
  `TestSanitisationIntegration`) make the coverage explicit.
- `proton_read_email` wraps `body_text` and `body_html` (when included) with
  `_wrap_untrusted` before returning. The opening tag uses a
  `secrets.token_hex(3)` nonce; the closing tag uses the same nonce. Both
  characteristics are asserted by `TestWrapUntrusted` in
  `tests/test_helpers.py`.
- `proton_read_email` calls `_parse_authentication_results` on the message
  and forwards the SPF / DKIM / DMARC tokens it finds into the wrapper as
  provenance attrs and into the JSON payload's `authentication` field. The
  parser keeps the first result it sees per method across multiple
  `Authentication-Results` headers, on the convention that the topmost
  header is added by the closest trusted MTA (Proton's own MX for
  Bridge users). Coverage is in `TestParseAuthenticationResults` in
  `tests/test_helpers.py`.
- `SendEmailInput`, `DeleteInput`, `CreateDraftInput`, and
  `DownloadAttachmentInput` all declare `acknowledged: bool = Field(...)`
  with no default — pydantic rejects calls that omit the field. The tool
  bodies of `proton_send_email`, `proton_delete_email`, and
  `proton_download_attachment` short-circuit unconditionally on
  `acknowledged=False` and return `_refused_unack(...)`.
  `proton_create_draft` short-circuits only when `_external_recipients`
  finds at least one non-self address among the recipients. Both
  behaviours are pinned by `TestSendEmailInputRequiresAck`,
  `TestDeleteInputRequiresAck`, `TestCreateDraftInputRequiresAck`,
  `TestDownloadAttachmentInputRequiresAck`, `TestExternalRecipients`,
  and `TestRefusedUnack` in `tests/test_helpers.py`.
- `ATTACHMENT_DIRS` is empty unless `PROTON_BRIDGE_ATTACHMENT_DIRS` is set, and
  `_load_attachments` then refuses every file. When folders are configured, it
  checks them against the path with symlinks resolved. Both behaviours are
  pinned by `TestLoadAttachments` and `TestAttachmentDirsEnv` in
  `tests/test_helpers.py`.
- No credential, cert path, or message body is logged at `INFO` or `DEBUG`.

If any of these is no longer true, that itself is a security bug — please
report it via the channel above.

## Hardening recommendations for operators

- Stay on the default `PROTON_BRIDGE_TLS_POLICY=pinned`. `best_effort` exists
  as an explicit downgrade for first-install diagnostics — not as a
  long-term posture. If you've set it during troubleshooting, drop it from
  the env once `bootstrap.py` has captured Bridge's cert.
- Keep Bridge up to date. Bridge regenerates its TLS cert on some upgrades; in
  pinned mode, that means re-running `bootstrap.py` (the cert capture step).
- Review the MCP client's destructive-action confirmation policy. Never let
  the model auto-execute send/delete/move based on inbound email content.
- Leave `PROTON_BRIDGE_ATTACHMENT_DIRS` unset unless you need to send local
  files. If you do, name a dedicated folder without secrets, not your home
  directory or a whole cloud drive.
- Rotate the Bridge app-password periodically via Bridge → *Mailbox details*,
  followed by `setup_keychain.sh` (or `bootstrap.py --force-password`).
