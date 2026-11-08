# Security review: Craft Anything 0.4.0

A read-only audit of this repository, answering one question: **does this code try to compromise
the user's API keys, their machine, or anything else?**

Scope: the whole workspace at `1f8508a` — `crates/`, `apps/`, `xtask/`, `vendor/`, build scripts,
and the dependency manifest. Method: reading the source, not running it against a live provider.
Two builds were run to confirm the tree compiles (`cargo build -p craft-anything-cli` and
`cargo build -p craft-anything`), and the CLI was exercised (`doctor`, `capabilities`, `triage`,
`ai detect`).

## Verdict

**No evidence of malicious intent.** There is no telemetry, no analytics, no phone-home, no update
check, and no credential harvesting. Keys are stored in the OS keychain, are never returned by a
tool, and are redacted from journals and evidence. Every outbound request goes to a host the user
configured or a pinned vendor URL, over TLS with certificate validation that cannot be turned off.

The real risks are **design** risks, not deception: a builder agent you point at this tool can act
with your full user privileges, and child processes inherit your environment. Those are documented
below as findings, because a user should know them before running a build.

## Findings

| # | Severity | File | Lines | Vulnerability | Confidence |
|---|----------|------|-------|---------------|------------|
| 1 | 🟠 HIGH | `crates/ai/src/cli_agents/adapters/antigravity.rs` | 4, 17–19 | Builder mode passes `--dangerously-skip-permissions`, and the adapter has no `validate_access` override, so Clean room is not enforced. Grok and Aider both refuse Clean room explicitly. | 8/10 |
| 2 | 🟡 MEDIUM | `crates/ai/src/ssh.rs` | 15–22 | `ssh_host` is not checked for a leading `-` and is placed before `--` in `ssh_line_args`, so a crafted value can be read as an ssh option. | 7/10 |
| 3 | 🟡 MEDIUM | `crates/engine/src/tools/build_tools.rs` | 338–341 | `build_command_run` runs arbitrary shell (`cmd /C` / `sh -c`). In Auto mode the `commands` kind defaults to allow, so a builder can run any command as the user. | 9/10 |
| 4 | 🟡 MEDIUM | `crates/platform/src/process.rs` | 124, 278–286 | Child processes inherit the full environment by default (`env_clear` is opt-in), so agent CLIs and MCP servers see API keys present in the environment. | 8/10 |
| 5 | ⚪ LOW | `crates/engines/src/assets/fal.rs` | 121–140 | Generated files are downloaded from whatever https URL the provider returns, with no host allowlist. | 7/10 |
| 6 | ⚪ LOW | `crates/engine/src/tools/web_common.rs` | 192, 247 | A launched Chromium gets `--remote-allow-origins=*` on its CDP port. The port is loopback-only and ephemeral, so exposure is limited to local processes. | 7/10 |
| 7 | ⚪ LOW | `crates/engine/src/tools/web_common.rs` | 205 | `--no-sandbox` is available as an opt-in browser flag (`no_sandbox`). | 9/10 |
| 8 | ⚪ LOW | `crates/engines/src/game.rs` | 852–915 | Unity and Unreal installers are downloaded and then run, after an Authenticode publisher check. Godot's checksum comes from the same release over HTTPS, which catches a broken download but not a compromised release. | 8/10 |

No CRITICAL findings.

## Why the keys are not being harvested

This is the question worth answering precisely, so here is the evidence rather than an assurance.

### Where a key can come from

`crates/ai/src/keys.rs` resolves a key in three places, in order:

1. The OS keychain, via the `keyring` crate, under service `ai.storyteller.craft-anything`.
2. `<config dir>/ai-keys.toml`, written with `write_atomic_private` (mode 0600 on Unix), and only
   as a labelled fallback when no keychain is available.
3. A named environment variable — `ANTHROPIC_API_KEY`, `OPENAI_API_KEY`, `OPENROUTER_API_KEY`,
   `GEMINI_API_KEY`, `FAL_KEY`, and the per-provider names in `providers.rs`.

Nothing else is read. There is no scan of the filesystem for credentials.

### Where a key can go

Every place a key is attached to a request:

- `crates/ai/src/openai.rs:116` — `authorization: Bearer <key>`, sent to `self.base_url`, which is
  the user's configured base URL or a pinned constant (`api.openai.com`, `openrouter.ai`,
  `generativelanguage.googleapis.com`, `opencode.ai`).
- `crates/ai/src/anthropic.rs:67` — `x-api-key`, and `is_anthropic_api` requires `https` plus the
  exact host `api.anthropic.com` before a key is used that way.
- `crates/engines/src/assets/fal.rs:89` — `Authorization: Key <key>`, sent only to
  `https://fal.run/{model}`.

`providers::of_base` (`crates/ai/src/providers.rs:120`) is the gate for handing an environment key
to a base URL, and it is deliberately strict: **HTTPS only**, and an exact host match against a
known provider row. A settings file edited to point at an attacker's host does not receive an
environment key, because `of_base` returns `None` for an unknown host and for any `http://` base.

The one non-obvious header is `x-opencode-session` (`crates/ai/src/openai.rs:31`), sent only when
the base URL is OpenCode Go's own. Its value is `craft-<pid>-<nanos>` (`crates/ai/src/lib.rs:121`),
generated locally with no personal data in it.

### What is not there

- **No telemetry or analytics.** Searching the workspace for `telemetry`, `analytics`, `sentry`,
  `posthog`, `mixpanel`, `amplitude`, and update-check patterns finds only third-party names in
  detection tables (`crates/js/src/vendor.rs`, `crates/engines/src/game.rs`) and Aider's own
  `--no-analytics` flag, which this tool passes to *disable* it.
- **No credential-store access.** No code opens browser `Login Data` or `Cookies`, `~/.aws`,
  `id_rsa`, `.netrc`, `.git-credentials`, wallet files, or Chrome's `Local State`. The only files
  read from a home directory for credentials are `~/.ssh/config` (host aliases only) and
  `~/.npmrc` (the `prefix` setting only).
- **No key echo.** `status_error` (`crates/ai/src/http.rs:52`) builds its message from the
  provider's human-readable error fields and never serialises the request. The journal redacts
  secret-named fields and credential-shaped tokens (`crates/engine/src/journal.rs`,
  `crates/analysis/src/standin.rs`).
- **No TLS escape hatch.** `ureq` with `rustls` and `webpki-roots`; there is no
  `danger_accept_invalid_certs` anywhere in the workspace.
- **No `unsafe` in first-party code.** `crates/` and `apps/` contain no `unsafe` block, function,
  or impl; the workspace sets `unsafe_code = "forbid"` (`Cargo.toml:69`). The only `unsafe` in the
  tree is inside `vendor/wgpu-hal`, which is upstream wgpu code, not this project's.
- **No hidden network path.** Every `ureq` agent in the workspace is accounted for: model calls
  (`crates/ai/src/http.rs`), engine downloads (`crates/engines/src/install.rs`), fal assets
  (`crates/engines/src/assets/fal.rs`), MCP clients (`crates/engines/src/mcp_client.rs`), and the
  cutter's local helper (`crates/engines/src/cutter.rs`). The `xtask` secret scanner reads the
  environment but makes no network calls.

### The honest caveat

A key *is* sent to whatever base URL the user configures for an OpenAI-compatible backend. That is
the feature — pointing the tool at Ollama, LM Studio, or a hosted service. If you paste a base URL
belonging to someone else and give it a key, that party receives the key. The code cannot tell a
legitimate server from a hostile one; it only refuses to leak an *environment* key to an unknown
host. Treat a custom base URL as you would any other place you type a credential.

### What this review cannot prove

"Absolutely positive" is not a claim a source review can honestly make. What was established, and
what was not:

- **Established:** in first-party source at `1f8508a`, every code path that sends a key was read,
  and each goes to a user-configured base URL or a pinned vendor host. No telemetry or
  credential-store access exists in that source.
- **Not established — third-party crates.** `Cargo.lock` pins hundreds of crates.io dependencies;
  they were checked for source (crates.io only, no git deps) but not read line by line. A
  compromised dependency release is the realistic route for exfiltration in any Rust project.
- **Not established — the published binaries.** The release installers were not built from source
  here and compared. Only a binary you build yourself from this tree (`cargo build --release`)
  matches what was reviewed.
- **Not established — other commits.** Later commits can change any of the above.
- **Not established — a runtime trace.** No network capture was taken while a build ran.

To get closer to certainty: build from source, run `cargo audit` and `cargo deny check` (the repo
ships `deny.toml`), and watch outbound connections (Wireshark, or Windows Resource Monitor) while
running a build. Expect connections only to the model host you configured. For keys specifically,
prefer a provider key with a spend limit, and keep it in the OS keychain rather than the
environment, because child processes inherit the environment (finding 4).

## What the tool does to the machine

- **Process execution** goes through `crates/platform/src/process.rs`: stdin is closed or piped and
  never inherited, wall-clock and idle deadlines apply, output is capped, and the process group or
  Job Object is killed on timeout.
- **Approvals** are enforced in `crates/engine/src/lib.rs::call_inner` and
  `crates/engine/src/workspace.rs::ACTION_KINDS`. Auto mode allows `web`, `commands`, and
  `outside_files`, and refuses `publish`, `delete_outside`, `system`, and `other_tools`. An agent
  can only make a kind stricter, never looser (`project_tools.rs::project_approvals_set`).
- **Consent** is required for tools whose effects include `EXECUTES_FOREIGN_CODE` or
  `MUTATES_DEVICE`, unless the project has allowed that tool or `ask_before_running` is off
  (default: on).
- **Local servers** bind `127.0.0.1` only, check the `Host` header against loopback, check
  `Origin`, and reject `..` and absolute paths after canonicalisation
  (`crates/platform/src/serve.rs`, `crates/platform/src/standin_server.rs`).
- **WASM plugins** are wasmtime components with an empty `Linker` — no WASI, so no files, network,
  or environment — plus memory, instance, and fuel limits (`crates/engines/src/wasm_plugin.rs`).
- **Engine installs** are HTTPS-only, SHA-256 verified while streaming, unpacked zip-slip-safe into
  a temp directory and then renamed into place (`crates/engines/src/install.rs`).
- **Setup** writes MCP server entries into agent app configs with a first-time backup, an atomic
  private write, a read-back check, and rollback on failure (`crates/setup/src/plan.rs`).

## Supply chain

- `Cargo.lock` contains only crates.io sources; there are no git dependencies.
- The only vendored crate is `vendor/wgpu-hal`, patched solely for Metal MSL version probing and
  documented in `vendor/wgpu-hal/CRAFT_ANYTHING.md`. It was scanned for process, network,
  environment, and credential calls and contains none.
- Build scripts exist only in `crates/ui-egui` (optional `CRAFT_FONTS_DIR` embedding) and the two
  app crates (Windows icon and manifest via `winresource`).
- `.githooks/pre-commit` runs `cargo xtask secrets`, which scans staged files for secret-shaped
  values and for this machine's own environment values.

## Recommendations

1. Give the Antigravity adapter a `validate_access` that refuses Clean room, as Grok and Aider do
   (finding 1).
2. Reject an `ssh_host` that starts with `-`, or place it after `--` (finding 2).
3. Consider defaulting `commands` to `ask` in Auto mode, or documenting the current default more
   prominently (finding 3).
4. Consider `env_clear` plus an explicit allowlist for agent CLI and MCP child processes, so keys
   in the environment are not inherited by default (finding 4).
5. Restrict fal's generated-file download to the provider's own media hosts (finding 5).
