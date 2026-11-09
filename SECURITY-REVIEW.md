# Security review: Craft Anything 0.4.0

A read-only audit of this repository, answering one question: **does this code try to compromise
the user's API keys, their machine, or anything else?**

Scope: the whole workspace at `35e580e` — `crates/`, `apps/`, `xtask/`, `vendor/`, build scripts,
the dependency manifest, and the dependency tree itself. Method: reading the source, plus the
tooling this review previously only recommended. `cargo audit` and `cargo deny check` were run
against the real lockfile, every dependency build script and proc-macro was scanned, and the
lockfile was updated to clear what could be cleared. Two builds were run to confirm the tree
compiles after the update.

## Verdict

**No evidence of malicious intent.** There is no telemetry, no analytics, no phone-home, no update
check, and no credential harvesting. Keys are stored in the OS keychain, are never returned by a
tool, and are redacted from journals and evidence. Every outbound request goes to a host the user
configured or a pinned vendor URL, over TLS with certificate validation that cannot be turned off.

**But the TLS stack was out of date, and that is the most important change since the last review.**
`cargo audit` found two live vulnerabilities in the certificate-verification path that every
connection uses. Both are fixed in this branch by a lockfile update. Details in finding 9.

The real risks remain **design** risks, not deception: a builder agent you point at this tool can
act with your full user privileges, and child processes inherit your environment. Those are
documented below as findings, because a user should know them before running a build.

## Findings

| # | Severity | File | Lines | Vulnerability | Confidence |
|---|----------|------|-------|---------------|------------|
| 1 | 🟠 HIGH | `crates/ai/src/cli_agents/adapters/antigravity.rs` | 4, 17–19 | Builder mode passes `--dangerously-skip-permissions`, and the adapter has no `validate_access` override, so Clean room is not enforced. Grok and Aider both refuse Clean room explicitly. | 8/10 |
| 2 | 🟡 MEDIUM | `crates/ai/src/ssh.rs` | 15–22 | `ssh_host` is not checked for a leading `-` and is placed before `--` in `ssh_line_args`, so a crafted value can be read as an ssh option. | 7/10 |
| 3 | 🟡 MEDIUM | `crates/engine/src/tools/build_tools.rs` | 338–341 | `build_command_run` runs arbitrary shell (`cmd /C` / `sh -c`). In Auto mode the `commands` kind defaults to allow, so a builder can run any command as the user. | 9/10 |
| 4 | 🟡 MEDIUM | `crates/platform/src/process.rs` | 124, 278–286 | Child processes inherit the full environment by default (`env_clear` is opt-in), so agent CLIs and MCP servers see API keys present in the environment. Only `CLAUDE_*` variables are stripped (`cli_agents/mod.rs::host_session_vars`). | 9/10 |
| 5 | ⚪ LOW | `crates/engines/src/assets/fal.rs` | 121–140 | Generated files are downloaded from whatever https URL the provider returns, with no host allowlist. | 7/10 |
| 6 | ⚪ LOW | `crates/engine/src/tools/web_common.rs` | 192, 247 | A launched Chromium gets `--remote-allow-origins=*` on its CDP port. The port is loopback-only and ephemeral, so exposure is limited to local processes. | 7/10 |
| 7 | ⚪ LOW | `crates/engine/src/tools/web_common.rs` | 205 | `--no-sandbox` is available as an opt-in browser flag (`no_sandbox`). | 9/10 |
| 8 | ⚪ LOW | `crates/engines/src/game.rs` | 852–915 | Unity and Unreal installers are downloaded and then run, after an Authenticode publisher check. Godot's checksum comes from the same release over HTTPS, which catches a broken download but not a compromised release. | 8/10 |
| 9 | 🟠 HIGH (fixed here) | `Cargo.lock` | `rustls-webpki` 0.103.15, `webpki-roots` 1.0.9 | Two live advisories in the certificate-verification path used by every HTTPS request: RUSTSEC-2026-0382 (accepts distrusted intermediates) and RUSTSEC-2026-0381 (bundled roots trust distrusted emSign intermediates). Both are in the default build via `ureq`. Fixed by updating to 0.103.16 and 1.0.11. | 10/10 |
| 10 | 🟡 MEDIUM (open) | `Cargo.lock` | `rsa` 0.9.10, `crypto-bigint` 0.5.5 | RUSTSEC-2023-0071 (Marvin timing attack) and RUSTSEC-2026-0387 (timing variability). Reached through `formats` → `p256`/`ecdsa` for signature verification. No fixed version is reachable without a major-version bump; `deny.toml` already documents the rsa one. | 8/10 |
| 11 | ⚪ LOW (open) | `Cargo.lock` | `wasmtime` 49.0.4 | Three advisories (RUSTSEC-2026-0422/0423/0424): a panic, cross-engine type confusion, and unchecked memory in component resource transfer. Only in builds with the optional `wasm-plugins` feature, which is off by default. Fixed in 49.0.5. | 9/10 |

No CRITICAL findings.

### What the tooling found, and what was done about it

`cargo audit` reported 7 vulnerabilities and `cargo deny check` reported the same 7 plus 2 yanked
crates. After the lockfile update in this branch:

| Advisory | Crate | Status |
|---|---|---|
| RUSTSEC-2026-0382 | `rustls-webpki` 0.103.15 | **Fixed** → 0.103.16 |
| RUSTSEC-2026-0381 | `webpki-roots` 1.0.9 | **Fixed** → 1.0.11 |
| RUSTSEC-2026-0422/0423/0424 | `wasmtime` 49.0.4 | Open; optional feature only |
| RUSTSEC-2023-0071 | `rsa` 0.9.10 | Open; documented in `deny.toml` |
| RUSTSEC-2026-0387 | `crypto-bigint` 0.5.5 | Open; no compatible fix |
| yanked | `clipboard-win` 5.4.1 | **Fixed** → 5.4.3 |
| yanked | `async-executor` 1.14.0 | **Fixed** → 1.14.1 |

`cargo build -p craft-anything-cli` passes with the updated lockfile.

**Why finding 9 matters more than its advisory text suggests.** The previous review said "no TLS
escape hatch" and stopped there. That was true and incomplete: the verifier itself was vulnerable.
RUSTSEC-2026-0382 means a certificate chain containing a distrusted intermediate could be accepted,
which is the exact failure mode a user assumes TLS prevents. It is fixed now, but it shows why
"the code has no bypass" is not the same as "the connection is trustworthy" — the dependency
versions matter as much as the code.

### Dependency build scripts and proc-macros

The previous review named this as a gap. It is now closed for the crates actually in the tree.

- **53 dependency build scripts** were scanned for network, process, credential and filesystem
  access. Every `Command::new` found invokes `rustc --version` (or `freebsd-version`, `emcc
  -dumpversion`, `nasm`) to detect compiler features. None open a socket, read a credential file,
  or write outside `OUT_DIR`.
- **31 proc-macro crates** were scanned the same way. The only hits are `clap::Command::new`
  (clap's own argument builder, not a process spawn), `rustversion` writing its detected version
  to `OUT_DIR`, and `zerocopy-derive` writing test output when `ZEROCOPY_BLESS` is set. None
  reach the network or a credential store.
- This is a scan for the operations that could exfiltrate, not a line-by-line proof of every
  crate. A build script could still be malicious in a way these patterns miss, and a proc-macro
  runs arbitrary code by design. `--locked` plus a reviewed lockfile is the practical control.

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
- **No TLS escape hatch in the code.** `ureq` with `rustls` and `webpki-roots`; there is no
  `danger_accept_invalid_certs` anywhere in the workspace. This says nothing about the *version*
  of the verifier — see finding 9, where the verifier itself was vulnerable until this branch.
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

### Complete inventory of outbound paths (first-party source)

Found by searching `crates/`, `apps/` and `xtask/` for every route to the network, not by reading
the AI code alone. Re-run these to check it yourself.

| Route | How it was searched | Result |
|---|---|---|
| HTTP clients | `ureq`, `reqwest`, `hyper`, `curl`, `isahc`, `surf`, `attohttpc`, `minreq` in `Cargo.lock` and every `Cargo.toml` | Only `ureq` 3 (rustls + webpki-roots), declared by `crates/ai` and `crates/engines` only. No async runtime or HTTP stack of our own. |
| `ureq` call sites | `.get(` / `.post(` / `.call(` / `.send(` | Six, all listed below. |
| Raw sockets | `std::net`, `TcpStream`, `TcpListener`, `UdpSocket`, `ToSocketAddrs` | Loopback servers and probes (preview, stand-in, Ghidra, Cutter, CDP, JEB), plus `detect.rs` port probes of hosts you configure. `formats/src/pcap.rs` only *parses* capture files. |
| Shelling out to a downloader | `curl`, `wget`, `Invoke-WebRequest`, `Invoke-RestMethod`, `DownloadFile`, `certutil`, `bitsadmin`, `nc` | None. Every `powershell` call is local: keep-awake, end a process tree, `Get-AuthenticodeSignature`. |
| Programs spawned | every `Process::new("…")` / `Command::new("…")` literal | `git`, `cargo`, `ssh`, `sh`, `cmd`, `powershell`, `caffeinate`, `xcrun`, `tasklist`, `ps`, `sleep`, plus agent CLIs and browsers you choose. |
| Browser build | `fetch`, `XmlHttpRequest`, `WebSocket`, `sendBeacon` in `apps/craft-anything-web` | None. It reads one local file you pick. |
| UI image loading | `egui_extras` features | `svg` only. The `http` loader is off, so the UI cannot fetch an image from a URL. |
| Telemetry | `telemetry`, `analytics`, `sentry`, `posthog`, `mixpanel`, `amplitude`, `update_check` | None (only detection tables and Aider's `--no-analytics`). |
| Runtime-built URLs | `format!("https://…")`, `format!("{scheme}://…")` | The website target you type (`ui-egui/src/make.rs`), the Godot download (`engines/src/game.rs`), loopback test servers, and parsers of captured data. No URL is assembled from file contents or secrets. |
| Build scripts | all `build.rs`, including `vendor/` and every dependency | Four first-party: font embedding, Windows resources (two apps), and the vendored `wgpu-hal`'s `cfg_aliases` block. Plus 53 dependency build scripts, scanned: all invoke `rustc --version` or similar, none touch the network. |

The six `ureq` call sites and where each URL comes from:

| File | Destination | Carries |
|---|---|---|
| `ai/src/http.rs` (POST, GET) | the model backend you configured, or a pinned provider host (`api.openai.com`, `api.anthropic.com`, `openrouter.ai`, Gemini, `opencode.ai`, plus rows in `providers.rs`: DeepSeek, Moonshot, Z.ai, xAI, Together, Mistral, Groq, Fireworks, DeepInfra) | your prompt, tool results, and that backend's key |
| `engines/src/install.rs` | pinned `https://` URLs in `engines/src/table.rs`: `dl.google.com`, `github.com` releases (Vineflower, Rizin, Apktool, JADX, Ghidra, Temurin) | nothing; GET, SHA-256 checked |
| `engines/src/game.rs` via `download_to` | `github.com/godotengine/godot` releases; Unity, Epic and Visual Studio download pages | nothing; GET |
| `engines/src/assets/fal.rs` | `https://fal.run/{model}`, then the file URL fal returns | your prompt and fal key; the key goes to `fal.run` only |
| `engines/src/mcp_client.rs` | a plugin URL you added; `https://` or loopback only | tool arguments, and headers you set |
| `engines/src/cutter.rs` | `http://127.0.0.1:{port}` | local only |

Hostnames elsewhere in the source (`example.test`, `x.test`, `app.test`, `192.168.1.20`,
`attacker.example`, `evil.com`, schema namespaces and so on) are test fixtures, documentation
examples, or parser sample data, not connections. `registry.npmjs.org` appears only in a unit-test
`.npmrc`, `www.apple.com` only in plist DTD strings, and `fonts.googleapis.com` only in a regex
that recognises fonts in a page being studied.

Two outbound headers identify the *app*, not you: `HTTP-Referer: https://github.com/storytold/craft-anything`
and `X-Title: Craft Anything` on OpenRouter calls, and `x-opencode-session` (a random local id) on
OpenCode Go calls.

Two things leave your machine by design and are worth knowing: the website you ask it to study (a
launched Chromium visits it), and everything a coding-agent CLI you choose (Claude Code, Copilot,
and so on) sends under its own terms. This tool starts those programs; it does not control their
networking.

### What this review cannot prove

"Absolutely positive" is not a claim a source review can honestly make. What was established, and
what was not:

- **Established:** in first-party source (`crates/`, `apps/`, `xtask/`; audited at `1f8508a`,
  inventory re-run at `35e580e`), every route to the network is listed above, and each goes to a
  user-configured base URL or a pinned vendor host. No telemetry or credential-store access
  exists in that source.
- **Established:** `cargo audit` and `cargo deny check` were run against the real lockfile, and
  every dependency build script and proc-macro in the tree was scanned for network, process and
  credential access. The two TLS advisories that mattered are fixed in this branch.
- **Not established — third-party crates, line by line.** `Cargo.lock` pins hundreds of crates.io
  dependencies. They were checked for source (crates.io only, no git deps) and their build scripts
  and proc-macros were scanned, but their runtime code was not read line by line. A compromised
  dependency release is the realistic route for exfiltration in any Rust project.
- **Not established — the published binaries.** The release installers were not built from source
  here and compared. Only a binary you build yourself from this tree (`cargo build --release`)
  matches what was reviewed.
- **Not established — other commits.** Later commits can change any of the above.
- **Not established — a runtime trace.** No network capture was taken while a build ran.

To get closer to certainty: build from source with `--locked`, run `cargo audit` and `cargo deny
check` yourself (both are now installed on this machine), and watch outbound connections
(Wireshark, or Windows Resource Monitor) while running a build. Expect connections only to the
model host you configured. For keys specifically, prefer a provider key with a spend limit, and
keep it in the OS keychain rather than the environment, because child processes inherit the
environment (finding 4).

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
- First-party build scripts: `crates/ui-egui` (optional `CRAFT_FONTS_DIR` embedding), the two app
  crates (Windows icon and manifest via `winresource`), and the vendored `wgpu-hal`
  (`cfg_aliases` only). All four were read; none do I/O beyond the build.

### Cargo configuration: what runs when you build

Building runs code before the app ever starts, so the manifests were checked for anything that
changes *what* gets built or *what runs* at build time.

- **`.cargo/config.toml`** contains one line, an alias (`xtask = "run --quiet --package xtask --"`).
  No `rustflags`, no `runner`, no `linker`, no source replacement, no registry override.
- **Root `Cargo.toml`:** a workspace of local path crates, release-profile settings, and a single
  `[patch.crates-io]` that points `wgpu-hal` at the local `vendor/wgpu-hal` copy (documented in
  `vendor/wgpu-hal/CRAFT_ANYTHING.md`). No `[replace]`, no git dependency, no alternative registry.
- **No `rust-toolchain` file**, so nothing selects a toolchain for you.
- **Member manifests:** no git, branch, rev or registry dependencies anywhere. The only
  `[build-dependencies]` are `winresource` (two apps) and `cfg_aliases` (vendored). `xtask`
  depends on `syn` and `proc-macro2` for its own source scans.
- **`deny.toml`** sets `unknown-registry = "deny"` and `unknown-git = "deny"`, so `cargo deny
  check` would fail the build on either.

**What this does not cover.** Every crate in the dependency tree may ship its own `build.rs`, and
procedural macros are compiled and run by the compiler. Both execute arbitrary code with your user
privileges during `cargo build` or `cargo install`, and neither is visible from this repo's
manifests. `Cargo.lock` pins versions and checksums, and `--locked` makes cargo refuse to deviate
from it, which protects against a *later* tampered release but not against a crate that was
malicious when locked. To reduce that risk: build with `--locked`, run `cargo deny check` and
`cargo audit`, and for a high-stakes machine build inside a VM or container with no keys present.

- `.githooks/pre-commit` runs `cargo xtask secrets`, which scans staged files for secret-shaped
  values and for this machine's own environment values.

## Redirects and header forwarding

A key can leak through a redirect even when the original host is trusted. Checked directly:

- `ureq` 3.4.2 defaults to `RedirectAuthHeaders::Never` (`ureq/src/config.rs:952`), so
  `authorization` and `x-api-key` are **not** re-sent when a request is redirected to another host.
- No first-party agent overrides that setting: searching `crates/ai` and `crates/engines` for
  `redirect`, `max_redirects` and `RedirectAuthHeaders` finds nothing.
- The consequence: a hostile or compromised provider cannot bounce a request to a third party and
  collect the key. It can still see the key itself, which is the documented caveat above.

## Recommendations

1. Give the Antigravity adapter a `validate_access` that refuses Clean room, as Grok and Aider do
   (finding 1).
2. Reject an `ssh_host` that starts with `-`, or place it after `--` (finding 2).
3. Consider defaulting `commands` to `ask` in Auto mode, or documenting the current default more
   prominently (finding 3).
4. Consider `env_clear` plus an explicit allowlist for agent CLI and MCP child processes, so keys
   in the environment are not inherited by default (finding 4). Today only `CLAUDE_*` variables are
   removed.
5. Restrict fal's generated-file download to the provider's own media hosts (finding 5).
6. **Keep the lockfile current.** Finding 9 was a live TLS vulnerability that a routine
   `cargo update` fixed. Add `cargo audit` to CI so the next one is caught on the day it is
   published rather than at the next review.
7. Bump `wasmtime` to 49.0.5 for the three component-model advisories (finding 11), and revisit
   `rsa`/`crypto-bigint` when a compatible release exists (finding 10).
