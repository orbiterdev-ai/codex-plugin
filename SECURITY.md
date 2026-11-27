# Security Policy - Orbiter Dev OpenAI Codex Plugin

## Supported Versions

Orbiter Dev actively maintains security fixes for `orbiterdev-ai/codex-plugin`.

| Version | Supported |
| :--- | :--- |
| `1.0.x` | Yes |
| `< 1.0.0` | No |

## Reporting a Vulnerability

Please do not open a public GitHub issue for suspected security vulnerabilities, credential leaks, or hook bypasses.

Send a private security report to **`support@orbiterdev.ai`** with the subject line `[Security] codex-plugin: <short summary>`.

Include as much of the following as you can:

- Plugin version and OpenAI Codex CLI / ChatGPT version.
- Operating system and Node.js runtime version.
- Minimal reproduction steps, sample hook stdin payload (with real secrets removed), and expected versus actual hook output.
- Potential impact on the approval boundary or host credential safety.

### Response Timeline

- **Acknowledgment:** Within 48 hours of receiving your report.
- **Triage and severity assessment:** Within 5 business days.
- **Remediation and coordinated disclosure:** We coordinate fix validation and release notes before any public disclosure.

## Enterprise Hardening Invariants

The bundled hook runner (`hooks/orbiter-codex-hook.cjs`) is a self-contained, zero-dependency Node.js (`>=18`) fail-closed enforcement engine implementing 11 verified security controls plus structural command normalization and strict read-only allowlisting:

1. **No self-hook substring bypass:** Loop prevention matches explicit Orbiter MCP tool names only, never command strings or argument substrings.
2. **Command structure normalization and cross-platform destructive detection:** Deterministic quote-aware shell tokenization strips wrapper prefixes (`env`, `sudo`, `doas`, `command`, `exec`, `nohup`, `xargs`, full binary paths) and CLI global options (`git -C`/`--git-dir`/`--work-tree`, `aws --profile`/`--region`, `kubectl --context`/`-n`, `docker --host`, `terraform -chdir`, `npm --prefix`, `wrangler --env`) before risk classification across POSIX, PowerShell (`Remove-Item -Recurse -Force`, `Format-Volume`, `Clear-Disk`), Windows `del`/`rmdir`, SQL, Git, container, Kubernetes, Terraform, and cloud CLIs.
3. **SSRF and credential-exfiltration protection:** `ORBITER_API_URL` is restricted to `https://` (or explicit loopback `http://127.0.0.1`, `http://localhost`, `http://[::1]` for local development) with zero embedded credentials, zero query or fragment parameters, and `redirect: "error"`.
4. **Strict token-parsed read-only allowlist and exec-option escalation:** Fast-path allow permits only strictly allowlisted read-only flags on in-workspace non-sensitive targets. Shell metacharacters (`;`, `&`, `|`, backticks, `$`, `<`, `>`, `(`, `)`, newlines, null bytes) and external-execution flags (`rg --pre`/`--pre-glob`/`--hostname-bin`, `git -c`/`--config-env`/`--exec-path`/`--ext-diff`/`--textconv`/`--output`, `fd -x`/`-X`, `find`, `tar`) are never fast-allowed and route to mobile approval.
5. **Sensitive credential and infrastructure-write protection:** Detects `.env`, `.ssh/`, `.aws/`, `.gnupg/`, `.kube/config`, `.docker/config.json`, `.orbiter/`, `.npmrc`, `.pypirc`, `.netrc`, `.git-credentials`, `id_ed25519`/`id_rsa`, `credentials`, `secrets`, `.pem`/`.key`/`.p8`, `/etc/shadow`, and infrastructure writes (`.github/workflows/`, `migrations/`, `.git/`, `.tf`, `Dockerfile`, hook runners).
6. **Path traversal and workspace isolation:** Canonicalizes paths with drive-aware `path.posix.normalize()` against active workspace roots. Any `..`, `~/`, or out-of-workspace target blocks fast-path allow on both read and write actions.
7. **Secret redaction and Zero Data Mode:** Strips Bearer/Basic headers, API keys, JWTs, cloud credentials, PEM private keys, and active `ORBITER_API_KEY` / `ORBITER_TOKEN` values from payloads, `stdout`, `stderr`, and errors. Set `ORBITER_ZERO_DATA_MODE=1` to withhold raw tool arguments locally.
8. **Symlink-safe credential loading and DoS resilience:** Rejects symlinks, non-regular files, and files over `64 KiB` when reading local credential files, honors `ORBITER_DISABLE_CREDENTIAL_FILE=1`, enforces a `2 MiB` stdin cap with early abort, caps JSON nesting depth (`64`), rejects null bytes, uses zero `eval`, and fails closed with deterministic `deny` output on every error path.
9. **Zero runtime dependency and shell-wrapper attack surface:** Runs directly on built-in Node.js `>=18` APIs with zero external npm dependencies, zero `npx` wrappers, and zero `shell: true` subprocess invocations.
10. **Supply-chain and static-analysis hygiene:** Uniform LF line endings, automated E2E and adversarial security tests, 40-char SHA-pinned GitHub Actions (`ci.yml` and `codeql.yml` CodeQL v4), and SHA-256 verified MIT Gitleaks `v8.30.1` scanning in CI.
11. **Zero telemetry by default:** Non-gating hooks transmit zero telemetry unless `ORBITER_CODEX_REPORT_TELEMETRY=true` is explicitly configured.

## Security Boundary Assumptions

- Local pre-execution hooks depend on OpenAI Codex trusting and enabling `[features] hooks = true` so `PreToolUse` and `PermissionRequest` hooks execute before tool invocations. The E2E suite also enforces byte-identical parity between root files and the `plugins/orbiter-dev/` marketplace mirror.
- A compromised workstation OS account with direct shell access outside the agent harness can bypass any local hook process.
- Store operator tokens in restricted local files (`~/.orbiter/credentials.json`, owner-only permissions) or environment variables rather than committing them to repositories.
