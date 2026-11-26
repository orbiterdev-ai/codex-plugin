# Security Policy

## Supported Versions

Orbiter Dev actively maintains security fixes for the official OpenAI Codex and ChatGPT plugin bundle (`orbiterdev-ai/codex-plugin`).

| Version | Supported |
| :--- | :--- |
| `1.0.x` | Yes |
| `< 1.0.0` | No |

## Reporting a Vulnerability

Please do not open a public GitHub issue for suspected security vulnerabilities, credential leaks, or hook bypasses.

Send a private security report to **`support@orbiterdev.ai`** with the subject line `[Security] codex-plugin: <short summary>`.

Include as much of the following as you can:

- Plugin version (`plugin.json` and `.codex-plugin/plugin.json`) and Codex CLI or ChatGPT runtime version.
- Operating system and Node.js runtime version.
- Minimal reproduction steps, sample hook stdin payload (with real secrets removed), and expected versus actual hook output.
- Potential impact on the approval boundary or host credential safety.

### Response Timeline

- **Acknowledgment:** Within 48 hours of receiving your report.
- **Triage and severity assessment:** Within 5 business days.
- **Remediation and coordinated disclosure:** We coordinate fix validation and release notes before any public disclosure.

## Security Architecture and Trust Boundary

This plugin enforces an **out-of-band mobile approval boundary** between autonomous AI agents running inside OpenAI Codex or ChatGPT and high-risk actions on your workstation or connected services.

### Core Guarantees

1. **Out-of-Band Human Sign-Off (iOS and Android):** High-risk actions (`rm -rf`, `git push --force`, `DROP DATABASE`, `terraform destroy`, `kubectl delete`, `curl | sh`, `base64 -d | bash`, credential reads, production deploys) pause locally. Execution waits for approval on your paired mobile device using Face ID or Android biometrics.
2. **Fail-Closed Execution:** Missing credentials, HTTP `401`/`403` errors, approval timeouts, unreachable API endpoints, oversized stdin payloads (`>2 MiB`), null bytes, or malformed JSON deterministically return `deny`.
3. **SSRF and Transport Hardening:** `ORBITER_API_URL` enforces `https://` for remote backends, permits explicit loopback (`http://127.0.0.1`, `http://localhost`, `http://[::1]`) only for local development, rejects embedded URL credentials, and disables HTTP redirects (`redirect: "error"`).
4. **Secret Redaction and Zero Data Mode:** The hook runner scrubs `Bearer` headers, API keys, JWTs, cloud credentials, private key blocks, and active runtime `ORBITER_TOKEN` / `ORBITER_API_KEY` values before metadata leaves your host. Setting `ORBITER_ZERO_DATA_MODE=1` withholds tool arguments completely.
5. **Hosted Remote MCP Authentication:** `mcp.json` connects to `https://mcp.orbiterdev.ai/mcp` over Streamable HTTP with OAuth 2.1 PKCE rather than storing long-lived plaintext credentials in the repository.
6. **Zero Runtime Dependencies and Mirror Parity:** `hooks/orbiter-codex-hook.cjs` uses Node.js built-in modules only, and the E2E suite enforces byte-identical parity between root files and the `plugins/orbiter-dev/` marketplace mirror.

### Security Boundary Assumptions

- Local pre-execution hooks depend on OpenAI Codex trusting and enabling `[features] hooks = true` so `PreToolUse` and `PermissionRequest` hooks execute before tool invocations.
- A compromised workstation OS account with direct shell access outside the agent harness can bypass any local hook process.
- Users should store operator tokens in restricted local files (`~/.orbiter/credentials.json`, owner-only permissions) or environment variables rather than committing them to repositories.
