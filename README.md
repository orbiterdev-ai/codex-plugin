# Orbiter Dev - OpenAI Codex & ChatGPT Plugin

One-tap human sign-off on **iOS and Android** (Face ID and Android biometrics) before AI agents take real-world action.

Orbiter Dev brings deterministic pre-execution lifecycle hooks and zero-install Hosted Remote MCP tools into OpenAI Codex and ChatGPT in a single plugin bundle, built for engineering, DevOps, and business teams alike.

## What Is Included

- **Dual-compatible plugin manifests:** `plugin.json` (Agent Plugins 1.0 / OpenAI Developer Plugins Dashboard) and `.codex-plugin/plugin.json` (native Codex CLI plugin format).
- **Hosted Remote MCP (`mcp.json`):** Zero-install Streamable HTTP + OAuth 2.1 PKCE connection to `https://mcp.orbiterdev.ai/mcp` (exposing `orbiter_auth_status`, `orbiter_request_approval`, `orbiter_await_approval`, `orbiter_list_pending_approvals`, and `orbiter_get_approval_status`).
- **Deterministic lifecycle hooks (`hooks/hooks.json` + `hooks/orbiter-codex-hook.cjs`):** Zero-dependency Node.js (`>=18`) hook runner for `PreToolUse`, `PermissionRequest`, `PostToolUse`, and `Stop`.
- **Progressive-disclosure skill (`skills/orbiter-approvals/SKILL.md`):** Guides AI agents on when and how to request and await mobile biometric confirmation.
- **Git Marketplace catalog (`.agents/plugins/marketplace.json`):** Ready for direct team installs through `codex plugin marketplace add` and `codex plugin add`.
- **Self-contained E2E test suite (`tests/e2e_codex_plugin.test.js`):** Verifies manifests, live Hosted Remote MCP discovery/OAuth challenge, fast-path read-only allow, mobile approval/rejection polling, secret redaction, and fail-closed security.

## Installation

### Option 1: Codex CLI Git Marketplace (Recommended)

```bash
codex plugin marketplace add https://github.com/orbiterdev-ai/codex-plugin
codex plugin add orbiter-dev@orbiter-dev
```

After installation, review and trust the bundled Orbiter Dev hooks in Codex (**Settings -> Hooks** or the workspace trust prompt) and enable hooks in `~/.codex/config.toml`:

```toml
[features]
hooks = true
```

### Option 2: OpenAI Developer Plugins Dashboard (ZIP Upload)

Upload the packaged `orbiterdev-ai-codex-plugin.zip` archive directly in the OpenAI Developer Plugins Dashboard. The bundle ships with root `plugin.json`, `.codex-plugin/plugin.json`, `mcp.json`, `hooks/hooks.json`, `skills/orbiter-approvals/SKILL.md`, and `assets/logo.png` / `assets/logo.svg`.

### Option 3: Local Stdio MCP Fallback

If your environment requires local stdio MCP instead of Hosted Remote MCP (`https://mcp.orbiterdev.ai/mcp`), configure the published npm server:

```json
{
  "mcpServers": {
    "orbiter-dev": {
      "command": "npx",
      "args": ["-y", "@orbiterdev/mcp-server"],
      "env": {
        "ORBITER_SERVER_URL": "https://api.orbiterdev.ai",
        "ORBITER_CREDENTIAL_PROFILE": "codex",
        "ORBITER_IDE_NAME": "Codex"
      }
    }
  }
}
```

## Pairing Your Phone (iOS & Android)

1. Install the Orbiter Dev mobile app on **iOS** (App Store, APNs + Face ID) or **Android** (Google Play, FCM + Android biometrics) via [orbiterdev.ai/setup](https://orbiterdev.ai/setup).
2. For Hosted Remote MCP, sign in through the OAuth 2.1 PKCE prompt when Codex connects to `https://mcp.orbiterdev.ai/mcp`.
3. For local pre-execution hooks (`hooks/orbiter-codex-hook.cjs`), set your Orbiter API token or pair your desktop credential profile:

```bash
export ORBITER_API_URL="https://api.orbiterdev.ai"
export ORBITER_API_KEY="your_paired_orbiter_token"
```

## Security & Fail-Closed Design

- **Instant local fast-path allow:** Safe read-only tools and single read-only commands (`git status`, `git diff`, `ls`, `cat`, `rg`) on non-sensitive workspace files allow locally with zero network calls.
- **High-risk interception:** Destructive shell commands (`rm -rf`, `git push --force`, `terraform destroy`, `kubectl delete`, `curl | sh`, `base64 -d | bash`, `Format-Volume`) pause for mobile sign-off. Destructive SQL (`DROP DATABASE`, `TRUNCATE TABLE`, `DELETE FROM`), path traversal (`../../.env`), credential reads (`~/.ssh/id_rsa`, `~/.aws/credentials`, `.npmrc`), production deploys, and package publishing also pause.
- **SSRF & transport guardrails:** `ORBITER_API_URL` requires HTTPS (with explicit `http://127.0.0.1` or `http://localhost` allowed for local development), forbids embedded credentials, and disables HTTP redirects.
- **Redacted payloads & Zero Data Mode:** Tokens, bearer headers, API keys, JWTs, AWS secrets, and private keys are scrubbed before leaving your machine. Set `ORBITER_ZERO_DATA_MODE=1` to withhold tool arguments entirely.
- **Fail-closed guarantee:** Mobile rejection, approval timeout, unreachable backend, missing credentials, oversized stdin (`>2 MiB`), or malformed hook input always return `deny`.

## Pricing

- **Free:** `€0` (50 mobile approvals per week)
- **Pro:** `€19.99/mo` (or `€219.99/yr` annual) for unlimited mobile approvals and full audit history

Learn more at [orbiterdev.ai/setup](https://orbiterdev.ai/setup).

## Running the E2E Test Suite

Requires Node.js 18 or newer with zero external packages:

```bash
node --check hooks/orbiter-codex-hook.cjs
node --test tests/e2e_codex_plugin.test.js
```

## License

MIT License. Copyright (c) 2026 Orbiter Dev. See [LICENSE](LICENSE).
