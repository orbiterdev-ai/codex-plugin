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

- **Strict read-only fast-path allowlist:** Safe read-only tools and single read-only commands (`git status`, `git diff`, `ls`, `cat`, `rg "foo" src/`) with strictly allowlisted read-only flags on in-workspace non-sensitive files allow locally with zero network calls. Effectful or external-exec flags (`rg --pre`, `rg --pre-glob`, `rg --hostname-bin`, `rg -z`, `git -c`, `git --config-env`, `git --exec-path`, `git --git-dir` outside workspace, `git diff --ext-diff`, `git log --textconv`, redirects, pipes) are never fast-allowed and route to approval on both `PreToolUse` and `PermissionRequest`.
- **Command structure normalization & high-risk interception:** Wrappers (`env`, `sudo`, full executable paths like `/usr/bin/git` or `git.exe`) and CLI global options (`git -C`, `--git-dir`, `--work-tree`, `-c`; `aws --profile --region`; `kubectl --context -n`; `docker --host`; `terraform -chdir`; `npm --prefix`; `wrangler --env`) are normalized before risk classification. Equivalent forms of destructive shell, Git, cloud, container, database, and publishing actions always reach the same high/critical approval threshold.
- **Default vs. strict profile for unknown/effectful operations:** Under the default profile (`ORBITER_HOOK_PROFILE=default`, `ORBITER_MIN_RISK=high`), `PreToolUse` gates all `high` and `critical` actions while allowing unclassified `medium` workspace commands and routine in-workspace edits locally, and `PermissionRequest` gates every non-allowlisted action including `medium`. Set `ORBITER_HOOK_PROFILE=strict` (or `ORBITER_MIN_RISK=medium`) to require mobile sign-off for all unknown/effectful commands and edits on `PreToolUse` as well.
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
