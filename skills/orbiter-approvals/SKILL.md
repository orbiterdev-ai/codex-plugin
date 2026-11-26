---
name: orbiter-approvals
description: Request and await one-tap human sign-off on iOS and Android (Face ID and Android biometrics) via Orbiter Dev Hosted MCP before AI agents execute high-risk real-world actions.
---

# Orbiter Dev Mobile Approvals

Use this skill when an AI agent plans to run a high-risk, irreversible, external, or credential-sensitive action. Route the action to the operator's phone on iOS (Face ID via APNs) or Android (Android biometrics via FCM) before execution.

## Hosted Remote MCP Connection

This plugin configures the zero-install Orbiter Dev Hosted Remote MCP server:

- **Endpoint:** `https://mcp.orbiterdev.ai/mcp`
- **Transport:** Streamable HTTP (`streamable-http`)
- **Authentication:** OAuth 2.1 with PKCE
- **Setup & Mobile Pairing:** `https://orbiterdev.ai/setup`

### Available Remote MCP Tools

1. `orbiter_auth_status` - Verify sign-in status, user profile, and active plan (read-only).
2. `orbiter_request_approval` - Create a pending mobile approval request for the operator's phone. Never auto-approves.
   - Required argument: `action` (concise summary of the action)
   - Optional arguments: `description`, `risk_level` (`low` | `medium` | `high` | `critical`), `tool_name`, `details`, `workspace_name`, `response_format` (`concise` | `detailed`)
3. `orbiter_await_approval` - Wait up to 60 seconds (default 50s) for the operator's biometric decision on iOS or Android.
   - Required argument: `approval_id`
   - Optional argument: `max_wait_seconds` (1 to 60)
   - If the response returns `still_pending`, call `orbiter_await_approval` again to continue waiting until the phone settles the request.
4. `orbiter_list_pending_approvals` - List pending owner-scoped approvals.
5. `orbiter_get_approval_status` - Fetch point-in-time status for one `approval_id`.

## Mandatory Workflow for High-Risk Actions

1. Before running destructive shell commands (`rm -rf`, `git push --force`, `terraform destroy`, `kubectl delete`, `curl | sh`), database schema changes (`DROP TABLE`, `DELETE FROM`), production deployments, package publishing, or `.env` / private-key edits:
   - Call `orbiter_request_approval` with a clear `action`, accurate `risk_level`, and redacted `details` (never include raw secrets or API keys).
   - Call `orbiter_await_approval` with the returned `approval_id` and wait for a terminal decision.
2. Only proceed if the decision is explicitly `approved`.
3. If the decision is `rejected`, `denied`, `expired`, `timeout`, or if Orbiter Dev cannot be reached, stop immediately and report the block to the user. Never proceed without approval.

## Deterministic Lifecycle Hooks

In addition to MCP tools, this plugin bundles a zero-dependency Node.js (`>=18`) lifecycle hook (`hooks/orbiter-codex-hook.cjs`) wired to `PreToolUse`, `PermissionRequest`, `PostToolUse`, and `Stop`:

- **Fast-path local allow:** Read-only tools and safe read-only commands (`git status`, `git diff`, `ls`, `cat`, `rg`) allow locally in milliseconds with zero network calls.
- **Pre-execution mobile gate:** High-risk and critical actions pause, submit a redacted approval request to `ORBITER_API_URL` (`https://api.orbiterdev.ai`), and poll for signed mobile biometric sign-off.
- **Fail-closed safety:** Missing credentials, offline backend, polling timeout, or explicit mobile rejection always return `deny`.

## Pricing & Account Setup

Install the Orbiter Dev mobile app on iOS or Android and pair your session at `https://orbiterdev.ai/setup`:

- **Free:** `€0` (50 mobile approvals per week)
- **Pro:** `€19.99/mo` (or `€219.99/yr` annual) for unlimited mobile approvals and audit history
