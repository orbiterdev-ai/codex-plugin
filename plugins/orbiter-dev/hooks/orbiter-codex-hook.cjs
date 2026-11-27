#!/usr/bin/env node
'use strict';

/**
 * Orbiter Dev - Self-Contained OpenAI Codex Lifecycle Hook Runner (v1.0.0)
 *
 * Requirements:
 * - Node.js >= 18 (uses built-in fetch, node:crypto, node:fs, node:os, node:path)
 * - Zero external dependencies, zero hardcoded local paths, zero embedded secrets
 *
 * Security invariants:
 * - Fast-paths verified read-only tools and safe read-only shell commands locally
 *   with zero network calls (never on traversal, home-dir secrets, or shell chaining).
 * - Routes high-risk shell, database, cloud, publishing, exfiltration, and sensitive
 *   file actions to ORBITER_API_URL (default: https://api.orbiterdev.ai) and polls for
 *   a signed mobile biometric decision (iOS Face ID or Android biometrics).
 * - SSRF protection: ORBITER_API_URL must use HTTPS (or explicit localhost/127.0.0.1
 *   for local development/tests) with zero embedded credentials and redirects disabled.
 * - Secret redaction and Zero Data Mode: API keys, bearer tokens, JWTs, AWS secrets,
 *   private keys, and active ORBITER_TOKEN values are stripped from payloads, stdout,
 *   stderr, and error messages.
 * - Fail-closed resilience: oversized stdin (>2 MiB), null bytes, deeply nested JSON,
 *   missing/invalid tool_name, rejection, timeout, unreachable backend, missing
 *   credentials, or malformed payloads always return `deny`.
 */

const crypto = require('node:crypto');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');

const PLUGIN_VERSION = '1.0.0';
const DEFAULT_API_URL = 'https://api.orbiterdev.ai';
const DEFAULT_TIMEOUT_SECONDS = 300;
const DEFAULT_POLL_INTERVAL_MS = 2000;
const SETUP_URL = 'https://orbiterdev.ai/setup';
const MAX_STDIN_BYTES = 2 * 1024 * 1024;
const MAX_JSON_DEPTH = 64;
const MAX_CREDENTIAL_FILE_BYTES = 64 * 1024;

const LOOPBACK_HOSTS = new Set(['127.0.0.1', 'localhost', '::1', '[::1]']);

const SUPPORTED_EVENTS = new Set([
  'SessionStart',
  'SubagentStart',
  'UserPromptSubmit',
  'PreToolUse',
  'PermissionRequest',
  'PostToolUse',
  'PreCompact',
  'PostCompact',
  'SubagentStop',
  'Stop',
]);

const TERMINAL_ALLOW_STATUSES = new Set(['approved']);
const TERMINAL_DENY_STATUSES = new Set([
  'rejected',
  'denied',
  'cancelled',
  'canceled',
  'expired',
  'timeout',
  'timed_out',
]);

const READ_ONLY_FILE_TOOLS = new Set([
  'read',
  'read_file',
  'view_file',
  'ls',
  'list_dir',
  'notebookread',
  'view_file_outline',
  'view_code_item',
  'view_image',
]);

const READ_ONLY_SEARCH_AND_COORDINATION_TOOLS = new Set([
  ...READ_ONLY_FILE_TOOLS,
  'glob',
  'grep',
  'todoread',
  'todowrite',
  'find_by_name',
  'grep_search',
  'grep_files',
  'file_search',
  'codebase_search',
  'read_lints',
  'list_resources',
  'read_resource',
  'list_permissions',
]);

const SHELL_TOOL_NAMES = new Set([
  'bash',
  'shell',
  'shell_command',
  'exec',
  'exec_command',
  'run_command',
  'run_shell_command',
  'terminal',
  'powershell',
  'cmd',
]);

const FILE_MUTATION_TOOL_NAMES = new Set([
  'apply_patch',
  'write',
  'write_file',
  'write_to_file',
  'edit',
  'edit_file',
  'replace_file_content',
  'multi_replace_file_content',
  'notebookedit',
]);

const CREDENTIAL_PATH_PATTERNS = [
  /(?:^|[\s/\\"'=`])\.env(?:\.[a-z0-9_.-]+)?(?=$|[\s/\\"'`,:;])/i,
  /(?:^|[\s/\\"'=])\.ssh(?:[\\/]|$)/i,
  /(?:^|[\s/\\"'=])\.aws(?:[\\/]|$)/i,
  /(?:^|[\s/\\"'=])\.gnupg(?:[\\/]|$)/i,
  /(?:^|[\s/\\"'=])\.kube[\\/]config(?=$|[\s/\\"'`,:;])/i,
  /(?:^|[\s/\\"'=])\.docker[\\/]config\.json(?=$|[\s/\\"'`,:;])/i,
  /(?:^|[\s/\\"'=])\.orbiter(?:[\\/]|$)/i,
  /(?:^|[\s/\\"'=])(?:id_rsa|id_dsa|id_ecdsa|id_ed25519)(?:\.pub)?(?=$|[\s/\\"'`,:;])/i,
  /(?:^|[\s/\\"'=])(?:\.npmrc|\.pypirc|\.netrc|\.git-credentials|\.pgpass|\.my\.cnf)(?=$|[\s/\\"'`,:;])/i,
  /(?:^|[\s/\\"'=])secrets?(?:[\\/._-]|$)/i,
  /(?:^|[\s/\\"'=])credentials?(?:\.[a-z0-9_-]+)?(?=$|[\s/\\"'`,:;])/i,
  /\.(?:pem|key|p8|p12|pfx|jks)(?=$|[\s/\\"'`,:;])/i,
  /(?:^|[\s"'=])\/etc\/(?:shadow|passwd|sudoers)(?=$|[\s"'`,:;])/i,
  /\b(?:production\.ya?ml|private\s+key|aws_secret|api_key)\b/i,
];

const INFRA_WRITE_PATH_PATTERNS = [
  /(?:^|[\\/])\.github[\\/]workflows[\\/]/i,
  /(?:^|[\\/])migrations?[\\/]/i,
  /(?:^|[\\/])hooks[\\/].*hook\.cjs(?=$|[\s"'`])/i,
  /(?:^|[\\/])\.git(?:[\\/]|$)/i,
  /\.tf(?:\s|$|["'])/i,
  /Dockerfile(?:\s|$|["'])/i,
];

const CRITICAL_PATTERNS = [
  {
    id: 'critical_rm_root',
    regex: /\brm\s+-[a-z]*[rf][a-z]*\s+(?:\/(?:\s|["']|$)|\/\*|[a-z]:\\)/i,
    reason: 'Recursive forced deletion targeting a root or drive path',
  },
  {
    id: 'critical_rm_rf',
    regex: /\brm\b(?=[\s\S]*(?:\s-[a-z]*r[a-z]*\b|\s--recursive\b))(?=[\s\S]*(?:\s-[a-z]*f[a-z]*\b|\s--force\b))/i,
    reason: 'Recursive forced file deletion (rm -rf)',
  },
  {
    id: 'critical_powershell_remove',
    regex: /\bremove-item\b[\s\S]*\s-(?:recurse|force)\b/i,
    reason: 'PowerShell recursive or forced deletion',
  },
  {
    id: 'critical_powershell_disk',
    regex: /\b(?:format-volume|clear-disk|initialize-disk|stop-computer|restart-computer)\b/i,
    reason: 'PowerShell destructive disk or host power command',
  },
  {
    id: 'critical_win_del',
    regex: /\b(?:del|rmdir|rd)\s+\/[a-z]*[sfq]/i,
    reason: 'Windows recursive or forced deletion',
  },
  {
    id: 'critical_disk_format',
    regex: /\b(?:format\s+[a-z]:|mkfs(?:\.[a-z0-9]+)?|dd\s+if=)\b/i,
    reason: 'Disk or filesystem formatting command',
  },
  {
    id: 'critical_pipe_to_shell',
    regex: /\|\s*(?:sudo\s+)?(?:env\s+)?(?:\/(?:usr\/)?bin\/)?(?:sh|bash|zsh|dash|ksh|pwsh|powershell)\b/i,
    reason: 'Piping content directly into a shell interpreter',
  },
  {
    id: 'critical_decode_to_exec',
    regex: /\b(?:base64|openssl\s+enc|xxd)\b[\s\S]*\|\s*(?:sudo\s+)?(?:sh|bash|zsh|dash|ksh|pwsh|powershell|eval|python3?|node|perl|ruby)\b/i,
    reason: 'Decoding encoded payload directly into an execution interpreter',
  },
  {
    id: 'critical_powershell_exec',
    regex: /\b(?:iex|invoke-expression)\b[\s\S]*(?:irm|invoke-restmethod|invoke-webrequest|downloadstring)|\b(?:powershell|pwsh)\b[\s\S]*\s-(?:e|ec|enc|encodedcommand)\b/i,
    reason: 'PowerShell encoded or remote download-and-execute command',
  },
  {
    id: 'critical_network_exfil',
    regex: /\|\s*(?:nc|ncat|netcat|socat)\b|\b(?:nc|ncat|netcat)\b[\s\S]*\s-[a-z]*[ec]\b|\/dev\/(?:tcp|udp)\/|\b(?:curl|wget)\b[\s\S]*(?:--upload-file|-T\b|--data-binary|--data-raw|--data\b|-d\b|-F\b|--form)\s*(?:@|-)/i,
    reason: 'Network socket pipe, reverse shell, or file exfiltration command',
  },
  {
    id: 'critical_sql_drop',
    regex: /\b(?:drop\s+(?:table|database|schema|index)|truncate\s+(?:table\s+)?[a-z_][a-z0-9_."`[\]-]*)\b/i,
    reason: 'Destructive SQL schema or table operation',
  },
  {
    id: 'critical_sql_delete_unfiltered',
    regex: /\bdelete\s+from\s+[a-z_][a-z0-9_."`[\]-]*(?:\s*;|\s*["'`]|\s*$)/i,
    reason: 'Unfiltered SQL DELETE FROM statement without WHERE clause',
  },
  {
    id: 'critical_terraform_destroy',
    regex: /\b(?:terraform|tofu|pulumi)\s+destroy\b|\bsupabase\s+db\s+reset\b|\bfly(?:ctl)?\s+apps\s+destroy\b/i,
    reason: 'Infrastructure or database destruction command',
  },
  {
    id: 'critical_docker_destructive',
    regex: /\b(?:docker|podman|nerdctl)\s+(?:(?:compose\s+)?down\b[\s\S]*\s(?:-v|--volumes)\b|system\s+prune\b[\s\S]*\s(?:-a|--all)\b|volume\s+(?:rm|prune)\b|run\b[\s\S]*\s--privileged\b)/i,
    reason: 'Destructive container volume wipe, full prune, or privileged container execution',
  },
  {
    id: 'critical_git_force_push',
    regex: /\bgit\s+push\b[\s\S]*(?:--force(?:-with-lease|-if-includes)?|\s-f\b)/i,
    reason: 'Force pushing to a Git remote',
  },
  {
    id: 'critical_system_power',
    regex: /\b(?:shutdown|reboot|halt|poweroff)\b/i,
    reason: 'System shutdown or reboot command',
  },
];

const HIGH_RISK_PATTERNS = [
  {
    id: 'high_sql_delete',
    regex: /\bdelete\s+from\b/i,
    reason: 'Destructive SQL DELETE FROM statement',
  },
  {
    id: 'high_kubectl_delete',
    regex: /\bkubectl\s+(?:delete|apply|patch|replace|scale|rollout|drain|cordon|taint|exec|edit|create|set)\b/i,
    reason: 'Mutating or deleting Kubernetes cluster resources',
  },
  {
    id: 'high_terraform_apply',
    regex: /\b(?:terraform|tofu)\s+apply\b|\bpulumi\s+up\b/i,
    reason: 'Infrastructure apply change',
  },
  {
    id: 'high_aws_delete',
    regex: /\baws\s+[\s\S]*--delete\b|\baws\s+s3\s+(?:rm|rb)\b|\baws\s+[a-z0-9-]+\s+(?:delete|destroy|terminate|remove|purge|deregister|revoke|wipe|reset)-[a-z0-9-]+|\b(?:gcloud|az)\b[\s\S]*\b(?:delete|destroy|remove|purge|deploy)\b/i,
    reason: 'Cloud resource deletion or mutation command',
  },
  {
    id: 'high_docker_mutate',
    regex: /\b(?:docker|podman|nerdctl)\s+(?:rm|rmi|kill|exec|push|compose\s+down|system\s+prune|(?:container|image|network)\s+(?:rm|prune)|buildx\s+build[\s\S]*--push)\b/i,
    reason: 'Destructive or mutating container/image operation',
  },
  {
    id: 'high_cloud_destroy_or_deploy',
    regex: /\b(?:helm\s+(?:install|upgrade|rollback|uninstall|delete)|fly(?:ctl)?\s+(?:apps\s+destroy|destroy|deploy)|(?:wrangler|vercel|railway|netlify)\s+(?:deploy|up|--prod)|wrangler\s+d1\s+execute|supabase\s+db\s+push|prisma\s+(?:migrate\s+(?:deploy|reset)|db\s+push)|drizzle-kit\s+(?:push|migrate))\b/i,
    reason: 'Cloud deployment, migration, or uninstall command',
  },
  {
    id: 'high_git_push_or_rewrite',
    regex: /\bgit\s+(?:push|reset\s+--hard|clean\s+-[a-z]*f|clean\s+--force|branch\s+-D|worktree\s+remove)\b/i,
    reason: 'Git remote push or destructive history/workspace rewrite',
  },
  {
    id: 'high_package_publish',
    regex: /\b(?:npm|pnpm|yarn|cargo|gem|twine)\s+(?:npm\s+)?(?:publish|unpublish|deprecate|upload|push)\b/i,
    reason: 'Publishing a package to a registry',
  },
  {
    id: 'high_privilege_or_perms',
    regex: /\b(?:sudo\b|doas\b|chmod\s+(?:-R\s+)?777\b|chown\s+-R\b)/i,
    reason: 'Privilege escalation or recursive permission change',
  },
  {
    id: 'high_indirect_shell_exec',
    regex: /\b(?:sh|bash|zsh|dash|pwsh|powershell)\s+(?:-c|-command)\b|\beval\s+|\bfind\b[\s\S]*\s-(?:delete|exec|execdir|ok|okdir)\b|\bawk\b[\s\S]*\bsystem\s*\(/i,
    reason: 'Indirect shell evaluation or destructive wrapper command',
  },
  {
    id: 'high_prod_deploy',
    regex: /\b(?:deploy|merge)\b[\s\S]*\b(?:prod|production|main|master)\b|\b(?:prod|production|main|master)\b[\s\S]*\b(?:deploy|merge)\b/i,
    reason: 'Deployment or merge targeting production or a protected branch',
  },
];

const RISK_ORDER = { low: 0, medium: 1, high: 2, critical: 3 };

const SHELL_CHAIN_OR_REDIRECT_PATTERN = /[;&|`$<>()\r\n\0]/;

const CLI_GLOBAL_OPTIONS = {
  git: {
    valueFlags: new Set(['-c', '-C', '--git-dir', '--work-tree', '--namespace', '--super-prefix', '--config-env', '--exec-path', '--list-cmds']),
    boolFlags: new Set(['--bare', '--no-pager', '-p', '--paginate', '-P', '--no-replace-objects', '--literal-pathspecs', '--glob-pathspecs', '--noglob-pathspecs', '--icase-pathspecs', '--no-optional-locks', '--no-lazy-fetch']),
    attachedShortValueFlags: ['-c', '-C'],
  },
  aws: {
    valueFlags: new Set(['--profile', '--region', '--endpoint-url', '--output', '--color', '--cli-read-timeout', '--cli-connect-timeout', '--cli-input-json', '--cli-input-yaml', '--ca-bundle', '--query']),
    boolFlags: new Set(['--debug', '--no-verify-ssl', '--no-paginate', '--no-sign-request', '--no-cli-pager']),
  },
  gcloud: {
    valueFlags: new Set(['--project', '--account', '--configuration', '--impersonate-service-account', '--region', '--zone', '--format', '--verbosity', '--billing-project', '--filter', '--sort-by', '--limit', '--page-size']),
    boolFlags: new Set(['--quiet', '-q', '--no-user-output-enabled', '--log-http']),
  },
  az: {
    valueFlags: new Set(['--subscription', '--output', '-o', '--query']),
    boolFlags: new Set(['--debug', '--verbose', '--only-show-errors', '--yes', '-y']),
  },
  kubectl: {
    valueFlags: new Set(['--context', '--cluster', '--user', '-n', '--namespace', '--kubeconfig', '--server', '-s', '--token', '--as', '--as-group', '--as-uid', '--certificate-authority', '--client-certificate', '--client-key', '--request-timeout', '--cache-dir', '-v', '--v', '--tls-server-name']),
    boolFlags: new Set(['--insecure-skip-tls-verify', '-A', '--all-namespaces', '--match-server-version']),
    attachedShortValueFlags: ['-n', '-s'],
  },
  helm: {
    valueFlags: new Set(['--kube-context', '-n', '--namespace', '--kubeconfig', '--kube-apiserver', '--kube-token', '--kube-as-user', '--kube-as-group', '--kube-ca-file', '--registry-config', '--repository-cache', '--repository-config', '--burst-limit', '--qps']),
    boolFlags: new Set(['--debug', '--kube-insecure-skip-tls-verify']),
    attachedShortValueFlags: ['-n'],
  },
  docker: {
    valueFlags: new Set(['-H', '--host', '--context', '-c', '--config', '-l', '--log-level', '--tlscacert', '--tlscert', '--tlskey']),
    boolFlags: new Set(['-D', '--debug', '--tls', '--tlsverify']),
    attachedShortValueFlags: ['-H'],
  },
  podman: {
    valueFlags: new Set(['-H', '--host', '--connection', '-c', '--url', '--identity', '--log-level', '--root', '--runroot', '--runtime']),
    boolFlags: new Set(['--remote', '-r']),
  },
  nerdctl: {
    valueFlags: new Set(['-H', '--host', '-a', '--address', '-n', '--namespace', '--data-root']),
    boolFlags: new Set(['--debug', '--debug-full']),
  },
  terraform: {
    valueFlags: new Set(['-chdir', '--chdir']),
    boolFlags: new Set(['-help', '--help', '-version', '--version']),
  },
  tofu: {
    valueFlags: new Set(['-chdir', '--chdir']),
    boolFlags: new Set(['-help', '--help', '-version', '--version']),
  },
  pulumi: {
    valueFlags: new Set(['-C', '--cwd', '-s', '--stack', '--color', '--profiling', '--tracing', '-v', '--verbose']),
    boolFlags: new Set(['--emoji', '--logflow', '--logtostderr', '--non-interactive', '-j', '--json']),
  },
  npm: {
    valueFlags: new Set(['--prefix', '-C', '--workspace', '-w', '--registry', '--userconfig', '--cache', '--loglevel', '--otp', '--tag', '--access']),
    boolFlags: new Set(['--silent', '-s', '--quiet', '-q', '--workspaces', '--ws', '--yes', '-y', '--verbose', '--dd', '--ddd']),
  },
  pnpm: {
    valueFlags: new Set(['-C', '--dir', '--filter', '-F', '--reporter', '--loglevel']),
    boolFlags: new Set(['--workspace-root', '-w', '--recursive', '-r', '--silent', '-s']),
  },
  yarn: {
    valueFlags: new Set(['--cwd', '--registry']),
    boolFlags: new Set(['--silent', '-s', '--verbose', '--non-interactive']),
  },
  cargo: {
    valueFlags: new Set(['--manifest-path', '--color', '--config', '-Z', '-C']),
    boolFlags: new Set(['-q', '--quiet', '-v', '-vv', '--verbose', '--frozen', '--locked', '--offline']),
    skipPlusToolchain: true,
  },
  wrangler: {
    valueFlags: new Set(['--env', '-e', '--config', '-c', '--cwd', '--env-file']),
    boolFlags: new Set(['--experimental-remote-bindings', '--local', '--remote']),
    attachedShortValueFlags: ['-e', '-c'],
  },
  fly: {
    valueFlags: new Set(['-a', '--app', '-c', '--config', '-t', '--access-token', '-o', '--org', '-r', '--region']),
    boolFlags: new Set(['--verbose', '--debug', '-j', '--json']),
    attachedShortValueFlags: ['-a'],
  },
  flyctl: {
    valueFlags: new Set(['-a', '--app', '-c', '--config', '-t', '--access-token', '-o', '--org', '-r', '--region']),
    boolFlags: new Set(['--verbose', '--debug', '-j', '--json']),
    attachedShortValueFlags: ['-a'],
  },
  vercel: {
    valueFlags: new Set(['--cwd', '--scope', '-S', '--token', '-t', '--local-config', '-A', '--global-config', '-Q']),
    boolFlags: new Set(['--debug', '-d', '--yes', '-y']),
  },
  netlify: {
    valueFlags: new Set(['--cwd', '--site', '--auth', '--dir', '--filter']),
    boolFlags: new Set(['--debug']),
  },
  railway: {
    valueFlags: new Set(['--environment', '-e', '--service', '-s']),
    boolFlags: new Set([]),
  },
  supabase: {
    valueFlags: new Set(['--workdir', '--project-ref', '--profile', '--dns-resolver']),
    boolFlags: new Set(['--debug', '--yes', '--experimental']),
  },
  prisma: {
    valueFlags: new Set(['--schema', '--config']),
    boolFlags: new Set([]),
  },
};

const VERSION_CHECK_EXECUTABLES = new Set([
  'node',
  'npm',
  'npx',
  'pnpm',
  'yarn',
  'python',
  'python3',
  'go',
  'rustc',
  'cargo',
  'git',
  'codex',
  'claude',
  'cursor',
]);

const VERSION_CHECK_FLAGS = new Set(['--version', '-v', '-V', 'version']);

const READ_ONLY_COMMAND_SPECS = {
  rg: {
    shortBool: new Set(['n', 'N', 'H', 'I', 'i', 's', 'S', 'F', 'w', 'x', 'v', 'l', 'c', 'o', 'q', 'a', 'u', 'U', 'P', '.']),
    longBool: new Set([
      '--line-number', '--no-line-number', '--with-filename', '--no-filename', '--ignore-case',
      '--case-sensitive', '--smart-case', '--fixed-strings', '--word-regexp', '--line-regexp',
      '--invert-match', '--files-with-matches', '--files-without-match', '--files', '--count',
      '--count-matches', '--only-matching', '--quiet', '--hidden', '--no-ignore', '--no-ignore-vcs',
      '--no-heading', '--heading', '--vimgrep', '--json', '--stats', '--column', '--no-config',
      '--text', '--multiline', '--pcre2', '--trim', '--sort-files',
    ]),
    valueFlags: new Set([
      '-e', '--regexp', '-g', '--glob', '--iglob', '-t', '--type', '-T', '--type-not',
      '-A', '--after-context', '-B', '--before-context', '-C', '--context',
      '-m', '--max-count', '--max-depth', '--max-filesize', '--color', '--sort', '-j', '--threads',
    ]),
    patternArgUnlessFlag: new Set(['-e', '--regexp', '--files']),
    pathArgs: true,
  },
  ripgrep: null,
  grep: {
    shortBool: new Set(['n', 'H', 'h', 'i', 'F', 'E', 'G', 'P', 'w', 'x', 'v', 'l', 'L', 'c', 'o', 'q', 'r', 'I', 's']),
    longBool: new Set([
      '--line-number', '--with-filename', '--no-filename', '--ignore-case', '--fixed-strings',
      '--extended-regexp', '--basic-regexp', '--perl-regexp', '--word-regexp', '--line-regexp',
      '--invert-match', '--files-with-matches', '--files-without-match', '--count', '--only-matching',
      '--quiet', '--recursive', '--no-messages', '--color',
    ]),
    valueFlags: new Set([
      '-e', '--regexp', '-A', '--after-context', '-B', '--before-context', '-C', '--context',
      '-m', '--max-count', '--include', '--exclude', '--exclude-dir', '--color',
    ]),
    patternArgUnlessFlag: new Set(['-e', '--regexp']),
    pathArgs: true,
  },
  egrep: null,
  fgrep: null,
  ls: {
    shortBool: new Set(['a', 'A', 'l', 'h', '1', 'r', 't', 'S', 'R', 'd', 'F', 'p', 'n', 'i', 's', 'X', 'v', 'U', 'c', 'u', 'G', 'g', 'o', 'k', 'm', 'Q', 'q']),
    longBool: new Set([
      '--all', '--almost-all', '--human-readable', '--reverse', '--recursive', '--directory',
      '--classify', '--color', '--group-directories-first',
    ]),
    valueFlags: new Set(['--color', '--time-style', '--sort']),
    pathArgs: true,
  },
  ll: null,
  dir: {
    shortBool: new Set(['a', 'A', 'l', 'h', '1', 'r', 't', 'S', 'R', 'd']),
    longBool: new Set(['--all', '--human-readable', '--reverse']),
    valueFlags: new Set([]),
    allowWinSlashFlags: new Set(['/b', '/a', '/o', '/s', '/w', '/p']),
    pathArgs: true,
  },
  tree: {
    shortBool: new Set(['a', 'd', 'f', 'F', 'n', 'C']),
    longBool: new Set(['--dirsfirst', '--noreport']),
    valueFlags: new Set(['-L', '-I', '-P']),
    pathArgs: true,
  },
  cat: {
    shortBool: new Set(['n', 'b', 's', 'E', 'T', 'A', 'v', 'e', 't', 'u']),
    longBool: new Set(['--number', '--number-nonblank', '--squeeze-blank', '--show-ends', '--show-tabs', '--show-all', '--show-nonprinting']),
    valueFlags: new Set([]),
    pathArgs: true,
  },
  head: {
    shortBool: new Set(['q', 'v']),
    longBool: new Set(['--quiet', '--silent', '--verbose']),
    valueFlags: new Set(['-n', '--lines', '-c', '--bytes']),
    allowNumericDash: true,
    pathArgs: true,
  },
  tail: {
    shortBool: new Set(['q', 'v']),
    longBool: new Set(['--quiet', '--silent', '--verbose']),
    valueFlags: new Set(['-n', '--lines', '-c', '--bytes']),
    allowNumericDash: true,
    pathArgs: true,
  },
  wc: {
    shortBool: new Set(['l', 'w', 'c', 'm', 'L']),
    longBool: new Set(['--lines', '--words', '--bytes', '--chars', '--max-line-length']),
    valueFlags: new Set([]),
    pathArgs: true,
  },
  stat: {
    shortBool: new Set(['t', 'x']),
    longBool: new Set(['--terse']),
    valueFlags: new Set(['-c', '--format', '-f']),
    pathArgs: true,
  },
  file: {
    shortBool: new Set(['b', 'i']),
    longBool: new Set(['--brief', '--mime', '--mime-type', '--mime-encoding']),
    valueFlags: new Set([]),
    pathArgs: true,
  },
  pwd: {
    shortBool: new Set(['P', 'L']),
    longBool: new Set(['--physical', '--logical']),
    valueFlags: new Set([]),
    maxPositional: 0,
  },
  whoami: {
    shortBool: new Set([]),
    longBool: new Set([]),
    valueFlags: new Set([]),
    maxPositional: 0,
  },
  id: {
    shortBool: new Set(['u', 'g', 'G', 'n', 'r']),
    longBool: new Set(['--user', '--group', '--groups', '--name', '--real']),
    valueFlags: new Set([]),
    maxPositional: 0,
  },
  uname: {
    shortBool: new Set(['a', 's', 'n', 'r', 'v', 'm', 'p', 'i', 'o']),
    longBool: new Set(['--all', '--kernel-name', '--nodename', '--kernel-release', '--kernel-version', '--machine', '--processor', '--hardware-platform', '--operating-system']),
    valueFlags: new Set([]),
    maxPositional: 0,
  },
  date: {
    shortBool: new Set(['u']),
    longBool: new Set(['--utc', '--universal']),
    valueFlags: new Set([]),
    allowPlusFormat: true,
    maxPositional: 0,
  },
  which: {
    shortBool: new Set(['a']),
    longBool: new Set(['--all']),
    valueFlags: new Set([]),
    bareNameArgsOnly: true,
  },
  where: {
    shortBool: new Set([]),
    longBool: new Set([]),
    valueFlags: new Set([]),
    bareNameArgsOnly: true,
  },
  type: {
    shortBool: new Set(['a', 't', 'p', 'P']),
    longBool: new Set([]),
    valueFlags: new Set([]),
    bareNameArgsOnly: true,
  },
  echo: {
    shortBool: new Set(['n', 'e', 'E']),
    longBool: new Set([]),
    valueFlags: new Set([]),
    pathArgs: false,
  },
};
READ_ONLY_COMMAND_SPECS.ripgrep = READ_ONLY_COMMAND_SPECS.rg;
READ_ONLY_COMMAND_SPECS.egrep = READ_ONLY_COMMAND_SPECS.grep;
READ_ONLY_COMMAND_SPECS.fgrep = READ_ONLY_COMMAND_SPECS.grep;
READ_ONLY_COMMAND_SPECS.ll = READ_ONLY_COMMAND_SPECS.ls;

const GIT_READ_ONLY_SUBCOMMANDS = {
  status: {
    shortBool: new Set(['s', 'b', 'v', 'u', 'z']),
    longBool: new Set([
      '--short', '--branch', '--show-stash', '--verbose', '--untracked-files', '--ignored',
      '--porcelain', '--long', '--renames', '--no-renames', '--ahead-behind', '--no-ahead-behind',
      '--no-optional-locks',
    ]),
    valueFlags: new Set(['--untracked-files', '--porcelain', '--ignored', '-u']),
    pathArgs: true,
  },
  diff: {
    shortBool: new Set(['p', 'w', 'b', 'q']),
    longBool: new Set([
      '--stat', '--numstat', '--shortstat', '--summary', '--name-only', '--name-status',
      '--cached', '--staged', '--no-ext-diff', '--no-textconv', '--no-color', '--color',
      '--word-diff', '--ignore-all-space', '--ignore-space-change', '--ignore-blank-lines',
      '--check', '--compact-summary', '--raw', '--patch', '--quiet', '--exit-code',
      '--histogram', '--patience', '--minimal', '--no-prefix',
    ]),
    valueFlags: new Set(['-U', '--unified', '--color', '--word-diff', '--src-prefix', '--dst-prefix']),
    pathArgs: true,
  },
  log: {
    shortBool: new Set(['s', 'p']),
    longBool: new Set([
      '--oneline', '--stat', '--numstat', '--shortstat', '--name-only', '--name-status',
      '--graph', '--decorate', '--no-decorate', '--all', '--branches', '--tags', '--remotes',
      '--first-parent', '--merges', '--no-merges', '--reverse', '--abbrev-commit', '--no-abbrev-commit',
      '--pretty', '--no-patch', '--patch', '--no-textconv', '--no-ext-diff', '--color', '--no-color',
    ]),
    valueFlags: new Set([
      '-n', '--max-count', '--decorate', '--date', '--since', '--after', '--until', '--before',
      '--author', '--grep', '--format', '--pretty', '--color',
    ]),
    allowNumericDash: true,
    pathArgs: true,
  },
  show: {
    shortBool: new Set(['s', 'p']),
    longBool: new Set([
      '--stat', '--numstat', '--shortstat', '--name-only', '--name-status', '--oneline',
      '--no-patch', '--patch', '--no-textconv', '--no-ext-diff', '--color', '--no-color',
      '--abbrev-commit',
    ]),
    valueFlags: new Set(['--format', '--pretty', '--color']),
    pathArgs: true,
  },
  branch: {
    shortBool: new Set(['l', 'a', 'r', 'v']),
    longBool: new Set([
      '--list', '--all', '--remotes', '--verbose', '--show-current', '--merged', '--no-merged',
      '--color', '--no-color',
    ]),
    valueFlags: new Set(['--contains', '--no-contains', '--sort', '--format', '--color']),
    requireZeroPositionalUnlessFlag: new Set(['--list', '-l']),
    pathArgs: false,
  },
  'rev-parse': {
    shortBool: new Set(['q']),
    longBool: new Set([
      '--show-toplevel', '--abbrev-ref', '--short', '--verify', '--git-dir',
      '--is-inside-work-tree', '--is-bare-repository', '--symbolic', '--symbolic-full-name',
      '--show-prefix', '--show-cdup', '--all', '--branches', '--tags', '--remotes', '--quiet',
    ]),
    valueFlags: new Set(['--short', '--abbrev-ref']),
    pathArgs: false,
  },
  describe: {
    shortBool: new Set([]),
    longBool: new Set(['--tags', '--always', '--long', '--dirty', '--exact-match', '--all', '--first-parent']),
    valueFlags: new Set(['--abbrev', '--dirty']),
    pathArgs: false,
  },
  remote: {
    shortBool: new Set(['v']),
    longBool: new Set(['--verbose']),
    valueFlags: new Set([]),
    maxPositional: 0,
  },
};

const SECRET_KEY_PATTERN = /(?:token|secret|password|passwd|api[_-]?key|access[_-]?key|authorization|credential|private[_-]?key|bearer|auth)/i;
const SECRET_VALUE_PATTERNS = [
  /\bBearer\s+[A-Za-z0-9._~+/=-]{6,}/gi,
  /\bBasic\s+[A-Za-z0-9+/=]{8,}/gi,
  /\bsk-(?:proj-|ant-)?[A-Za-z0-9_-]{16,}\b/g,
  /\b(?:sk|rk|pk)_(?:live|test)_[A-Za-z0-9]{12,}\b/g,
  /\b(?:ghp|gho|ghu|ghs|ghr|github_pat)_[A-Za-z0-9_]{16,}\b/g,
  /\bsbp_[a-f0-9]{16,}\b/gi,
  /\borb_[A-Za-z0-9_-]{12,}\b/g,
  /\b(?:AKIA|ASIA)[0-9A-Z]{16}\b/g,
  /\bAIza[0-9A-Za-z_-]{30,}\b/g,
  /\bxox[baprs]-[A-Za-z0-9-]{10,}\b/g,
  /\beyJ[A-Za-z0-9_-]{6,}\.eyJ[A-Za-z0-9_-]{6,}\.[A-Za-z0-9_-]{6,}\b/g,
  /-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z0-9 ]*PRIVATE KEY-----/g,
];

class StdinLimitError extends Error {
  constructor(message) {
    super(message);
    this.name = 'StdinLimitError';
  }
}

function isRecord(value) {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function normalizeMinRisk(value, fallback = 'high') {
  const lower = typeof value === 'string' ? value.trim().toLowerCase() : '';
  return Object.prototype.hasOwnProperty.call(RISK_ORDER, lower) ? lower : fallback;
}

function meetsMinRisk(level, minRisk) {
  return (RISK_ORDER[level] ?? 0) >= (RISK_ORDER[minRisk] ?? RISK_ORDER.high);
}

function exceedsMaxDepth(value, maxDepth = MAX_JSON_DEPTH) {
  const stack = [{ node: value, depth: 0 }];
  while (stack.length > 0) {
    const { node, depth } = stack.pop();
    if (depth > maxDepth) return true;
    if (Array.isArray(node)) {
      for (let i = 0; i < node.length; i += 1) {
        const item = node[i];
        if (item !== null && typeof item === 'object') {
          stack.push({ node: item, depth: depth + 1 });
        }
      }
    } else if (isRecord(node)) {
      const values = Object.values(node);
      for (let i = 0; i < values.length; i += 1) {
        const item = values[i];
        if (item !== null && typeof item === 'object') {
          stack.push({ node: item, depth: depth + 1 });
        }
      }
    }
  }
  return false;
}

function containsNullByte(value, maxDepth = MAX_JSON_DEPTH) {
  const stack = [{ node: value, depth: 0 }];
  while (stack.length > 0) {
    const { node, depth } = stack.pop();
    if (depth > maxDepth) return true;
    if (typeof node === 'string') {
      if (node.includes('\0')) return true;
    } else if (Array.isArray(node)) {
      for (let i = 0; i < node.length; i += 1) {
        stack.push({ node: node[i], depth: depth + 1 });
      }
    } else if (isRecord(node)) {
      for (const [k, v] of Object.entries(node)) {
        if (k.includes('\0')) return true;
        stack.push({ node: v, depth: depth + 1 });
      }
    }
  }
  return false;
}

function stableStringify(value, depth = 0) {
  if (depth > 16) return '"[truncated]"';
  if (value === null || typeof value !== 'object') {
    return JSON.stringify(value);
  }
  if (Array.isArray(value)) {
    return `[${value.map((item) => stableStringify(item, depth + 1)).join(',')}]`;
  }
  const keys = Object.keys(value).sort();
  return `{${keys.map((key) => `${JSON.stringify(key)}:${stableStringify(value[key], depth + 1)}`).join(',')}}`;
}

function sha256Hex(value) {
  const input = typeof value === 'string' ? value : stableStringify(value);
  return crypto.createHash('sha256').update(input).digest('hex');
}

function truncate(text, maxLen) {
  if (typeof text !== 'string') return '';
  if (text.length <= maxLen) return text;
  return `${text.slice(0, Math.max(0, maxLen - 3))}...`;
}

function collectRuntimeSecrets(env = process.env, extraSecrets = []) {
  const secrets = [];
  if (env && typeof env.ORBITER_API_KEY === 'string' && env.ORBITER_API_KEY.trim().length >= 6) {
    secrets.push(env.ORBITER_API_KEY.trim());
  }
  if (env && typeof env.ORBITER_TOKEN === 'string' && env.ORBITER_TOKEN.trim().length >= 6) {
    secrets.push(env.ORBITER_TOKEN.trim());
  }
  for (const s of extraSecrets) {
    if (typeof s === 'string' && s.trim().length >= 6) {
      secrets.push(s.trim());
    }
  }
  return [...new Set(secrets)];
}

function redactString(input, extraSecrets = []) {
  let output = String(input);
  for (const pattern of SECRET_VALUE_PATTERNS) {
    output = output.replace(pattern, '[redacted]');
  }
  output = output.replace(/((?:Authorization|X-Api-Key|Proxy-Authorization)\s*:\s*)[^\r\n"']+/gi, '$1[redacted]');
  output = output.replace(
    /(\b[A-Za-z0-9_.-]*(?:token|secret|password|passwd|api[_-]?key|access[_-]?key|private[_-]?key|credential|auth[_-]?key)[A-Za-z0-9_.-]*\s*[:=]\s*)(?:"[^"\r\n]*"|'[^'\r\n]*'|[^\s&"'`]+)/gi,
    '$1[redacted]',
  );
  output = output.replace(/([a-z][a-z0-9+.-]*:\/\/)([^/\s@]+)@/gi, '$1[redacted]@');
  for (const secret of extraSecrets) {
    if (typeof secret === 'string' && secret.length >= 6) {
      output = output.split(secret).join('[redacted]');
    }
  }
  return output;
}

function redactValue(value, depth = 0, extraSecrets = []) {
  if (depth > 8) return '[truncated]';
  if (typeof value === 'string') return redactString(value, extraSecrets);
  if (Array.isArray(value)) return value.map((item) => redactValue(item, depth + 1, extraSecrets));
  if (isRecord(value)) {
    const out = {};
    for (const [key, item] of Object.entries(value)) {
      if (SECRET_KEY_PATTERN.test(key)) {
        out[key] = '[redacted]';
      } else {
        out[key] = redactValue(item, depth + 1, extraSecrets);
      }
    }
    return out;
  }
  return value;
}

function extractCommand(toolInput) {
  if (!isRecord(toolInput)) return '';
  const candidate = toolInput.command ?? toolInput.cmd ?? toolInput.CommandLine ?? toolInput.script;
  if (typeof candidate === 'string') return candidate.trim();
  if (Array.isArray(candidate)) {
    return candidate.map((part) => String(part)).join(' ').trim();
  }
  return '';
}

function extractTargetPaths(toolInput) {
  if (!isRecord(toolInput)) return [];
  const paths = [];
  const pathKeys = [
    'path',
    'file_path',
    'target',
    'target_file',
    'notebook_path',
    'Path',
    'AbsolutePath',
    'TargetFile',
    'FilePath',
    'DirectoryPath',
    'SearchDirectory',
    'SearchPath',
    'directory',
    'dir',
    'glob',
  ];
  for (const key of pathKeys) {
    if (typeof toolInput[key] === 'string' && toolInput[key].trim()) {
      paths.push(toolInput[key].trim());
    }
  }
  for (const listKey of ['files', 'paths', 'Paths', 'Includes', 'includes']) {
    if (Array.isArray(toolInput[listKey])) {
      for (const item of toolInput[listKey]) {
        if (typeof item === 'string' && item.trim()) paths.push(item.trim());
      }
    }
  }
  if (typeof toolInput.pattern === 'string' && containsSensitiveMarker(toolInput.pattern)) {
    paths.push(toolInput.pattern.trim());
  }
  const patchText = typeof toolInput.patch === 'string'
    ? toolInput.patch
    : (typeof toolInput.input === 'string' ? toolInput.input : '');
  if (patchText) {
    const patchMatches = patchText.matchAll(/^\*\*\*\s+(?:Update|Add|Delete)\s+File:\s+(.+)$/gm);
    for (const match of patchMatches) {
      if (match[1]) paths.push(match[1].trim());
    }
    const diffMatches = patchText.matchAll(/^(?:\+\+\+|---)\s+[ab]\/(.+)$/gm);
    for (const match of diffMatches) {
      if (match[1]) paths.push(match[1].trim());
    }
  }
  return [...new Set(paths)];
}

function containsSensitiveMarker(text) {
  const value = String(text || '');
  return CREDENTIAL_PATH_PATTERNS.some((pattern) => pattern.test(value));
}

function containsPathTraversal(value) {
  return /(?:^|[\\/\s"'=])\.\.(?:$|[\\/\s"'=])/.test(String(value || ''));
}

function isHomeRelativePath(value) {
  return /(?:^|[\s"'=])~(?:[\\/]|$)/.test(String(value || ''));
}

function normalizeDriveAndPosixPath(value) {
  const str = String(value || '').trim().replace(/\\/g, '/');
  const driveMatch = str.match(/^([A-Za-z]):(.*)$/);
  const drive = driveMatch ? driveMatch[1].toLowerCase() : '';
  const rawRest = driveMatch ? driveMatch[2] : str;
  const normalized = path.posix.normalize(rawRest || '/').replace(/\/+$/, '') || '/';
  return { drive, normalized: normalized.toLowerCase() };
}

function isOutsideWorkspace(target, cwd) {
  const raw = String(target || '').trim();
  if (!raw) return false;
  if (containsPathTraversal(raw) || isHomeRelativePath(raw)) {
    return true;
  }
  if (!cwd || typeof cwd !== 'string' || !cwd.trim()) {
    return false;
  }
  const isAbs = raw.startsWith('/') || /^[A-Za-z]:[\\/]/.test(raw);
  if (!isAbs) return false;
  const normTarget = normalizeDriveAndPosixPath(raw);
  const normCwd = normalizeDriveAndPosixPath(cwd);
  if (normTarget.drive !== normCwd.drive) return true;
  return normTarget.normalized !== normCwd.normalized && !normTarget.normalized.startsWith(`${normCwd.normalized}/`);
}

function isOrbiterTool(toolName) {
  const lowerTool = String(toolName || '').trim().toLowerCase();
  return (
    lowerTool === 'orbiter_request_approval' ||
    lowerTool === 'orbiter_await_approval' ||
    lowerTool === 'orbiter_auth_status' ||
    lowerTool === 'orbiter_list_pending_approvals' ||
    lowerTool === 'orbiter_get_approval_status' ||
    lowerTool.startsWith('mcp__orbiter-dev__') ||
    lowerTool.startsWith('mcp_orbiter-dev_')
  );
}

function isCodexInternalPlanApproval(event) {
  if (event.hook_event_name !== 'PermissionRequest') return false;
  const lowerTool = String(event.tool_name || '').trim().toLowerCase();
  if (!/^(?:plan|implementation[_ -]?plan|update[_ -]?plan)$/.test(lowerTool)) {
    return false;
  }
  const input = isRecord(event.tool_input) ? event.tool_input : {};
  const executionKeys = ['command', 'cmd', 'CommandLine', 'script', 'patch', 'diff', 'file_path', 'path'];
  for (const key of executionKeys) {
    if (key in input) return false;
  }
  return true;
}

function isAbsolutePathArg(value) {
  const raw = String(value || '').trim();
  return raw.startsWith('/') || /^[A-Za-z]:[\\/]/.test(raw) || raw.startsWith('\\\\');
}

function isPathInsideRoots(target, workspaceRoots) {
  const roots = Array.isArray(workspaceRoots)
    ? workspaceRoots.filter((r) => typeof r === 'string' && r.trim().length > 0)
    : [];
  if (roots.length === 0) return false;
  const normTarget = normalizeDriveAndPosixPath(target);
  return roots.some((root) => {
    const normRoot = normalizeDriveAndPosixPath(root);
    if (normTarget.drive !== normRoot.drive) return false;
    return normTarget.normalized === normRoot.normalized || normTarget.normalized.startsWith(`${normRoot.normalized}/`);
  });
}

function splitShellSegments(command) {
  const input = String(command || '');
  const segments = [];
  const subexpressions = [];
  let current = '';
  let inSingle = false;
  let inDouble = false;

  for (let i = 0; i < input.length; i += 1) {
    const ch = input[i];
    const next = input[i + 1];

    if (inSingle) {
      if (ch === '\'') inSingle = false;
      current += ch;
      continue;
    }

    if (ch === '\\' && i + 1 < input.length) {
      current += ch + next;
      i += 1;
      continue;
    }

    if (inDouble) {
      if (ch === '"') inDouble = false;
      current += ch;
      continue;
    }

    if (ch === '\'') {
      inSingle = true;
      current += ch;
      continue;
    }
    if (ch === '"') {
      inDouble = true;
      current += ch;
      continue;
    }

    if (ch === '$' && next === '(') {
      let depth = 1;
      let j = i + 2;
      let inner = '';
      while (j < input.length && depth > 0) {
        if (input[j] === '(') depth += 1;
        else if (input[j] === ')') depth -= 1;
        if (depth > 0) inner += input[j];
        j += 1;
      }
      if (inner.trim()) subexpressions.push(inner.trim());
      current += input.slice(i, j);
      i = j - 1;
      continue;
    }

    if (ch === '`') {
      let j = i + 1;
      let inner = '';
      while (j < input.length && input[j] !== '`') {
        inner += input[j];
        j += 1;
      }
      if (inner.trim()) subexpressions.push(inner.trim());
      current += input.slice(i, j + 1);
      i = j;
      continue;
    }

    if (ch === ';' || ch === '\n' || ch === '\r') {
      if (current.trim()) segments.push(current.trim());
      current = '';
      continue;
    }

    if ((ch === '&' && next === '&') || (ch === '|' && next === '|')) {
      if (current.trim()) segments.push(current.trim());
      current = '';
      i += 1;
      continue;
    }

    if (ch === '|' || ch === '&') {
      if (current.trim()) segments.push(current.trim());
      current = '';
      continue;
    }

    current += ch;
  }

  if (current.trim()) segments.push(current.trim());
  for (const expr of subexpressions) {
    for (const sub of splitShellSegments(expr)) {
      segments.push(sub);
    }
  }
  return segments;
}

function tokenizeShellSegment(segment) {
  const input = String(segment || '').trim();
  const tokens = [];
  let current = '';
  let hasToken = false;
  let inSingle = false;
  let inDouble = false;

  for (let i = 0; i < input.length; i += 1) {
    const ch = input[i];
    const next = input[i + 1];

    if (inSingle) {
      if (ch === '\'') {
        inSingle = false;
      } else {
        current += ch;
      }
      continue;
    }

    if (inDouble) {
      if (ch === '\\' && next && (next === '"' || next === '\\' || next === '$' || next === '`')) {
        current += next;
        i += 1;
      } else if (ch === '"') {
        inDouble = false;
      } else {
        current += ch;
      }
      continue;
    }

    if (ch === '\'') {
      inSingle = true;
      hasToken = true;
      continue;
    }
    if (ch === '"') {
      inDouble = true;
      hasToken = true;
      continue;
    }

    if (ch === '\\' && next && /[\s'"\\;&|<>$`()]/.test(next)) {
      current += next;
      hasToken = true;
      i += 1;
      continue;
    }

    if (/\s/.test(ch)) {
      if (hasToken) {
        tokens.push(current);
        current = '';
        hasToken = false;
      }
      continue;
    }

    current += ch;
    hasToken = true;
  }

  if (inSingle || inDouble) {
    return { ok: false, tokens };
  }
  if (hasToken) {
    tokens.push(current);
  }
  return { ok: true, tokens };
}

function normalizeExecutableName(rawToken) {
  const base = String(rawToken || '').trim().split(/[\\/]/).pop() || '';
  return base.toLowerCase().replace(/\.(?:exe|cmd|bat|com|ps1)$/i, '');
}

function stripWrapperPrefixes(tokens) {
  let working = [...tokens];
  let idx = 0;
  let hadSudo = false;
  let wrapped = false;
  let guard = 0;

  while (idx < working.length && guard < 16) {
    guard += 1;
    const tok = working[idx];
    if (/^[A-Za-z_][A-Za-z0-9_]*=/.test(tok)) {
      idx += 1;
      wrapped = true;
      continue;
    }
    const exec = normalizeExecutableName(tok);

    if (exec === 'env') {
      wrapped = true;
      idx += 1;
      while (idx < working.length) {
        const arg = working[idx];
        if (arg === '--') {
          idx += 1;
          break;
        }
        if (/^[A-Za-z_][A-Za-z0-9_]*=/.test(arg)) {
          idx += 1;
          continue;
        }
        if (arg === '-S' || arg === '--split-string') {
          const val = working[idx + 1] || '';
          const splitRes = tokenizeShellSegment(val);
          if (splitRes.ok && splitRes.tokens.length > 0) {
            working = [...working.slice(0, idx), ...splitRes.tokens, ...working.slice(idx + 2)];
            continue;
          }
          idx += 2;
          continue;
        }
        if (arg.startsWith('--split-string=')) {
          const splitRes = tokenizeShellSegment(arg.slice('--split-string='.length));
          if (splitRes.ok && splitRes.tokens.length > 0) {
            working = [...working.slice(0, idx), ...splitRes.tokens, ...working.slice(idx + 1)];
            continue;
          }
          idx += 1;
          continue;
        }
        if (arg === '-u' || arg === '--unset' || arg === '-C' || arg === '--chdir') {
          idx += 2;
          continue;
        }
        if (/^-(?:i|0|v)$/.test(arg) || arg === '-' || /^--(?:ignore-environment|null|debug|unset=|chdir=|default-signal|ignore-signal|block-signal)/.test(arg)) {
          idx += 1;
          continue;
        }
        break;
      }
      continue;
    }

    if (exec === 'sudo' || exec === 'doas') {
      hadSudo = true;
      wrapped = true;
      idx += 1;
      const sudoValFlags = new Set(['-u', '--user', '-g', '--group', '-h', '--host', '-p', '--prompt', '-r', '--role', '-t', '--type', '-T', '--command-timeout', '-C', '--close-from', '-D', '--chdir', '-R', '--chroot', '-U', '--other-user']);
      while (idx < working.length) {
        const arg = working[idx];
        if (arg === '--') {
          idx += 1;
          break;
        }
        if (/^[A-Za-z_][A-Za-z0-9_]*=/.test(arg)) {
          idx += 1;
          continue;
        }
        const eqIdx = arg.indexOf('=');
        if (eqIdx > 0 && sudoValFlags.has(arg.slice(0, eqIdx))) {
          idx += 1;
          continue;
        }
        if (sudoValFlags.has(arg)) {
          idx += 2;
          continue;
        }
        if (/^-[AbEeHiKknPSsvL]+$/.test(arg) || /^--(?:preserve-env|login|non-interactive|set-home|stdin)/.test(arg)) {
          idx += 1;
          continue;
        }
        break;
      }
      continue;
    }

    if (exec === 'command' || exec === 'builtin' || exec === 'exec' || exec === 'nohup' || exec === 'time') {
      wrapped = true;
      idx += 1;
      while (idx < working.length) {
        const arg = working[idx];
        if (arg === '--') {
          idx += 1;
          break;
        }
        if (exec === 'exec' && arg === '-a') {
          idx += 2;
          continue;
        }
        if (/^-[pvVlc]+$/.test(arg)) {
          idx += 1;
          continue;
        }
        break;
      }
      continue;
    }

    if (exec === 'nice') {
      wrapped = true;
      idx += 1;
      while (idx < working.length) {
        const arg = working[idx];
        if (arg === '--') { idx += 1; break; }
        if (arg === '-n' || arg === '--adjustment') { idx += 2; continue; }
        if (/^--adjustment=/.test(arg) || /^-\d+$/.test(arg)) { idx += 1; continue; }
        break;
      }
      continue;
    }

    if (exec === 'timeout') {
      wrapped = true;
      idx += 1;
      while (idx < working.length) {
        const arg = working[idx];
        if (arg === '--') { idx += 1; break; }
        if (arg === '-k' || arg === '--kill-after' || arg === '-s' || arg === '--signal') { idx += 2; continue; }
        if (/^--(?:kill-after|signal)=/.test(arg) || /^--(?:preserve-status|foreground|verbose)$/.test(arg) || arg === '-v') { idx += 1; continue; }
        break;
      }
      if (idx < working.length && /^\d+(?:\.\d+)?[smhd]?$/i.test(working[idx])) {
        idx += 1;
      }
      continue;
    }

    if (exec === 'stdbuf' || exec === 'ionice') {
      wrapped = true;
      idx += 1;
      while (idx < working.length) {
        const arg = working[idx];
        if (arg === '--') { idx += 1; break; }
        if (/^-[ioecnt]$/.test(arg) || /^--(?:input|output|error|class|classdata)$/.test(arg)) { idx += 2; continue; }
        if (/^-[ioecnt].+/.test(arg) || /^--(?:input|output|error|class|classdata)=/.test(arg)) { idx += 1; continue; }
        break;
      }
      continue;
    }

    if (exec === 'xargs') {
      wrapped = true;
      idx += 1;
      const xargsVal = new Set(['-I', '-L', '-n', '-P', '-d', '-E', '-s', '--replace', '--max-args', '--max-procs', '--delimiter', '--eof']);
      while (idx < working.length) {
        const arg = working[idx];
        if (arg === '--') { idx += 1; break; }
        const eqIdx = arg.indexOf('=');
        if (eqIdx > 0 && xargsVal.has(arg.slice(0, eqIdx))) { idx += 1; continue; }
        if (xargsVal.has(arg)) { idx += 2; continue; }
        if (/^-[0rtpx]+$/.test(arg) || /^--(?:null|no-run-if-empty|verbose)$/.test(arg)) { idx += 1; continue; }
        break;
      }
      continue;
    }

    break;
  }

  return { tokens: working.slice(idx), hadSudo, wrapped };
}

function stripCliGlobalOptions(execName, restTokens) {
  const spec = CLI_GLOBAL_OPTIONS[execName];
  if (!spec) {
    return { globalFlags: [], remaining: restTokens };
  }
  const globalFlags = [];
  let i = 0;
  while (i < restTokens.length) {
    const tok = restTokens[i];
    if (spec.skipPlusToolchain && /^\+[A-Za-z0-9._-]+$/.test(tok)) {
      globalFlags.push(tok);
      i += 1;
      continue;
    }
    if (!tok.startsWith('-') || tok === '-' || tok === '--') {
      break;
    }
    const eqIdx = tok.indexOf('=');
    if (eqIdx > 0) {
      const flagName = tok.slice(0, eqIdx);
      if (spec.valueFlags.has(flagName) || spec.boolFlags.has(flagName)) {
        globalFlags.push(tok);
        i += 1;
        continue;
      }
      if (spec.attachedShortValueFlags && spec.attachedShortValueFlags.some((f) => tok.startsWith(f) && tok.length > f.length)) {
        globalFlags.push(tok);
        i += 1;
        continue;
      }
      break;
    }
    if (spec.valueFlags.has(tok)) {
      globalFlags.push(tok);
      if (i + 1 < restTokens.length) {
        globalFlags.push(restTokens[i + 1]);
        i += 2;
      } else {
        i += 1;
      }
      continue;
    }
    if (spec.boolFlags.has(tok)) {
      globalFlags.push(tok);
      i += 1;
      continue;
    }
    if (spec.attachedShortValueFlags && spec.attachedShortValueFlags.some((f) => tok.startsWith(f) && tok.length > f.length)) {
      globalFlags.push(tok);
      i += 1;
      continue;
    }
    break;
  }

  let remaining = restTokens.slice(i);
  if ((execName === 'docker' || execName === 'podman' || execName === 'nerdctl') && remaining[0] === 'compose') {
    const composeValFlags = new Set(['-f', '--file', '-p', '--project-name', '--profile', '--env-file', '--project-directory']);
    let j = 1;
    while (j < remaining.length) {
      const ctok = remaining[j];
      if (!ctok.startsWith('-') || ctok === '--') break;
      const ceq = ctok.indexOf('=');
      if (ceq > 0 && composeValFlags.has(ctok.slice(0, ceq))) {
        globalFlags.push(ctok);
        j += 1;
        continue;
      }
      if (composeValFlags.has(ctok)) {
        globalFlags.push(ctok);
        if (j + 1 < remaining.length) {
          globalFlags.push(remaining[j + 1]);
          j += 2;
        } else {
          j += 1;
        }
        continue;
      }
      break;
    }
    remaining = ['compose', ...remaining.slice(j)];
  }

  return { globalFlags, remaining };
}

function normalizeCommandSegments(command) {
  const rawSegments = splitShellSegments(command);
  const parsedSegments = [];
  const normalizedLines = [];

  for (const seg of rawSegments) {
    const tokRes = tokenizeShellSegment(seg);
    if (!tokRes.tokens.length) continue;
    const unwrapped = stripWrapperPrefixes(tokRes.tokens);
    if (!unwrapped.tokens.length) continue;
    const execName = normalizeExecutableName(unwrapped.tokens[0]);
    const rest = unwrapped.tokens.slice(1);
    const { globalFlags, remaining } = stripCliGlobalOptions(execName, rest);
    const normalized = [execName, ...remaining].join(' ').trim();
    if (normalized) normalizedLines.push(normalized);
    parsedSegments.push({
      raw: seg,
      rawTokens: tokRes.tokens,
      execName,
      rawArgs: rest,
      globalFlags,
      remaining,
      hadSudo: unwrapped.hadSudo,
      wrapped: unwrapped.wrapped,
      normalized,
    });
  }

  return { parsedSegments, normalizedLines };
}

function inspectExecOptions(parsedSegments, workspaceRoots = []) {
  for (const seg of parsedSegments) {
    const { execName, globalFlags, remaining, rawArgs } = seg;

    if (execName === 'git') {
      for (let i = 0; i < globalFlags.length; i += 1) {
        const flag = globalFlags[i];
        if (
          flag === '-c' ||
          /^-c.+/.test(flag) ||
          flag === '--config-env' ||
          /^--config-env=/.test(flag) ||
          flag === '--exec-path' ||
          /^--exec-path=/.test(flag)
        ) {
          return {
            risk: 'high',
            fastAllow: false,
            ruleId: 'high_git_exec_option',
            reason: 'Git command uses a config or exec-path option capable of running external programs',
          };
        }
        let dirVal = '';
        if (flag === '--git-dir' || flag === '--work-tree' || flag === '-C') {
          dirVal = globalFlags[i + 1] || '';
          i += 1;
        } else if (/^--(?:git-dir|work-tree)=/.test(flag)) {
          dirVal = flag.slice(flag.indexOf('=') + 1);
        } else if (/^-C.+/.test(flag)) {
          dirVal = flag.slice(2);
        }
        if (dirVal) {
          if (containsSensitiveMarker(dirVal)) {
            return {
              risk: 'critical',
              fastAllow: false,
              ruleId: 'critical_sensitive_file',
              reason: 'Git directory option references a sensitive path',
            };
          }
          if (containsPathTraversal(dirVal) || isHomeRelativePath(dirVal) || (isAbsolutePathArg(dirVal) && !isPathInsideRoots(dirVal, workspaceRoots))) {
            return {
              risk: 'high',
              fastAllow: false,
              ruleId: 'high_git_outside_workspace',
              reason: 'Git directory option targets a path outside the active workspace',
            };
          }
        }
      }

      for (let i = 0; i < remaining.length; i += 1) {
        const arg = remaining[i];
        if (
          arg === '--ext-diff' ||
          arg === '--textconv' ||
          arg === '--upload-pack' ||
          /^--upload-pack=/.test(arg) ||
          arg === '--receive-pack' ||
          /^--receive-pack=/.test(arg) ||
          arg === '--output' ||
          /^--output=/.test(arg) ||
          arg === '--config-env' ||
          /^--config-env=/.test(arg) ||
          arg === '--exec-path' ||
          /^--exec-path=/.test(arg) ||
          (arg === '-c' && remaining[i + 1] && remaining[i + 1].includes('=')) ||
          /^-c=/.test(arg)
        ) {
          return {
            risk: 'high',
            fastAllow: false,
            ruleId: 'high_git_exec_option',
            reason: 'Git command uses a diff, textconv, config, output, or exec option capable of running programs or writing files',
          };
        }
      }
    }

    if (execName === 'rg' || execName === 'ripgrep') {
      for (const arg of rawArgs) {
        if (
          arg === '--pre' ||
          /^--pre=/.test(arg) ||
          arg === '--pre-glob' ||
          /^--pre-glob=/.test(arg) ||
          arg === '--hostname-bin' ||
          /^--hostname-bin=/.test(arg)
        ) {
          return {
            risk: 'high',
            fastAllow: false,
            ruleId: 'high_rg_exec_option',
            reason: 'Ripgrep option (--pre, --pre-glob, or --hostname-bin) invokes an external executable',
          };
        }
      }
    }

    if (execName === 'fd' || execName === 'fdfind') {
      for (const arg of rawArgs) {
        if (
          arg === '-x' ||
          arg === '-X' ||
          arg === '--exec' ||
          /^--exec=/.test(arg) ||
          arg === '--exec-batch' ||
          /^--exec-batch=/.test(arg)
        ) {
          return {
            risk: 'high',
            fastAllow: false,
            ruleId: 'high_fd_exec_option',
            reason: 'fd exec option invokes an external command on matched paths',
          };
        }
      }
    }

    if (execName === 'find') {
      for (const arg of rawArgs) {
        if (/^-(?:delete|exec|execdir|ok|okdir|fprint0?|fprintf|fls)$/.test(arg)) {
          return {
            risk: 'high',
            fastAllow: false,
            ruleId: 'high_find_exec_or_write',
            reason: 'find command uses a destructive, exec, or file-writing option',
          };
        }
      }
    }

    if (execName === 'tar') {
      for (const arg of rawArgs) {
        if (
          arg === '--checkpoint-action' ||
          /^--checkpoint-action=/.test(arg) ||
          arg === '--to-command' ||
          /^--to-command=/.test(arg) ||
          arg === '--rsh-command' ||
          /^--rsh-command=/.test(arg)
        ) {
          return {
            risk: 'high',
            fastAllow: false,
            ruleId: 'high_archive_exec_option',
            reason: 'tar option invokes an external command',
          };
        }
      }
    }
  }
  return null;
}

function validateReadOnlyArgs(args, spec, workspaceRoots = []) {
  let afterDoubleDash = false;
  const seenFlags = new Set();
  const positional = [];

  for (let i = 0; i < args.length; i += 1) {
    const tok = args[i];
    if (!afterDoubleDash && tok === '--') {
      afterDoubleDash = true;
      continue;
    }
    if (!afterDoubleDash && spec.allowPlusFormat && tok.startsWith('+')) {
      continue;
    }
    if (!afterDoubleDash && spec.allowWinSlashFlags && spec.allowWinSlashFlags.has(tok.toLowerCase())) {
      continue;
    }
    if (!afterDoubleDash && tok.startsWith('-') && tok.length > 1) {
      if (spec.allowNumericDash && /^-\d+$/.test(tok)) {
        continue;
      }
      const eqIdx = tok.indexOf('=');
      if (eqIdx > 0) {
        const flagName = tok.slice(0, eqIdx);
        const flagVal = tok.slice(eqIdx + 1);
        if (!spec.valueFlags.has(flagName)) return false;
        if (containsSensitiveMarker(flagVal) || containsPathTraversal(flagVal) || isHomeRelativePath(flagVal)) {
          return false;
        }
        seenFlags.add(flagName);
        continue;
      }
      if (tok.startsWith('--')) {
        if (spec.longBool.has(tok)) {
          seenFlags.add(tok);
          continue;
        }
        if (spec.valueFlags.has(tok)) {
          if (i + 1 >= args.length) return false;
          const nextVal = args[i + 1];
          if (containsSensitiveMarker(nextVal) || containsPathTraversal(nextVal) || isHomeRelativePath(nextVal)) {
            return false;
          }
          seenFlags.add(tok);
          i += 1;
          continue;
        }
        return false;
      }
      if (spec.valueFlags.has(tok)) {
        if (i + 1 >= args.length) return false;
        const nextVal = args[i + 1];
        if (containsSensitiveMarker(nextVal) || containsPathTraversal(nextVal) || isHomeRelativePath(nextVal)) {
          return false;
        }
        seenFlags.add(tok);
        i += 1;
        continue;
      }
      if (tok.length > 2 && spec.valueFlags.has(tok.slice(0, 2)) && /^\d+$/.test(tok.slice(2))) {
        seenFlags.add(tok.slice(0, 2));
        continue;
      }
      const chars = tok.slice(1);
      for (let c = 0; c < chars.length; c += 1) {
        if (!spec.shortBool.has(chars[c])) return false;
        seenFlags.add(`-${chars[c]}`);
      }
      continue;
    }
    positional.push(tok);
  }

  if (typeof spec.maxPositional === 'number' && positional.length > spec.maxPositional) {
    return false;
  }
  if (spec.requireZeroPositionalUnlessFlag && positional.length > 0) {
    const allowed = [...spec.requireZeroPositionalUnlessFlag].some((f) => seenFlags.has(f));
    if (!allowed) return false;
  }
  if (spec.bareNameArgsOnly) {
    for (const arg of positional) {
      if (!/^[A-Za-z0-9._+-]+$/.test(arg)) return false;
    }
  }
  if (spec.pathArgs) {
    const hasExplicitPattern = spec.patternArgUnlessFlag
      ? [...spec.patternArgUnlessFlag].some((f) => seenFlags.has(f))
      : true;
    const pathList = spec.patternArgUnlessFlag && !hasExplicitPattern
      ? positional.slice(1)
      : positional;
    for (const p of pathList) {
      if (containsSensitiveMarker(p) || containsPathTraversal(p) || isHomeRelativePath(p)) {
        return false;
      }
      if (isAbsolutePathArg(p) && !isPathInsideRoots(p, workspaceRoots)) {
        return false;
      }
    }
  }
  return true;
}

function isSafeReadOnlyCommand(command, workspaceRoots = []) {
  const trimmed = String(command || '').trim();
  if (!trimmed) return false;
  if (SHELL_CHAIN_OR_REDIRECT_PATTERN.test(trimmed)) return false;
  if (containsPathTraversal(trimmed) || isHomeRelativePath(trimmed)) return false;
  if (containsSensitiveMarker(trimmed)) return false;
  if (CRITICAL_PATTERNS.some((p) => p.regex.test(trimmed))) return false;
  if (HIGH_RISK_PATTERNS.some((p) => p.regex.test(trimmed))) return false;

  const tokenized = tokenizeShellSegment(trimmed);
  if (!tokenized.ok || tokenized.tokens.length === 0) return false;

  const rawExec = tokenized.tokens[0];
  if (/[\\/=]/.test(rawExec)) return false;
  const exec = rawExec.toLowerCase();
  const args = tokenized.tokens.slice(1);

  if (args.length === 1 && VERSION_CHECK_EXECUTABLES.has(exec) && VERSION_CHECK_FLAGS.has(args[0])) {
    return true;
  }

  if (exec === 'git') {
    let idx = 0;
    if (args[idx] === '--no-pager') idx += 1;
    if (idx >= args.length) return false;
    const subcmd = args[idx];
    if (subcmd.startsWith('-')) return false;
    const subSpec = GIT_READ_ONLY_SUBCOMMANDS[subcmd];
    if (!subSpec) return false;
    return validateReadOnlyArgs(args.slice(idx + 1), subSpec, workspaceRoots);
  }

  const spec = READ_ONLY_COMMAND_SPECS[exec];
  if (!spec) return false;
  return validateReadOnlyArgs(args, spec, workspaceRoots);
}

function validateApiUrl(rawUrl) {
  const trimmed = String(rawUrl || '').trim();
  if (!trimmed) {
    return { ok: false, error: 'ORBITER_API_URL is empty.' };
  }
  let parsed;
  try {
    parsed = new URL(trimmed);
  } catch {
    return { ok: false, error: 'ORBITER_API_URL is not a valid URL.' };
  }
  if (parsed.username || parsed.password) {
    return { ok: false, error: 'ORBITER_API_URL must not contain embedded credentials.' };
  }
  if (parsed.search || parsed.hash) {
    return { ok: false, error: 'ORBITER_API_URL must not contain query parameters or fragments.' };
  }
  const protocol = parsed.protocol.toLowerCase();
  const hostname = parsed.hostname.toLowerCase();
  if (!hostname) {
    return { ok: false, error: 'ORBITER_API_URL must include a hostname.' };
  }
  if (protocol === 'https:') {
    return { ok: true, url: trimmed.replace(/\/+$/, '') };
  }
  if (protocol === 'http:' && LOOPBACK_HOSTS.has(hostname)) {
    return { ok: true, url: trimmed.replace(/\/+$/, '') };
  }
  return {
    ok: false,
    error: `ORBITER_API_URL must use https:// (or http://127.0.0.1 / http://localhost for local development); rejected (${protocol}//${hostname}).`,
  };
}

function classifyToolCall(event) {
  const toolName = String(event.tool_name || '').trim();
  const lowerTool = toolName.toLowerCase();
  const toolInput = isRecord(event.tool_input) ? event.tool_input : {};
  const command = extractCommand(toolInput);
  const targetPaths = extractTargetPaths(toolInput);
  const cwd = typeof event.cwd === 'string' ? event.cwd : '';

  if (isOrbiterTool(toolName)) {
    return { risk: 'low', fastAllow: true, reason: 'Orbiter MCP loop prevention' };
  }

  if (isCodexInternalPlanApproval(event)) {
    return { risk: 'low', fastAllow: true, reason: 'Codex internal plan confirmation' };
  }

  // Pure read-only file/search tools: fast-path allow ONLY when targeting safe in-workspace paths.
  if (READ_ONLY_SEARCH_AND_COORDINATION_TOOLS.has(lowerTool)) {
    const sensitiveTarget = targetPaths.find((p) => containsSensitiveMarker(p));
    if (sensitiveTarget) {
      return {
        risk: 'critical',
        fastAllow: false,
        reason: `Read-only tool targets sensitive credential file (${path.basename(sensitiveTarget)})`,
        ruleId: 'critical_sensitive_read',
      };
    }
    const traversalTarget = targetPaths.find((p) => containsPathTraversal(p) || isHomeRelativePath(p));
    if (traversalTarget) {
      return {
        risk: 'high',
        fastAllow: false,
        reason: 'Read-only tool uses path traversal or home-directory reference',
        ruleId: 'high_path_traversal',
      };
    }
    const outsideTarget = targetPaths.find((p) => isOutsideWorkspace(p, cwd));
    if (outsideTarget) {
      return {
        risk: 'high',
        fastAllow: false,
        reason: 'Read-only tool targets a path outside the active workspace',
        ruleId: 'high_outside_workspace',
      };
    }
    return { risk: 'low', fastAllow: true, reason: `Read-only tool (${toolName})` };
  }

  // Shell / exec tools: check strict read-only allowlist first, then normalized critical/high-risk and exec-option checks.
  if (SHELL_TOOL_NAMES.has(lowerTool) || command) {
    const workspaceRoots = cwd ? [cwd] : [];
    if (command && isSafeReadOnlyCommand(command, workspaceRoots)) {
      return { risk: 'low', fastAllow: true, reason: 'Safe read-only shell command' };
    }
    const { parsedSegments, normalizedLines } = normalizeCommandSegments(command);
    const searchable = `${command}\n${normalizedLines.join('\n')}\n${targetPaths.join('\n')}\n${stableStringify(toolInput)}`;
    for (const rule of CRITICAL_PATTERNS) {
      if (rule.regex.test(searchable)) {
        return { risk: 'critical', fastAllow: false, reason: rule.reason, ruleId: rule.id };
      }
    }
    for (const rule of HIGH_RISK_PATTERNS) {
      if (rule.regex.test(searchable)) {
        return { risk: 'high', fastAllow: false, reason: rule.reason, ruleId: rule.id };
      }
    }
    const execOptionFinding = inspectExecOptions(parsedSegments, workspaceRoots);
    if (execOptionFinding) {
      return execOptionFinding;
    }
    if (containsSensitiveMarker(searchable)) {
      return {
        risk: 'critical',
        fastAllow: false,
        reason: 'Command references sensitive credentials or environment files',
        ruleId: 'critical_sensitive_file',
      };
    }
    if (containsPathTraversal(command) || isHomeRelativePath(command)) {
      return {
        risk: 'high',
        fastAllow: false,
        reason: 'Command references path traversal or a home-directory target',
        ruleId: 'high_path_traversal',
      };
    }
    return { risk: 'medium', fastAllow: false, reason: `Shell execution (${toolName || 'shell'})` };
  }

  // File write / apply_patch tools: gate sensitive file modifications, traversal, and infra files.
  if (FILE_MUTATION_TOOL_NAMES.has(lowerTool) || lowerTool.includes('patch') || lowerTool.includes('edit') || lowerTool.includes('write')) {
    const sensitiveTarget = targetPaths.find((p) => containsSensitiveMarker(p));
    const serialized = stableStringify(toolInput);
    if (sensitiveTarget || containsSensitiveMarker(serialized)) {
      return {
        risk: 'critical',
        fastAllow: false,
        reason: sensitiveTarget
          ? `Modification of sensitive file (${path.basename(sensitiveTarget)})`
          : 'File modification touches sensitive secrets or environment configuration',
        ruleId: 'critical_sensitive_edit',
      };
    }
    const infraTarget = targetPaths.find((p) => INFRA_WRITE_PATH_PATTERNS.some((pat) => pat.test(p)));
    if (infraTarget) {
      return {
        risk: 'high',
        fastAllow: false,
        reason: `Modification of security-sensitive workflow or hook file (${path.basename(infraTarget)})`,
        ruleId: 'high_infra_edit',
      };
    }
    if (targetPaths.some((p) => isOutsideWorkspace(p, cwd))) {
      return {
        risk: 'high',
        fastAllow: false,
        reason: 'File modification targets path outside active workspace',
        ruleId: 'high_outside_workspace',
      };
    }
    return { risk: 'medium', fastAllow: false, reason: `File modification (${toolName})` };
  }

  // External MCP or unknown tools: inspect arguments for critical/high-risk patterns.
  const searchable = `${toolName}\n${stableStringify(toolInput)}`;
  for (const rule of CRITICAL_PATTERNS) {
    if (rule.regex.test(searchable)) {
      return { risk: 'critical', fastAllow: false, reason: rule.reason, ruleId: rule.id };
    }
  }
  for (const rule of HIGH_RISK_PATTERNS) {
    if (rule.regex.test(searchable)) {
      return { risk: 'high', fastAllow: false, reason: rule.reason, ruleId: rule.id };
    }
  }
  if (containsSensitiveMarker(searchable)) {
    return {
      risk: 'critical',
      fastAllow: false,
      reason: 'Tool arguments reference sensitive credentials or key material',
      ruleId: 'critical_sensitive_mcp',
    };
  }
  return { risk: 'medium', fastAllow: false, reason: `Tool invocation (${toolName || 'unknown'})` };
}

function loadCredentialFile(env) {
  if (env.ORBITER_DISABLE_CREDENTIAL_FILE === '1' || env.ORBITER_DISABLE_CREDENTIAL_FILE === 'true') {
    return null;
  }
  const candidates = [];
  if (env.ORBITER_CREDENTIAL_PATH && env.ORBITER_CREDENTIAL_PATH.trim()) {
    candidates.push(path.resolve(env.ORBITER_CREDENTIAL_PATH.trim()));
  } else {
    const home = os.homedir() || env.HOME || env.USERPROFILE || '';
    if (home) {
      const profile = (env.ORBITER_CREDENTIAL_PROFILE || 'codex').trim().toLowerCase().replace(/[^a-z0-9_-]/g, '-');
      if (profile) {
        candidates.push(path.join(home, '.orbiter', 'profiles', profile, 'credentials.json'));
        candidates.push(path.join(home, '.orbiter', 'profiles', profile, 'credentials'));
      }
      candidates.push(path.join(home, '.orbiter', 'credentials.json'));
      candidates.push(path.join(home, '.orbiter', 'credentials'));
    }
  }

  for (const filePath of candidates) {
    try {
      const stat = fs.lstatSync(filePath);
      if (!stat.isFile() || stat.isSymbolicLink() || stat.size > MAX_CREDENTIAL_FILE_BYTES) {
        continue;
      }
      const parsed = JSON.parse(fs.readFileSync(filePath, 'utf8'));
      const token = isRecord(parsed)
        ? (typeof parsed.api_key === 'string' && parsed.api_key.trim())
          || (typeof parsed.token === 'string' && parsed.token.trim())
          || ''
        : '';
      if (token) {
        const rawUrl = parsed.backend_url || parsed.api_url || parsed.server_url || '';
        return {
          api_key: token,
          backend_url: typeof rawUrl === 'string' ? rawUrl.trim() : '',
        };
      }
    } catch {
      // Ignore unreadable credential file and continue fallback chain.
    }
  }
  return null;
}

function resolveRuntimeConfig(env, cliArgs = []) {
  let timeoutOverride;
  let serverUrlOverride;
  for (let i = 0; i < cliArgs.length; i += 1) {
    if (cliArgs[i] === '--timeout' && cliArgs[i + 1]) {
      const n = Number(cliArgs[i + 1]);
      if (Number.isFinite(n) && n > 0) timeoutOverride = n;
      i += 1;
    } else if (cliArgs[i] === '--server-url' && cliArgs[i + 1]) {
      serverUrlOverride = cliArgs[i + 1].trim();
      i += 1;
    }
  }

  const creds = loadCredentialFile(env);
  const rawApiUrl =
    serverUrlOverride ||
    env.ORBITER_API_URL ||
    env.ORBITER_SERVER_URL ||
    (creds && creds.backend_url) ||
    DEFAULT_API_URL;
  const apiUrl = String(rawApiUrl).trim().replace(/\/+$/, '');
  const apiKey = (env.ORBITER_API_KEY || env.ORBITER_TOKEN || (creds && creds.api_key) || '').trim();

  const envTimeout = Number(env.ORBITER_APPROVAL_TIMEOUT_SEC || env.ORBITER_CODEX_TIMEOUT_SECONDS);
  const timeoutSeconds = timeoutOverride || (Number.isFinite(envTimeout) && envTimeout > 0 ? envTimeout : DEFAULT_TIMEOUT_SECONDS);

  const envPollMs = Number(env.ORBITER_POLL_INTERVAL_MS);
  const pollIntervalMs = Number.isFinite(envPollMs) && envPollMs >= 20 ? envPollMs : DEFAULT_POLL_INTERVAL_MS;

  const zeroDataFlag = String(env.ORBITER_ZERO_DATA_MODE || '').trim().toLowerCase();
  const zeroDataMode = zeroDataFlag === '1' || zeroDataFlag === 'true';
  const minRisk = normalizeMinRisk(env.ORBITER_MIN_RISK, 'high');
  const hookProfile = String(env.ORBITER_HOOK_PROFILE || 'default').trim().toLowerCase();

  return { apiUrl, apiKey, timeoutSeconds, pollIntervalMs, zeroDataMode, minRisk, hookProfile };
}

function buildAuthHeaders(apiKey) {
  return {
    'Content-Type': 'application/json',
    Connection: 'close',
    Authorization: `Bearer ${apiKey}`,
    'X-Orbiter-Trace-Id': crypto.randomBytes(16).toString('hex'),
  };
}

function extractSqlNullableString(field) {
  if (typeof field === 'string') return field;
  if (isRecord(field) && typeof field.String === 'string') return field.String;
  return '';
}

function buildApprovalPayload(event, classification, config = {}, env = process.env) {
  const toolName = String(event.tool_name || event.hook_event_name || 'tool');
  const rawInput = event.tool_input ?? {};
  const runtimeSecrets = collectRuntimeSecrets(env, config.apiKey ? [config.apiKey] : []);
  const redactedInput = redactValue(rawInput, 0, runtimeSecrets);
  const command = extractCommand(redactedInput);
  const targetPaths = extractTargetPaths(redactedInput);
  const inputHash = sha256Hex(redactedInput);
  const zeroDataMode = Boolean(config.zeroDataMode);
  const preview = zeroDataMode ? '[zero_data_mode]' : truncate(stableStringify(redactedInput), 1800);

  const sessionId = typeof event.session_id === 'string' && event.session_id ? event.session_id : 'unknown-session';
  const turnId = typeof event.turn_id === 'string' && event.turn_id ? event.turn_id : 'unknown-turn';
  const toolUseId = typeof event.tool_use_id === 'string' && event.tool_use_id ? event.tool_use_id : 'unknown-tool-use';
  const cwd = typeof event.cwd === 'string' && event.cwd ? event.cwd : process.cwd();
  const workspaceName = path.basename(cwd) || 'codex-workspace';

  const action = zeroDataMode
    ? `Codex ${toolName} (${classification.risk} risk)`
    : command
      ? `Codex ${toolName}: ${truncate(redactString(command, runtimeSecrets), 120)}`
      : `Codex ${event.hook_event_name}: ${toolName}`;
  const description = zeroDataMode
    ? `${classification.reason}. Requested via OpenAI Codex (${toolName}). Zero Data Mode active: tool arguments withheld locally.`
    : `${classification.reason}. Requested via OpenAI Codex (${toolName}).`;
  const idempotencyKey = [
    'codex',
    sessionId,
    turnId,
    event.hook_event_name,
    toolName,
    toolUseId,
    inputHash,
  ].join(':');

  return {
    action,
    description,
    diff_summary: '',
    file_count: targetPaths.length,
    risk_level: classification.risk,
    source_ide: 'codex',
    source_extension_version: PLUGIN_VERSION,
    workspace_name: workspaceName,
    mcp_permission_id: toolUseId,
    tool_name: toolName,
    tool_input_json: JSON.stringify({
      payload_mode: zeroDataMode ? 'zero_data' : 'redacted_preview',
      preview,
      hash: inputHash,
      codex: {
        session_id: sessionId,
        turn_id: turnId,
        tool_use_id: toolUseId,
        hook_event_name: event.hook_event_name,
        model: typeof event.model === 'string' && event.model ? event.model : 'unknown',
      },
    }),
    auto_approve: false,
    codex_session_id: sessionId,
    codex_turn_id: turnId,
    codex_tool_use_id: toolUseId,
    codex_hook_event_name: event.hook_event_name,
    codex_tool_input_hash: inputHash,
    codex_tool_input_preview: preview,
    codex_idempotency_key: idempotencyKey,
  };
}

function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

async function fetchWithTimeout(url, options, timeoutMs) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  try {
    return await fetch(url, { ...options, redirect: 'error', signal: controller.signal });
  } finally {
    clearTimeout(timer);
  }
}

async function requestMobileApproval(payload, config, runtimeSecrets = []) {
  if (!config.apiKey) {
    return {
      status: 'denied',
      reason: `Orbiter Dev credentials missing. Pair your iOS or Android phone at ${SETUP_URL} and set ORBITER_API_KEY (or ORBITER_TOKEN).`,
    };
  }

  const urlCheck = validateApiUrl(config.apiUrl);
  if (!urlCheck.ok) {
    return {
      status: 'denied',
      reason: `Blocked unsafe ORBITER_API_URL (fail-closed): ${redactString(urlCheck.error, runtimeSecrets)}`,
    };
  }
  const safeApiUrl = urlCheck.url;

  let createResp;
  try {
    createResp = await fetchWithTimeout(
      `${safeApiUrl}/api/v1/approvals`,
      {
        method: 'POST',
        headers: buildAuthHeaders(config.apiKey),
        body: JSON.stringify(payload),
      },
      15000,
    );
  } catch (error) {
    const safeErr = redactString(String(error.message || error), runtimeSecrets);
    return {
      status: 'denied',
      reason: `Orbiter Dev backend unreachable (${safeErr}). Failing closed.`,
    };
  }

  const createText = await createResp.text();
  let createJson = null;
  try {
    createJson = createText ? JSON.parse(createText) : null;
  } catch {
    createJson = null;
  }

  if (createResp.status === 401 || createResp.status === 403) {
    const serverMsg = redactString(
      (isRecord(createJson) && (createJson.error || createJson.message)) || `HTTP ${createResp.status}`,
      runtimeSecrets,
    );
    return {
      status: 'denied',
      reason: `Orbiter Dev rejected approval request (${serverMsg}). Re-authenticate at ${SETUP_URL}.`,
    };
  }

  if (!createResp.ok || !isRecord(createJson)) {
    return {
      status: 'denied',
      reason: `Orbiter Dev approval creation failed (HTTP ${createResp.status}). Failing closed.`,
    };
  }

  const created = isRecord(createJson.data) ? createJson.data : createJson;
  const approvalId = created.id !== undefined && created.id !== null ? String(created.id) : '';
  const initialStatus = extractSqlNullableString(created.status).toLowerCase();

  if (TERMINAL_ALLOW_STATUSES.has(initialStatus)) {
    return {
      status: 'approved',
      approvalId,
      reason: redactString(extractSqlNullableString(created.response_notes) || 'Approved via Orbiter Dev mobile', runtimeSecrets),
    };
  }
  if (TERMINAL_DENY_STATUSES.has(initialStatus)) {
    return {
      status: 'denied',
      approvalId,
      reason: redactString(extractSqlNullableString(created.response_notes) || `Blocked by Orbiter Dev mobile decision (${initialStatus})`, runtimeSecrets),
    };
  }
  if (!approvalId) {
    return {
      status: 'denied',
      reason: 'Orbiter Dev backend did not return an approval ID. Failing closed.',
    };
  }

  const deadline = Date.now() + config.timeoutSeconds * 1000;
  let lastError = '';

  while (Date.now() < deadline) {
    const remainingMs = deadline - Date.now();
    if (remainingMs <= 0) break;

    try {
      const pollResp = await fetchWithTimeout(
        `${safeApiUrl}/api/v1/approvals/${encodeURIComponent(approvalId)}`,
        {
          method: 'GET',
          headers: buildAuthHeaders(config.apiKey),
        },
        Math.min(10000, Math.max(500, remainingMs)),
      );

      if (pollResp.status === 401 || pollResp.status === 403) {
        return {
          status: 'denied',
          approvalId,
          reason: `Orbiter Dev authorization failed while polling (HTTP ${pollResp.status}). Failing closed.`,
        };
      }

      if (pollResp.ok) {
        const pollJson = await pollResp.json();
        const record = isRecord(pollJson) && isRecord(pollJson.data) ? pollJson.data : pollJson;
        if (isRecord(record)) {
          const status = extractSqlNullableString(record.status).toLowerCase();
          const notes = extractSqlNullableString(record.response_notes) || extractSqlNullableString(record.notes);
          if (TERMINAL_ALLOW_STATUSES.has(status)) {
            return {
              status: 'approved',
              approvalId,
              reason: redactString(notes || 'Approved via Orbiter Dev mobile biometric sign-off', runtimeSecrets),
            };
          }
          if (TERMINAL_DENY_STATUSES.has(status)) {
            return {
              status: 'denied',
              approvalId,
              reason: redactString(notes || `Denied via Orbiter Dev mobile (${status})`, runtimeSecrets),
            };
          }
        }
      } else {
        lastError = `HTTP ${pollResp.status}`;
      }
    } catch (error) {
      lastError = redactString(String(error.message || error), runtimeSecrets);
    }

    const waitMs = Math.min(config.pollIntervalMs, Math.max(0, deadline - Date.now()));
    if (waitMs > 0) {
      await sleep(waitMs);
    }
  }

  const suffix = lastError ? ` Last error: ${lastError}.` : '';
  return {
    status: 'denied',
    approvalId,
    reason: `Orbiter Dev mobile approval timed out after ${config.timeoutSeconds}s.${suffix} Failing closed.`,
  };
}

async function maybeSendTelemetry(event, config, env, runtimeSecrets = []) {
  if (env.ORBITER_CODEX_REPORT_TELEMETRY !== 'true' || !config.apiKey) return;
  const urlCheck = validateApiUrl(config.apiUrl);
  if (!urlCheck.ok) return;
  try {
    if (event.hook_event_name === 'PostToolUse') {
      const responseText = truncate(stableStringify(redactValue(event.tool_response ?? {}, 0, runtimeSecrets)), 600);
      const failed = /error|failed|exception/i.test(responseText);
      await fetchWithTimeout(
        `${urlCheck.url}/api/v1/agent/tool-result`,
        {
          method: 'POST',
          headers: buildAuthHeaders(config.apiKey),
          body: JSON.stringify({
            session_id: event.session_id || 'unknown-session',
            tool_name: event.tool_name || 'unknown',
            success: !failed,
            error_message: failed ? responseText : '',
            file_path: '',
            duration_ms: 0,
            codex_turn_id: event.turn_id || 'unknown-turn',
            codex_tool_use_id: event.tool_use_id || 'unknown-tool-use',
          }),
        },
        3000,
      );
    } else if (event.hook_event_name === 'Stop' || event.hook_event_name === 'SessionStart') {
      await fetchWithTimeout(
        `${urlCheck.url}/api/v1/agent/heartbeat`,
        {
          method: 'POST',
          headers: buildAuthHeaders(config.apiKey),
          body: JSON.stringify({
            session_id: event.session_id || 'unknown-session',
            state: event.hook_event_name === 'Stop' ? 'idle' : 'working',
            task: `Codex ${event.hook_event_name}`,
          }),
        },
        3000,
      );
    }
  } catch (error) {
    const safeErr = redactString(String(error.message || error), runtimeSecrets);
    process.stderr.write(`[orbiter-codex-hook] Telemetry notice: ${safeErr}\n`);
  }
}

function buildAllowOutput(eventName, reason) {
  if (eventName === 'PermissionRequest') {
    return {
      hookSpecificOutput: {
        hookEventName: 'PermissionRequest',
        decision: { behavior: 'allow' },
      },
    };
  }
  return {
    hookSpecificOutput: {
      hookEventName: 'PreToolUse',
      permissionDecision: 'allow',
      permissionDecisionReason: reason || 'Allowed by Orbiter Dev policy',
    },
  };
}

function buildDenyOutput(eventName, reason) {
  if (eventName === 'PermissionRequest') {
    return {
      hookSpecificOutput: {
        hookEventName: 'PermissionRequest',
        decision: {
          behavior: 'deny',
          message: reason || 'Denied by Orbiter Dev policy',
        },
      },
    };
  }
  return {
    hookSpecificOutput: {
      hookEventName: 'PreToolUse',
      permissionDecision: 'deny',
      permissionDecisionReason: reason || 'Denied by Orbiter Dev policy',
    },
  };
}

async function processHookPayload(rawEvent, env = process.env, cliArgs = []) {
  const defaultEventName = isRecord(rawEvent) && rawEvent.hook_event_name === 'PermissionRequest'
    ? 'PermissionRequest'
    : 'PreToolUse';

  if (exceedsMaxDepth(rawEvent, MAX_JSON_DEPTH)) {
    return buildDenyOutput(defaultEventName, 'Codex hook payload exceeds maximum JSON nesting depth. Failing closed.');
  }
  if (containsNullByte(rawEvent, MAX_JSON_DEPTH)) {
    return buildDenyOutput(defaultEventName, 'Null byte detected in Codex hook payload. Failing closed.');
  }
  if (!isRecord(rawEvent) || typeof rawEvent.hook_event_name !== 'string' || !SUPPORTED_EVENTS.has(rawEvent.hook_event_name)) {
    return buildDenyOutput(defaultEventName, 'Invalid or unsupported Codex hook payload. Failing closed.');
  }

  const eventName = rawEvent.hook_event_name;
  const config = resolveRuntimeConfig(env, cliArgs);
  const runtimeSecrets = collectRuntimeSecrets(env, config.apiKey ? [config.apiKey] : []);

  // Non-gating lifecycle events return immediately (optional opt-in telemetry).
  if (
    eventName === 'PostToolUse' ||
    eventName === 'Stop' ||
    eventName === 'SessionStart' ||
    eventName === 'UserPromptSubmit' ||
    eventName === 'SubagentStart' ||
    eventName === 'SubagentStop' ||
    eventName === 'PreCompact' ||
    eventName === 'PostCompact'
  ) {
    await maybeSendTelemetry(rawEvent, config, env, runtimeSecrets);
    return {};
  }

  // Strict schema validation on gating events (PreToolUse / PermissionRequest)
  if (typeof rawEvent.tool_name !== 'string' || !rawEvent.tool_name.trim()) {
    return buildDenyOutput(eventName, 'Missing or non-string Codex tool_name. Failing closed.');
  }
  if (rawEvent.tool_input !== undefined && rawEvent.tool_input !== null && !isRecord(rawEvent.tool_input)) {
    return buildDenyOutput(eventName, 'Malformed Codex tool_input object. Failing closed.');
  }

  const classification = classifyToolCall(rawEvent);

  if (classification.fastAllow) {
    return buildAllowOutput(eventName, `Fast-path allow: ${classification.reason}`);
  }

  const shouldGate =
    eventName === 'PermissionRequest' ||
    config.hookProfile === 'strict' ||
    meetsMinRisk(classification.risk, config.minRisk);

  if (!shouldGate) {
    return buildAllowOutput(eventName, `Allowed (${classification.risk} risk): ${classification.reason}`);
  }

  const approvalPayload = buildApprovalPayload(rawEvent, classification, config, env);
  const decision = await requestMobileApproval(approvalPayload, config, runtimeSecrets);

  if (decision.status === 'approved') {
    return buildAllowOutput(eventName, decision.reason);
  }
  return buildDenyOutput(eventName, decision.reason);
}

function readStdin(maxBytes = MAX_STDIN_BYTES) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    let totalBytes = 0;
    let settled = false;

    const cleanup = () => {
      process.stdin.removeListener('data', onData);
      process.stdin.removeListener('end', onEnd);
      process.stdin.removeListener('error', onError);
    };

    const onData = (chunk) => {
      if (settled) return;
      const buf = Buffer.isBuffer(chunk) ? chunk : Buffer.from(String(chunk), 'utf8');
      totalBytes += buf.length;
      if (totalBytes > maxBytes) {
        settled = true;
        cleanup();
        process.stdin.pause();
        reject(new StdinLimitError(`Codex hook stdin exceeded ${maxBytes} byte safety limit.`));
        return;
      }
      chunks.push(buf);
    };

    const onEnd = () => {
      if (settled) return;
      settled = true;
      cleanup();
      resolve(Buffer.concat(chunks).toString('utf8'));
    };

    const onError = (err) => {
      if (settled) return;
      settled = true;
      cleanup();
      reject(err);
    };

    process.stdin.on('data', onData);
    process.stdin.on('end', onEnd);
    process.stdin.on('error', onError);
    process.stdin.resume();
  });
}

async function main() {
  const runtimeSecrets = collectRuntimeSecrets(process.env);
  const [nodeMajor] = process.versions.node.split('.').map(Number);
  if (nodeMajor < 18) {
    process.stderr.write('[orbiter-codex-hook] Node.js 18 or newer is required.\n');
    process.stdout.write(`${JSON.stringify(buildDenyOutput('PreToolUse', 'Node.js 18+ required for Orbiter Dev hook. Failing closed.'))}\n`);
    process.exitCode = 0;
    return;
  }

  let rawText = '';
  try {
    rawText = await readStdin(MAX_STDIN_BYTES);
  } catch (error) {
    const safeErr = redactString(String(error && error.message ? error.message : error), runtimeSecrets);
    process.stderr.write(`[orbiter-codex-hook] Stdin rejected: ${safeErr}\n`);
    process.stdout.write(`${JSON.stringify(buildDenyOutput('PreToolUse', `${safeErr} Failing closed.`))}\n`);
    process.exitCode = 0;
    return;
  }

  if (!rawText.trim()) {
    process.stdout.write(`${JSON.stringify(buildDenyOutput('PreToolUse', 'Empty Codex hook input received. Failing closed.'))}\n`);
    process.exitCode = 0;
    return;
  }

  if (rawText.includes('\0')) {
    process.stdout.write(`${JSON.stringify(buildDenyOutput('PreToolUse', 'Null byte detected in Codex hook stdin. Failing closed.'))}\n`);
    process.exitCode = 0;
    return;
  }

  let parsed;
  try {
    parsed = JSON.parse(rawText);
  } catch (error) {
    const safeErr = redactString(String(error && error.message ? error.message : error), runtimeSecrets);
    process.stderr.write(`[orbiter-codex-hook] Failed to parse stdin JSON: ${safeErr}\n`);
    process.stdout.write(`${JSON.stringify(buildDenyOutput('PreToolUse', 'Malformed Codex hook JSON payload. Failing closed.'))}\n`);
    process.exitCode = 0;
    return;
  }

  const output = await processHookPayload(parsed, process.env, process.argv.slice(2));
  process.stdout.write(`${JSON.stringify(output)}\n`);
  process.exitCode = 0;
}

if (require.main === module) {
  main().catch((error) => {
    const runtimeSecrets = collectRuntimeSecrets(process.env);
    const safeErr = redactString(String(error && error.message ? error.message : error), runtimeSecrets);
    process.stderr.write(`[orbiter-codex-hook] Fatal error: ${safeErr}\n`);
    process.stdout.write(`${JSON.stringify(buildDenyOutput('PreToolUse', 'Orbiter Dev hook encountered an unexpected error. Failing closed.'))}\n`);
    process.exitCode = 0;
  });
}

module.exports = {
  MAX_JSON_DEPTH,
  MAX_STDIN_BYTES,
  buildApprovalPayload,
  classifyToolCall,
  containsNullByte,
  containsPathTraversal,
  exceedsMaxDepth,
  inspectExecOptions,
  isOrbiterTool,
  isSafeReadOnlyCommand,
  normalizeCommandSegments,
  processHookPayload,
  redactString,
  redactValue,
  resolveRuntimeConfig,
  tokenizeShellSegment,
  validateApiUrl,
};
