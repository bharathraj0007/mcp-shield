# mcp-shield

[![CI](https://github.com/bharathraj0007/mcp-shield/actions/workflows/ci.yml/badge.svg)](https://github.com/bharathraj0007/mcp-shield/actions/workflows/ci.yml)
[![npm version](https://img.shields.io/npm/v/@bharathraj_07/mcp-shield.svg)](https://www.npmjs.com/package/@bharathraj_07/mcp-shield)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)
[![Node.js](https://img.shields.io/badge/node-%3E%3D20.0.0-green.svg)](https://nodejs.org)
[![Telemetry](https://img.shields.io/badge/telemetry-zero%20(100%25%20offline)-success.svg)](#3-system-architecture--threat-model)

> 100% Offline Local Security Scanner, Runtime Firewall, and Policy Engine for Model Context Protocol (MCP) and AI Coding Agents.

`mcp-shield` protects developer workstations from unauthorized AI agent actions. It scans local MCP configurations for hardcoded secrets, blocks path traversal attacks in real time, and enforces security policies across local Model Context Protocol servers.

The tool operates **100% offline**. It sends no network telemetry, makes zero outbound requests, and requires zero cloud accounts.

---

## Table of Contents
1. [Beginner's 5-Minute Walkthrough](#1-beginners-5-minute-walkthrough)
2. [Runtime Firewall Guide (`mcp-shield proxy`)](#2-runtime-firewall-guide-mcp-shield-proxy)
3. [System Architecture & Threat Model](#3-system-architecture--threat-model)
4. [CLI Command Reference](#4-cli-command-reference)
   - [`mcp-shield scan`](#mcp-shield-scan-path-options)
   - [`mcp-shield fix`](#mcp-shield-fix-path-options)
   - [`mcp-shield init`](#mcp-shield-init-options)
   - [`mcp-shield proxy`](#mcp-shield-proxy-options----cmd-args)
   - [`mcp-shield audit`](#mcp-shield-audit-options)
   - [`mcp-shield policy`](#mcp-shield-policy-validate--schema-path)
   - [`mcp-shield rules`](#mcp-shield-rules-options)
   - [`mcp-shield baseline`](#mcp-shield-baseline-path-options)
   - [`mcp-shield completions`](#mcp-shield-completions-shell)
5. [Customizing `policy.yaml`](#5-customizing-policyyaml)
6. [OWASP MCP Top 10 Rule Catalog](#6-owasp-mcp-top-10-rule-catalog)
7. [Exit Codes Reference](#7-exit-codes-reference)
8. [Programmatic TypeScript Library API](#8-programmatic-typescript-library-api)
9. [GitHub Actions SARIF Integration](#9-github-actions-sarif-integration)
10. [Benchmarks & Detection Coverage](#10-benchmarks--detection-coverage)
11. [License](#11-license)

---

## 1. Beginner's 5-Minute Walkthrough

### What is an MCP Server and Why Is It Risky?
Modern AI coding tools (Cursor, Claude Desktop, VS Code, Windsurf, Antigravity, Cline) use the **Model Context Protocol (MCP)**. MCP servers give AI agents tools to read your disk, execute terminal commands, and query databases.

Leaving MCP servers unprotected creates serious security risks:
- **Credential Theft:** Developers frequently paste raw API keys (`sk-ant-...`, `ghp_...`) into JSON config files.
- **Path Traversal Attacks:** A prompt-injected AI model can instruct an MCP filesystem server to read `../../.env` or `~/.ssh/id_rsa`.
- **Destructive Commands:** An agent can run destructive shell commands such as `rm -rf /` or pipe untrusted scripts to `sh`.
- **Tool Rug-Pulls:** An unpinned server can change its tool descriptions mid-session to mislead the AI into executing malicious actions.

`mcp-shield` provides an automated local shield that detects configuration vulnerabilities and stops live attacks at runtime.

---

### Step 1: Install `mcp-shield`

You need **Node.js v20.0.0 or higher**.

```bash
# Option A: Install globally (Recommended)
npm install -g @bharathraj_07/mcp-shield

# Option B: Run instantly without global install
npx @bharathraj_07/mcp-shield scan
```

Verify your installation:
```bash
mcp-shield --version
mcp-shield --help
```

---

### Step 2: Scan Your Machine for Vulnerabilities

Run `mcp-shield scan` without arguments. It automatically discovers client configurations across Cursor, Claude Desktop, VS Code, Windsurf, Antigravity, Gemini CLI, Zed, and Cline:

```bash
mcp-shield scan
```

To scan a specific project configuration file or directory directly:
```bash
mcp-shield scan ./mcp.json
```

If your configuration contains hardcoded API keys, unpinned packages, or unsafe path exposures, `mcp-shield` highlights the findings:

```text
=== mcp-shield Security Scan Report ===
Files Scanned: 1 | MCP Servers Found: 2

Detected Security Risks:
────────────────────────────────────────────────────────────

[1]  CRITICAL  MS-001 (MCP01:2025)
    Title:      Hardcoded Anthropic API Key Detected
    Server:     filesystem
    File:       ./mcp.json
    Evidence:   sk-ant-***...9999
    Remedy:     Move secret to environment variable or .env file and reference with ${VAR_NAME}.

[2]  HIGH  MS-002 (MCP02:2025)
    Title:      Unsafe Path Scope Exposure
    Server:     filesystem
    File:       ./mcp.json
    Evidence:   /
    Remedy:     Restrict filesystem server scope to a designated project subfolder (e.g. "./docs" or "./workspace").

────────────────────────────────────────────────────────────
 GRADE D  Security Score: 45/100 (2 findings)

Tip: Run 'mcp-shield fix <path>' to safely extract hardcoded secrets into .env.mcp.
```

---

### Step 3: Automatically Fix Exposed Secrets

Do not edit secrets by hand. Use `mcp-shield fix` to extract sensitive API keys into an isolated `.env.mcp` file.

> [!TIP]
> Run `mcp-shield scan` first to see the exact file path on your system, then copy that path directly into `mcp-shield fix <path>`.

```bash
# Preview changes safely without touching files (Standard project config)
mcp-shield fix ./mcp.json --dry-run

# Apply changes with automatic backup
mcp-shield fix ./mcp.json
```

#### Multi-Client Copy-Paste Commands:
```bash
# Standard project config
mcp-shield fix ./mcp.json

# Google Antigravity
mcp-shield fix ~/.gemini/config/mcp_config.json

# VS Code (workspace)
mcp-shield fix .vscode/mcp.json

# Claude Desktop (macOS)
mcp-shield fix ~/Library/Application\ Support/Claude/claude_desktop_config.json

# Claude Desktop (Windows PowerShell)
mcp-shield fix "$env:APPDATA\Claude\claude_desktop_config.json"

# Windsurf
mcp-shield fix ~/.codeium/windsurf/mcp_config.json

# Cursor
mcp-shield fix ~/.cursor/mcp.json

# Cline (VS Code extension)
mcp-shield fix ~/.cline/mcp_settings.json
```

What happens under the hood:
1. `mcp-shield` creates a timestamped `.bak` backup copy of your configuration file.
2. It extracts raw API keys into `.env.mcp` with strict file permissions (`0o600` on POSIX systems).
3. It updates the original configuration to reference `${ANTHROPIC_API_KEY}` safely while preserving JSON comments, trailing commas, and formatting.

---

### Step 4: Turn on the Live Runtime Firewall

Static scanning fixes existing files, but it cannot stop a live AI agent from requesting `../../.env` during a chat session.

To block runtime attacks, wrap your server command with `mcp-shield proxy` in your IDE configuration:

```json
{
  "mcpServers": {
    "filesystem": {
      "command": "mcp-shield",
      "args": [
        "proxy",
        "--",
        "npx",
        "-y",
        "@modelcontextprotocol/server-filesystem",
        "./workspace"
      ]
    }
  }
}
```

Now, every file read, shell command, and tool call passes through the `mcp-shield` firewall before reaching the real server.

---

## 2. Runtime Firewall Guide (`mcp-shield proxy`)

### How the Firewall Works
`mcp-shield proxy` sits between your AI coding editor and the target MCP server. It intercepts JSON-RPC 2.0 messages over standard input and output (`stdio`). It automatically detects whether the client uses newline-delimited JSON or `Content-Length` header framing.

```text
IDE / AI Agent  ──(stdio JSON-RPC)──>  [mcp-shield proxy]  ──(validated)──>  Real MCP Server
                                             │
                                     Blocked if malicious
                                             ▼
                                  Returns JSON-RPC -32001
```

- When an agent requests a safe project file, the proxy forwards the message immediately (< 0.1 ms average inspection latency).
- When an agent requests `.env`, `~/.ssh/id_rsa`, or runs `rm -rf`, the proxy drops the request, logs the violation to `stderr`, and returns a standard JSON-RPC error frame (`code: -32001`) to the agent.
- If a server modifies its tool definitions mid-session, the built-in rug-pull detector blocks execution and alerts the user.

---

### Configuration File Locations by Editor

Locate the configuration file for your AI editor:

| Editor | Platform | Exact Configuration File Path |
| :--- | :--- | :--- |
| **Cursor** | macOS / Linux / Windows | `~/.cursor/mcp.json` or `.cursor/mcp.json` (workspace) |
| **Claude Desktop** | macOS | `~/Library/Application Support/Claude/claude_desktop_config.json` |
| **Claude Desktop** | Windows | `%APPDATA%\Claude\claude_desktop_config.json` |
| **VS Code** | Windows | `%APPDATA%\Code\User\mcp.json` or `.vscode/mcp.json` |
| **VS Code** | macOS | `~/Library/Application Support/Code/User/mcp.json` |
| **VS Code** | Linux | `~/.config/Code/User/mcp.json` |
| **Windsurf** | macOS / Linux / Windows | `~/.codeium/windsurf/mcp_config.json` |
| **Google Antigravity**| macOS / Linux / Windows | `~/.gemini/config/mcp_config.json` or `.agents/mcp_config.json` |
| **Cline (VS Code)** | macOS | `~/Library/Application Support/Code/User/globalStorage/saoudrizwan.claude-dev/settings/cline_mcp_settings.json` |
| **Cline (VS Code)** | Windows | `%APPDATA%\Code\User\globalStorage\saoudrizwan.claude-dev\settings\cline_mcp_settings.json` |

---

### Before vs. After Configuration Examples

#### Example 1: Filesystem Server with Global Install

**Before (Unprotected):**
```json
{
  "mcpServers": {
    "filesystem": {
      "command": "npx",
      "args": [
        "-y",
        "@modelcontextprotocol/server-filesystem",
        "./workspace"
      ]
    }
  }
}
```

**After (Protected by `mcp-shield`):**
```json
{
  "mcpServers": {
    "filesystem": {
      "command": "mcp-shield",
      "args": [
        "proxy",
        "--",
        "npx",
        "-y",
        "@modelcontextprotocol/server-filesystem",
        "./workspace"
      ]
    }
  }
}
```

---

#### Example 2: Without Global Install (`npx`)

If you prefer not to install global npm packages, use `npx` directly inside the configuration:

```json
{
  "mcpServers": {
    "filesystem": {
      "command": "npx",
      "args": [
        "-y",
        "@bharathraj_07/mcp-shield",
        "proxy",
        "--",
        "npx",
        "-y",
        "@modelcontextprotocol/server-filesystem",
        "./workspace"
      ]
    }
  }
}
```

> [!NOTE]
> The `--` separator is mandatory. It informs `mcp-shield` where its options end and where the target MCP server command begins.

---

### Testing the Live Firewall in Your Terminal

You can verify that `mcp-shield` blocks path traversal attacks before connecting it to your editor.

#### macOS & Linux (bash / zsh):
```bash
echo '{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"read_file","arguments":{"path":"../../.env"}}}' | mcp-shield proxy -- node -e "process.stdin.resume()"
```

#### Windows (PowerShell):
> [!IMPORTANT]
> In PowerShell, quote the double-dash as `"--"` so PowerShell does not interpret it as a parameter delimiter.

```powershell
'{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"read_file","arguments":{"path":"../../.env"}}}' | mcp-shield proxy "--" node -e "process.stdin.resume()"
```

#### Expected Terminal Output:
`mcp-shield` logs the blocked rule on `stderr` and prints the JSON-RPC error frame on `stdout`:

```text
 MCP-SHIELD BLOCK  MS-001: Blocked by mcp-shield (MS-001): Unauthorized access to sensitive file (.env file)
{"jsonrpc":"2.0","id":1,"error":{"code":-32001,"message":"Blocked by mcp-shield (MS-001): Unauthorized access to sensitive file (.env file)","data":{"ruleId":"MS-001","owaspId":"MCP01:2025","action":"BLOCK","redactedTarget":"**/.env"}}}
```

---

## 3. System Architecture & Threat Model

### System Architecture

`mcp-shield` combines three defense layers into a single lightweight binary:

```text
 ┌──────────────────────┐
 │   AI Coding Agent    │  (Cursor, Claude Desktop, Antigravity, VS Code, Windsurf)
 └──────────┬───────────┘
            │
            ▼
 ┌────────────────────────────────────────────────────────┐
 │                   mcp-shield Gate                      │
 │                                                        │
 │  [Static Scanner]      Discovers configs & scores risks│
 │  [Runtime Firewall]    Intercepts live stdio JSON-RPC  │
 │  [Policy & Fixer]      Enforces Zod YAML & audit log   │
 └──────────┬─────────────────────────────────────────────┘
            │
            ▼
 ┌──────────────────────┐
 │ Protected Filesystem │  (.env, ~/.ssh, shell commands)
 └──────────────────────┘
```

1. **Static Scanner (`mcp-shield scan`)**: Recursively discovers configuration files across JSON, JSONC, YAML, and TOML formats. Evaluates rules against OWASP MCP Top 10 risks and computes a deterministic A-to-F security score.
2. **Runtime Firewall (`mcp-shield proxy`)**: Streams JSON-RPC frames over `stdio`. Resolves path encodings and symlinks, validates shell commands, monitors tool schema mutations, and blocks violations with error code `-32001`.
3. **Policy, Fixer & Audit (`mcp-shield init`, `fix`, `audit`, `policy`)**: Validates YAML schemas, safely migrates hardcoded secrets to `.env.mcp`, and maintains a tamper-evident SHA-256 hash-chained log.

---

### Threat Model & Explicit Limitations

#### Covered Threats
- **Path Traversal Attacks:** Detects and blocks traversal strings (`../`, `..\`), multi-layer URL encoding (`%2e%2e%2f`), Unicode escapes (`\u002e\u002e/`), Unicode fullwidth dots (`\uFF0E`), and Windows UNC paths (`\\server\share`).
- **Symlink Escapes:** Resolves canonical filesystem targets using `fs.realpathSync` to block symlinks that point outside authorized workspace roots.
- **Command Injection:** Tokenizes command arguments and blocks destructive operations (`rm -rf`, `curl | sh`, `wget | bash`, `chmod 777`, encoded PowerShell commands).
- **Hardcoded Secret Exposure:** Identifies API keys for OpenAI, Anthropic, GitHub, AWS, Google Cloud, Stripe, Slack, and high-entropy authentication tokens.
- **Mid-Session Rug-Pull Mutations:** Hashes tool definitions on session start and blocks subsequent calls if an MCP server alters its schema mid-session without authorization.
- **Audit Log Tampering:** Links audit events via monotonic sequence numbers and SHA-256 hash chains to detect log edits or record deletions.
- **Buffer Denial-of-Service:** Enforces a strict 1 MB frame size ceiling and discards oversized payloads to prevent process memory exhaustion.

#### Explicit Limitations
- **Tamper Evidence vs. Kernel Sandboxing:** `mcp-shield audit` provides cryptographic proof of log tampering after the fact; it is a tamper-evident audit logger, not a hardware hypervisor or OS kernel sandbox.
- **Channel Scope:** The runtime firewall monitors JSON-RPC messages transferred across standard input and output (`stdio`). Direct outbound network sockets opened independently by external binaries without traversing `stdio` are outside the proxy interception path.
- **Host Compromise:** Root or administrator-level operating system compromise is out of scope.

---

## 4. CLI Command Reference

### `mcp-shield scan [path] [options]`

#### Description & How It Works
`scan` is the static vulnerability analysis engine. It inspects local MCP configuration files without executing any child processes. It parses JSON, JSONC, YAML, and TOML configurations, matches values against deterministic OWASP security rules, masks detected secrets, and assigns a letter grade (A through F).

#### When to Use It
- After cloning a new repository containing `.cursor/mcp.json`, `.agents/mcp_config.json`, or `./mcp.json`.
- Before committing configuration changes to Git.
- In CI/CD pipelines to prevent developers from committing hardcoded credentials.

#### Flags & Options
| Flag | Type | Default | Description |
| :--- | :--- | :--- | :--- |
| `[path]` | Argument | Discovered client paths | Target configuration file or folder to scan. |
| `--json` | Flag | `false` | Outputs scan results as a raw JSON object. |
| `--format <type>`| Option | `terminal` | Output format: `terminal`, `json`, or `sarif`. |
| `--policy <path>`| Option | `policy.yaml` | Path to custom YAML policy file. |
| `--ci` | Flag | `false` | Sets process exit code to `1` if High or Critical risks are detected. |
| `--fail-on <sev>`| Option | `high` | Fail threshold severity: `critical`, `high`, `medium`, or `low`. |
| `--baseline <f>` | Option | `undefined` | Path to baseline file to suppress accepted findings. |
| `--baseline-update`| Flag | `false` | Update baseline file with current findings. |
| `--changed-only` | Flag | `false` | Show only new findings not in baseline. |
| `--output <file>`| Option | stdout | Write scan report to file instead of stdout. |

#### Step-by-Step Examples
```bash
# 1. Default scan across all discovered editors
mcp-shield scan

# 2. Scan a specific workspace folder or file
mcp-shield scan ./my-project/mcp.json

# 3. Output GitHub-compatible SARIF for Code Scanning
mcp-shield scan . --format sarif > mcp-shield.sarif

# 4. Enforce security gates in CI/CD (fails build on high/critical findings)
mcp-shield scan --ci --fail-on high

# 5. Suppress accepted findings using a baseline file
mcp-shield scan --baseline .mcp-shield-baseline.json --changed-only
```

---

### `mcp-shield fix [path] [options]`

#### Description & How It Works
`fix` remediates hardcoded secrets detected by rule `MS-001`. It extracts raw API keys into a local `.env.mcp` file, sets secure file permissions (`0o600` on POSIX systems), creates a timestamped `.bak` backup copy of the target configuration, and updates the original configuration to reference the variable as `${VAR_NAME}`.

#### When to Use It
- Immediately after `mcp-shield scan` flags rule `MS-001`.
- When preparing configuration files for public open-source publication.

#### Flags & Options
| Flag | Type | Default | Description |
| :--- | :--- | :--- | :--- |
| `[path]` | Argument | Discovered paths | Path to the configuration file requiring remediation. |
| `--dry-run` | Flag | `false` | Displays planned extraction changes without modifying any files. |
| `--yes` | Flag | `false` | Automatically apply changes without manual interactive prompt. |
| `--env-file <p>` | Option | `.env.mcp` | Path to target environment file. |
| `--rollback <p>` | Option | `undefined` | Roll back changes from a specified `.bak` backup file. |
| `--json` | Flag | `false` | Output fix report in JSON format. |

#### Step-by-Step Examples
```bash
# 1. Preview changes safely on a standard project configuration
mcp-shield fix ./mcp.json --dry-run

# 2. Execute safe remediation with automatic backup
mcp-shield fix ./mcp.json

# 3. Roll back if needed from backup
mcp-shield fix --rollback ./mcp.json.2026-11-24T18-30-00-000Z.bak
```

---

### `mcp-shield init [options]`

#### Description & How It Works
`init` writes a starter `policy.yaml` configuration into the target path. It supports both standard `default` and hardened `strict` templates. If a policy file already exists, `mcp-shield` stops and prevents accidental overwrites.

#### Flags & Options
| Flag | Type | Default | Description |
| :--- | :--- | :--- | :--- |
| `--policy <path>` | Option | `policy.yaml` | Path to target policy file. |
| `--template <type>`| Option | `default` | Policy template type: `default` or `strict`. |

#### Step-by-Step Examples
```bash
# Initialize standard default policy
mcp-shield init

# Initialize strict hardened policy
mcp-shield init --template strict
```

---

### `mcp-shield proxy [options] -- <cmd> [args...]`

#### Description & How It Works
`proxy` launches the target MCP server as a child process and wraps its standard input and output streams (`stdio`). It intercepts JSON-RPC frames, normalizes paths, checks shell arguments against allowlists, validates schema mutations, and returns JSON-RPC `-32001` error frames on policy violations.

#### Flags & Options
| Flag | Type | Default | Description |
| :--- | :--- | :--- | :--- |
| `--policy <path>` | Option | `policy.yaml` | Path to custom YAML policy file. |
| `--framing <mode>` | Option | `auto` | Framing mode: `line`, `content-length`, or `auto`. |
| `--fail-closed` | Flag | `true` | Fail closed with code -32001 on parse or policy errors. |
| `--passthrough` | Flag | `false` | Log findings but allow child execution (monitor mode). |
| `--rug-pull` | Flag | `true` | Monitor for mid-session tool schema mutations. |
| `--rug-pull-baseline <p>` | Option | `undefined` | Custom path to rug-pull baseline JSON file. |
| `--rug-pull-mode <m>` | Option | `enforce` | Rug-pull enforcement mode: `off`, `monitor`, `approve`, or `enforce`. |
| `<cmd>` | Argument | *(Required)* | Executable command of the target MCP server. |
| `[args...]` | Argument | `[]` | Arguments passed directly to the target MCP server. |

#### Step-by-Step Examples
```bash
# 1. Wrap a local filesystem server with default firewall
mcp-shield proxy -- npx -y @modelcontextprotocol/server-filesystem ./workspace

# 2. Enforce strict Content-Length framing mode
mcp-shield proxy --framing content-length -- node ./server.js

# 3. Windows PowerShell invocation
mcp-shield proxy "--" npx -y @modelcontextprotocol/server-filesystem ./workspace
```

---

### `mcp-shield audit [options]`

#### Description & How It Works
`audit` reads the local cryptographically chained audit log (`~/.mcp-shield/audit.jsonl`). Each scan and proxy action computes a SHA-256 hash over the current record combined with the previous entry's hash (`prevHash`). When invoked with `--verify`, it confirms that zero records were edited, removed, or truncated.

#### Flags & Options
| Flag | Type | Default | Description |
| :--- | :--- | :--- | :--- |
| `--verify` | Flag | `false` | Validates cryptographic SHA-256 hash chain and sequence continuity. |
| `--json` | Flag | `false` | Output audit report or verification status in JSON format. |
| `--hmac-key <key>` | Option | `undefined` | HMAC-SHA-256 secret key to sign or verify entries. |
| `--export <file>` | Option | `undefined` | Export verified audit log to specified file path. |
| `--tail <n>` | Option | `20` | Displays the last `N` audit entries. |

#### Step-by-Step Examples
```bash
# View recent audit events
mcp-shield audit

# Verify SHA-256 hash chain integrity
mcp-shield audit --verify

# Verify using an HMAC key
mcp-shield audit --verify --hmac-key my-signing-secret
```

---

### `mcp-shield policy <validate | schema> [path]`

#### Description & How It Works
`policy validate` verifies that a `policy.yaml` matches the strict Zod schema, checks for conflicting allow/deny rules, and resolves inheritance chains. `policy schema` outputs the complete JSON Schema definition for IDE autocompletion and schema validation.

#### Step-by-Step Examples
```bash
# Validate policy syntax and rules
mcp-shield policy validate ./policy.yaml

# Generate JSON Schema for policy.yaml
mcp-shield policy schema > mcp-shield-policy.schema.json
```

---

### `mcp-shield rules [options]`

#### Description & How It Works
`rules` displays all supported security detection rules (`MS-001` through `MS-007`), including their OWASP Top 10 category mappings, severities, descriptions, and recommended remediations.

```bash
# View rules table in terminal
mcp-shield rules

# View rules in JSON format
mcp-shield rules --json
```

---

### `mcp-shield baseline [path] [options]`

#### Description & How It Works
`baseline` inspects an existing findings baseline file (`.mcp-shield-baseline.json`). It displays active vs. suppressed findings, acceptance reasons, and expiration dates.

```bash
# View baseline summary
mcp-shield baseline

# View baseline in JSON format
mcp-shield baseline .mcp-shield-baseline.json --json
```

---

### `mcp-shield completions <shell>`

#### Description & How It Works
`completions` generates shell autocompletion scripts for subcommands, flags, and options.

```bash
# Bash
mcp-shield completions bash > ~/.local/share/bash-completion/completions/mcp-shield

# Zsh
mcp-shield completions zsh > ~/.zsh/completion/_mcp-shield

# Fish
mcp-shield completions fish > ~/.config/fish/completions/mcp-shield.fish

# PowerShell
mcp-shield completions powershell >> $PROFILE
```

---

## 5. Customizing `policy.yaml`

Run `mcp-shield init` to create a `policy.yaml` file in your repository:

```yaml
version: "1.0"

# Mode:
#   "enforce"    -> Blocks matching requests immediately with error -32001
#   "monitor"    -> Logs findings to audit log and stderr, but allows execution
#   "baseline"   -> Enforces policy only for findings not present in baseline
#   "quarantine" -> Blocks execution and isolates offending server
#   "audit-only" -> Disables active blocks and writes events exclusively to audit log
mode: "enforce"

# Policy inheritance:
# Inherit and extend base team policies with deterministic precedence
inherit: []

# Deny paths:
# Blocks filesystem access matching these glob patterns
denyPaths:
  - "**/.env"
  - "**/.env.*"
  - "~/.ssh/**"
  - "~/.aws/**"
  - "~/.gnupg/**"
  - "/etc/passwd"

# Allow paths:
# Explicit allowed workspace boundaries
allowPaths:
  - "./src/**"
  - "./docs/**"

# Blocked shell commands:
# Destructive command patterns rejected by the runtime firewall
blockedCommands:
  - "rm -rf"
  - "curl * | sh"
  - "wget * | bash"
  - "chmod 777"

# Disabled rules:
# List rule IDs to bypass (e.g. ["MS-004"])
disabledRules: []

# Allowed servers:
# Optional allowlist for MS-007 Shadow MCP Server detection
allowedServers: []

# Minimum severity triggering CI build failure:
# "critical" | "high" | "medium" | "low"
failOnSeverity: "high"

# Secret detection sensitivity:
# "low" | "balanced" | "strict"
secretDetection:
  sensitivity: "balanced"
  exclude: []

# Tool rug-pull protection configuration:
rugPull:
  mode: "enforce" # "off" | "monitor" | "approve" | "enforce"
  persistence: "local" # "local" (.mcp-shield/rugpull-baseline.json) or "memory"
  immutableFields:
    - "description"
    - "inputSchema"
```

---

## 6. OWASP MCP Top 10 Rule Catalog

`mcp-shield` implements deterministic detection rules mapped directly to the OWASP Top 10 for Model Context Protocol:

| Rule ID | OWASP Category | Severity | Description | Remediation |
| :--- | :--- | :--- | :--- | :--- |
| **`MS-001`** | `MCP01:2025` Token Mismanagement | **Critical** | Detects hardcoded API keys (OpenAI, Anthropic, GitHub, AWS, Google Cloud, Slack, Stripe) and high-entropy secrets. Always masks output. | Extract hardcoded secrets into environment variables or a protected `.env.mcp` file. |
| **`MS-002`** | `MCP02:2025` Privilege Escalation | **High** | Flags arguments granting full root, home, or sensitive credential access (`/`, `C:\`, `~`, `~/.ssh`, `~/.aws`, `.env`). | Constrain paths within approved workspace roots and avoid parent directory traversal (`../`). |
| **`MS-003`** | `MCP03:2025` Tool Poisoning | **Critical** | Detects prompt injection phrases (`ignore previous instructions`) and invisible Unicode control characters. | Remove natural-language prompt instructions from executable CLI arguments. |
| **`MS-004`** | `MCP04:2025` Supply Chain Tampering | **Medium** | Flags unpinned `npx -y`, `uvx`, or container image tags (`:latest` or untagged) without explicit semver. | Pin package versions (e.g. `package@1.0.0`) or container image tags/digests. |
| **`MS-005`** | `MCP05:2025` Command Injection | **Critical** | Blocks destructive shell patterns (`rm -rf`, `curl \| sh`, `chmod 777`, encoded PowerShell commands). | Replace raw destructive shell command strings with isolated, dedicated MCP binaries. |
| **`MS-006`** | `MCP07:2025` Insecure Transport | **High** | Flags remote MCP endpoints communicating over unencrypted plaintext `http://` transport. | Enforce HTTPS encryption for all remote MCP endpoints. |
| **`MS-007`** | `MCP09:2025` Shadow MCP Servers | **Medium** | Flags servers missing from `policy.yaml` `allowedServers`. | Register the server in `policy.yaml` `allowedServers` or disable the unapproved server. |

---

## 7. Exit Codes Reference

`mcp-shield` standardizes process exit codes across all subcommands for reliable scripting and CI/CD automation:

| Exit Code | Constant | Meaning | Typical Cause |
| :---: | :--- | :--- | :--- |
| **`0`** | `SUCCESS` | Success | Scan clean, fix applied, audit verified, command completed without error. |
| **`1`** | `BLOCKING_FINDINGS` | Blocking Risks Detected | Static scan found security risks exceeding `--fail-on` or `--ci` threshold. |
| **`2`** | `USAGE_ERROR` | CLI Usage Error | Missing required arguments, invalid flag value, unsupported shell. |
| **`3`** | `CONFIG_ERROR` | Policy or Config Error | `policy.yaml` schema validation failed, conflicting allow/deny rules, circular inheritance. |
| **`4`** | `AUDIT_VERIFICATION_FAILURE` | Audit Verification Failed | Tampered SHA-256 hash chain, broken sequence number, or missing audit log. |
| **`5`** | `PROXY_PROCESS_FAILURE` | Proxy Process Failure | Child MCP process could not be spawned or terminated abnormally. |
| **`6`** | `INTERNAL_ERROR` | Internal Error | Unexpected filesystem error or unhandled internal exception. |

---

## 8. Programmatic TypeScript Library API

`mcp-shield` exports a 100% side-effect-free TypeScript programmatic API. Library calls never print directly to stdout or call `process.exit()`.

```typescript
import {
  discoverConfigs,
  runScanEngine,
  loadPolicy,
  evaluateRequest,
  verifyAuditLog,
  calculateSecurityScore
} from "@bharathraj_07/mcp-shield";

// 1. Discover local MCP client configurations
const { servers, scannedFiles } = discoverConfigs("./mcp.json");

// 2. Load policy configuration
const policy = loadPolicy("./policy.yaml");

// 3. Run static scan analysis
const scanResult = runScanEngine(servers, scannedFiles, policy);
console.log(`Grade: ${scanResult.grade}, Score: ${scanResult.score}/100`);

// 4. Evaluate a live JSON-RPC request programmatically
const decision = evaluateRequest(
  {
    jsonrpc: "2.0",
    id: 1,
    method: "tools/call",
    params: {
      name: "read_file",
      arguments: { path: "../../.env" }
    }
  },
  policy
);

if (decision.action === "BLOCK") {
  console.error(`Blocked by rule ${decision.ruleId}: ${decision.reason}`);
}

// 5. Verify local audit log cryptographic chain
const auditStatus = verifyAuditLog();
console.log(`Audit log intact: ${auditStatus.valid}`);
```

---

## 9. GitHub Actions SARIF Integration

Integrate `mcp-shield` directly into your GitHub repository to display security findings in the **Security > Code scanning alerts** tab.

Create `.github/workflows/security.yml`:

```yaml
name: Security Scan

on:
  push:
    branches: [main]
  pull_request:

permissions:
  contents: read
  security-events: write
  actions: read

jobs:
  mcp-shield:
    runs-on: ubuntu-latest
    steps:
      - name: Check out repository
        uses: actions/checkout@v4

      - name: Set up Node.js
        uses: actions/setup-node@v4
        with:
          node-version: 20

      - name: Run mcp-shield Security Scan
        run: npx @bharathraj_07/mcp-shield scan . --format sarif > mcp-shield.sarif

      - name: Upload SARIF report to GitHub Code Scanning
        uses: github/codeql-action/upload-sarif@v4
        continue-on-error: true
        with:
          sarif_file: mcp-shield.sarif
```

---

## 10. Benchmarks & Detection Coverage

`mcp-shield` passes an automated verification corpus with **104 security test cases**:
- **Malicious Attack Coverage:** 100% detection rate across 63 attack vectors (path traversal, symlink escapes, UNC paths, command injection, secret leakage, rug-pull mutations).
- **False-Positive Target:** 0% false positives across 41 benign workspace operations.
- **Latency Overhead:** < 5.0 ms p99 per JSON-RPC message (benchmarked under 0.1 ms average).

### Reproduce Benchmarks Locally
```bash
git clone https://github.com/bharathraj0007/mcp-shield.git
cd mcp-shield/cli
npm install
npm run bench
```

Sample Benchmark Output:
```text
==================================================
MCP-SHIELD PROXY LATENCY BENCHMARK RESULTS (500 runs)
==================================================
  Average: 0.0169 ms
  p50:     0.0149 ms
  p90:     0.0362 ms
  p95:     0.0420 ms
  p99:     0.0596 ms (Target: < 5.0 ms)
==================================================
```

---

## 11. License

Apache-2.0
