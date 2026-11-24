# mcp-shield

[![CI](https://github.com/bharathraj0007/mcp-shield/actions/workflows/ci.yml/badge.svg)](https://github.com/bharathraj0007/mcp-shield/actions/workflows/ci.yml)
[![npm version](https://img.shields.io/npm/v/@bharathraj_07/mcp-shield.svg)](https://www.npmjs.com/package/@bharathraj_07/mcp-shield)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)
[![Node.js](https://img.shields.io/badge/node-%3E%3D20.0.0-green.svg)](https://nodejs.org)
[![Telemetry](https://img.shields.io/badge/telemetry-zero%20(100%25%20offline)-success.svg)](#3-system-architecture--threat-model)

> 100% Offline Local Security Scanner, Runtime Firewall, and Policy Engine for Model Context Protocol (MCP) and AI Coding Agents.

`mcp-shield` protects developer workstations from unauthorized AI agent actions. It scans local MCP configurations for hardcoded secrets, blocks path traversal attacks in real time, and enforces security policies across local Model Context Protocol servers.

The tool operates **100% offline**. It sends no telemetry, makes zero network requests, and requires zero cloud accounts.

---

## Table of Contents
1. [Beginner's 5-Minute Walkthrough](#1-beginners-5-minute-walkthrough)
2. [Runtime Firewall Guide (`mcp-shield proxy`)](#2-runtime-firewall-guide-mcp-shield-proxy)
3. [System Architecture & Threat Model](#3-system-architecture--threat-model)
4. [CLI Command Reference](#4-cli-command-reference)
   - [`mcp-shield scan`](#mcp-shield-scan-path-options)
   - [`mcp-shield fix`](#mcp-shield-fix-path-options)
   - [`mcp-shield init`](#mcp-shield-init)
   - [`mcp-shield proxy`](#mcp-shield-proxy-options----cmd-args)
   - [`mcp-shield audit`](#mcp-shield-audit-options)
5. [Customizing `policy.yaml`](#5-customizing-policyyaml)
6. [OWASP MCP Top 10 Rule Coverage](#6-owasp-mcp-top-10-rule-coverage)
7. [GitHub Actions SARIF Integration](#7-github-actions-sarif-integration)
8. [Benchmarks & Detection Coverage](#8-benchmarks--detection-coverage)
9. [License](#9-license)

---

## 1. Beginner's 5-Minute Walkthrough

### What is an MCP Server and Why Is It Risky?
Modern AI coding tools (Cursor, Claude Desktop, VS Code, Windsurf, Antigravity) use the **Model Context Protocol (MCP)**. MCP servers give AI agents tools to read your disk, execute terminal commands, and query databases.

Leaving MCP servers unprotected creates serious security risks:
- **Credential Theft:** Developers frequently paste raw API keys (`sk-ant-...`, `ghp_...`) into JSON config files.
- **Path Traversal Attacks:** A prompt-injected AI model can instruct an MCP filesystem server to read `../../.env` or `~/.ssh/id_rsa`.
- **Destructive Commands:** An agent can run destructive shell commands such as `rm -rf /` or pipe untrusted scripts to `sh`.

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
mcp-shield --help
```

---

### Step 2: Scan Your Machine for Vulnerabilities

Run `mcp-shield scan` without arguments. It automatically discovers client configurations across Cursor, Claude Desktop, VS Code, Windsurf, Antigravity, and Gemini CLI:

```bash
mcp-shield scan
```

If your configuration contains hardcoded API keys or grants full root access, `mcp-shield` highlights the findings:

```text
=== mcp-shield Security Scan Report ===
Files Scanned: 1 | MCP Servers Found: 1

Detected Security Risks:
────────────────────────────────────────────────────────────

[1]  CRITICAL  MS-001 (MCP01:2025)
    Title:      Hardcoded Anthropic API Key Detected
    Server:     filesystem
    File:       ~/.cursor/mcp.json
    Evidence:   sk-ant-***...9999
    Remedy:     Move secret to environment variable or .env file and reference with ${VAR_NAME}.

[2]  HIGH  MS-002 (MCP02:2025)
    Title:      Unsafe Path Scope Exposure
    Server:     filesystem
    File:       ~/.cursor/mcp.json
    Evidence:   /
    Remedy:     Restrict filesystem server scope to a designated project subfolder (e.g. "./docs" or "./workspace").

────────────────────────────────────────────────────────────
 GRADE F  Security Score: 30/100 (2 findings)

Tip: Run 'mcp-shield fix <path>' to safely extract hardcoded secrets into .env.mcp.
```

---

### Step 3: Automatically Fix Exposed Secrets

Do not edit secrets by hand. Use `mcp-shield fix` to extract sensitive API keys into an isolated `.env.mcp` file:

```bash
# Preview changes safely without touching files
mcp-shield fix ~/.cursor/mcp.json --dry-run

# Apply changes with automatic backup
mcp-shield fix ~/.cursor/mcp.json
```

What happens under the hood:
1. `mcp-shield` creates a timestamped `.bak` backup copy of your configuration file.
2. It extracts raw API keys into `.env.mcp` with strict file permissions (`0o600`).
3. It updates the original configuration to reference `${ANTHROPIC_API_KEY}` safely.

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
`mcp-shield proxy` sits between your AI coding editor and the target MCP server. It intercepts newline-delimited JSON-RPC 2.0 messages over standard input and output (`stdio`).

```text
IDE / AI Agent  ──(stdio JSON-RPC)──>  [mcp-shield proxy]  ──(validated)──>  Real MCP Server
                                             │
                                     Blocked if malicious
                                             ▼
                                  Returns JSON-RPC -32001
```

- When an agent requests a safe project file, the proxy forwards the message immediately (< 1 ms latency).
- When an agent requests `.env`, `~/.ssh/id_rsa`, or runs `rm -rf`, the proxy drops the request, logs the violation to `stderr`, and returns a standard JSON-RPC error frame (`code: -32001`) to the agent.

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
 │  [Policy & Fixer]      Extracts secrets & writes audit │
 └──────────┬─────────────────────────────────────────────┘
            │
            ▼
 ┌──────────────────────┐
 │ Protected Filesystem │  (.env, ~/.ssh, shell commands)
 └──────────────────────┘
```

1. **Static Scanner (`mcp-shield scan`)**: Recursively discovers configuration files across 9 MCP clients. Evaluates rules against OWASP MCP Top 10 risks and computes a deterministic A-to-F security score.
2. **Runtime Firewall (`mcp-shield proxy`)**: Streams JSON-RPC frames over `stdio`. Resolves path encodings and symlinks, validates shell commands, and blocks mid-session tool mutations with error code `-32001`.
3. **Policy, Fixer & Audit (`mcp-shield init`, `fix`, `audit`)**: Provides custom `policy.yaml` rules, safely migrates hardcoded secrets to `.env.mcp`, and maintains a tamper-evident SHA-256 hash-chained log.

---

### Threat Model Summary

#### Covered Threats
- **Path Traversal Attacks:** Detects and blocks traversal strings (`../`, `..\`), multi-layer URL encoding (`%2e%2e%2f`), Unicode escapes (`\u002e\u002e/`), Unicode fullwidth dots (`\uFF0E`), and Windows UNC paths (`\\server\share`).
- **Symlink Escapes:** Resolves canonical filesystem targets using `fs.realpathSync` to block symlinks that point outside authorized workspace roots.
- **Command Injection:** Tokenizes command arguments and blocks destructive operations (`rm -rf`, `curl | sh`, `wget | bash`, `chmod 777`, encoded PowerShell commands).
- **Hardcoded Secret Exposure:** Identifies API keys for OpenAI, Anthropic, GitHub, AWS, Google Cloud, Stripe, Slack, and high-entropy authentication tokens.
- **Mid-Session Rug-Pull Mutations:** Hashes tool definitions on session start and blocks subsequent calls if an MCP server alters its schema mid-session.
- **Audit Log Tampering:** Links audit events via monotonic sequence numbers and SHA-256 hash chains to detect log edits or record deletions.
- **Buffer Denial-of-Service:** Enforces a strict 1 MB frame size limit and discards oversized payloads to prevent process memory exhaustion.

#### Out of Scope
- Compromised host operating system kernel or administrator-level malware.
- Attacks occurring across external network sockets outside the MCP `stdio` stream.
- Physical access compromise of the developer workstation.

---

## 4. CLI Command Reference

### `mcp-shield scan [path] [options]`

#### Description & How It Works
`scan` is the static vulnerability analysis engine. It inspects local MCP configuration files without executing any child processes. It parses JSON and JSONC configurations, matches values against deterministic OWASP security rules, masks detected secrets, and assigns a letter grade (A through F).

#### When to Use It
- After cloning a new repository containing `.cursor/mcp.json` or `.agents/mcp_config.json`.
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

#### Step-by-Step Examples
```bash
# 1. Default scan across all discovered editors
mcp-shield scan

# 2. Scan a specific workspace folder
mcp-shield scan ./my-project

# 3. Output GitHub-compatible SARIF for Code Scanning
mcp-shield scan . --format sarif > mcp-shield.sarif

# 4. Enforce security gates in CI/CD (fails build on high/critical findings)
mcp-shield scan --ci
```

#### Realistic Sample Output
```text
=== mcp-shield Security Scan Report ===
Files Scanned: 2 | MCP Servers Found: 3

Detected Security Risks:
────────────────────────────────────────────────────────────

[1]  CRITICAL  MS-001 (MCP01:2025)
    Title:      Hardcoded OpenAI API Key Detected
    Server:     agent-helper
    File:       .cursor/mcp.json
    Evidence:   sk-proj-***...7a2f
    Remedy:     Move secret to environment variable or .env file and reference with ${VAR_NAME}.

[2]  MEDIUM  MS-004 (MCP04:2025)
    Title:      Unpinned Package Execution
    Server:     filesystem
    File:       ~/.cursor/mcp.json
    Evidence:   npx -y @modelcontextprotocol/server-filesystem
    Remedy:     Pin package to an exact version (e.g. package@1.2.3).

────────────────────────────────────────────────────────────
 GRADE D  Security Score: 60/100 (2 findings)

Tip: Run 'mcp-shield fix <path>' to safely extract hardcoded secrets into .env.mcp.
```

---

### `mcp-shield fix <path> [options]`

#### Description & How It Works
`fix` remediates hardcoded secrets detected by rule `MS-001`. It extracts raw API keys into a local `.env.mcp` file, sets secure file permissions (`0o600` on POSIX systems), creates a timestamped `.bak` backup copy of the target configuration, and updates the original configuration to reference the variable as `${VAR_NAME}`.

#### When to Use It
- Immediately after `mcp-shield scan` flags rule `MS-001`.
- When preparing configuration files for public open-source publication.

#### Flags & Options
| Flag | Type | Default | Description |
| :--- | :--- | :--- | :--- |
| `<path>` | Argument | *(Required)* | Exact path to the configuration file requiring remediation. |
| `--dry-run` | Flag | `false` | Displays planned extraction changes without modifying any files. |

#### Step-by-Step Examples
```bash
# 1. Preview changes safely
mcp-shield fix ~/.cursor/mcp.json --dry-run

# 2. Execute safe remediation
mcp-shield fix ~/.cursor/mcp.json
```

#### Realistic Sample Output
```text
=== mcp-shield Safe Fix Plan (Dry Run) ===
Target: ~/.cursor/mcp.json

  • Server "anthropicServer": Extract ANTHROPIC_API_KEY=sk-ant-***...9999 -> ${ANTHROPIC_API_KEY}

Dry run active. No files were modified on disk.

# Running without --dry-run:
✓ mcp-shield Safe Fix Completed Successfully
  Target:  ~/.cursor/mcp.json
  Backup:  ~/.cursor/mcp.json.2026-11-24T18-30-00-000Z.bak
  Secrets: ~/.cursor/.env.mcp (mode: 0o600)
```

---

### `mcp-shield init`

#### Description & How It Works
`init` writes a starter `policy.yaml` configuration into the current working directory. If a `policy.yaml` already exists, `mcp-shield` stops and prevents overwriting existing settings.

#### When to Use It
- When onboarding a new project repository.
- When configuring custom path allowlists or command restrictions.

#### Flags & Options
*None.*

#### Step-by-Step Examples
```bash
# Create starter policy in project folder
mcp-shield init
```

#### Realistic Sample Output
```text
✓ Initialized starter policy at: /Users/developer/project/policy.yaml
```

---

### `mcp-shield proxy [options] -- <cmd> [args...]`

#### Description & How It Works
`proxy` launches the target MCP server as a child process and wraps its standard input and output streams (`stdio`). It intercepts JSON-RPC frames, resolves path normalization, verifies shell commands, enforces a 1 MB payload ceiling, and fails closed (`code: -32001`) if violations occur.

#### When to Use It
- Inside IDE configuration files (`mcp.json`, `claude_desktop_config.json`) for continuous runtime protection.
- In automated test harnesses to verify server isolation.

#### Flags & Options
| Flag | Type | Default | Description |
| :--- | :--- | :--- | :--- |
| `--policy <path>` | Option | `policy.yaml` | Path to custom YAML policy file. |
| `<cmd>` | Argument | *(Required)* | Executable command of the target MCP server. |
| `[args...]` | Argument | `[]` | Arguments passed directly to the target MCP server. |

#### Step-by-Step Examples
```bash
# 1. Wrap a local Node.js MCP server
mcp-shield proxy -- node ./dist/server.js

# 2. Wrap an npx-managed server with a custom policy
mcp-shield proxy --policy custom-policy.yaml -- npx -y @modelcontextprotocol/server-filesystem ./workspace

# 3. Windows PowerShell syntax (note quoted "--")
mcp-shield proxy "--" npx -y @modelcontextprotocol/server-filesystem ./workspace
```

#### Realistic Sample Output
```text
# Stderr when an attack is blocked:
 MCP-SHIELD BLOCK  MS-005: Blocked by mcp-shield (MS-005): Dangerous shell pattern detected (Recursive directory deletion (rm -rf))

# Stdout returned to AI agent:
{"jsonrpc":"2.0","id":42,"error":{"code":-32001,"message":"Blocked by mcp-shield (MS-005): Dangerous shell pattern detected (Recursive directory deletion (rm -rf))","data":{"ruleId":"MS-005","owaspId":"MCP05:2025","action":"BLOCK","redactedTarget":"rm -rf /"}}}
```

---

### `mcp-shield audit [options]`

#### Description & How It Works
`audit` reads the local cryptographically chained audit log (`~/.mcp-shield/audit.jsonl`). Each scan and proxy action computes a SHA-256 hash over the current record combined with the previous entry's hash (`prevHash`). When invoked with `--verify`, it confirms that zero records were edited, removed, or truncated.

#### When to Use It
- During security reviews and compliance verification.
- To detect if an agent attempted unauthorized operations during a coding session.
- To prove tamper resistance in regulated environments.

#### Flags & Options
| Flag | Type | Default | Description |
| :--- | :--- | :--- | :--- |
| `--verify` | Flag | `false` | Validates cryptographic SHA-256 hash chain and sequence continuity. |
| `--tail <n>` | Option | `20` | Displays the last `N` audit entries. |

#### Step-by-Step Examples
```bash
# 1. View recent audit events
mcp-shield audit

# 2. View last 5 events
mcp-shield audit --tail 5

# 3. Cryptographically verify log integrity
mcp-shield audit --verify
```

#### Realistic Sample Output
```text
=== mcp-shield Audit Log Inspection ===
Log File: ~/.mcp-shield/audit.jsonl
✓ Cryptographic SHA-256 Hash Chain Verified (24 entries intact with sequence tracking)

Recent Audit Events (Last 3 Entries):
────────────────────────────────────────────────────────────
#22 2026-11-24T18:40:12.100Z  SCAN   SCAN_COMPLETE 
  Hash: 3f8a9b1c2d3e4f5a... <- Prev: 1a2b3c4d5e6f7a8b...
#23 2026-11-24T18:41:05.320Z  ALLOW  PROXY 
  Hash: 7a8b9c0d1e2f3a4b... <- Prev: 3f8a9b1c2d3e4f5a...
#24 2026-11-24T18:41:22.450Z  BLOCK  PROXY MS-001
  Hash: 9e8d7c6b5a4f3e2d... <- Prev: 7a8b9c0d1e2f3a4b...
```

---

## 5. Customizing `policy.yaml`

Run `mcp-shield init` to create a `policy.yaml` file in your repository. This file allows team leads and security engineers to define explicit restrictions.

```yaml
version: "1.0"

# Mode:
#   "enforce" -> Blocks matching requests immediately with code -32001
#   "monitor" -> Logs findings to audit log and stderr, but allows execution
mode: "enforce"

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
# Commands rejected by the runtime firewall
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
allowedServers:
  - "filesystem"
  - "github"

# Minimum severity triggering CI build failure:
# "critical" | "high" | "medium" | "low"
failOnSeverity: "high"
```

---

## 6. OWASP MCP Top 10 Rule Coverage

`mcp-shield` implements deterministic detection rules mapped directly to the OWASP Top 10 for Model Context Protocol:

| Rule ID | OWASP Category | Severity | Description |
| :--- | :--- | :--- | :--- |
| **`MS-001`** | `MCP01:2025` Token Mismanagement | **Critical** | Detects hardcoded API keys (OpenAI, Anthropic, GitHub, AWS, Google Cloud, Slack, Stripe) and high-entropy secrets. Always masks output. |
| **`MS-002`** | `MCP02:2025` Privilege Escalation | **High** | Flags arguments granting full root, home, or sensitive credential access (`/`, `C:\`, `~`, `~/.ssh`, `~/.aws`, `.env`). |
| **`MS-003`** | `MCP03:2025` Tool Poisoning | **Critical** | Detects prompt injection phrases (`ignore previous instructions`) and invisible Unicode control characters. |
| **`MS-004`** | `MCP04:2025` Supply Chain Tampering | **Medium** | Flags unpinned `npx -y` and `uvx` executions that omit an exact semver version. |
| **`MS-005`** | `MCP05:2025` Command Injection | **Critical** | Blocks destructive shell patterns (`rm -rf`, `curl \| sh`, `chmod 777`, encoded PowerShell commands). |
| **`MS-006`** | `MCP07:2025` Insecure Transport | **High** | Flags remote MCP endpoints communicating over unencrypted plaintext `http://` transport. |
| **`MS-007`** | `MCP09:2025` Shadow MCP Servers | **Medium** | Flags servers missing from `policy.yaml` `allowedServers`. |

---

## 7. GitHub Actions SARIF Integration

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
      - uses: actions/checkout@v4

      - uses: actions/setup-node@v4
        with:
          node-version: 20

      - name: Run mcp-shield Scan
        run: npx @bharathraj_07/mcp-shield scan . --format sarif > mcp-shield.sarif

      - name: Upload SARIF report
        uses: github/codeql-action/upload-sarif@v4
        continue-on-error: true
        with:
          sarif_file: mcp-shield.sarif
```

---

## 8. Benchmarks & Detection Coverage

`mcp-shield` passes an automated verification corpus with **104 security test cases**:
- **Malicious Attack Coverage:** 100% detection rate across 63 attack vectors (path traversal, symlink escapes, UNC paths, command injection, secret leakage, rug-pull mutations).
- **False-Positive Target:** 0% false positives across 41 benign workspace operations.
- **Latency Overhead:** < 5 ms p99 per JSON-RPC message (benchmarked under 0.1 ms average).

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
  Average: 0.0224 ms
  p50:     0.0162 ms
  p90:     0.0644 ms
  p95:     0.0755 ms
  p99:     0.0959 ms (Target: < 5.0 ms)
==================================================
```

---

## 9. License

Apache-2.0
