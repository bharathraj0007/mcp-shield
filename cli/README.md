# mcp-shield

[![CI](https://github.com/bharathraj0007/mcp-shield/actions/workflows/ci.yml/badge.svg)](https://github.com/bharathraj0007/mcp-shield/actions/workflows/ci.yml)
[![npm version](https://img.shields.io/npm/v/@bharathraj0007/mcp-shield.svg)](https://www.npmjs.com/package/@bharathraj0007/mcp-shield)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)
[![Node.js](https://img.shields.io/badge/node-%3E%3D20.0.0-green.svg)](https://nodejs.org)
[![Telemetry](https://img.shields.io/badge/telemetry-zero%20(100%25%20offline)-success.svg)](SECURITY.md)

> 100% Offline Local Security Scanner, Runtime Firewall, and Policy Engine for AI Coding Agents.

`mcp-shield` reduces risk for developer machines running AI coding agents. It detects hardcoded secrets, blocks path traversal attacks, and enforces security policies across local Model Context Protocol (MCP) servers.

The tool operates **100% offline**. It sends no data over the network and collects zero telemetry.

---

## 1. Installation & Quick Start

### Prerequisites
- **Node.js** `v20.0.0` or higher

### Install

```bash
# Option A: Install globally from npm
npm install -g @bharathraj0007/mcp-shield

# Option B: Run directly via npx
npx @bharathraj0007/mcp-shield scan

# Option C: Build from source (100% offline)
git clone https://github.com/bharathraj0007/mcp-shield.git
cd mcp-shield/cli
npm install
npm run build
npm link
```

### Step 1: Scan, Fix & Initialize Policy

```bash
# Scan local MCP configurations for security risks
mcp-shield scan

# Automatically extract hardcoded secrets into .env.mcp
mcp-shield fix ~/.cursor/mcp.json

# Create starter policy.yaml in project folder
mcp-shield init
```

### Step 2: Protect Live MCP Servers in Your IDE

Add `mcp-shield` as a proxy wrapper inside your client configuration (`mcp.json`, `claude_desktop_config.json`, or `.agents/mcp_config.json`):

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

## 2. System Architecture

`mcp-shield` unites three protection layers in one lightweight CLI:

```text
 ┌──────────────────────┐
 │   AI Coding Agent    │  (Cursor, Claude Desktop, Antigravity, VS Code)
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

1. **Static Scanner (`mcp-shield scan`)**: Discovers MCP client configurations across macOS, Windows, and Linux. Computes an A-to-F security score against OWASP MCP Top 10 risks.
2. **Runtime Firewall (`mcp-shield proxy`)**: Intercepts real-time `stdio` JSON-RPC 2.0 frames between the IDE and MCP servers. Blocks path traversal (`../../.env`) and destructive shell commands (`rm -rf`) with error code `-32001`.
3. **Policy, Safe Fixer & Audit (`mcp-shield init`, `fix`, `audit`)**: Enforces portable `policy.yaml` rules, safely moves hardcoded secrets into `.env.mcp` (permissions `0600`), and writes tamper-evident SHA-256 hash-chained logs.

---

## 3. Threat Model Summary

`mcp-shield` provides deterministic protection boundaries across the local machine:

### Covered Threat Vectors
- **Path Traversal & Symlink Escapes:** Normalizes URL-encoded sequences (`%2e%2e`), Unicode escapes, and Windows UNC paths (`\\server\share`). Resolves canonical symlinks (`fs.realpathSync`) to prevent workspace escapes.
- **Destructive Command Execution:** Tokenizes and blocks shell injection patterns (`rm -rf`, `curl | sh`, `chmod 777`, encoded PowerShell).
- **Hardcoded Secret Leakage:** Detects API keys across 9 MCP client configurations and automatically extracts them into isolated `.env.mcp` files.
- **Mid-Session Rug-Pull Mutations:** Computes SHA-256 hashes of `tools/list` schemas upon connection and blocks subsequent calls if tool definitions mutate mid-session.
- **Audit Log Tampering:** Links all security events via SHA-256 hash chains with monotonic sequence numbers, detecting modification and truncation.

### Out of Scope
- Compromised host operating system kernel or administrator/root malware.
- Attacks occurring across external network sockets outside the MCP `stdio` channel.

For detailed security architecture, see [THREAT_MODEL.md](../THREAT_MODEL.md) and [SECURITY.md](../SECURITY.md).

---

## 4. CLI Command Reference

### `mcp-shield scan [path] [options]`
Scans discovered or specified configuration files for security vulnerabilities.

```bash
# Scan default client configurations
mcp-shield scan

# Output machine-readable JSON
mcp-shield scan --json

# Output GitHub-compatible SARIF 2.1.0
mcp-shield scan --format sarif

# Enforce in CI pipelines (exits code 1 on High or Critical risk)
mcp-shield scan --ci
```

### `mcp-shield proxy [options] -- <command> [args...]`
Wraps an MCP server command in a real-time JSON-RPC firewall.

```bash
mcp-shield proxy -- node ./dist/server.js
mcp-shield proxy --policy custom-policy.yaml -- npx -y @modelcontextprotocol/server-filesystem ./src
```

### `mcp-shield init`
Creates a starter `policy.yaml` configuration in the current folder.

```bash
mcp-shield init
```

### `mcp-shield fix <path> [options]`
Safely extracts hardcoded API keys into `.env.mcp` and updates the configuration.

```bash
# Preview planned changes without editing files
mcp-shield fix ~/.cursor/mcp.json --dry-run

# Create .bak backup and extract secrets
mcp-shield fix ~/.cursor/mcp.json
```

### `mcp-shield audit [options]`
Inspects the local audit log and verifies cryptographic integrity.

```bash
# View last 20 audit events
mcp-shield audit --tail 20

# Verify SHA-256 hash chain for tamper evidence
mcp-shield audit --verify
```

---

## 5. OWASP MCP Top 10 Rule Coverage

| Rule ID | OWASP Category | Severity | Detection Summary |
| :--- | :--- | :--- | :--- |
| **`MS-001`** | `MCP01:2025` Token Mismanagement | **Critical** | Detects hardcoded API keys (OpenAI, Anthropic, GitHub, AWS, Google) and high-entropy strings. Always masks output. |
| **`MS-002`** | `MCP02:2025` Privilege Escalation | **High** | Flags arguments granting access to `/`, `C:\`, `~`, `~/.ssh`, `~/.aws`, or `.env`. |
| **`MS-003`** | `MCP03:2025` Tool Poisoning | **Critical** | Detects prompt injection phrases (`ignore previous instructions`) and invisible Unicode control characters. |
| **`MS-004`** | `MCP04:2025` Supply Chain Tampering | **Medium** | Flags unpinned `npx -y` and `uvx` package executions missing an exact semver version. |
| **`MS-005`** | `MCP05:2025` Command Injection | **Critical** | Blocks destructive shell commands (`rm -rf`, `curl \| sh`, `chmod 777`, encoded PowerShell). |
| **`MS-006`** | `MCP07:2025` Insecure Transport | **High** | Flags remote MCP endpoints using unencrypted plaintext `http://` transport. |
| **`MS-007`** | `MCP09:2025` Shadow MCP Servers | **Medium** | Flags servers not listed in `policy.yaml` `allowedServers`. |

---

## 6. GitHub Actions SARIF Integration

Add this step to your GitHub Actions workflow to publish findings to GitHub Code Scanning:

```yaml
name: Security Scan

on:
  push:
    branches: [main]
  pull_request:

jobs:
  mcp-shield:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - uses: actions/setup-node@v4
        with:
          node-version: 20

      - name: Run mcp-shield Scan
        run: npx @bharathraj0007/mcp-shield scan . --format sarif > mcp-shield.sarif

      - name: Upload SARIF report
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: mcp-shield.sarif
```

---

## 7. Benchmarks & Detection Coverage

`mcp-shield` passes an automated test suite with a 104-case security corpus:
- **Detection Rate:** 100% on malicious fixtures (path traversal, symlink escapes, UNC paths, command injection, secret leakage, rug-pull tool mutations).
- **False-Positive Rate:** 0% on standard workspace reads and benign configurations.
- **Latency Overhead:** < 5 ms p99 per JSON-RPC frame (measured across 500 messages).

To reproduce benchmarks locally:
```bash
cd cli
npm run bench
```

The tool performs all inspections locally and operates 100% offline.

---

## 8. Open Source Governance

- **Threat Model:** [THREAT_MODEL.md](../THREAT_MODEL.md)
- **Security Policy:** [SECURITY.md](../SECURITY.md)
- **Contribution Guide:** [CONTRIBUTING.md](../CONTRIBUTING.md)
- **Changelog:** [CHANGELOG.md](../CHANGELOG.md)
- **Terminal Demo Script:** [demo.tape](../demo.tape)

---

## 9. License

Apache-2.0
