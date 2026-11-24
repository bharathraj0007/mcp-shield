# Security Policy

`mcp-shield` protects developer machines running Model Context Protocol (MCP) clients and AI coding agents. We take the security of this software and developer environments seriously.

---

## 1. Supported Versions

We provide security updates for the following versions:

| Version | Supported |
| :--- | :--- |
| `0.1.x` | :white_check_mark: Yes |
| `< 0.1.0` | :x: No |

---

## 2. Threat Model & Covered Scope

`mcp-shield` provides local defense-in-depth across the developer workstation.

### Defenses in Scope
- **Path Traversal Defenses:** Blocks URL-encoded (`%2e%2e`), Unicode, and Windows UNC path attacks targeting sensitive files (`.env`, `~/.ssh`, `~/.aws`, `credentials.json`, `/etc/passwd`).
- **Symlink Escapes:** Resolves canonical paths (`fs.realpathSync`) to block symlinks that escape allowed folders.
- **Command Injection:** Intercepts and blocks destructive shell commands (`rm -rf`, `curl | sh`, `chmod 777`, encoded PowerShell).
- **Hardcoded Secret Exposure:** Detects and masks API keys (OpenAI, Anthropic, GitHub, AWS, Google Cloud, Slack, Stripe).
- **Rug-Pull Tool Mutations:** Detects and blocks mid-session tool schema mutations (`tools/list` hashing).
- **Audit Tamper Evidence:** Writes SHA-256 hash-chained JSONL logs and detects modified or truncated records.
- **100% Offline Guarantee:** Executes zero outbound network calls, collects zero telemetry, and imports zero network libraries.

### Threats Out of Scope
- Compromised operating system kernel or host supervisor.
- Pre-existing malware running with administrative or root privileges.
- Network attacks outside the standard MCP `stdio` communication channel.
- Physical theft or physical hardware compromise of the workstation.

---

## 3. Reporting a Vulnerability

**Do not report security vulnerabilities through public GitHub issues.**

To report a vulnerability:
1. Open a private security advisory through GitHub:
   [Submit GitHub Security Advisory](https://github.com/bharathraj0007/mcp-shield/security/advisories/new)
2. Include the following details in your report:
   - Component affected (`scanner`, `proxy`, `policy`, `audit`, or `fixer`).
   - Operating system and Node.js version.
   - Minimal reproduction script or configuration file.
   - Description of the bypass or impact.

---

## 4. Response Timeline & SLAs

- **Initial Response:** Within 48 hours of receipt.
- **Triage & Reproduction:** Within 5 business days.
- **Patch Release:** Target within 14 business days of confirmation.
- **Coordinated Disclosure:** We publish security advisories on GitHub after releasing the patch.
