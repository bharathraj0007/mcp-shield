# Security Policy — mcp-shield

`mcp-shield` protects developer workstations running Model Context Protocol (MCP) clients and AI coding agents. We treat security as our primary engineering requirement.

---

## 1. Supported Versions

Security patches and updates are provided for the following release branches:

| Version | Supported | Description |
| :--- | :--- | :--- |
| `1.0.x` | :white_check_mark: Yes | Active Production Release |
| `< 1.0.0` | :x: No | Deprecated Pre-Release Milestones |

---

## 2. 100% Offline & Zero-Telemetry Guarantee

`mcp-shield` guarantees complete local execution:
- **Zero Outbound Calls:** `mcp-shield` makes zero network connections. It does not import or use `fetch`, `http`, `https`, `net`, `dgram`, `tls`, or `WebSocket`.
- **Zero Telemetry:** `mcp-shield` collects zero analytics, tracking beacons, error reports, or telemetry data.
- **Verification:** Our offline guard test suite (`cli/tests/offlineGuard.test.ts`) inspects the compiled Abstract Syntax Tree (AST) on every commit to enforce this invariant.

---

## 3. Reporting a Vulnerability

**Please do not report security vulnerabilities through public GitHub issues.**

If you discover a security flaw or bypass in `mcp-shield`:

1. **Submit via GitHub Private Vulnerability Reporting:**  
   Navigate to the [Security Advisories](https://github.com/bharathraj0007/mcp-shield/security/advisories/new) tab and open a private disclosure draft.
2. **Alternative Contact:**  
   If GitHub Advisories is inaccessible, email the maintainer directly at:  
   `bharathraj0007@gmail.com` with `[SECURITY: mcp-shield]` in the subject line.
3. **Include Reproduction Data:**
   - Affected component (`scanner`, `proxy`, `policy`, `audit`, or `fixer`).
   - Operating system and Node.js version.
   - Minimal reproduction config or JSON-RPC payload demonstrating the issue.
   - Attack impact and suggested remediation (if known).

### Response SLA
- **Initial Response:** Within 24 hours.
- **Triage & Reproduction:** Within 48 hours.
- **Patch & Release:** Within 5 business days for critical vulnerabilities.
