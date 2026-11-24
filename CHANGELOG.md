# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [0.1.0] - 2026-11-24

### Added
- **Static Configuration Scanner (`mcp-shield scan`)**:
  - Automatic cross-platform discovery across 9 MCP client configurations (Cursor, Claude Desktop, Antigravity, VS Code, Windsurf, Claude Code, Gemini CLI, Zed, and custom paths).
  - OWASP MCP Top 10 deterministic security rules (`MS-001` through `MS-007`).
  - Letter grade scoring (A through F) with color-coded terminal reports.
  - Machine-readable `--json` and `--ci` exit code enforcement flags.
- **Runtime JSON-RPC Firewall (`mcp-shield proxy`)**:
  - Live newline-delimited JSON-RPC 2.0 `stdio` proxy wrapper.
  - Fail-closed security architecture: returns error code `-32001` on malformed frames, oversized payloads, or policy violations.
  - 1 MB frame size enforcement to prevent memory denial-of-service.
  - Canonical path traversal resolution: normalizes URL-encoded strings, Unicode NFKC, and symlinks (`fs.realpathSync`).
  - Windows UNC path detection (`\\server\share`, `\\?\UNC\...`).
  - Safe shell command tokenization and dangerous execution blocking (`rm -rf`, `curl | sh`, `chmod 777`).
  - Mid-session tool description mutation detection (rug-pull defense).
- **Policy Engine & Safe Fixer (`mcp-shield init`, `mcp-shield fix`)**:
  - Portable YAML policy schema (`policy.yaml`) for project-specific allow and deny lists.
  - Automated secret isolation into `.env.mcp` with `0o600` permissions.
  - Timestamped `.bak` backup creation before any configuration write.
  - Preview mode via `--dry-run`.
- **Compliance Audit & SARIF Exporter (`mcp-shield audit`, `mcp-shield scan --format sarif`)**:
  - Tamper-evident SHA-256 hash-chained JSONL audit logging.
  - Log verification command (`mcp-shield audit --verify`) that detects modified and truncated records.
  - GitHub Code Scanning SARIF 2.1.0 report generator.
- **Testing, Verification & Benchmarks**:
  - 104-case security corpus (100% detection rate, 0% false positives).
  - Sub-5ms p99 proxy latency benchmark runner (`npm run bench`).
  - Protected 26-check black-box end-to-end self-test harness (`npm run self-test`).
  - Static AST and package offline guard guaranteeing zero outbound network calls.
