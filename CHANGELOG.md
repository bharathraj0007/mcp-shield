# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [1.0.0] - 2026-11-25

### Added
- **Ed25519 Cryptographic Checkpoints**:
  - Offline keypair generator `mcp-shield audit keygen --out <dir>` generating `audit-signing.key` (`0o600`) and `audit-signing.pub` (`0o644`) with deterministic 16-character hex `keyId`.
  - Checkpoint creation `mcp-shield audit --checkpoint [--private-key <file>]` appending signed audit checkpoints.
  - Checkpoint verification `mcp-shield audit --verify [--public-key <file>]` returning exit code `4` on `INVALID_SIGNATURE` or `CHECKPOINT_MISMATCH`.
- **High-Scale & Adversarial Stress Test Suite (`cli/tests/scaleAndAdversarial.test.ts`)**:
  - 1,000+ sequential audit log writes with sub-second verification.
  - Truncated record, reordered entry, and sequence gap detection.
  - 500+ MCP server configuration parsing without performance degradation.
  - Depth-32 nested JSON object fail-closed parsing enforcement.
  - 1 MB exact boundary frames and multi-chunk buffer reassembly.
  - Unicode homoglyph normalization (`..／..／..／.env` fullwidth solidus blocking).
- **Pre-Commit Hook Integration**:
  - Root `.pre-commit-hooks.yaml` enabling automated `mcp-shield scan . --ci` execution.
- **Offline CycloneDX 1.5 JSON SBOM Generator**:
  - `cli/scripts/release-artifacts.mjs` (`npm run release:artifacts`) offline-generating `sbom.cdx.json` and `SHA256SUMS.txt`.
- **Automated Tag Release Workflow**:
  - `.github/workflows/release.yml` triggering on `v*` tags with release artifact attachments.

### Changed
- Production v1.0.0 release version bump.
- Hardened TOCTOU file operations using native file descriptors and `O_CREAT | O_EXCL` flags.

---

## [0.2.1] - 2026-11-25

### Fixed
- Fixed CodeQL polynomial regular expression (ReDoS) vulnerability in rollback backup path parsing.
- Eliminated file-system race conditions (TOCTOU) across `fixer.ts`, `discover.ts`, `baseline.ts`, `logWriter.ts`, and `index.ts`.
- Configured Dependabot to ignore breaking semver-major bumps for `npm` and `github-actions`.
- Replaced predictable temporary test directory paths with `fs.mkdtempSync`.

---

## [0.2.0] - 2026-11-25

### Added
- Multi-format MCP configuration discovery supporting JSON, JSONC, YAML (`.yaml`, `.yml`), and zero-dependency TOML (`.toml`).
- Dual framing protocol support: line-delimited and `Content-Length` header-delimited framing with auto-detection.
- Transactional and structure-preserving secret fixer (`mcp-shield fix`) with comment and formatting preservation.
- Findings baseline suppression system (`--baseline`, `--baseline-update`, `--changed-only`).
- Strict Zod policy validation with inheritance hierarchy (`inherit: [...]`).
- Shell completions generator for Bash, Zsh, Fish, and PowerShell.
- Side-effect-free programmatic library export with bundled TypeScript declarations (`dist/index.d.ts`).

---

## [0.1.0] - 2026-11-24

### Added
- Initial release of `mcp-shield` security scanner and stdio runtime firewall.
- OWASP MCP Top 10 static security rules (`MS-001` through `MS-007`).
- Fail-closed JSON-RPC 2.0 stdio proxy wrapper (`mcp-shield proxy`).
- Tamper-evident SHA-256 hash-chained JSONL audit logger (`mcp-shield audit`).
- GitHub Actions SARIF 2.1.0 Code Scanning integration.
