# Contributing to mcp-shield

Thank you for contributing to `mcp-shield`. This document explains how to set up your local development environment, run test suites, and submit pull requests.

---

## 1. Development Environment Setup

### Prerequisites
- **Node.js** `v20.0.0` or higher
- **npm** `v10.0.0` or higher
- **Git**

### Installation
```bash
# 1. Clone repository
git clone https://github.com/bharathraj0007/mcp-shield.git
cd mcp-shield/cli

# 2. Install dependencies (strictly lockfile-reproducible)
npm ci
```

---

## 2. Verification Test Commands

Run the full test and benchmark cycle before submitting any changes:

```bash
# 1. Build TypeScript bundle & declaration types
npm run build

# 2. Run unit, integration, and fuzz test suites (13 suites, 119+ tests)
npm test

# 3. Run the 104-case attack corpus and sub-5ms latency benchmark
npm run bench

# 4. Run the black-box end-to-end self-test verification harness
npm run self-test

# 5. Offline-generate CycloneDX SBOM & release artifacts
npm run release:artifacts
```

---

## 3. Development Invariants & Code Standards

Every contribution must satisfy these core invariants:

1. **100% Offline Operation:**  
   Never import or invoke network libraries (`fetch`, `http`, `https`, `net`, `tls`, `dgram`, `WebSocket`, `axios`). Our offline guard test enforces this rule.
2. **Zero `any` in TypeScript:**  
   Use strict TypeScript. Use `unknown` with Zod schemas or user-defined type guards. Never silence the compiler with `@ts-ignore` or `@ts-expect-error`.
3. **No Weakened Assertions:**  
   Never delete, weaken, or `.skip` existing assertions in `cli/tests/` or `cli/scripts/agent-self-test.mjs`.
4. **ASD-STE100 Simplified Technical English (~80%):**  
   Write comments, CLI error messages, and documentation in short sentences, active voice, and plain terminology.
5. **Atomic File Operations:**  
   Avoid check-then-act (`fs.existsSync` before read/write) patterns to eliminate file-system TOCTOU race conditions.

---

## 4. Pull Request Checklist

Before opening a pull request:
- [ ] Code compiles with `npm run build` (zero TypeScript errors).
- [ ] All tests pass via `npm test`.
- [ ] Benchmark passes with p99 inspection latency < 5.0 ms via `npm run bench`.
- [ ] End-to-end self-test passes 26/26 checks via `npm run self-test`.
- [ ] Documentation updated if CLI commands, flags, or configuration options changed.
