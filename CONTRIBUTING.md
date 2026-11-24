# Contributing to mcp-shield

Thank you for contributing to `mcp-shield`. This guide outlines how to build, test, and contribute new security rules.

---

## 1. Development Setup

### Prerequisites
- **Node.js** `v20.0.0` or higher
- **npm** `v10.0.0` or higher
- **Git**

### Clone & Install
```bash
git clone https://github.com/bharathraj0007/mcp-shield.git
cd mcp-shield/cli
npm install
```

### Build & Test Suite
```bash
# Build the TypeScript CLI
npm run build

# Run unit, integration, and fuzz test suites
npm test

# Run the 104-case security corpus and p99 latency benchmark
npm run bench

# Run the protected black-box self-test harness
npm run self-test
```

---

## 2. Core Development Rules

All contributions must follow these rules:

1. **100% Offline Guarantee:** Never import or execute network calls (`fetch`, `http`, `https`, `net`, `tls`, `dgram`, `WebSocket`). The test suite enforces this rule via `tests/offlineGuard.test.ts`.
2. **Strict TypeScript:** No `any` types. Use `unknown` with Zod or TypeScript type guards. Never use `@ts-ignore` or `@ts-expect-error`.
3. **No Weakened Assertions:** Never delete, skip (`.skip`), or weaken assertions in existing test files.
4. **ASD-STE100 Style:** Write all comments, documentation, and error messages in Simplified Technical English. Use short sentences and active voice.

---

## 3. How to Add a New Security Rule (`MS-008+`)

Follow this 5-step procedure to add a new OWASP MCP Top 10 rule:

### Step 1: Register the Rule in Types
Open `cli/src/types/index.ts` and add your rule identifier and OWASP mapping:
```ts
export type RuleId =
  | "MS-001"
  // ...
  | "MS-008"; // Your new rule identifier
```

### Step 2: Implement the Detection Rule
Open `cli/src/scanner/rules.ts` and write a deterministic detection function:
```ts
export function checkMyNewRule(server: NormalizedMcpServer): ScanFinding[] {
  const findings: ScanFinding[] = [];
  // Inspect server configuration properties
  // Append ScanFinding objects when a vulnerability matches
  return findings;
}
```

### Step 3: Wire into the Scanner Engine
Open `cli/src/scanner/engine.ts` and include your detection function in the scan loop:
```ts
findings.push(...checkMyNewRule(server));
```

### Step 4: Add Positive and Negative Test Fixtures
Create test cases:
1. Add a vulnerable fixture under `cli/tests/fixtures/` that must trigger the rule.
2. Add a clean fixture under `cli/tests/fixtures/` that must produce zero findings.
3. Update `cli/tests/corpus.test.ts` to include your new test cases.

### Step 5: Verify the Build & Performance
Execute the full test and benchmark suite:
```bash
npm run build
npm test
npm run bench
npm run self-test
```
Confirm:
- Detection rate: 100% on vulnerable fixtures.
- False-positive rate: 0% on clean fixtures.
- Proxy latency overhead: < 5 ms p99.

---

## 4. Submitting a Pull Request

1. Create a feature branch: `git checkout -b rule/ms-008-my-rule`.
2. Commit your changes with a clear message: `git commit -m "feat(scanner): add MS-008 rule for ..."`.
3. Push to your branch and open a Pull Request against `main`.
4. Ensure all GitHub Actions CI checks pass.
