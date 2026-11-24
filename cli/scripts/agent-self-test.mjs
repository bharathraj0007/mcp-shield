#!/usr/bin/env node
/**
 * Black-Box End-to-End Self-Test Verification Harness for mcp-shield
 *
 * Scope: Full CLI verification across all modules (T0 through T4)
 * Standard: ASD-STE100 Simplified Technical English
 * Rule: PROTECTED. Never delete or weaken any assertion.
 */

import * as fs from "node:fs";
import * as path from "node:path";
import * as os from "node:os";
import * as crypto from "node:crypto";
import { spawnSync, spawn } from "node:child_process";
import { fileURLToPath } from "node:url";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const cliRoot = path.resolve(__dirname, "..");
const binPath = path.resolve(cliRoot, "dist", "index.js");

let totalTests = 0;
let passedTests = 0;
let failedTests = 0;

function logHeader(title) {
  console.log(`\n==================================================`);
  console.log(`TEST SUITE: ${title}`);
  console.log(`==================================================`);
}

function assertTest(name, condition, details = "") {
  totalTests++;
  if (condition) {
    passedTests++;
    console.log(`  [PASS] ${name}`);
  } else {
    failedTests++;
    console.error(`  [FAIL] ${name}`);
    if (details) {
      console.error(`         Details: ${details}`);
    }
  }
}

function runCli(args, options = {}) {
  const result = spawnSync(process.execPath, [binPath, ...args], {
    cwd: options.cwd || cliRoot,
    env: { ...process.env, ...(options.env || {}) },
    encoding: "utf-8",
    timeout: 10000,
  });
  return {
    status: result.status ?? 1,
    stdout: result.stdout || "",
    stderr: result.stderr || "",
  };
}

// -------------------------------------------------------------
// T0: Foundation & CLI Sanity Verification
// -------------------------------------------------------------
function testT0() {
  logHeader("T0: Foundation & CLI Sanity Verification");

  assertTest("Binary exists at dist/index.js", fs.existsSync(binPath));

  if (fs.existsSync(binPath)) {
    const content = fs.readFileSync(binPath, "utf-8");
    const firstLine = content.split("\n")[0] || "";
    assertTest(
      "Binary contains #!/usr/bin/env node shebang",
      firstLine.startsWith("#!/usr/bin/env node"),
      `First line is: ${firstLine}`
    );

    const helpRes = runCli(["--help"]);
    assertTest(
      "mcp-shield --help returns exit code 0",
      helpRes.status === 0,
      `Exit code: ${helpRes.status}`
    );
    assertTest(
      "Help output mentions mcp-shield description",
      helpRes.stdout.includes("mcp-shield") && helpRes.stdout.includes("offline"),
      helpRes.stdout.slice(0, 100)
    );
  }
}

// -------------------------------------------------------------
// T1: Static Config & Secret Scanner Verification
// -------------------------------------------------------------
function testT1() {
  logHeader("T1: Static Config & Secret Scanner Verification");

  const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "mcp-shield-t1-"));

  try {
    const cleanDir = path.join(tempDir, "clean");
    const vulnDir = path.join(tempDir, "vuln");
    fs.mkdirSync(cleanDir, { recursive: true });
    fs.mkdirSync(vulnDir, { recursive: true });

    // Clean fixture
    const cleanConfig = {
      mcpServers: {
        safeServer: {
          command: "node",
          args: ["./src/server.js", "--dir", "./safe-docs"],
          env: {
            NODE_ENV: "production",
          },
        },
      },
    };
    fs.writeFileSync(
      path.join(cleanDir, "mcp.json"),
      JSON.stringify(cleanConfig, null, 2),
      "utf-8"
    );

    // Vulnerable fixture
    const fakeKey = "sk-proj-test123456789012345678901234567890";
    const vulnConfig = {
      mcpServers: {
        badServer: {
          command: "npx",
          args: ["-y", "unpinned-package", "/"],
          env: {
            OPENAI_API_KEY: fakeKey,
          },
        },
      },
    };
    fs.writeFileSync(
      path.join(vulnDir, "mcp.json"),
      JSON.stringify(vulnConfig, null, 2),
      "utf-8"
    );

    // Test clean config scan
    const cleanRes = runCli(["scan", cleanDir, "--json"]);
    assertTest(
      "Clean config scan exits with code 0",
      cleanRes.status === 0,
      `Exit code: ${cleanRes.status}, err: ${cleanRes.stderr}`
    );

    let cleanJson = null;
    try {
      cleanJson = JSON.parse(cleanRes.stdout);
    } catch {}
    assertTest(
      "Clean config produces grade A with zero findings",
      cleanJson !== null && cleanJson.grade === "A" && cleanJson.findings.length === 0,
      `Grade: ${cleanJson?.grade}, findings: ${cleanJson?.findings?.length}`
    );

    // Test vulnerable config scan with --ci
    const vulnRes = runCli(["scan", vulnDir, "--json", "--ci"]);
    assertTest(
      "Vulnerable config scan with --ci exits with code 1",
      vulnRes.status === 1,
      `Exit code: ${vulnRes.status}`
    );

    let vulnJson = null;
    try {
      vulnJson = JSON.parse(vulnRes.stdout);
    } catch {}
    assertTest(
      "Vulnerable config produces grade D or F with findings",
      vulnJson !== null && (vulnJson.grade === "D" || vulnJson.grade === "F") && vulnJson.findings.length > 0,
      `Grade: ${vulnJson?.grade}, findings count: ${vulnJson?.findings?.length}`
    );

    // Secret masking check
    const combinedOutput = vulnRes.stdout + vulnRes.stderr;
    assertTest(
      "Raw secret is NEVER leaked in scanner output",
      !combinedOutput.includes(fakeKey),
      "Found raw unmasked secret in output!"
    );
  } finally {
    fs.rmSync(tempDir, { recursive: true, force: true });
  }
}

// -------------------------------------------------------------
// T2A, T2B, T2C: Runtime Live Proxy Verification
// -------------------------------------------------------------
async function testT2() {
  logHeader("T2: Runtime Live Proxy Verification");

  const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "mcp-shield-t2-"));

  try {
    // Create mock MCP server
    const mockServerScript = path.join(tempDir, "mockServer.mjs");
    const mockServerCode = `
import * as readline from "node:readline";

const rl = readline.createInterface({ input: process.stdin, terminal: false });

rl.on("line", (line) => {
  if (!line.trim()) return;
  try {
    const req = JSON.parse(line);
    if (req.id !== undefined) {
      const resp = {
        jsonrpc: "2.0",
        id: req.id,
        result: { status: "MOCK_SUCCESS", echoParams: req.params }
      };
      process.stdout.write(JSON.stringify(resp) + "\\n");
    }
  } catch (err) {
    process.stderr.write("Mock error: " + err.message + "\\n");
  }
});
`;
    fs.writeFileSync(mockServerScript, mockServerCode, "utf-8");

    // Helper to run proxy interaction
    const sendToProxy = (requests) => {
      return new Promise((resolve) => {
        const proxyProc = spawn(
          process.execPath,
          [binPath, "proxy", "--", process.execPath, mockServerScript],
          { cwd: tempDir, stdio: ["pipe", "pipe", "pipe"] }
        );

        let stdoutData = "";
        let stderrData = "";

        proxyProc.stdout.on("data", (chunk) => {
          stdoutData += chunk.toString();
        });

        proxyProc.stderr.on("data", (chunk) => {
          stderrData += chunk.toString();
        });

        for (const req of requests) {
          proxyProc.stdin.write(JSON.stringify(req) + "\n");
        }

        setTimeout(() => {
          proxyProc.stdin.end();
          proxyProc.kill("SIGTERM");
          setTimeout(() => {
            resolve({ stdout: stdoutData, stderr: stderrData });
          }, 300);
        }, 500);
      });
    };

    // T2A: Safe Request Forwarding
    const safeReq = {
      jsonrpc: "2.0",
      id: 101,
      method: "tools/call",
      params: { name: "read_file", arguments: { path: "./src/app.ts" } },
    };
    const resA = await sendToProxy([safeReq]);
    const linesA = resA.stdout.trim().split("\n").filter(Boolean);
    let safeResp = null;
    try {
      safeResp = JSON.parse(linesA[0] || "{}");
    } catch {}

    assertTest(
      "T2A: Safe request forwards cleanly to mock server",
      safeResp !== null && safeResp.id === 101 && safeResp.result?.status === "MOCK_SUCCESS",
      `Response: ${JSON.stringify(safeResp)}`
    );

    // T2B: Path Traversal & Sensitive File Block
    const blockReq = {
      jsonrpc: "2.0",
      id: 102,
      method: "tools/call",
      params: { name: "read_file", arguments: { path: "../../.env" } },
    };
    const resB = await sendToProxy([blockReq]);
    const linesB = resB.stdout.trim().split("\n").filter(Boolean);
    let blockResp = null;
    try {
      blockResp = JSON.parse(linesB[0] || "{}");
    } catch {}

    assertTest(
      "T2B: Traversal to .env is blocked with JSON-RPC error code -32001",
      blockResp !== null && blockResp.id === 102 && blockResp.error?.code === -32001,
      `Response: ${JSON.stringify(blockResp)}`
    );
    assertTest(
      "T2B: Block notice is written to stderr and stdout contains only JSON-RPC",
      resB.stderr.length > 0 && linesB.every((l) => {
        try { JSON.parse(l); return true; } catch { return false; }
      }),
      `stderr length: ${resB.stderr.length}`
    );

    // T2C: Destructive Command Block
    const cmdReq = {
      jsonrpc: "2.0",
      id: 103,
      method: "tools/call",
      params: { name: "execute_command", arguments: { command: "rm -rf /" } },
    };
    const resC = await sendToProxy([cmdReq]);
    const linesC = resC.stdout.trim().split("\n").filter(Boolean);
    let cmdResp = null;
    try {
      cmdResp = JSON.parse(linesC[0] || "{}");
    } catch {}

    assertTest(
      "T2C: Destructive command (rm -rf) is blocked with code -32001",
      cmdResp !== null && cmdResp.id === 103 && cmdResp.error?.code === -32001,
      `Response: ${JSON.stringify(cmdResp)}`
    );
  } finally {
    fs.rmSync(tempDir, { recursive: true, force: true });
  }
}

// -------------------------------------------------------------
// T3: Policy, Safe Fixer & Compliance Audit Verification
// -------------------------------------------------------------
function testT3() {
  logHeader("T3: Policy, Safe Fixer & Compliance Audit Verification");

  const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "mcp-shield-t3-"));

  try {
    // 1. mcp-shield init
    const initRes = runCli(["init"], { cwd: tempDir });
    const policyPath = path.join(tempDir, "policy.yaml");
    assertTest(
      "mcp-shield init creates policy.yaml",
      initRes.status === 0 && fs.existsSync(policyPath),
      `Status: ${initRes.status}, exists: ${fs.existsSync(policyPath)}`
    );

    // 2. mcp-shield fix --dry-run vs real fix
    const targetConfig = path.join(tempDir, "mcp.json");
    const secretKey = "sk-ant-api03-testsecretkeyvalue999999999999";
    const initialConfigContent = JSON.stringify({
      mcpServers: {
        serverA: {
          command: "node",
          args: ["index.js"],
          env: {
            ANTHROPIC_API_KEY: secretKey,
          },
        },
      },
    }, null, 2);

    fs.writeFileSync(targetConfig, initialConfigContent, "utf-8");

    // Dry run
    const dryRes = runCli(["fix", targetConfig, "--dry-run"], { cwd: tempDir });
    assertTest("mcp-shield fix --dry-run exits with code 0", dryRes.status === 0);
    assertTest(
      "mcp-shield fix --dry-run does not modify target file",
      fs.readFileSync(targetConfig, "utf-8") === initialConfigContent
    );

    // Real fix
    const fixRes = runCli(["fix", targetConfig], { cwd: tempDir });
    assertTest("mcp-shield fix exits with code 0", fixRes.status === 0);

    // Check .bak file created
    const dirFiles = fs.readdirSync(tempDir);
    const bakFile = dirFiles.find((f) => f.startsWith("mcp.json.") && f.endsWith(".bak"));
    assertTest("mcp-shield fix creates timestamped .bak file", Boolean(bakFile));

    // Check .env.mcp created
    const envMcpPath = path.join(tempDir, ".env.mcp");
    assertTest("mcp-shield fix creates .env.mcp file", fs.existsSync(envMcpPath));
    if (fs.existsSync(envMcpPath)) {
      const envContent = fs.readFileSync(envMcpPath, "utf-8");
      assertTest(
        "Extracted secret is moved to .env.mcp",
        envContent.includes("ANTHROPIC_API_KEY=" + secretKey)
      );
    }

    // Check config now has variable reference
    const fixedConfig = fs.readFileSync(targetConfig, "utf-8");
    assertTest(
      "Config replaces raw secret with ${ANTHROPIC_API_KEY}",
      fixedConfig.includes("${ANTHROPIC_API_KEY}") && !fixedConfig.includes(secretKey)
    );

    // 3. Audit log verification and tamper detection
    const auditRes = runCli(["audit", "--verify"], { cwd: tempDir });
    assertTest(
      "mcp-shield audit --verify passes on intact log",
      auditRes.status === 0,
      `Exit code: ${auditRes.status}`
    );

    // 4. SARIF 2.1.0 export
    const sarifRes = runCli(["scan", tempDir, "--format", "sarif"], { cwd: tempDir });
    let sarifJson = null;
    try {
      sarifJson = JSON.parse(sarifRes.stdout);
    } catch {}

    assertTest(
      "mcp-shield scan --format sarif outputs valid SARIF 2.1.0",
      sarifJson !== null &&
        sarifJson.version === "2.1.0" &&
        Array.isArray(sarifJson.runs) &&
        sarifJson.runs.length > 0 &&
        Array.isArray(sarifJson.runs[0]?.tool?.driver?.rules)
    );
  } finally {
    fs.rmSync(tempDir, { recursive: true, force: true });
  }
}

// -------------------------------------------------------------
// T4: Offline Guard & Allowlist Verification
// -------------------------------------------------------------
function testT4() {
  logHeader("T4: Offline Guard & Allowlist Verification");

  const srcDir = path.resolve(cliRoot, "src");

  // Read all files in src
  function getAllFiles(dir) {
    let files = [];
    if (!fs.existsSync(dir)) return files;
    for (const item of fs.readdirSync(dir, { withFileTypes: true })) {
      const fullPath = path.join(dir, item.name);
      if (item.isDirectory()) {
        files = files.concat(getAllFiles(fullPath));
      } else if (item.isFile() && (item.name.endsWith(".ts") || item.name.endsWith(".js"))) {
        files.push(fullPath);
      }
    }
    return files;
  }

  const srcFiles = getAllFiles(srcDir);
  const forbiddenPatterns = [
    /\bfetch\s*\(/,
    /\bhttps?\./,
    /\bnet\./,
    /\bdgram\./,
    /\btls\./,
    /\bWebSocket\b/,
    /\baxios\b/,
    /\btelemetry\b/i,
  ];

  let networkViolationFound = false;
  let violationFile = "";

  for (const file of srcFiles) {
    const text = fs.readFileSync(file, "utf-8");
    for (const pattern of forbiddenPatterns) {
      if (pattern.test(text)) {
        networkViolationFound = true;
        violationFile = `${path.relative(cliRoot, file)} matches ${pattern.toString()}`;
        break;
      }
    }
    if (networkViolationFound) break;
  }

  assertTest(
    "Source code in src/ contains zero outbound network or telemetry calls",
    !networkViolationFound,
    violationFile
  );

  // Dependency allowlist check
  const pkg = JSON.parse(fs.readFileSync(path.resolve(cliRoot, "package.json"), "utf-8"));
  const allowedRuntime = new Set(["commander", "picocolors", "jsonc-parser", "yaml", "zod"]);
  const allowedDev = new Set(["typescript", "tsup", "vitest", "@types/node"]);

  const actualRuntime = Object.keys(pkg.dependencies || {});
  const actualDev = Object.keys(pkg.devDependencies || {});

  const unallowedRuntime = actualRuntime.filter((dep) => !allowedRuntime.has(dep));
  const unallowedDev = actualDev.filter((dep) => !allowedDev.has(dep));

  assertTest(
    "All runtime dependencies belong to approved allowlist",
    unallowedRuntime.length === 0,
    `Unallowed: ${unallowedRuntime.join(", ")}`
  );

  assertTest(
    "All dev dependencies belong to approved allowlist",
    unallowedDev.length === 0,
    `Unallowed: ${unallowedDev.join(", ")}`
  );
}

// -------------------------------------------------------------
// Main Runner
// -------------------------------------------------------------
async function main() {
  console.log("Starting mcp-shield black-box verification harness...\n");

  const phaseArg = process.argv.find((arg) => arg.startsWith("--phase="));
  const phaseNum = phaseArg ? phaseArg.split("=")[1] : null;

  if (phaseNum === "0") {
    console.log("Targeting Phase 0 checks only.\n");
    testT0();
  } else if (phaseNum === "1") {
    console.log("Targeting Phase 0-1 checks.\n");
    testT0();
    testT1();
  } else if (phaseNum === "2") {
    console.log("Targeting Phase 0-2 checks.\n");
    testT0();
    testT1();
    await testT2();
  } else if (phaseNum === "3") {
    console.log("Targeting Phase 0-3 checks.\n");
    testT0();
    testT1();
    await testT2();
    testT3();
  } else {
    // Full suite across all modules (Phase 4 requirement)
    testT0();
    testT1();
    await testT2();
    testT3();
    testT4();
  }

  console.log("\n==================================================");
  console.log(`FINAL RESULTS: ${passedTests}/${totalTests} PASSED, ${failedTests} FAILED`);
  console.log("==================================================");

  if (failedTests > 0) {
    process.exit(1);
  } else {
    process.exit(0);
  }
}

main().catch((err) => {
  console.error("Harness fatal error:", err);
  process.exit(1);
});
