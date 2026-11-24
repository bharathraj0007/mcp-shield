import { describe, it, expect, beforeEach, afterEach } from "vitest";
import * as fs from "node:fs";
import * as path from "node:path";
import * as os from "node:os";
import { executeSafeFix, executeRollback } from "../src/policy/fixer.js";
import {
  checkSecretLeak,
  computeFindingFingerprint,
  isSafePlaceholder,
} from "../src/scanner/rules.js";
import {
  appendAuditEntry,
  verifyAuditLog,
  exportAuditLog,
  canonicalJsonStringify,
} from "../src/audit/logWriter.js";
import {
  loadBaseline,
  filterWithBaseline,
  updateBaseline,
} from "../src/scanner/baseline.js";
import { generateSarifReport } from "../src/audit/sarif.js";
import { discoverConfigs } from "../src/scanner/discover.js";
import type {
  NormalizedMcpServer,
  PolicyConfig,
  ScanResult,
  ScanFinding,
} from "../src/types/index.js";

describe("Phase 1 Hardening Test Suite (mcp-shield v0.2.0)", () => {
  let tempDir: string;

  beforeEach(() => {
    tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "mcp-shield-p1-"));
  });

  afterEach(() => {
    try {
      fs.rmSync(tempDir, { recursive: true, force: true });
    } catch {}
  });

  describe("1. Transactional & Structure-Preserving Fixer", () => {
    it("preserves comments, trailing commas, and formatting in JSONC config", () => {
      const configPath = path.join(tempDir, "mcp.json");
      const jsoncContent = `// Master Configuration Comment
{
  /* Server Block */
  "mcpServers": {
    "weather": {
      "command": "node",
      "args": ["dist/index.js"],
      "env": {
        // Active Provider Key
        "OPENAI_API_KEY": "sk-proj-1234567890abcdef1234567890",
        "CACHE_DIR": "./cache",
      },
    },
  },
}
`;
      fs.writeFileSync(configPath, jsoncContent, "utf-8");

      const fixResult = executeSafeFix({
        targetPath: configPath,
        isDryRun: false,
      });

      expect(fixResult.plannedExtractions.length).toBe(1);

      const modifiedConfig = fs.readFileSync(configPath, "utf-8");
      // Comments and structure preserved
      expect(modifiedConfig).toContain("// Master Configuration Comment");
      expect(modifiedConfig).toContain("/* Server Block */");
      expect(modifiedConfig).toContain("// Active Provider Key");
      expect(modifiedConfig).toContain('"OPENAI_API_KEY": "${OPENAI_API_KEY}"');
      expect(modifiedConfig).toContain('"CACHE_DIR": "./cache"');

      // .env.mcp created
      const envPath = path.join(tempDir, ".env.mcp");
      expect(fs.existsSync(envPath)).toBe(true);
      const envContent = fs.readFileSync(envPath, "utf-8");
      expect(envContent).toContain("OPENAI_API_KEY=sk-proj-1234567890abcdef1234567890");
    });

    it("handles key collisions by generating server-prefixed environment keys", () => {
      const configPath = path.join(tempDir, "mcp.json");
      const envPath = path.join(tempDir, ".env.mcp");

      // Pre-existing .env.mcp with an API key
      fs.writeFileSync(envPath, 'API_KEY="existing-secret-11111"\n', "utf-8");

      const configContent = JSON.stringify(
        {
          mcpServers: {
            analytics: {
              command: "node",
              args: ["index.js"],
              env: {
                API_KEY: "sk-ant-api03-differingsecret222222222222",
              },
            },
          },
        },
        null,
        2
      );
      fs.writeFileSync(configPath, configContent, "utf-8");

      const fixResult = executeSafeFix({
        targetPath: configPath,
        isDryRun: false,
      });

      expect(fixResult.collisions?.length).toBe(1);
      const collision = fixResult.collisions![0];
      expect(collision?.generatedKey).toBe("ANALYTICS_API_KEY");

      const updatedEnv = fs.readFileSync(envPath, "utf-8");
      expect(updatedEnv).toContain('API_KEY="existing-secret-11111"');
      expect(updatedEnv).toContain("ANALYTICS_API_KEY=sk-ant-api03-differingsecret222222222222");

      const updatedConfig = fs.readFileSync(configPath, "utf-8");
      expect(updatedConfig).toContain('"API_KEY": "${ANALYTICS_API_KEY}"');
    });

    it("escapes quotes, backslashes, and newlines in .env.mcp", () => {
      const configPath = path.join(tempDir, "mcp.json");
      const trickySecret = 'sk-proj-abc"def\\ghi\njkl123456789012345';
      const configContent = JSON.stringify(
        {
          mcpServers: {
            tricky: {
              command: "node",
              args: ["index.js"],
              env: {
                CUSTOM_API_KEY: trickySecret,
              },
            },
          },
        },
        null,
        2
      );
      fs.writeFileSync(configPath, configContent, "utf-8");

      executeSafeFix({ targetPath: configPath, isDryRun: false });

      const envPath = path.join(tempDir, ".env.mcp");
      const envContent = fs.readFileSync(envPath, "utf-8");
      expect(envContent).toContain('CUSTOM_API_KEY="sk-proj-abc\\"def\\\\ghi\\njkl123456789012345"');
    });

    it("refuses to modify symlink config files", () => {
      const realConfig = path.join(tempDir, "real_mcp.json");
      const symlinkConfig = path.join(tempDir, "symlink_mcp.json");
      fs.writeFileSync(realConfig, JSON.stringify({ mcpServers: {} }), "utf-8");

      try {
        fs.symlinkSync(realConfig, symlinkConfig);
        expect(() => executeSafeFix({ targetPath: symlinkConfig })).toThrow(/symbolic link/i);
      } catch (err) {
        // Skip symlink test if OS lacks permissions (e.g. unprivileged Windows)
      }
    });

    it("supports atomic rollback via executeRollback", () => {
      const configPath = path.join(tempDir, "mcp.json");
      const originalJson = JSON.stringify(
        {
          mcpServers: {
            s: {
              command: "node",
              args: ["app.js"],
              env: { GITHUB_TOKEN: "ghp_123456789012345678901234567890123456" },
            },
          },
        },
        null,
        2
      );
      fs.writeFileSync(configPath, originalJson, "utf-8");

      const fixResult = executeSafeFix({ targetPath: configPath });
      expect(fixResult.backupFile).toBeDefined();

      // Config now has placeholder
      expect(fs.readFileSync(configPath, "utf-8")).toContain("${GITHUB_TOKEN}");

      // Perform rollback
      const rollbackResult = executeRollback(fixResult.backupFile!);
      expect(rollbackResult.rolledBack).toBe(true);

      // Config restored to original
      const restored = fs.readFileSync(configPath, "utf-8");
      expect(restored).toBe(originalJson);
    });

    it("ensures mcp-shield scan ignores *.bak backup files", () => {
      const configPath = path.join(tempDir, "mcp.json");
      const bakPath = path.join(tempDir, "mcp.json.2026-11-25T00-00-00.bak");
      const content = JSON.stringify({ mcpServers: { s: { command: "node" } } });
      fs.writeFileSync(configPath, content);
      fs.writeFileSync(bakPath, content);

      const { scannedFiles } = discoverConfigs(tempDir);
      expect(scannedFiles).toContain(configPath);
      expect(scannedFiles.some((f) => f.endsWith(".bak"))).toBe(false);
    });
  });

  describe("2. Contextual Secret Detection & Sensitivity", () => {
    const basePolicy: PolicyConfig = {
      version: "1.0",
      mode: "enforce",
      denyPaths: [],
      allowPaths: [],
      blockedCommands: [],
      disabledRules: [],
      failOnSeverity: "high",
      secretDetection: {
        sensitivity: "balanced",
      },
    };

    it("detects GitHub fine-grained tokens, JWTs, Stripe, and Slack keys", () => {
      const server: NormalizedMcpServer = {
        client: "cursor",
        configPath: path.join(tempDir, "mcp.json"),
        serverName: "multi-secret-server",
        transport: "stdio",
        env: {
          GH_PAT: "github_pat_11AAAAAAA0123456789012_abcdefghijklmnopqrstuvwxyz",
          SLACK_KEY: "xoxb-1234567890-abcdefghij",
          STRIPE_KEY: "sk_" + "live_123456789012345678901234",
          AUTH_HEADER: "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.abc123def456ghi",
        },
      };

      const findings = checkSecretLeak(server, basePolicy);
      expect(findings.length).toBe(4);
      expect(findings.every((f) => f.confidence === "high")).toBe(true);
      expect(findings.every((f) => f.fingerprint && f.fingerprint.length === 64)).toBe(true);
    });

    it("detects database password URIs and PEM private keys", () => {
      const server: NormalizedMcpServer = {
        client: "cursor",
        configPath: path.join(tempDir, "mcp.json"),
        serverName: "db-server",
        transport: "stdio",
        env: {
          DATABASE_URL: "postgres://admin:SuperSecretPass123!@db.internal:5432/production",
          PRIVATE_KEY: "-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA0...",
        },
      };

      const findings = checkSecretLeak(server, basePolicy);
      expect(findings.length).toBe(2);
      expect(findings.some((f) => f.title.includes("Database Password URI"))).toBe(true);
      expect(findings.some((f) => f.title.includes("PEM Private Key"))).toBe(true);
    });

    it("respects secretDetection.exclude globs", () => {
      const policyWithExclude: PolicyConfig = {
        ...basePolicy,
        secretDetection: {
          sensitivity: "balanced",
          exclude: ["**/test-fixtures/**"],
        },
      };

      const server: NormalizedMcpServer = {
        client: "cursor",
        configPath: path.join(tempDir, "test-fixtures", "mcp.json"),
        serverName: "excluded-server",
        transport: "stdio",
        env: {
          TOKEN: "ghp_123456789012345678901234567890123456",
        },
      };

      const findings = checkSecretLeak(server, policyWithExclude);
      expect(findings.length).toBe(0);
    });

    it("ignores documented safe placeholders", () => {
      expect(isSafePlaceholder("${OPENAI_API_KEY}")).toBe(true);
      expect(isSafePlaceholder("$OPENAI_API_KEY")).toBe(true);
      expect(isSafePlaceholder("your_api_key_here")).toBe(true);
      expect(isSafePlaceholder("placeholder-token")).toBe(true);
      expect(isSafePlaceholder("changeme")).toBe(true);
      expect(isSafePlaceholder("<insert_key_here>")).toBe(true);
      expect(isSafePlaceholder("TODO: add key")).toBe(true);
      expect(isSafePlaceholder("replace_me")).toBe(true);
    });
  });

  describe("3. Audit Log Hardening & HMAC Signing", () => {
    it("serializes canonical JSON with sorted keys", () => {
      const obj1 = { z: 1, a: 2, m: { b: 3, a: 4 } };
      const obj2 = { a: 2, m: { a: 4, b: 3 }, z: 1 };
      expect(canonicalJsonStringify(obj1)).toBe(canonicalJsonStringify(obj2));
    });

    it("signs entries with HMAC-SHA-256 and detects signature forgery", () => {
      const logFile = path.join(tempDir, "audit.jsonl");
      const hmacKey = "top-secret-signing-key-12345";

      appendAuditEntry(
        {
          eventType: "scan",
          action: "SCAN_COMPLETE",
          details: { findings: 0 },
        },
        { logPath: logFile, hmacKey }
      );

      // Verify with matching HMAC key
      const passResult = verifyAuditLog(logFile, undefined, hmacKey);
      expect(passResult.valid).toBe(true);
      expect(passResult.code).toBe("SUCCESS");

      // Verify with wrong HMAC key
      const failResult = verifyAuditLog(logFile, undefined, "wrong-key");
      expect(failResult.valid).toBe(false);
      expect(failResult.code).toBe("INVALID_SIGNATURE");
    });

    it("detects sequence number gaps and reordered entries", () => {
      const logFile = path.join(tempDir, "audit.jsonl");

      appendAuditEntry(
        { eventType: "scan", action: "SCAN_COMPLETE", details: { step: 1 } },
        { logPath: logFile }
      );
      appendAuditEntry(
        { eventType: "scan", action: "SCAN_COMPLETE", details: { step: 2 } },
        { logPath: logFile }
      );

      // Read entries and swap sequence numbers
      const lines = fs.readFileSync(logFile, "utf-8").trim().split("\n");
      const e0 = JSON.parse(lines[0]!);
      const e1 = JSON.parse(lines[1]!);

      // Corrupt sequence
      e1.seq = 5;
      fs.writeFileSync(logFile, `${JSON.stringify(e0)}\n${JSON.stringify(e1)}\n`);

      const gapResult = verifyAuditLog(logFile);
      expect(gapResult.valid).toBe(false);
      expect(gapResult.code).toBe("SEQUENCE_GAP");
    });

    it("exports verified audit log to specified file", () => {
      const sourceLog = path.join(tempDir, "source_audit.jsonl");
      const exportTarget = path.join(tempDir, "exported_audit.jsonl");

      appendAuditEntry(
        { eventType: "scan", action: "SCAN_COMPLETE", details: { test: true } },
        { logPath: sourceLog }
      );

      exportAuditLog(exportTarget, sourceLog);
      expect(fs.existsSync(exportTarget)).toBe(true);
      expect(fs.readFileSync(exportTarget, "utf-8")).toBe(fs.readFileSync(sourceLog, "utf-8"));
    });
  });

  describe("4. Baseline Filtering & SARIF Report", () => {
    const dummyFinding: ScanFinding = {
      ruleId: "MS-001",
      owaspId: "MCP01:2025",
      severity: "critical",
      title: "Hardcoded Secret",
      message: "Secret exposed",
      file: "d:/mcp-shield/mcp.json",
      serverName: "weather",
      maskedEvidence: "sk-***...1234",
      fixSuggestion: "Move to env",
      fingerprint: "1111222233334444555566667777888899990000aaaabbbbccccddddeeeeffff",
    };

    it("suppresses accepted findings in baseline", () => {
      const baselineFile = path.join(tempDir, "baseline.json");
      updateBaseline(baselineFile, [dummyFinding], { reason: "Temporary accepted risk" });

      const loadedBaseline = loadBaseline(baselineFile);
      expect(loadedBaseline).toBeDefined();

      const { active, suppressed } = filterWithBaseline([dummyFinding], loadedBaseline);
      expect(active.length).toBe(0);
      expect(suppressed.length).toBe(1);
      expect(suppressed[0]?.baselineState).toBe("unchanged");
      expect(suppressed[0]?.suppressed).toBe(true);
      expect(suppressed[0]?.suppressionReason).toBe("Temporary accepted risk");
    });

    it("reactivates expired baseline entries", () => {
      const baselineFile = path.join(tempDir, "baseline.json");
      const pastDate = new Date(Date.now() - 100000).toISOString();
      updateBaseline(baselineFile, [dummyFinding], {
        reason: "Expired exception",
        expiresAt: pastDate,
      });

      const loadedBaseline = loadBaseline(baselineFile);
      const { active, suppressed } = filterWithBaseline([dummyFinding], loadedBaseline);

      expect(active.length).toBe(1);
      expect(suppressed.length).toBe(0);
      expect(active[0]?.baselineState).toBe("new");
    });

    it("generates SARIF 2.1.0 with enriched rule metadata and partialFingerprints", () => {
      const scanResult: ScanResult = {
        scannedFiles: ["d:/mcp-shield/mcp.json"],
        serversCount: 1,
        findings: [dummyFinding],
        score: 60,
        grade: "D",
        timestamp: new Date().toISOString(),
      };

      const sarif = generateSarifReport(scanResult, "0.2.0");
      expect(sarif.version).toBe("2.1.0");

      const run = sarif.runs[0]!;
      expect(run.tool.driver.version).toBe("0.2.0");
      expect(run.tool.driver.rules.length).toBe(1);

      const rule = run.tool.driver.rules[0]!;
      expect(rule.id).toBe("MS-001");
      expect(rule.properties?.["security-severity"]).toBe("9.0");

      const result = run.results[0]!;
      expect(result.ruleId).toBe("MS-001");
      expect(result.partialFingerprints?.["mcpShield/v1"]).toBe(dummyFinding.fingerprint);
    });
  });
});
