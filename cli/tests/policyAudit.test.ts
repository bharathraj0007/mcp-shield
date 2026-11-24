import { describe, it, expect, beforeEach, afterEach } from "vitest";
import * as fs from "node:fs";
import * as path from "node:path";
import * as os from "node:os";
import { loadPolicy } from "../src/policy/loader.js";
import { executeSafeFix } from "../src/policy/fixer.js";
import {
  appendAuditEntry,
  verifyAuditLog,
  getAuditTail,
} from "../src/audit/logWriter.js";
import { generateSarifReport } from "../src/audit/sarif.js";
import type { ScanResult } from "../src/types/index.js";

describe("Phase 3: v3 Policy, Safe Fixer & Compliance Audit", () => {
  let tempDir: string;

  beforeEach(() => {
    tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "mcp-shield-p3-"));
  });

  afterEach(() => {
    fs.rmSync(tempDir, { recursive: true, force: true });
  });

  describe("Policy Loader & Validation", () => {
    it("loads default policy fallback when no custom policy file exists", () => {
      const policy = loadPolicy();
      expect(policy.version).toBe("1.0");
      expect(policy.mode).toBe("enforce");
      expect(policy.denyPaths.length).toBeGreaterThan(0);
    });

    it("loads and strictly validates custom policy.yaml with Zod", () => {
      const customPolicyPath = path.join(tempDir, "policy.yaml");
      const yamlContent = `version: "1.0"
mode: "monitor"
denyPaths:
  - "**/private/**"
allowPaths:
  - "./public/**"
blockedCommands:
  - "dangerous-script"
disabledRules:
  - "MS-004"
failOnSeverity: "critical"
`;
      fs.writeFileSync(customPolicyPath, yamlContent, "utf-8");

      const policy = loadPolicy(customPolicyPath);
      expect(policy.mode).toBe("monitor");
      expect(policy.denyPaths).toContain("**/private/**");
      expect(policy.blockedCommands).toContain("dangerous-script");
      expect(policy.disabledRules).toContain("MS-004");
      expect(policy.failOnSeverity).toBe("critical");
    });

    it("fails with clear Zod validation error on invalid policy schema", () => {
      const invalidPolicyPath = path.join(tempDir, "invalid-policy.yaml");
      const badContent = `version: "1.0"
mode: "invalid_mode_value"
denyPaths: "not-an-array"
`;
      fs.writeFileSync(invalidPolicyPath, badContent, "utf-8");

      expect(() => loadPolicy(invalidPolicyPath)).toThrow(/Policy validation error/);
    });
  });

  describe("Safe Config Fixer (mcp-shield fix)", () => {
    const rawDummyKey = "sk-ant-api03-testdummykey999999999999";

    it("dry-run displays planned changes and leaves target file unmodified", () => {
      const configPath = path.join(tempDir, "mcp.json");
      const originalJson = JSON.stringify(
        {
          mcpServers: {
            anthropicServer: {
              command: "node",
              args: ["index.js"],
              env: {
                ANTHROPIC_API_KEY: rawDummyKey,
              },
            },
          },
        },
        null,
        2
      );
      fs.writeFileSync(configPath, originalJson, "utf-8");

      const fixResult = executeSafeFix(configPath, true);
      expect(fixResult.isDryRun).toBe(true);
      expect(fixResult.plannedExtractions.length).toBe(1);
      expect(fixResult.plannedExtractions[0]?.key).toBe("ANTHROPIC_API_KEY");

      // Original file must be completely untouched
      const afterContent = fs.readFileSync(configPath, "utf-8");
      expect(afterContent).toBe(originalJson);

      // No .bak or .env.mcp should be created in dry-run
      const files = fs.readdirSync(tempDir);
      expect(files.some((f) => f.endsWith(".bak"))).toBe(false);
      expect(files.includes(".env.mcp")).toBe(false);
    });

    it("real fix creates timestamped .bak backup and extracts secrets to .env.mcp", () => {
      const configPath = path.join(tempDir, "mcp.json");
      const originalJson = JSON.stringify(
        {
          mcpServers: {
            anthropicServer: {
              command: "node",
              args: ["index.js"],
              env: {
                ANTHROPIC_API_KEY: rawDummyKey,
              },
            },
          },
        },
        null,
        2
      );
      fs.writeFileSync(configPath, originalJson, "utf-8");

      const fixResult = executeSafeFix(configPath, false);
      expect(fixResult.isDryRun).toBe(false);
      expect(fixResult.backupFile).toBeDefined();
      expect(fs.existsSync(fixResult.backupFile!)).toBe(true);

      // Backup content matches original
      const backupContent = fs.readFileSync(fixResult.backupFile!, "utf-8");
      expect(backupContent).toBe(originalJson);

      // .env.mcp created with extracted key
      const envPath = path.join(tempDir, ".env.mcp");
      expect(fs.existsSync(envPath)).toBe(true);
      const envContent = fs.readFileSync(envPath, "utf-8");
      expect(envContent).toContain(`ANTHROPIC_API_KEY=${rawDummyKey}`);

      // Target config updated with ${ANTHROPIC_API_KEY} variable reference
      const updatedConfig = fs.readFileSync(configPath, "utf-8");
      expect(updatedConfig).toContain("${ANTHROPIC_API_KEY}");
      expect(updatedConfig.includes(rawDummyKey)).toBe(false);
    });
  });

  describe("Tamper-Evident SHA-256 Audit Log", () => {
    it("creates hash-chained audit log and verifies intact entries", () => {
      const logFile = path.join(tempDir, "audit.jsonl");

      const e1 = appendAuditEntry(
        {
          eventType: "scan",
          action: "SCAN_COMPLETE",
          details: { score: 100, findingsCount: 0 },
        },
        logFile
      );
      expect(e1.seq).toBe(1);
      expect(e1.prevHash).toBe("0".repeat(64));
      expect(e1.entryHash.length).toBe(64);

      const e2 = appendAuditEntry(
        {
          eventType: "proxy",
          action: "BLOCK",
          ruleId: "MS-001",
          owaspId: "MCP01:2025",
          details: { path: ".env" },
        },
        logFile
      );
      expect(e2.seq).toBe(2);
      expect(e2.prevHash).toBe(e1.entryHash);

      const verifyRes = verifyAuditLog(logFile);
      expect(verifyRes.valid).toBe(true);
      expect(verifyRes.totalEntries).toBe(2);

      // Truncation detection test
      const truncationCheck = verifyAuditLog(logFile, 3);
      expect(truncationCheck.valid).toBe(false);
      expect(truncationCheck.errorReason).toContain("Truncation detected");

      const tail = getAuditTail(10, logFile);
      expect(tail.length).toBe(2);
      expect(tail[1]?.action).toBe("BLOCK");
    });

    it("detects tampering when an audit log entry is modified", () => {
      const logFile = path.join(tempDir, "tamper_audit.jsonl");

      appendAuditEntry(
        {
          eventType: "scan",
          action: "SCAN_COMPLETE",
          details: { score: 100 },
        },
        logFile
      );
      appendAuditEntry(
        {
          eventType: "proxy",
          action: "BLOCK",
          ruleId: "MS-001",
          details: { reason: "blocked access" },
        },
        logFile
      );

      // Modify line 1 manually
      const content = fs.readFileSync(logFile, "utf-8");
      const lines = content.trim().split("\n");
      const tamperedLine = lines[0]!.replace("SCAN_COMPLETE", "ALLOW");
      lines[0] = tamperedLine;
      fs.writeFileSync(logFile, lines.join("\n") + "\n", "utf-8");

      const verifyRes = verifyAuditLog(logFile);
      expect(verifyRes.valid).toBe(false);
      expect(verifyRes.errorLine).toBe(1);
      expect(verifyRes.errorReason).toContain("Tamper detected");
    });
  });

  describe("SARIF 2.1.0 Exporter", () => {
    it("generates valid SARIF 2.1.0 report matching GitHub Code Scanning schema", () => {
      const mockScanResult: ScanResult = {
        scannedFiles: ["/repo/mcp.json"],
        serversCount: 1,
        score: 65,
        grade: "C",
        timestamp: "2026-11-24T12:00:00.000Z",
        findings: [
          {
            ruleId: "MS-001",
            owaspId: "MCP01:2025",
            severity: "critical",
            title: "Hardcoded API Key",
            message: "Server exposes hardcoded secret.",
            file: "D:/repo/mcp.json",
            serverName: "test-server",
            fixSuggestion: "Move secret to .env.mcp",
          },
          {
            ruleId: "MS-004",
            owaspId: "MCP04:2025",
            severity: "medium",
            title: "Unpinned Package",
            message: "Server runs unpinned package.",
            file: "D:/repo/mcp.json",
            serverName: "test-server",
            fixSuggestion: "Pin package version",
          },
        ],
      };

      const sarif = generateSarifReport(mockScanResult);
      expect(sarif.$schema).toBe("https://json.schemastore.org/sarif-2.1.0.json");
      expect(sarif.version).toBe("2.1.0");
      expect(sarif.runs.length).toBe(1);

      const run = sarif.runs[0]!;
      expect(run.tool.driver.name).toBe("mcp-shield");
      expect(run.tool.driver.rules.length).toBe(2);

      const ruleIds = run.tool.driver.rules.map((r) => r.id);
      expect(ruleIds).toContain("MS-001");
      expect(ruleIds).toContain("MS-004");

      expect(run.results.length).toBe(2);
      expect(run.results[0]?.ruleId).toBe("MS-001");
      expect(run.results[0]?.level).toBe("error");
      expect(run.results[1]?.ruleId).toBe("MS-004");
      expect(run.results[1]?.level).toBe("warning");
    });
  });
});
