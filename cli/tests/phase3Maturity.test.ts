import { describe, it, expect, beforeAll, afterAll } from "vitest";
import * as fs from "node:fs";
import * as path from "node:path";
import * as os from "node:os";
import {
  loadPolicy,
  validatePolicyFile,
  getPolicyJsonSchema,
  getStarterPolicyContent,
} from "../src/policy/loader.js";
import { parseConfigFile, expandEnvVars, parseSimpleToml } from "../src/scanner/discover.js";
import { checkUnpinnedPackage, RULE_DEFINITIONS } from "../src/scanner/rules.js";
import { runScanEngine, calculateSecurityScore } from "../src/scanner/engine.js";
import { generateCompletions } from "../src/completions/index.js";
import * as mcpShieldLib from "../src/index.js";
import type { NormalizedMcpServer, ScanFinding } from "../src/types/index.js";

describe("Phase 3: Zod Schema, Format Maturity & Programmatic API", () => {
  let tempDir: string;

  beforeAll(() => {
    tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "mcp-shield-p3-"));
  });

  afterAll(() => {
    try {
      if (tempDir) {
        fs.rmSync(tempDir, { recursive: true, force: true });
      }
    } catch {}
  });

  describe("1. Zod-Backed Policy Validation & Inheritance", () => {
    it("validates default policy against Zod schema", () => {
      const defaultYaml = getStarterPolicyContent("default");
      const testFile = path.join(tempDir, "default-policy.yaml");
      fs.writeFileSync(testFile, defaultYaml, "utf-8");

      const res = validatePolicyFile(testFile);
      expect(res.valid).toBe(true);
      expect(res.policy).toBeDefined();
      expect(res.policy?.mode).toBe("enforce");
    });

    it("rejects unknown keys due to .strict() mode", () => {
      const invalidYaml = `version: "1.0"\nmode: "enforce"\nunknownKey: "dangerous"\n`;
      const testFile = path.join(tempDir, "strict-fail.yaml");
      fs.writeFileSync(testFile, invalidYaml, "utf-8");

      const res = validatePolicyFile(testFile);
      expect(res.valid).toBe(false);
      expect(res.errors.some((e) => e.toLowerCase().includes("unrecognized"))).toBe(true);
    });

    it("detects conflicting tool allow/deny rules", () => {
      const conflictYaml = `version: "1.0"\nallowedTools: ["fetch"]\ndeniedTools: ["fetch"]\n`;
      const testFile = path.join(tempDir, "conflict-tools.yaml");
      fs.writeFileSync(testFile, conflictYaml, "utf-8");

      const res = validatePolicyFile(testFile);
      expect(res.valid).toBe(false);
      expect(res.errors.some((e) => e.includes("Conflicting rule: Tool \"fetch\""))).toBe(true);
    });

    it("detects conflicting host allow/deny rules", () => {
      const conflictYaml = `version: "1.0"\nallowedHosts: ["api.github.com"]\ndeniedHosts: ["api.github.com"]\n`;
      const testFile = path.join(tempDir, "conflict-hosts.yaml");
      fs.writeFileSync(testFile, conflictYaml, "utf-8");

      const res = validatePolicyFile(testFile);
      expect(res.valid).toBe(false);
      expect(res.errors.some((e) => e.includes("Conflicting rule: Host \"api.github.com\""))).toBe(true);
    });

    it("detects conflicting path allow/deny rules", () => {
      const conflictYaml = `version: "1.0"\nallowPaths: ["./src/**"]\ndenyPaths: ["./src/**"]\n`;
      const testFile = path.join(tempDir, "conflict-paths.yaml");
      fs.writeFileSync(testFile, conflictYaml, "utf-8");

      const res = validatePolicyFile(testFile);
      expect(res.valid).toBe(false);
      expect(res.errors.some((e) => e.includes("Conflicting rule: Path pattern"))).toBe(true);
    });

    it("resolves inheritance hierarchy and detects circular dependencies", () => {
      const baseYaml = `version: "1.0"\ndenyPaths: ["/root/**"]\n`;
      const baseFile = path.join(tempDir, "base.yaml");
      fs.writeFileSync(baseFile, baseYaml, "utf-8");

      const childYaml = `version: "1.0"\ninherit: ["./base.yaml"]\nallowPaths: ["./workspace/**"]\n`;
      const childFile = path.join(tempDir, "child.yaml");
      fs.writeFileSync(childFile, childYaml, "utf-8");

      const policy = loadPolicy(childFile);
      expect(policy.denyPaths).toContain("/root/**");
      expect(policy.allowPaths).toContain("./workspace/**");

      // Circular test
      const circAYaml = `version: "1.0"\ninherit: ["./circB.yaml"]\n`;
      const circBYaml = `version: "1.0"\ninherit: ["./circA.yaml"]\n`;
      const circAFile = path.join(tempDir, "circA.yaml");
      const circBFile = path.join(tempDir, "circB.yaml");
      fs.writeFileSync(circAFile, circAYaml, "utf-8");
      fs.writeFileSync(circBFile, circBYaml, "utf-8");

      expect(() => loadPolicy(circAFile)).toThrow(/Circular policy inheritance detected/);
    });

    it("generates valid JSON schema for policy", () => {
      const schema = getPolicyJsonSchema();
      expect(schema).toBeDefined();
      expect(typeof schema).toBe("object");
      expect(schema.title).toBe("McpShieldPolicy");
      expect(schema.properties).toHaveProperty("mode");
      expect(schema.properties).toHaveProperty("denyPaths");
      expect(schema.properties).toHaveProperty("allowPaths");
    });
  });

  describe("2. Scanner Format, Path & Discovery Maturity", () => {
    it("parses zero-dependency TOML configuration", () => {
      const tomlContent = `
[mcpServers.sqlite]
command = "uvx"
args = ["mcp-server-sqlite", "--db-path", "./test.db"]

[mcpServers.fetch]
command = "npx"
args = ["-y", "@modelcontextprotocol/server-fetch@1.0.0"]
`;
      const parsed = parseSimpleToml(tomlContent);
      expect(parsed).toHaveProperty("mcpServers");
      const servers = parsed["mcpServers"] as Record<string, any>;
      expect(servers["sqlite"].command).toBe("uvx");
      expect(servers["sqlite"].args).toEqual(["mcp-server-sqlite", "--db-path", "./test.db"]);
      expect(servers["fetch"].command).toBe("npx");
    });

    it("scans YAML and TOML config files directly", () => {
      const yamlFile = path.join(tempDir, "mcp.yaml");
      fs.writeFileSync(
        yamlFile,
        `mcpServers:\n  yamlServer:\n    command: "node"\n    args: ["server.js"]\n`,
        "utf-8"
      );
      const yamlServers = parseConfigFile(yamlFile, "custom");
      expect(yamlServers).toHaveLength(1);
      expect(yamlServers[0]?.serverName).toBe("yamlServer");

      const tomlFile = path.join(tempDir, "mcp.toml");
      fs.writeFileSync(
        tomlFile,
        `[mcpServers.tomlServer]\ncommand = "python"\nargs = ["server.py"]\n`,
        "utf-8"
      );
      const tomlServers = parseConfigFile(tomlFile, "custom");
      expect(tomlServers).toHaveLength(1);
      expect(tomlServers[0]?.serverName).toBe("tomlServer");
    });

    it("expands environment variables safely without shell execution", () => {
      process.env["MCP_TEST_VAR_1"] = "my-secret-val";
      const expanded = expandEnvVars("api-key=${MCP_TEST_VAR_1}-suffix and $MCP_TEST_VAR_1");
      expect(expanded).toBe("api-key=my-secret-val-suffix and my-secret-val");

      const untouched = expandEnvVars("${NON_EXISTENT_VAR_xyz}");
      expect(untouched).toBe("${NON_EXISTENT_VAR_xyz}");
    });

    it("resolves relative command paths against config directory", () => {
      const configFile = path.join(tempDir, "sub", "mcp.json");
      fs.mkdirSync(path.dirname(configFile), { recursive: true });
      fs.writeFileSync(
        configFile,
        JSON.stringify({
          mcpServers: {
            relServer: {
              command: "./run.sh",
              args: ["test"],
            },
          },
        }),
        "utf-8"
      );

      const servers = parseConfigFile(configFile, "custom");
      expect(servers).toHaveLength(1);
      expect(servers[0]?.command).toBe(path.resolve(path.dirname(configFile), "./run.sh"));
    });

    it("detects unpinned Docker and Podman container images in MS-004", () => {
      const unpinnedServer: NormalizedMcpServer = {
        client: "custom",
        configPath: "/test/mcp.json",
        serverName: "dockerServer",
        transport: "stdio",
        command: "docker",
        args: ["run", "-i", "--rm", "-v", "/tmp:/data", "mcp/everything:latest"],
      };

      const findings = checkUnpinnedPackage(unpinnedServer);
      expect(findings).toHaveLength(1);
      expect(findings[0]?.ruleId).toBe("MS-004");
      expect(findings[0]?.title).toContain("Container Image");

      // Pinned container image
      const pinnedServer: NormalizedMcpServer = {
        client: "custom",
        configPath: "/test/mcp.json",
        serverName: "dockerPinned",
        transport: "stdio",
        command: "docker",
        args: ["run", "-i", "--rm", "mcp/everything:1.2.3"],
      };
      expect(checkUnpinnedPackage(pinnedServer)).toHaveLength(0);
    });

    it("computes ScoreBreakdown across all 7 rule categories", () => {
      const mockFindings: ScanFinding[] = [
        {
          ruleId: "MS-001",
          owaspId: "MCP01:2025",
          severity: "critical",
          title: "Secret",
          message: "Secret",
          file: "mcp.json",
          serverName: "srv",
          fixSuggestion: "fix",
        },
        {
          ruleId: "MS-004",
          owaspId: "MCP04:2025",
          severity: "medium",
          title: "Supply Chain",
          message: "Unpinned",
          file: "mcp.json",
          serverName: "srv",
          fixSuggestion: "fix",
        },
      ];

      const { score, grade, breakdown } = calculateSecurityScore(mockFindings);
      expect(score).toBe(55); // 100 - 35 (critical) - 10 (medium)
      expect(grade).toBe("D");
      expect(breakdown.secrets).toBe(35);
      expect(breakdown.supplyChain).toBe(10);
      expect(breakdown.commands).toBe(0);
      expect(breakdown.paths).toBe(0);

      const scanResult = runScanEngine([], ["mcp.json"]);
      expect(scanResult.scoreBreakdown).toBeDefined();
      expect(scanResult.score).toBe(100);
      expect(scanResult.grade).toBe("A");
    });
  });

  describe("3. CLI Subcommands & Programmatic Library API", () => {
    it("exports all 7 RULE_DEFINITIONS covering MS-001 through MS-007", () => {
      expect(RULE_DEFINITIONS).toHaveLength(7);
      const ruleIds = RULE_DEFINITIONS.map((r) => r.id);
      expect(ruleIds).toEqual([
        "MS-001",
        "MS-002",
        "MS-003",
        "MS-004",
        "MS-005",
        "MS-006",
        "MS-007",
      ]);

      for (const rule of RULE_DEFINITIONS) {
        expect(rule.remediation).toBeDefined();
        expect(rule.owaspId).toMatch(/^MCP\d{2}:2025$/);
      }
    });

    it("generates shell completion scripts for all 4 supported shells", () => {
      const bash = generateCompletions("bash");
      expect(bash).toContain("_mcp_shield_completions");

      const zsh = generateCompletions("zsh");
      expect(zsh).toContain("#compdef mcp-shield");

      const fish = generateCompletions("fish");
      expect(fish).toContain("complete -c mcp-shield");

      const powershell = generateCompletions("powershell");
      expect(powershell).toContain("Register-ArgumentCompleter");

      expect(() => generateCompletions("cmd")).toThrow(/Unsupported shell/);
    });

    it("exports side-effect-free programmatic functions from index.js", () => {
      expect(typeof mcpShieldLib.discoverConfigs).toBe("function");
      expect(typeof mcpShieldLib.runScanEngine).toBe("function");
      expect(typeof mcpShieldLib.calculateSecurityScore).toBe("function");
      expect(typeof mcpShieldLib.evaluateRequest).toBe("function");
      expect(typeof mcpShieldLib.startStdioProxy).toBe("function");
      expect(typeof mcpShieldLib.loadPolicy).toBe("function");
      expect(typeof mcpShieldLib.validatePolicyFile).toBe("function");
      expect(typeof mcpShieldLib.getPolicyJsonSchema).toBe("function");
      expect(typeof mcpShieldLib.executeSafeFix).toBe("function");
      expect(typeof mcpShieldLib.verifyAuditLog).toBe("function");
      expect(typeof mcpShieldLib.generateSarifReport).toBe("function");
      expect(typeof mcpShieldLib.generateCompletions).toBe("function");
    });
  });
});
