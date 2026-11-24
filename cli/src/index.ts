import * as fs from "node:fs";
import * as path from "node:path";
import { Command } from "commander";
import pc from "picocolors";
import { discoverConfigs } from "./scanner/discover.js";
import { runScanEngine } from "./scanner/engine.js";
import { printTerminalReport } from "./audit/terminal.js";
import { startStdioProxy } from "./proxy/stdioProxy.js";
import { loadPolicy } from "./policy/loader.js";
import { executeSafeFix } from "./policy/fixer.js";
import { appendAuditEntry, printAuditTerminalReport } from "./audit/logWriter.js";
import { generateSarifReport } from "./audit/sarif.js";

const program = new Command();

program
  .name("mcp-shield")
  .description("100% offline local security CLI for AI coding agents")
  .version("1.0.0");

program
  .command("scan")
  .description("Scan local MCP configurations for security risks")
  .argument("[path]", "Path to directory or config file to scan")
  .option("--json", "Output results in JSON format")
  .option("--format <type>", "Output format: terminal, json, or sarif", "terminal")
  .option("--policy <path>", "Path to custom policy.yaml")
  .option("--ci", "Exit with code 1 if High or Critical risks are found")
  .action((targetPath?: string, options?: { json?: boolean; format?: string; policy?: string; ci?: boolean }) => {
    try {
      const policy = loadPolicy(options?.policy);
      const { servers, scannedFiles } = discoverConfigs(targetPath);
      const result = runScanEngine(servers, scannedFiles, policy);

      const format = options?.json ? "json" : options?.format || "terminal";

      if (format === "sarif") {
        const sarif = generateSarifReport(result);
        process.stdout.write(JSON.stringify(sarif, null, 2) + "\n");
      } else if (format === "json") {
        process.stdout.write(JSON.stringify(result, null, 2) + "\n");
      } else {
        printTerminalReport(result);
      }

      // Record scan in local audit log
      try {
        appendAuditEntry({
          eventType: "scan",
          action: "SCAN_COMPLETE",
          details: {
            scannedFilesCount: scannedFiles.length,
            serversCount: servers.length,
            findingsCount: result.findings.length,
            score: result.score,
            grade: result.grade,
          },
        });
      } catch {
        // Continue if audit writing encounters local disk restriction
      }

      if (options?.ci) {
        const hasFailure = result.findings.some(
          (f) => f.severity === "critical" || f.severity === "high"
        );
        if (hasFailure) {
          process.exitCode = 1;
        }
      }
    } catch (err) {
      process.stderr.write(pc.red(`Error: ${(err as Error).message}\n`));
      process.exitCode = 1;
    }
  });

program
  .command("proxy")
  .description("Run runtime security proxy over stdio JSON-RPC")
  .option("--policy <path>", "Path to custom policy.yaml")
  .argument("<cmd>", "Command to execute")
  .argument("[args...]", "Command arguments")
  .action(async (cmd: string, cmdArgs?: string[], options?: { policy?: string }) => {
    try {
      const policy = loadPolicy(options?.policy);
      const code = await startStdioProxy({
        command: cmd,
        args: cmdArgs || [],
        policy,
        onBlock: (decision, req) => {
          try {
            appendAuditEntry({
              eventType: "proxy",
              action: "BLOCK",
              ruleId: decision.ruleId,
              owaspId: decision.owaspId,
              details: {
                method: req.method,
                reason: decision.reason,
                redactedTarget: decision.redactedTarget,
              },
            });
          } catch {}
        },
      });
      process.exitCode = code;
    } catch (err) {
      process.stderr.write(pc.red(`Proxy error: ${(err as Error).message}\n`));
      process.exitCode = 1;
    }
  });

program
  .command("init")
  .description("Initialize default policy.yaml in the current directory")
  .action(() => {
    const targetPolicy = path.resolve(process.cwd(), "policy.yaml");
    if (fs.existsSync(targetPolicy)) {
      console.log(pc.yellow(`Policy file already exists at: ${targetPolicy}`));
      return;
    }

    const defaultContent = `version: "1.0"
mode: "enforce" # "enforce" | "monitor"
denyPaths:
  - "**/.env"
  - "**/.env.*"
  - "~/.ssh/**"
  - "~/.aws/**"
  - "~/.gnupg/**"
  - "/etc/passwd"
allowPaths:
  - "./src/**"
blockedCommands:
  - "rm -rf"
  - "curl * | sh"
  - "wget * | bash"
  - "chmod 777"
disabledRules: []
allowedServers: [] # Optional allowlist for MS-007 Shadow MCP detection
failOnSeverity: "high" # "critical" | "high" | "medium" | "low"
`;

    fs.writeFileSync(targetPolicy, defaultContent, "utf-8");
    console.log(pc.green(`✓ Initialized starter policy at: ${targetPolicy}`));
  });

program
  .command("fix")
  .description("Safely extract hardcoded secrets into .env.mcp")
  .argument("<path>", "Path to config file to fix")
  .option("--dry-run", "Show planned changes without modifying files")
  .action((targetPath: string, options?: { dryRun?: boolean }) => {
    try {
      executeSafeFix(targetPath, Boolean(options?.dryRun));
    } catch (err) {
      process.stderr.write(pc.red(`Fix error: ${(err as Error).message}\n`));
      process.exitCode = 1;
    }
  });

program
  .command("audit")
  .description("Inspect or verify tamper-evident audit log")
  .option("--verify", "Verify SHA-256 hash chain integrity")
  .option("--tail <n>", "Show last N entries", "20")
  .action((options?: { verify?: boolean; tail?: string }) => {
    const tailNum = options?.tail ? parseInt(options.tail, 10) : 20;
    const ok = printAuditTerminalReport(Boolean(options?.verify), tailNum);
    if (!ok) {
      process.exitCode = 1;
    }
  });

program.parse();
