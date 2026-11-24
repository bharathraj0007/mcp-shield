import * as fs from "node:fs";
import * as path from "node:path";
import { fileURLToPath } from "node:url";
import { Command } from "commander";
import pc from "picocolors";
import { discoverConfigs } from "./scanner/discover.js";
import { runScanEngine, calculateSecurityScore } from "./scanner/engine.js";
import { printTerminalReport } from "./audit/terminal.js";
import { startStdioProxy } from "./proxy/stdioProxy.js";
import { evaluateRequest } from "./proxy/evaluator.js";
import {
  loadPolicy,
  validatePolicyFile,
  getPolicyJsonSchema,
  getStarterPolicyContent,
} from "./policy/loader.js";
import { executeSafeFix } from "./policy/fixer.js";
import {
  appendAuditEntry,
  printAuditTerminalReport,
  verifyAuditLog,
} from "./audit/logWriter.js";
import { generateSarifReport } from "./audit/sarif.js";
import { loadBaseline, filterWithBaseline, updateBaseline } from "./scanner/baseline.js";
import { RULE_DEFINITIONS } from "./scanner/rules.js";
import { generateCompletions } from "./completions/index.js";
import { ExitCode, type RuleSeverity, type ScanResult, type BaselineFile } from "./types/index.js";

// Read package version dynamically
let cliVersion = "0.2.0";
try {
  const currentFilename = fileURLToPath(import.meta.url);
  const currentDir = path.dirname(currentFilename);
  const pkgPath = path.resolve(currentDir, "../package.json");
  const pkg = JSON.parse(fs.readFileSync(pkgPath, "utf-8")) as { version?: string };
  if (pkg.version) {
    cliVersion = pkg.version;
  }
} catch {
  // Fallback to "0.2.0"
}

const SEVERITY_LEVELS: Record<RuleSeverity, number> = {
  low: 1,
  medium: 2,
  high: 3,
  critical: 4,
};

const program = new Command();

program
  .name("mcp-shield")
  .description("100% offline local security CLI for AI coding agents")
  .version(cliVersion)
  .option("--config <path>", "Path to directory or config file to scan")
  .option("--policy <path>", "Path to custom policy.yaml")
  .option("--format <type>", "Output format: terminal, json, or sarif")
  .option("--output <file>", "Write scan report to file instead of stdout")
  .option(
    "--fail-on <severity>",
    "Fail if risks reach or exceed severity: critical, high, medium, low"
  )
  .option("--quiet", "Suppress non-error terminal output")
  .option("--no-color", "Disable colored terminal output")
  .option("--debug", "Enable debug output")
  .option("--offline", "Enforce 100% offline execution");

program
  .command("scan")
  .description("Scan local MCP configurations for security risks")
  .argument("[path]", "Path to directory or config file to scan")
  .option("--json", "Output results in JSON format")
  .option("--format <type>", "Output format: terminal, json, or sarif")
  .option("--policy <path>", "Path to custom policy.yaml")
  .option("--ci", "Exit with code 1 if blocking risks are found")
  .option(
    "--fail-on <severity>",
    "Fail if risks reach or exceed severity: critical, high, medium, low"
  )
  .option("--baseline <file>", "Path to baseline file to suppress accepted findings")
  .option("--baseline-update", "Update baseline file with current findings")
  .option("--changed-only", "Show only new findings not in baseline")
  .option("--output <file>", "Write scan report to file instead of stdout")
  .action(
    (
      targetPath?: string,
      options?: {
        json?: boolean;
        format?: string;
        policy?: string;
        ci?: boolean;
        failOn?: string;
        baseline?: string;
        baselineUpdate?: boolean;
        changedOnly?: boolean;
        output?: string;
      }
    ) => {
      try {
        const globalOpts = program.opts();
        const effectiveTargetPath = targetPath || (globalOpts.config as string | undefined);
        const effectivePolicyPath =
          options?.policy || (globalOpts.policy as string | undefined);
        const effectiveFormat =
          (options?.json ? "json" : undefined) ||
          options?.format ||
          (globalOpts.format as string | undefined) ||
          (globalOpts.json ? "json" : undefined) ||
          "terminal";
        const effectiveOutput = options?.output || (globalOpts.output as string | undefined);
        const effectiveFailOn = options?.failOn || (globalOpts.failOn as string | undefined);

        let policy;
        try {
          policy = loadPolicy(effectivePolicyPath);
        } catch (policyErr) {
          process.stderr.write(pc.red(`Policy error: ${(policyErr as Error).message}\n`));
          process.exitCode = ExitCode.CONFIG_ERROR;
          return;
        }

        const { servers, scannedFiles } = discoverConfigs(effectiveTargetPath);
        const rawResult = runScanEngine(servers, scannedFiles, policy);

        let finalResult: ScanResult = rawResult;

        // Baseline handling
        if (options?.baseline) {
          const baselineData = loadBaseline(options.baseline);
          const { active, suppressed } = filterWithBaseline(
            rawResult.findings,
            baselineData,
            Boolean(options.changedOnly)
          );

          if (options.baselineUpdate) {
            updateBaseline(options.baseline, rawResult.findings);
          }

          finalResult = {
            ...rawResult,
            findings: active,
            activeFindings: active,
            suppressedFindings: suppressed,
          };
        }

        const format = effectiveFormat;
        let formattedOutput = "";

        if (format === "sarif") {
          const sarif = generateSarifReport(finalResult, cliVersion);
          formattedOutput = JSON.stringify(sarif, null, 2) + "\n";
        } else if (format === "json") {
          formattedOutput = JSON.stringify(finalResult, null, 2) + "\n";
        }

        if (effectiveOutput) {
          const outputPath = path.resolve(effectiveOutput);
          const outputDir = path.dirname(outputPath);
          fs.mkdirSync(outputDir, { recursive: true });
          if (format === "terminal") {
            fs.writeFileSync(outputPath, JSON.stringify(finalResult, null, 2) + "\n", "utf-8");
          } else {
            fs.writeFileSync(outputPath, formattedOutput, "utf-8");
          }
        } else {
          if (format === "sarif" || format === "json") {
            process.stdout.write(formattedOutput);
          } else {
            printTerminalReport(finalResult);
          }
        }

        // Record scan in local audit log
        try {
          appendAuditEntry({
            eventType: "scan",
            action: "SCAN_COMPLETE",
            details: {
              scannedFilesCount: scannedFiles.length,
              serversCount: servers.length,
              findingsCount: finalResult.findings.length,
              score: finalResult.score,
              grade: finalResult.grade,
            },
          });
        } catch {
          // Continue if audit writing encounters local disk restriction
        }

        // Determine failure threshold
        let thresholdSeverity: RuleSeverity | undefined;
        if (effectiveFailOn) {
          const inputSeverity = effectiveFailOn.toLowerCase() as RuleSeverity;
          if (SEVERITY_LEVELS[inputSeverity] !== undefined) {
            thresholdSeverity = inputSeverity;
          } else {
            process.stderr.write(pc.red(`Invalid --fail-on severity: ${effectiveFailOn}\n`));
            process.exitCode = ExitCode.USAGE_ERROR;
            return;
          }
        } else if (options?.ci) {
          thresholdSeverity = policy.failOnSeverity || "high";
        }

        if (thresholdSeverity) {
          const minLevel = SEVERITY_LEVELS[thresholdSeverity];
          const hasBlockingFindings = finalResult.findings.some(
            (f) => !f.suppressed && SEVERITY_LEVELS[f.severity] >= minLevel
          );
          if (hasBlockingFindings) {
            process.exitCode = ExitCode.BLOCKING_FINDINGS;
          } else {
            process.exitCode = ExitCode.SUCCESS;
          }
        } else {
          process.exitCode = ExitCode.SUCCESS;
        }
      } catch (err) {
        process.stderr.write(pc.red(`Error: ${(err as Error).message}\n`));
        process.exitCode = ExitCode.INTERNAL_ERROR;
      }
    }
  );

program
  .command("proxy")
  .description("Run runtime security proxy over stdio JSON-RPC")
  .option("--policy <path>", "Path to custom policy.yaml")
  .option("--framing <type>", "Framing protocol: line, content-length, or auto", "auto")
  .option("--approve-rug-pull", "Approve pending tool mutations and update baseline")
  .option("--shutdown-timeout <ms>", "Child process termination timeout in milliseconds", "2000")
  .option("--max-frame-size <bytes>", "Maximum allowed JSON-RPC frame size in bytes", "1048576")
  .argument("<cmd>", "Command to execute")
  .argument("[args...]", "Command arguments")
  .action(
    async (
      cmd: string,
      cmdArgs?: string[],
      options?: {
        policy?: string;
        framing?: string;
        approveRugPull?: boolean;
        shutdownTimeout?: string;
        maxFrameSize?: string;
      }
    ) => {
      try {
        let policy;
        try {
          policy = loadPolicy(options?.policy);
        } catch (policyErr) {
          process.stderr.write(pc.red(`Policy error: ${(policyErr as Error).message}\n`));
          process.exitCode = ExitCode.CONFIG_ERROR;
          return;
        }

        const framingMode = (options?.framing || "auto") as "line" | "content-length" | "auto";
        const shutdownTimeoutMs = options?.shutdownTimeout
          ? parseInt(options.shutdownTimeout, 10)
          : 2000;
        const maxFrameSize = options?.maxFrameSize
          ? parseInt(options.maxFrameSize, 10)
          : 1048576;

        const code = await startStdioProxy({
          command: cmd,
          args: cmdArgs || [],
          policy,
          framing: framingMode,
          shutdownTimeoutMs,
          maxFrameSize,
          approveRugPull: Boolean(options?.approveRugPull),
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
        process.exitCode = ExitCode.PROXY_PROCESS_FAILURE;
      }
    }
  );

const policyCmd = program
  .command("policy")
  .description("Policy validation and schema utilities");

policyCmd
  .command("validate")
  .description("Validate a policy.yaml file against the strict schema")
  .argument("<path>", "Path to policy.yaml file")
  .action((policyPath: string) => {
    try {
      const res = validatePolicyFile(policyPath);
      if (res.valid) {
        console.log(pc.green(`✓ Valid policy: ${path.resolve(policyPath)}`));
        process.exitCode = ExitCode.SUCCESS;
      } else {
        process.stderr.write(
          pc.red(`✗ Invalid policy: ${path.resolve(policyPath)}\n${res.errors.join("\n")}\n`)
        );
        process.exitCode = ExitCode.CONFIG_ERROR;
      }
    } catch (err) {
      process.stderr.write(pc.red(`Policy error: ${(err as Error).message}\n`));
      process.exitCode = ExitCode.CONFIG_ERROR;
    }
  });

policyCmd
  .command("schema")
  .description("Output JSON schema for policy.yaml")
  .action(() => {
    try {
      const schema = getPolicyJsonSchema();
      console.log(JSON.stringify(schema, null, 2));
      process.exitCode = ExitCode.SUCCESS;
    } catch (err) {
      process.stderr.write(pc.red(`Schema error: ${(err as Error).message}\n`));
      process.exitCode = ExitCode.INTERNAL_ERROR;
    }
  });

program
  .command("init")
  .description("Initialize starter policy.yaml in the current directory")
  .option("--policy <path>", "Path to target policy file", "policy.yaml")
  .option(
    "--template <type>",
    "Policy template type: default or strict",
    "default"
  )
  .action((options?: { policy?: string; template?: "default" | "strict" }) => {
    try {
      const targetPolicy = path.resolve(process.cwd(), options?.policy || "policy.yaml");
      const templateType = options?.template === "strict" ? "strict" : "default";
      const content = getStarterPolicyContent(templateType);

      try {
        fs.writeFileSync(targetPolicy, content, { encoding: "utf-8", flag: "wx" });
        console.log(pc.green(`✓ Initialized starter policy (${templateType}) at: ${targetPolicy}`));
        process.exitCode = ExitCode.SUCCESS;
      } catch (writeErr) {
        if ((writeErr as NodeJS.ErrnoException).code === "EEXIST") {
          console.log(pc.yellow(`Policy file already exists at: ${targetPolicy}`));
          process.exitCode = ExitCode.SUCCESS;
          return;
        }
        throw writeErr;
      }
    } catch (err) {
      process.stderr.write(pc.red(`Init error: ${(err as Error).message}\n`));
      process.exitCode = ExitCode.INTERNAL_ERROR;
    }
  });

program
  .command("fix")
  .description("Safely extract hardcoded secrets into .env.mcp")
  .argument("[path]", "Path to config file to fix")
  .option("--dry-run", "Show planned changes without modifying files")
  .option("--yes", "Automatically apply changes without manual prompt")
  .option("--env-file <path>", "Path to target .env.mcp file")
  .option("--rollback <path>", "Roll back changes from a .bak backup file")
  .option("--json", "Output fix report in JSON format")
  .action(
    (
      targetPath?: string,
      options?: {
        dryRun?: boolean;
        yes?: boolean;
        envFile?: string;
        rollback?: string;
        json?: boolean;
      }
    ) => {
      try {
        if (!targetPath && !options?.rollback) {
          process.stderr.write(pc.red("Error: Missing required path argument or --rollback\n"));
          process.exitCode = ExitCode.USAGE_ERROR;
          return;
        }

        executeSafeFix({
          targetPath: targetPath || "",
          isDryRun: Boolean(options?.dryRun),
          yes: Boolean(options?.yes),
          envFile: options?.envFile,
          rollback: options?.rollback,
          isJson: Boolean(options?.json),
        });
        process.exitCode = ExitCode.SUCCESS;
      } catch (err) {
        process.stderr.write(pc.red(`Fix error: ${(err as Error).message}\n`));
        process.exitCode = ExitCode.INTERNAL_ERROR;
      }
    }
  );

program
  .command("audit")
  .description("Inspect or verify tamper-evident audit log")
  .option("--verify", "Verify SHA-256 hash chain integrity")
  .option("--json", "Output audit report or verification status in JSON format")
  .option("--hmac-key <key>", "HMAC-SHA-256 secret key to sign or verify entries")
  .option("--export <file>", "Export verified audit log to specified file path")
  .option("--tail <n>", "Show last N entries", "20")
  .action(
    (options?: {
      verify?: boolean;
      json?: boolean;
      hmacKey?: string;
      export?: string;
      tail?: string;
    }) => {
      try {
        const tailNum = options?.tail ? parseInt(options.tail, 10) : 20;
        const ok = printAuditTerminalReport({
          verifyOnly: Boolean(options?.verify),
          isJson: Boolean(options?.json),
          hmacKey: options?.hmacKey,
          exportPath: options?.export,
          tailCount: tailNum,
        });

        if (!ok) {
          process.exitCode = ExitCode.AUDIT_VERIFICATION_FAILURE;
        } else {
          process.exitCode = ExitCode.SUCCESS;
        }
      } catch (err) {
        process.stderr.write(pc.red(`Audit error: ${(err as Error).message}\n`));
        process.exitCode = ExitCode.AUDIT_VERIFICATION_FAILURE;
      }
    }
  );

program
  .command("rules")
  .description("List all supported security detection rules (MS-001 through MS-007)")
  .option("--json", "Output rules in JSON format")
  .action((options?: { json?: boolean }) => {
    if (options?.json) {
      console.log(JSON.stringify(RULE_DEFINITIONS, null, 2));
      process.exitCode = ExitCode.SUCCESS;
      return;
    }

    console.log(pc.bold("\nmcp-shield Supported Detection Rules\n"));
    for (const rule of RULE_DEFINITIONS) {
      const sevColor =
        rule.severity === "critical"
          ? pc.red
          : rule.severity === "high"
          ? pc.yellow
          : pc.blue;

      console.log(
        `${pc.bold(rule.id)} [${rule.owaspId}] ${sevColor(`[${rule.severity.toUpperCase()}]`)} - ${pc.bold(rule.title)}`
      );
      console.log(`  ${rule.description}`);
      console.log(`  ${pc.dim("Remediation:")} ${rule.remediation}\n`);
    }
    process.exitCode = ExitCode.SUCCESS;
  });

program
  .command("baseline")
  .description("Inspect or manage accepted findings baseline")
  .argument("[path]", "Path to baseline file", ".mcp-shield-baseline.json")
  .option("--json", "Output baseline in JSON format")
  .action((targetPath?: string, options?: { json?: boolean }) => {
    try {
      const baselineFile = path.resolve(process.cwd(), targetPath || ".mcp-shield-baseline.json");
      let content: string;
      try {
        content = fs.readFileSync(baselineFile, "utf-8");
      } catch (err) {
        if ((err as NodeJS.ErrnoException).code === "ENOENT") {
          process.stderr.write(pc.red(`Error: Baseline file not found at: ${baselineFile}\n`));
        } else {
          process.stderr.write(pc.red(`Error: Invalid or unreadable baseline file at: ${baselineFile}\n`));
        }
        process.exitCode = ExitCode.USAGE_ERROR;
        return;
      }

      let data: BaselineFile | undefined;
      try {
        const parsed = JSON.parse(content) as unknown;
        if (
          typeof parsed === "object" &&
          parsed !== null &&
          "findings" in parsed &&
          Array.isArray((parsed as { findings: unknown }).findings)
        ) {
          data = parsed as BaselineFile;
        }
      } catch {}

      if (!data) {
        process.stderr.write(pc.red(`Error: Invalid or unreadable baseline file at: ${baselineFile}\n`));
        process.exitCode = ExitCode.USAGE_ERROR;
        return;
      }

      if (options?.json) {
        console.log(JSON.stringify(data, null, 2));
        process.exitCode = ExitCode.SUCCESS;
        return;
      }

      console.log(pc.bold(`\nBaseline: ${baselineFile}`));
      console.log(`Version: ${data.version}`);
      console.log(`Generated: ${data.generatedAt}`);
      console.log(`Suppressed Findings Count: ${data.findings.length}\n`);

      for (const item of data.findings) {
        console.log(`- ${pc.bold((item.fingerprint || "").slice(0, 12))}... [${item.ruleId}] in ${item.file}`);
        console.log(`  Reason: ${item.reason || "Accepted suppression"} | Server: ${item.server}`);
        if (item.expiresAt) {
          console.log(`  Expires: ${item.expiresAt}`);
        }
      }
      process.exitCode = ExitCode.SUCCESS;
    } catch (err) {
      process.stderr.write(pc.red(`Baseline error: ${(err as Error).message}\n`));
      process.exitCode = ExitCode.INTERNAL_ERROR;
    }
  });

program
  .command("completions")
  .description("Generate shell completion script for bash, zsh, fish, or powershell")
  .argument("<shell>", "Target shell: bash, zsh, fish, or powershell")
  .action((shell: string) => {
    try {
      const script = generateCompletions(shell);
      console.log(script);
      process.exitCode = ExitCode.SUCCESS;
    } catch (err) {
      process.stderr.write(pc.red(`Completions error: ${(err as Error).message}\n`));
      process.exitCode = ExitCode.USAGE_ERROR;
    }
  });

// Programmatic library exports
export {
  discoverConfigs,
  runScanEngine,
  calculateSecurityScore,
  evaluateRequest,
  startStdioProxy,
  loadPolicy,
  validatePolicyFile,
  getPolicyJsonSchema,
  executeSafeFix,
  verifyAuditLog,
  generateSarifReport,
  generateCompletions,
  RULE_DEFINITIONS,
};
export * from "./types/index.js";

export function isMainModule(): boolean {
  if (typeof process === "undefined" || !process.argv || !process.argv[1]) return false;
  try {
    const scriptPath = fs.realpathSync(process.argv[1]);
    const modulePath = fs.realpathSync(fileURLToPath(import.meta.url));
    return scriptPath === modulePath;
  } catch {
    const arg = process.argv[1];
    return arg.endsWith("index.js") || arg.endsWith("mcp-shield");
  }
}

if (isMainModule()) {
  program.parse();
}
