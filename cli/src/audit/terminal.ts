import pc from "picocolors";
import type { ScanResult, RuleSeverity } from "../types/index.js";

function formatSeverity(severity: RuleSeverity): string {
  switch (severity) {
    case "critical":
      return pc.bgRed(pc.white(" CRITICAL "));
    case "high":
      return pc.red(" HIGH ");
    case "medium":
      return pc.yellow(" MEDIUM ");
    case "low":
      return pc.cyan(" LOW ");
  }
}

function formatGrade(grade: string): string {
  switch (grade) {
    case "A":
      return pc.bgGreen(pc.black(" GRADE A "));
    case "B":
      return pc.bgCyan(pc.black(" GRADE B "));
    case "C":
      return pc.bgYellow(pc.black(" GRADE C "));
    case "D":
      return pc.bgMagenta(pc.white(" GRADE D "));
    case "F":
      return pc.bgRed(pc.white(" GRADE F "));
    default:
      return grade;
  }
}

export function printTerminalReport(result: ScanResult): void {
  console.log("\n" + pc.bold(pc.blue("=== mcp-shield Security Scan Report ===")));
  console.log(
    pc.gray(
      `Files Scanned: ${result.scannedFiles.length} | MCP Servers Found: ${result.serversCount}`
    )
  );

  if (result.scannedFiles.length === 0) {
    console.log(
      pc.yellow("\nNo MCP configuration files detected in target location.")
    );
    return;
  }

  if (result.findings.length === 0) {
    console.log("\n" + pc.green("✓ Zero security risks detected across all MCP configurations."));
    console.log("\n" + formatGrade(result.grade) + ` Security Score: ${result.score}/100\n`);
    return;
  }

  console.log("\n" + pc.bold("Detected Security Risks:"));
  console.log(pc.gray("─".repeat(60)));

  for (let i = 0; i < result.findings.length; i++) {
    const f = result.findings[i];
    if (!f) continue;

    console.log(
      `\n${pc.bold(`[${i + 1}]`)} ${formatSeverity(f.severity)} ${pc.bold(f.ruleId)} (${pc.dim(f.owaspId)})`
    );
    console.log(`    ${pc.bold("Title:")}      ${f.title}`);
    console.log(`    ${pc.bold("Server:")}     ${f.serverName}`);
    console.log(`    ${pc.bold("File:")}       ${f.file}`);
    if (f.maskedEvidence) {
      console.log(`    ${pc.bold("Evidence:")}   ${pc.yellow(f.maskedEvidence)}`);
    }
    console.log(`    ${pc.bold("Remedy:")}     ${pc.cyan(f.fixSuggestion)}`);
  }

  console.log("\n" + pc.gray("─".repeat(60)));
  console.log(
    `${formatGrade(result.grade)} Security Score: ${pc.bold(`${result.score}/100`)} (${result.findings.length} findings)`
  );

  const hasFixableSecrets = result.findings.some((f) => f.ruleId === "MS-001");
  if (hasFixableSecrets) {
    console.log(
      pc.dim("\nTip: Run 'mcp-shield fix <path>' to safely extract hardcoded secrets into .env.mcp.")
    );
  }
  console.log();
}
