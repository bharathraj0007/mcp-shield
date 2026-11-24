import * as fs from "node:fs";
import * as path from "node:path";
import { parse as parseJsonc } from "jsonc-parser";
import pc from "picocolors";
import { maskSecret } from "../scanner/rules.js";

const SECRET_DETECTION_PATTERNS: readonly RegExp[] = [
  /\b(sk-[a-zA-Z0-9_\-]{20,})\b/,
  /\b(sk-ant-[a-zA-Z0-9_\-]{20,})\b/,
  /\b(ghp_[a-zA-Z0-9]{36})\b/,
  /\b(github_pat_[a-zA-Z0-9_]{22,})\b/,
  /\b(AKIA[0-9A-Z]{16})\b/,
  /\b(AIza[0-9A-Za-z-_]{35})\b/,
  /\b(xox[baprs]-[0-9a-zA-Z]{10,})\b/,
  /\b(sk_live_[0-9a-zA-Z]{24,})\b/,
  /\bBearer\s+([a-zA-Z0-9_\-\.]{20,})\b/i,
];

export interface FixPlanItem {
  readonly serverName: string;
  readonly key: string;
  readonly rawValue: string;
}

export interface FixResult {
  readonly targetFile: string;
  readonly isDryRun: boolean;
  readonly plannedExtractions: readonly FixPlanItem[];
  readonly backupFile?: string;
  readonly envFile?: string;
}

function isSecretValue(val: string): boolean {
  if (val.startsWith("${") && val.endsWith("}")) return false;
  for (const pat of SECRET_DETECTION_PATTERNS) {
    if (pat.test(val)) return true;
  }
  // Shannon entropy check for high entropy strings
  if (val.length >= 24 && !val.includes(" ") && !val.includes("/") && !val.includes("\\")) {
    return true;
  }
  return false;
}

export function executeSafeFix(targetFilePath: string, isDryRun: boolean = false): FixResult {
  const resolvedPath = path.resolve(targetFilePath);
  if (!fs.existsSync(resolvedPath)) {
    throw new Error(`Target configuration file not found: ${targetFilePath}`);
  }

  const rawContent = fs.readFileSync(resolvedPath, "utf-8");
  const parsed = parseJsonc(rawContent, undefined, { allowTrailingComma: true });

  if (!parsed || typeof parsed !== "object") {
    throw new Error(`Could not parse JSON in target configuration: ${resolvedPath}`);
  }

  const record = parsed as Record<string, unknown>;
  let serversBlock: Record<string, unknown> | undefined;

  if (record["mcpServers"] && typeof record["mcpServers"] === "object") {
    serversBlock = record["mcpServers"] as Record<string, unknown>;
  } else if (record["servers"] && typeof record["servers"] === "object") {
    serversBlock = record["servers"] as Record<string, unknown>;
  } else if (record["context_servers"] && typeof record["context_servers"] === "object") {
    serversBlock = record["context_servers"] as Record<string, unknown>;
  }

  if (!serversBlock) {
    return {
      targetFile: resolvedPath,
      isDryRun,
      plannedExtractions: [],
    };
  }

  const plannedExtractions: FixPlanItem[] = [];

  for (const [serverName, serverVal] of Object.entries(serversBlock)) {
    if (!serverVal || typeof serverVal !== "object") continue;
    const s = serverVal as { env?: Record<string, unknown> };
    if (!s.env || typeof s.env !== "object") continue;

    for (const [k, v] of Object.entries(s.env)) {
      if (typeof v === "string" && isSecretValue(v)) {
        plannedExtractions.push({
          serverName,
          key: k,
          rawValue: v,
        });
      }
    }
  }

  if (plannedExtractions.length === 0) {
    return {
      targetFile: resolvedPath,
      isDryRun,
      plannedExtractions: [],
    };
  }

  if (isDryRun) {
    console.log(pc.bold(pc.cyan("\n=== mcp-shield Safe Fix Plan (Dry Run) ===")));
    console.log(pc.gray(`Target: ${resolvedPath}\n`));
    for (const item of plannedExtractions) {
      console.log(
        `  ${pc.yellow("•")} Server "${item.serverName}": Extract ${pc.bold(item.key)}=${maskSecret(item.rawValue)} -> \${${item.key}}`
      );
    }
    console.log(pc.dim("\nDry run active. No files were modified on disk.\n"));
    return {
      targetFile: resolvedPath,
      isDryRun: true,
      plannedExtractions,
    };
  }

  // 1. Create timestamped backup file
  const timestamp = new Date().toISOString().replace(/[:.]/g, "-");
  const backupFile = `${resolvedPath}.${timestamp}.bak`;
  fs.writeFileSync(backupFile, rawContent, "utf-8");

  // 2. Write or append to .env.mcp in target file directory
  const targetDir = path.dirname(resolvedPath);
  const envFile = path.join(targetDir, ".env.mcp");

  let existingEnvContent = "";
  if (fs.existsSync(envFile)) {
    existingEnvContent = fs.readFileSync(envFile, "utf-8");
  }

  const newEnvLines: string[] = [];
  for (const item of plannedExtractions) {
    const keyAssignment = `${item.key}=${item.rawValue}`;
    if (!existingEnvContent.includes(item.key + "=")) {
      newEnvLines.push(keyAssignment);
    }
  }

  if (newEnvLines.length > 0) {
    const appendText = (existingEnvContent && !existingEnvContent.endsWith("\n") ? "\n" : "") +
      newEnvLines.join("\n") +
      "\n";
    fs.writeFileSync(envFile, existingEnvContent + appendText, {
      mode: 0o600,
      encoding: "utf-8",
    });
  }

  // 3. Replace inline secrets with ${VAR} references in target config
  let updatedContent = rawContent;
  for (const item of plannedExtractions) {
    // Replace the exact quoted raw secret value with "${KEY}"
    const targetPattern = JSON.stringify(item.rawValue);
    const replacement = JSON.stringify(`\${${item.key}}`);
    updatedContent = updatedContent.replaceAll(targetPattern, replacement);
  }

  fs.writeFileSync(resolvedPath, updatedContent, "utf-8");

  console.log(pc.bold(pc.green("\n✓ mcp-shield Safe Fix Completed Successfully")));
  console.log(`  Target:  ${resolvedPath}`);
  console.log(`  Backup:  ${backupFile}`);
  console.log(`  Secrets: ${envFile} (mode: 0o600)\n`);

  return {
    targetFile: resolvedPath,
    isDryRun: false,
    plannedExtractions,
    backupFile,
    envFile,
  };
}
