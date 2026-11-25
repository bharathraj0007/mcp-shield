import * as fs from "node:fs";
import * as path from "node:path";
import * as crypto from "node:crypto";
import { parseTree, findNodeAtLocation, modify, applyEdits } from "jsonc-parser";
import pc from "picocolors";
import { maskSecret, isSafePlaceholder } from "../scanner/rules.js";

const SECRET_DETECTION_PATTERNS: readonly RegExp[] = [
  /\b(sk-[a-zA-Z0-9_\-]{20,})\b/,
  /\b(sk-ant-[a-zA-Z0-9_\-]{20,})\b/,
  /\b(ghp_[a-zA-Z0-9]{36})\b/,
  /\b(github_pat_[a-zA-Z0-9_]{22,})\b/,
  /\b(AKIA[0-9A-Z]{16})\b/,
  /\b(AIza[0-9A-Za-z-_]{35})\b/,
  /\b(xox[baprs]-[0-9a-zA-Z]{10,})\b/,
  /\b(sk_live_[0-9a-zA-Z]{24,})\b/,
  /\b(npm_[a-zA-Z0-9]{36})\b/,
  /(?:AccountKey|SharedAccessSignature)=([a-zA-Z0-9+/=]{20,})/i,
  /\b(SK[0-9a-fA-F]{32})\b/,
  /\b(ey[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,})\b/,
  /-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----/,
  /(?:postgres|postgresql|mysql|mongodb|mongodb\+srv|redis|amqp|mssql):\/\/[^:\s]+:([^@\s]+)@/i,
  /\bBearer\s+([a-zA-Z0-9_\-\.]{20,})\b/i,
  /\bBasic\s+([a-zA-Z0-9+/=]{16,})\b/i,
];

const SENSITIVE_KEY_NAME_REGEX =
  /(?:api[_-]?key|secret|token|auth|password|passwd|credential|private[_-]?key|access[_-]?key)/i;

export interface FixPlanItem {
  readonly serverName: string;
  readonly jsonPath: (string | number)[];
  readonly originalKey: string;
  readonly targetEnvKey: string;
  readonly key?: string;
  readonly rawValue: string;
  readonly collisionDetected?: boolean;
}

export interface FixCollision {
  readonly serverName: string;
  readonly originalKey: string;
  readonly generatedKey: string;
  readonly existingValueMasked: string;
  readonly newValueMasked: string;
}

export interface FixResult {
  readonly targetFile: string;
  readonly isDryRun: boolean;
  readonly plannedExtractions: readonly FixPlanItem[];
  readonly backupFile?: string | undefined;
  readonly envBackupFile?: string | undefined;
  readonly envFile?: string | undefined;
  readonly collisions?: readonly FixCollision[] | undefined;
  readonly rolledBack?: boolean | undefined;
}

export interface FixOptions {
  readonly targetPath: string;
  readonly isDryRun?: boolean | undefined;
  readonly isJson?: boolean | undefined;
  readonly yes?: boolean | undefined;
  readonly envFile?: string | undefined;
  readonly rollback?: string | undefined;
}

function isSecretValue(val: string, keyName?: string): boolean {
  if (isSafePlaceholder(val)) return false;
  for (const pat of SECRET_DETECTION_PATTERNS) {
    if (pat.test(val)) return true;
  }
  // Contextual check: sensitive key name and non-trivial string
  if (keyName && SENSITIVE_KEY_NAME_REGEX.test(keyName) && val.length >= 16) {
    // Exclude filesystem paths
    if (
      !val.startsWith("/") &&
      !val.startsWith("./") &&
      !val.startsWith("../") &&
      !/^[a-zA-Z]:[\\/]/.test(val)
    ) {
      return true;
    }
  }
  return false;
}

function parseEnvFile(content: string): {
  lines: string[];
  keyMap: Map<string, string>;
} {
  const lines = content.split(/\r?\n/);
  const keyMap = new Map<string, string>();

  for (const line of lines) {
    const trimmed = line.trim();
    if (!trimmed || trimmed.startsWith("#")) continue;
    const eqIdx = line.indexOf("=");
    if (eqIdx !== -1) {
      const k = line.slice(0, eqIdx).trim();
      let v = line.slice(eqIdx + 1).trim();
      if ((v.startsWith('"') && v.endsWith('"')) || (v.startsWith("'") && v.endsWith("'"))) {
        v = v.slice(1, -1);
      }
      keyMap.set(k, v);
    }
  }

  return { lines, keyMap };
}

function formatEnvValue(val: string): string {
  if (val.includes("\0")) {
    throw new Error("Secret value contains forbidden null byte");
  }
  const escaped = val.replace(/\\/g, "\\\\").replace(/"/g, '\\"').replace(/\n/g, "\\n");
  if (val.includes(" ") || val.includes('"') || val.includes("'") || val.includes("\n") || val.includes("=")) {
    return `"${escaped}"`;
  }
  return val;
}

function readTextFileSecurely(filePath: string, symlinkErrorMessage?: string): string {
  const resolved = path.resolve(filePath);

  const noFollowFlag = fs.constants.O_NOFOLLOW ?? 0;
  let fd: number;
  try {
    fd = fs.openSync(resolved, fs.constants.O_RDONLY | noFollowFlag);
  } catch (openErr: unknown) {
    const code = (openErr as NodeJS.ErrnoException).code;
    if (code === "ELOOP") {
      throw new Error(symlinkErrorMessage || `Refusing to access symbolic link: ${resolved}`);
    }
    if (code === "EINVAL" && noFollowFlag !== 0) {
      fd = fs.openSync(resolved, fs.constants.O_RDONLY);
    } else {
      throw openErr;
    }
  }

  try {
    const stat = fs.fstatSync(fd);
    if (!stat.isFile()) {
      throw new Error(`Expected a regular file: ${resolved}`);
    }
    return fs.readFileSync(fd, "utf-8");
  } finally {
    try {
      fs.closeSync(fd);
    } catch {}
  }
}

function writeTextFileAtomically(targetPath: string, content: string, mode: number = 0o644): void {
  const resolved = path.resolve(targetPath);
  const targetDir = path.dirname(resolved);
  const tmpPath = path.join(
    targetDir,
    `.${path.basename(resolved)}.tmp.${crypto.randomBytes(16).toString("hex")}`
  );

  const fd = fs.openSync(
    tmpPath,
    fs.constants.O_WRONLY | fs.constants.O_CREAT | fs.constants.O_EXCL,
    mode
  );
  try {
    fs.writeFileSync(fd, content, "utf-8");
    fs.fsyncSync(fd);
  } finally {
    try {
      fs.closeSync(fd);
    } catch {}
  }

  try {
    fs.renameSync(tmpPath, resolved);
  } catch (renameErr) {
    try {
      fs.unlinkSync(tmpPath);
    } catch {}
    throw renameErr;
  }
}

export function executeRollback(backupPath: string): FixResult {
  const resolvedBackup = path.resolve(backupPath);
  let backupContent: string;
  try {
    backupContent = readTextFileSecurely(
      resolvedBackup,
      `Refusing to restore from symbolic link: ${backupPath}`
    );
  } catch (err: unknown) {
    if ((err as Error).message.includes("symbolic link")) throw err;
    throw new Error(`Backup file not found: ${backupPath}`);
  }

  let targetConfig = resolvedBackup;
  if (resolvedBackup.endsWith(".bak")) {
    const withoutBak = resolvedBackup.slice(0, -4);
    const lastDot = withoutBak.lastIndexOf(".");
    if (lastDot !== -1) {
      const suffix = withoutBak.slice(lastDot + 1);
      // Bounded linear-time pattern without leading wildcard backtracking
      if (/^\d{4}-\d{2}-\d{2}T[0-9a-zA-Z_\-]+$/.test(suffix)) {
        targetConfig = withoutBak.slice(0, lastDot);
      } else {
        targetConfig = withoutBak;
      }
    } else {
      targetConfig = withoutBak;
    }
  }

  writeTextFileAtomically(targetConfig, backupContent, 0o644);

  // Check if matching .env.mcp backup exists
  const targetDir = path.dirname(targetConfig);
  let envBackupFound: string | undefined;
  const envFile = path.join(targetDir, ".env.mcp");

  // Look for .env.mcp.<timestamp>.bak
  try {
    const entries = fs.readdirSync(targetDir);
    const envBaks = entries
      .filter((e) => e.startsWith(".env.mcp") && e.endsWith(".bak"))
      .sort()
      .reverse();
    if (envBaks.length > 0 && envBaks[0]) {
      envBackupFound = path.join(targetDir, envBaks[0]);
      const envContent = readTextFileSecurely(envBackupFound);
      writeTextFileAtomically(envFile, envContent, 0o600);
    }
  } catch {}

  return {
    targetFile: targetConfig,
    isDryRun: false,
    plannedExtractions: [],
    backupFile: resolvedBackup,
    envBackupFile: envBackupFound,
    rolledBack: true,
  };
}

export function executeSafeFix(
  targetPathOrOptions: string | FixOptions,
  isDryRun: boolean = false,
  extraOptions?: Partial<FixOptions>
): FixResult {
  const options: FixOptions =
    typeof targetPathOrOptions === "string"
      ? {
          targetPath: targetPathOrOptions,
          isDryRun,
          ...extraOptions,
        }
      : targetPathOrOptions;
  if (options.rollback) {
    return executeRollback(options.rollback);
  }

  const resolvedPath = path.resolve(options.targetPath);
  let rawContent: string;
  try {
    rawContent = readTextFileSecurely(
      resolvedPath,
      `Refusing to modify symbolic link: ${resolvedPath}`
    );
  } catch (err: unknown) {
    if ((err as Error).message.includes("symbolic link")) throw err;
    throw new Error(`Target configuration file not found: ${options.targetPath}`);
  }

  const rootNode = parseTree(rawContent, undefined, { allowTrailingComma: true });

  if (!rootNode || rootNode.type !== "object") {
    throw new Error(`Could not parse JSON in target configuration: ${resolvedPath}`);
  }

  // Identify servers block location: mcpServers, servers, or context_servers
  let serversKey = "mcpServers";
  let serversNode = findNodeAtLocation(rootNode, ["mcpServers"]);
  if (!serversNode) {
    serversNode = findNodeAtLocation(rootNode, ["servers"]);
    if (serversNode) serversKey = "servers";
  }
  if (!serversNode) {
    serversNode = findNodeAtLocation(rootNode, ["context_servers"]);
    if (serversNode) serversKey = "context_servers";
  }

  if (!serversNode || serversNode.type !== "object" || !serversNode.children) {
    return {
      targetFile: resolvedPath,
      isDryRun: Boolean(options.isDryRun),
      plannedExtractions: [],
    };
  }

  // Target .env.mcp file
  const targetDir = path.dirname(resolvedPath);
  const envFile = options.envFile ? path.resolve(options.envFile) : path.join(targetDir, ".env.mcp");

  // Read existing .env.mcp if present
  let existingEnvContent = "";
  let existingKeyMap = new Map<string, string>();
  try {
    existingEnvContent = readTextFileSecurely(
      envFile,
      `Refusing to write to symbolic link env file: ${envFile}`
    );
    const parsedEnv = parseEnvFile(existingEnvContent);
    existingKeyMap = parsedEnv.keyMap;
  } catch (err: unknown) {
    if ((err as Error).message.includes("symbolic link")) {
      throw err;
    }
    const code = (err as NodeJS.ErrnoException).code;
    if (code !== "ENOENT") {
      throw err;
    }
  }

  const plannedExtractions: FixPlanItem[] = [];
  const collisions: FixCollision[] = [];
  const allocatedKeys = new Map<string, string>(existingKeyMap);

  for (const serverProp of serversNode.children) {
    if (serverProp.type !== "property" || !serverProp.children || serverProp.children.length < 2) continue;
    const serverNameNode = serverProp.children[0];
    const serverObjNode = serverProp.children[1];
    if (!serverNameNode || !serverObjNode || serverObjNode.type !== "object") continue;

    const serverName = String(serverNameNode.value);

    // 1. Inspect env property
    const envProp = serverObjNode.children?.find(
      (c) => c.children?.[0]?.value === "env" && c.children[1]?.type === "object"
    );

    if (envProp && envProp.children && envProp.children[1]) {
      const envObjNode = envProp.children[1];
      if (envObjNode.children) {
        for (const kvProp of envObjNode.children) {
          if (kvProp.type !== "property" || !kvProp.children || kvProp.children.length < 2) continue;
          const kNode = kvProp.children[0];
          const vNode = kvProp.children[1];
          if (!kNode || !vNode || vNode.type !== "string") continue;

          const key = String(kNode.value);
          const rawVal = String(vNode.value);

          if (isSecretValue(rawVal, key)) {
            let targetEnvKey = key;
            let collisionDetected = false;

            // Check if key already exists in .env.mcp
            if (allocatedKeys.has(key)) {
              const existingVal = allocatedKeys.get(key)!;
              if (existingVal !== rawVal) {
                // Collision!
                collisionDetected = true;
                const cleanServer = serverName.toUpperCase().replace(/[^A-Z0-9_]/g, "_");
                let candidate = `${cleanServer}_${key}`;
                let counter = 1;
                while (allocatedKeys.has(candidate) && allocatedKeys.get(candidate) !== rawVal) {
                  candidate = `${cleanServer}_${key}_${counter}`;
                  counter++;
                }
                targetEnvKey = candidate;
                collisions.push({
                  serverName,
                  originalKey: key,
                  generatedKey: candidate,
                  existingValueMasked: maskSecret(existingVal),
                  newValueMasked: maskSecret(rawVal),
                });
              }
            }

            allocatedKeys.set(targetEnvKey, rawVal);

            plannedExtractions.push({
              serverName,
              jsonPath: [serversKey, serverName, "env", key],
              originalKey: key,
              targetEnvKey,
              key: targetEnvKey,
              rawValue: rawVal,
              collisionDetected,
            });
          }
        }
      }
    }
  }

  if (plannedExtractions.length === 0) {
    if (options.isJson) {
      process.stdout.write(
        JSON.stringify(
          {
            targetFile: resolvedPath,
            isDryRun: Boolean(options.isDryRun),
            plannedExtractions: [],
            collisions: [],
            message: "No unextracted secrets found in configuration.",
          },
          null,
          2
        ) + "\n"
      );
    } else {
      console.log(pc.green("\n✓ No unextracted secrets detected in target configuration."));
    }
    return {
      targetFile: resolvedPath,
      isDryRun: Boolean(options.isDryRun),
      plannedExtractions: [],
      collisions: [],
    };
  }

  // Handle dry-run output
  if (options.isDryRun) {
    if (options.isJson) {
      process.stdout.write(
        JSON.stringify(
          {
            targetFile: resolvedPath,
            isDryRun: true,
            plannedExtractions,
            collisions,
          },
          null,
          2
        ) + "\n"
      );
    } else {
      console.log(pc.bold(pc.cyan("\n=== mcp-shield Safe Fix Plan (Dry Run) ===")));
      console.log(pc.gray(`Target: ${resolvedPath}\n`));
      for (const item of plannedExtractions) {
        const collisionNotice = item.collisionDetected
          ? pc.yellow(` [Collision: auto-renamed to ${item.targetEnvKey}]`)
          : "";
        console.log(
          `  ${pc.yellow("•")} Server "${item.serverName}": Extract ${pc.bold(item.originalKey)}=${maskSecret(item.rawValue)} -> \${${item.targetEnvKey}}${collisionNotice}`
        );
      }
      if (collisions.length > 0) {
        console.log(pc.yellow(`\nNotice: ${collisions.length} key collisions detected and resolved with server prefixes.`));
      }
      console.log(pc.dim("\nDry run active. No files were modified on disk.\n"));
    }
    return {
      targetFile: resolvedPath,
      isDryRun: true,
      plannedExtractions,
      collisions,
    };
  }

  // 1. Create backups
  const timestamp = new Date().toISOString().replace(/[:.]/g, "-");
  const configBackupFile = `${resolvedPath}.${timestamp}.bak`;
  writeTextFileAtomically(configBackupFile, rawContent, 0o644);

  let envBackupFile: string | undefined;
  if (existingEnvContent) {
    envBackupFile = `${envFile}.${timestamp}.bak`;
    writeTextFileAtomically(envBackupFile, existingEnvContent, 0o600);
  }

  // 2. Perform structure-preserving JSONC edit
  let updatedContent = rawContent;
  for (const item of plannedExtractions) {
    const edits = modify(updatedContent, item.jsonPath, `\${${item.targetEnvKey}}`, {
      formattingOptions: { insertSpaces: true, tabSize: 2 },
    });
    updatedContent = applyEdits(updatedContent, edits);
  }

  // 3. Format and update .env.mcp content
  const newEnvLines: string[] = [];
  const writtenKeys = new Set<string>();

  for (const item of plannedExtractions) {
    if (writtenKeys.has(item.targetEnvKey)) continue;
    // Only append if not already in existing file with same value
    if (existingKeyMap.get(item.targetEnvKey) === item.rawValue) continue;

    const formatted = `${item.targetEnvKey}=${formatEnvValue(item.rawValue)}`;
    newEnvLines.push(formatted);
    writtenKeys.add(item.targetEnvKey);
  }

  let finalEnvContent = existingEnvContent;
  if (newEnvLines.length > 0) {
    const separator = finalEnvContent && !finalEnvContent.endsWith("\n") ? "\n" : "";
    finalEnvContent = finalEnvContent + separator + newEnvLines.join("\n") + "\n";
  }

  // 4. Atomic file write via temp files
  const tmpConfig = path.join(
    targetDir,
    `.${path.basename(resolvedPath)}.tmp.${crypto.randomBytes(16).toString("hex")}`
  );
  const tmpEnv = path.join(
    targetDir,
    `.${path.basename(envFile)}.tmp.${crypto.randomBytes(16).toString("hex")}`
  );

  try {
    const configFd = fs.openSync(
      tmpConfig,
      fs.constants.O_WRONLY | fs.constants.O_CREAT | fs.constants.O_EXCL,
      0o644
    );
    try {
      fs.writeFileSync(configFd, updatedContent, "utf-8");
      fs.fsyncSync(configFd);
    } finally {
      try {
        fs.closeSync(configFd);
      } catch {}
    }

    const envFd = fs.openSync(
      tmpEnv,
      fs.constants.O_WRONLY | fs.constants.O_CREAT | fs.constants.O_EXCL,
      0o600
    );
    try {
      fs.writeFileSync(envFd, finalEnvContent, "utf-8");
      fs.fsyncSync(envFd);
    } finally {
      try {
        fs.closeSync(envFd);
      } catch {}
    }

    // Atomic renames
    fs.renameSync(tmpConfig, resolvedPath);
    fs.renameSync(tmpEnv, envFile);
  } catch (err) {
    // Rollback on partial failure
    try {
      try {
        fs.unlinkSync(tmpConfig);
      } catch {}
      try {
        fs.unlinkSync(tmpEnv);
      } catch {}
      if (configBackupFile) {
        writeTextFileAtomically(resolvedPath, rawContent, 0o644);
      }
      if (envBackupFile) {
        writeTextFileAtomically(envFile, existingEnvContent, 0o600);
      }
    } catch {}
    throw new Error(`Atomic write failed: ${(err as Error).message}. Rolled back to original files.`);
  }

  if (options.isJson) {
    process.stdout.write(
      JSON.stringify(
        {
          targetFile: resolvedPath,
          isDryRun: false,
          plannedExtractions,
          backupFile: configBackupFile,
          envBackupFile,
          envFile,
          collisions,
        },
        null,
        2
      ) + "\n"
    );
  } else {
    console.log(pc.bold(pc.green("\n✓ mcp-shield Safe Fix Completed Successfully")));
    console.log(`  Target:  ${resolvedPath}`);
    console.log(`  Backup:  ${configBackupFile}`);
    console.log(`  Secrets: ${envFile} (mode: 0o600)`);
    if (collisions.length > 0) {
      console.log(
        pc.yellow(`  Notice:  ${collisions.length} key collisions resolved with server prefixes.`)
      );
    }
    console.log();
  }

  return {
    targetFile: resolvedPath,
    isDryRun: false,
    plannedExtractions,
    backupFile: configBackupFile,
    envBackupFile,
    envFile,
    collisions,
  };
}
