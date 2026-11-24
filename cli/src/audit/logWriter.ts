import * as fs from "node:fs";
import * as path from "node:path";
import * as os from "node:os";
import * as crypto from "node:crypto";
import pc from "picocolors";
import type { AuditLogEntry, AuditVerificationCode } from "../types/index.js";

const GENESIS_PREV_HASH = "0".repeat(64);

export function getDefaultAuditLogPath(): string {
  return path.join(os.homedir(), ".mcp-shield", "audit.jsonl");
}

export function computeSha256(content: string): string {
  return crypto.createHash("sha256").update(content).digest("hex");
}

/**
 * Deterministic canonical JSON serialization with sorted keys.
 */
export function canonicalJsonStringify(obj: unknown): string {
  if (obj === null || typeof obj !== "object") {
    return JSON.stringify(obj);
  }
  if (Array.isArray(obj)) {
    return "[" + obj.map((item) => canonicalJsonStringify(item)).join(",") + "]";
  }
  const record = obj as Record<string, unknown>;
  const sortedKeys = Object.keys(record).sort();
  const entries: string[] = [];
  for (const k of sortedKeys) {
    const v = record[k];
    if (v !== undefined) {
      entries.push(`${JSON.stringify(k)}:${canonicalJsonStringify(v)}`);
    }
  }
  return "{" + entries.join(",") + "}";
}

export function computeCanonicalEntryHash(
  prevHash: string,
  entryData: {
    schemaVersion?: number;
    seq: number;
    timestamp: string;
    eventType: string;
    action: string;
    ruleId?: string | undefined;
    owaspId?: string | undefined;
    details: Record<string, unknown>;
    prevHash: string;
  }
): string {
  const canonical = canonicalJsonStringify({
    action: entryData.action,
    details: entryData.details,
    eventType: entryData.eventType,
    owaspId: entryData.owaspId,
    prevHash: entryData.prevHash,
    ruleId: entryData.ruleId,
    schemaVersion: entryData.schemaVersion ?? 1,
    seq: entryData.seq,
    timestamp: entryData.timestamp,
  });
  return computeSha256(prevHash + canonical);
}

export function computeHmacSignature(entryHash: string, hmacKey: string): string {
  return crypto.createHmac("sha256", hmacKey).update(entryHash).digest("hex");
}

export function appendAuditEntry(
  entry: {
    eventType: "scan" | "proxy";
    action: "SCAN_COMPLETE" | "ALLOW" | "BLOCK";
    ruleId?: string | undefined;
    owaspId?: string | undefined;
    details: Record<string, unknown>;
  },
  customLogPathOrOptions?:
    | string
    | { logPath?: string | undefined; hmacKey?: string | undefined }
    | undefined,
  explicitHmacKey?: string | undefined
): AuditLogEntry {
  let customLogPath: string | undefined;
  let hmacKey: string | undefined = explicitHmacKey;

  if (typeof customLogPathOrOptions === "string") {
    customLogPath = customLogPathOrOptions;
  } else if (customLogPathOrOptions && typeof customLogPathOrOptions === "object") {
    customLogPath = customLogPathOrOptions.logPath;
    hmacKey = customLogPathOrOptions.hmacKey || explicitHmacKey;
  }

  const logPath = customLogPath || getDefaultAuditLogPath();
  const dir = path.dirname(logPath);

  // 1. Check directory symlink & create directory safely
  if (fs.existsSync(dir)) {
    const dStat = fs.lstatSync(dir);
    if (dStat.isSymbolicLink()) {
      throw new Error("SYMLINK_DETECTED: Audit directory cannot be a symbolic link");
    }
  } else {
    fs.mkdirSync(dir, {
      recursive: true,
      mode: process.platform === "win32" ? undefined : 0o700,
    });
  }

  // 2. Check file symlink
  if (fs.existsSync(logPath)) {
    const fStat = fs.lstatSync(logPath);
    if (fStat.isSymbolicLink()) {
      throw new Error("SYMLINK_DETECTED: Audit log file cannot be a symbolic link");
    }
  }

  let prevHash = GENESIS_PREV_HASH;
  let seq = 1;

  if (fs.existsSync(logPath)) {
    const lines = fs
      .readFileSync(logPath, "utf-8")
      .trim()
      .split("\n")
      .filter(Boolean);

    if (lines.length > 0) {
      const lastLine = lines[lines.length - 1];
      if (lastLine) {
        try {
          const parsed = JSON.parse(lastLine) as AuditLogEntry;
          if (parsed.entryHash) {
            prevHash = parsed.entryHash;
          }
          if (typeof parsed.seq === "number") {
            seq = parsed.seq + 1;
          } else {
            seq = lines.length + 1;
          }
        } catch {
          // Fall back to genesis if last line was corrupt
        }
      }
    }
  }

  const baseEntry = {
    schemaVersion: 1,
    seq,
    timestamp: new Date().toISOString(),
    eventType: entry.eventType,
    action: entry.action,
    ruleId: entry.ruleId,
    owaspId: entry.owaspId,
    details: entry.details,
    prevHash,
  };

  const entryHash = computeCanonicalEntryHash(prevHash, baseEntry);

  const activeHmacKey = hmacKey || process.env.MCP_SHIELD_AUDIT_HMAC_KEY;
  let signature: string | undefined;
  if (activeHmacKey) {
    signature = computeHmacSignature(entryHash, activeHmacKey);
  }

  const fullEntry: AuditLogEntry = {
    ...baseEntry,
    entryHash,
    ...(signature ? { signature } : {}),
  };

  const lineToWrite = canonicalJsonStringify(fullEntry) + "\n";
  fs.appendFileSync(logPath, lineToWrite, {
    mode: process.platform === "win32" ? undefined : 0o600,
    encoding: "utf-8",
  });

  // Enforce POSIX permissions on directory and file
  if (process.platform !== "win32") {
    try {
      fs.chmodSync(dir, 0o700);
      fs.chmodSync(logPath, 0o600);
    } catch {}
  }

  return fullEntry;
}

export interface AuditVerifyResult {
  readonly valid: boolean;
  readonly totalEntries: number;
  readonly code: AuditVerificationCode;
  readonly errorLine?: number;
  readonly errorReason?: string;
}

export function verifyAuditLog(
  customLogPath?: string,
  expectedTotalRecords?: number,
  hmacKey?: string
): AuditVerifyResult {
  const logPath = customLogPath || getDefaultAuditLogPath();
  const dir = path.dirname(logPath);

  // Check symlinks
  if (fs.existsSync(dir)) {
    try {
      if (fs.lstatSync(dir).isSymbolicLink()) {
        return {
          valid: false,
          totalEntries: 0,
          code: "SYMLINK_DETECTED",
          errorReason: "Audit directory is a symbolic link",
        };
      }
    } catch {}
  }

  if (fs.existsSync(logPath)) {
    try {
      if (fs.lstatSync(logPath).isSymbolicLink()) {
        return {
          valid: false,
          totalEntries: 0,
          code: "SYMLINK_DETECTED",
          errorReason: "Audit log file is a symbolic link",
        };
      }
    } catch {}
  }

  if (!fs.existsSync(logPath)) {
    if (expectedTotalRecords && expectedTotalRecords > 0) {
      return {
        valid: false,
        totalEntries: 0,
        code: "MISSING_LOG",
        errorReason: `Audit log file is missing; expected ${expectedTotalRecords} records`,
      };
    }
    return { valid: true, totalEntries: 0, code: "SUCCESS" };
  }

  const content = fs.readFileSync(logPath, "utf-8");
  const lines = content.split("\n").filter((l) => l.trim().length > 0);

  if (lines.length === 0) {
    if (expectedTotalRecords && expectedTotalRecords > 0) {
      return {
        valid: false,
        totalEntries: 0,
        code: "TRUNCATED_ENTRY",
        errorReason: `Audit log is empty; expected ${expectedTotalRecords} records`,
      };
    }
    return { valid: true, totalEntries: 0, code: "SUCCESS" };
  }

  if (expectedTotalRecords !== undefined && lines.length < expectedTotalRecords) {
    return {
      valid: false,
      totalEntries: lines.length,
      code: "TRUNCATED_ENTRY",
      errorReason: `Truncation detected: log has ${lines.length} records, but expected at least ${expectedTotalRecords}`,
    };
  }

  let expectedPrevHash = GENESIS_PREV_HASH;
  const activeHmacKey = hmacKey || process.env.MCP_SHIELD_AUDIT_HMAC_KEY;

  for (let i = 0; i < lines.length; i++) {
    const rawLine = lines[i];
    if (!rawLine) continue;

    let parsed: AuditLogEntry;
    try {
      parsed = JSON.parse(rawLine) as AuditLogEntry;
    } catch {
      return {
        valid: false,
        totalEntries: lines.length,
        code: "CORRUPT_JSON",
        errorLine: i + 1,
        errorReason: `Line ${i + 1} contains malformed non-JSON data`,
      };
    }

    const expectedSeq = i + 1;
    if (parsed.seq !== undefined && parsed.seq !== expectedSeq) {
      const code: AuditVerificationCode =
        parsed.seq < expectedSeq ? "REORDERED_ENTRY" : "SEQUENCE_GAP";
      return {
        valid: false,
        totalEntries: lines.length,
        code,
        errorLine: i + 1,
        errorReason: `Sequence break at line ${i + 1}: expected seq ${expectedSeq}, found ${parsed.seq}`,
      };
    }

    if (parsed.prevHash !== expectedPrevHash) {
      return {
        valid: false,
        totalEntries: lines.length,
        code: "INVALID_HASH",
        errorLine: i + 1,
        errorReason: `Hash chain broken at line ${i + 1}: expected prevHash "${expectedPrevHash.slice(0, 16)}...", received "${parsed.prevHash?.slice(0, 16)}..."`,
      };
    }

    const recomputedHash = computeCanonicalEntryHash(expectedPrevHash, {
      schemaVersion: parsed.schemaVersion ?? 1,
      seq: parsed.seq ?? expectedSeq,
      timestamp: parsed.timestamp,
      eventType: parsed.eventType,
      action: parsed.action,
      ruleId: parsed.ruleId,
      owaspId: parsed.owaspId,
      details: parsed.details as Record<string, unknown>,
      prevHash: parsed.prevHash,
    });

    if (recomputedHash !== parsed.entryHash) {
      return {
        valid: false,
        totalEntries: lines.length,
        code: "INVALID_HASH",
        errorLine: i + 1,
        errorReason: `Tamper detected at line ${i + 1}: stored hash does not match computed content hash`,
      };
    }

    // Verify HMAC signature if active
    if (activeHmacKey) {
      if (!parsed.signature) {
        return {
          valid: false,
          totalEntries: lines.length,
          code: "INVALID_SIGNATURE",
          errorLine: i + 1,
          errorReason: `Missing HMAC signature at line ${i + 1}`,
        };
      }
      const expectedSig = computeHmacSignature(parsed.entryHash, activeHmacKey);
      if (expectedSig !== parsed.signature) {
        return {
          valid: false,
          totalEntries: lines.length,
          code: "INVALID_SIGNATURE",
          errorLine: i + 1,
          errorReason: `Invalid HMAC signature at line ${i + 1}`,
        };
      }
    }

    expectedPrevHash = parsed.entryHash;
  }

  return {
    valid: true,
    totalEntries: lines.length,
    code: "SUCCESS",
  };
}

export function exportAuditLog(
  destinationPath: string,
  customLogPath?: string,
  hmacKey?: string
): void {
  const verifyResult = verifyAuditLog(customLogPath, undefined, hmacKey);
  if (!verifyResult.valid) {
    throw new Error(`Cannot export corrupted audit log: ${verifyResult.errorReason}`);
  }
  const source = customLogPath || getDefaultAuditLogPath();
  const dest = path.resolve(destinationPath);
  fs.copyFileSync(source, dest);
}

export function getAuditTail(n: number = 20, customLogPath?: string): AuditLogEntry[] {
  const logPath = customLogPath || getDefaultAuditLogPath();
  if (!fs.existsSync(logPath)) return [];

  const content = fs.readFileSync(logPath, "utf-8");
  const lines = content.split("\n").filter((l) => l.trim().length > 0);
  const selected = lines.slice(-n);
  const entries: AuditLogEntry[] = [];

  for (const line of selected) {
    try {
      entries.push(JSON.parse(line) as AuditLogEntry);
    } catch {}
  }

  return entries;
}

export function printAuditTerminalReport(options: {
  verifyOnly?: boolean | undefined;
  tailCount?: number | undefined;
  isJson?: boolean | undefined;
  hmacKey?: string | undefined;
  exportPath?: string | undefined;
}): boolean {
  const logPath = getDefaultAuditLogPath();
  const tailCount = options.tailCount ?? 20;

  if (options.exportPath) {
    try {
      exportAuditLog(options.exportPath, logPath, options.hmacKey);
      if (options.isJson) {
        process.stdout.write(
          JSON.stringify({ exportedTo: path.resolve(options.exportPath), success: true }) + "\n"
        );
      } else {
        console.log(pc.green(`✓ Audit log verified and exported to: ${path.resolve(options.exportPath)}`));
      }
      return true;
    } catch (err) {
      if (options.isJson) {
        process.stdout.write(
          JSON.stringify({ error: (err as Error).message, success: false }) + "\n"
        );
      } else {
        process.stderr.write(pc.red(`Export error: ${(err as Error).message}\n`));
      }
      return false;
    }
  }

  const verifyResult = verifyAuditLog(logPath, undefined, options.hmacKey);

  if (options.isJson) {
    const payload = {
      valid: verifyResult.valid,
      code: verifyResult.code,
      totalEntries: verifyResult.totalEntries,
      errorLine: verifyResult.errorLine,
      errorReason: verifyResult.errorReason,
      logPath,
    };
    process.stdout.write(JSON.stringify(payload, null, 2) + "\n");
    return verifyResult.valid;
  }

  console.log("\n" + pc.bold(pc.blue("=== mcp-shield Audit Log Inspection ===")));
  console.log(pc.gray(`Log File: ${logPath}\n`));

  if (!verifyResult.valid) {
    console.log(
      pc.bgRed(pc.white(` AUDIT INTEGRITY FAILURE [${verifyResult.code}] `)) +
        pc.red(` Tamper detected: ${verifyResult.errorReason}\n`)
    );
    return false;
  }

  console.log(
    pc.green(
      `✓ Cryptographic SHA-256 Hash Chain Verified (${verifyResult.totalEntries} entries intact with sequence tracking)`
    )
  );

  if (options.verifyOnly) {
    console.log();
    return true;
  }

  const entries = getAuditTail(tailCount, logPath);
  if (entries.length === 0) {
    console.log(pc.gray("Audit log is currently empty.\n"));
    return true;
  }

  console.log(pc.bold(`\nRecent Audit Events (Last ${entries.length} Entries):`));
  console.log(pc.gray("─".repeat(60)));

  for (const entry of entries) {
    const badge =
      entry.action === "BLOCK"
        ? pc.bgRed(pc.white(" BLOCK "))
        : entry.action === "ALLOW"
        ? pc.green(" ALLOW ")
        : pc.cyan(" SCAN  ");

    console.log(
      `#${entry.seq} ${pc.dim(entry.timestamp)} ${badge} ${pc.bold(entry.eventType.toUpperCase())} ${entry.ruleId ? pc.yellow(entry.ruleId) : ""}`
    );
    console.log(
      `  Hash: ${pc.dim(entry.entryHash.slice(0, 16))}... <- Prev: ${pc.dim(entry.prevHash.slice(0, 16))}...`
    );
  }
  console.log();
  return true;
}
