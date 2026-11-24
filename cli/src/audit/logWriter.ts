import * as fs from "node:fs";
import * as path from "node:path";
import * as os from "node:os";
import * as crypto from "node:crypto";
import pc from "picocolors";
import type { AuditLogEntry } from "../types/index.js";

const GENESIS_PREV_HASH = "0".repeat(64);

export function getDefaultAuditLogPath(): string {
  return path.join(os.homedir(), ".mcp-shield", "audit.jsonl");
}

export function computeSha256(content: string): string {
  return crypto.createHash("sha256").update(content).digest("hex");
}

export function computeCanonicalEntryHash(
  prevHash: string,
  entryData: Omit<AuditLogEntry, "entryHash">
): string {
  const canonical = JSON.stringify({
    seq: entryData.seq,
    timestamp: entryData.timestamp,
    eventType: entryData.eventType,
    action: entryData.action,
    ruleId: entryData.ruleId,
    owaspId: entryData.owaspId,
    details: entryData.details,
    prevHash: entryData.prevHash,
  });
  return computeSha256(prevHash + canonical);
}

export function appendAuditEntry(
  entry: {
    eventType: "scan" | "proxy";
    action: "SCAN_COMPLETE" | "ALLOW" | "BLOCK";
    ruleId?: string | undefined;
    owaspId?: string | undefined;
    details: Record<string, unknown>;
  },
  customLogPath?: string
): AuditLogEntry {
  const logPath = customLogPath || getDefaultAuditLogPath();
  const dir = path.dirname(logPath);

  if (!fs.existsSync(dir)) {
    fs.mkdirSync(dir, { recursive: true });
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
          // Fall back to genesis if last line corrupted
        }
      }
    }
  }

  const baseEntry = {
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

  const fullEntry: AuditLogEntry = {
    ...baseEntry,
    entryHash,
  };

  fs.appendFileSync(logPath, JSON.stringify(fullEntry) + "\n", "utf-8");
  return fullEntry;
}

export interface AuditVerifyResult {
  readonly valid: boolean;
  readonly totalEntries: number;
  readonly errorLine?: number;
  readonly errorReason?: string;
}

export function verifyAuditLog(
  customLogPath?: string,
  expectedTotalRecords?: number
): AuditVerifyResult {
  const logPath = customLogPath || getDefaultAuditLogPath();

  if (!fs.existsSync(logPath)) {
    if (expectedTotalRecords && expectedTotalRecords > 0) {
      return {
        valid: false,
        totalEntries: 0,
        errorReason: `Audit log file is missing; expected ${expectedTotalRecords} records`,
      };
    }
    return { valid: true, totalEntries: 0 };
  }

  const content = fs.readFileSync(logPath, "utf-8");
  const lines = content.split("\n").filter((l) => l.trim().length > 0);

  if (lines.length === 0) {
    if (expectedTotalRecords && expectedTotalRecords > 0) {
      return {
        valid: false,
        totalEntries: 0,
        errorReason: `Audit log is empty; expected ${expectedTotalRecords} records`,
      };
    }
    return { valid: true, totalEntries: 0 };
  }

  if (expectedTotalRecords !== undefined && lines.length < expectedTotalRecords) {
    return {
      valid: false,
      totalEntries: lines.length,
      errorReason: `Truncation detected: log has ${lines.length} records, but expected at least ${expectedTotalRecords}`,
    };
  }

  let expectedPrevHash = GENESIS_PREV_HASH;

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
        errorLine: i + 1,
        errorReason: `Line ${i + 1} contains malformed non-JSON data`,
      };
    }

    // Sequence continuity check (detects missing initial or middle records)
    const expectedSeq = i + 1;
    if (parsed.seq !== undefined && parsed.seq !== expectedSeq) {
      return {
        valid: false,
        totalEntries: lines.length,
        errorLine: i + 1,
        errorReason: `Sequence break detected at line ${i + 1}: expected seq ${expectedSeq}, found ${parsed.seq}`,
      };
    }

    if (parsed.prevHash !== expectedPrevHash) {
      return {
        valid: false,
        totalEntries: lines.length,
        errorLine: i + 1,
        errorReason: `Hash chain broken at line ${i + 1}: expected prevHash "${expectedPrevHash.slice(0, 16)}...", received "${parsed.prevHash?.slice(0, 16)}..."`,
      };
    }

    const recomputedHash = computeCanonicalEntryHash(expectedPrevHash, {
      seq: parsed.seq ?? expectedSeq,
      timestamp: parsed.timestamp,
      eventType: parsed.eventType,
      action: parsed.action,
      ruleId: parsed.ruleId,
      owaspId: parsed.owaspId,
      details: parsed.details,
      prevHash: parsed.prevHash,
    });

    if (recomputedHash !== parsed.entryHash) {
      return {
        valid: false,
        totalEntries: lines.length,
        errorLine: i + 1,
        errorReason: `Tamper detected at line ${i + 1}: stored hash does not match computed content hash`,
      };
    }

    expectedPrevHash = parsed.entryHash;
  }

  return {
    valid: true,
    totalEntries: lines.length,
  };
}

export function getAuditTail(n: number = 20, customLogPath?: string): AuditLogEntry[] {
  const logPath = customLogPath || getDefaultAuditLogPath();
  if (!fs.existsSync(logPath)) return [];

  const lines = fs
    .readFileSync(logPath, "utf-8")
    .trim()
    .split("\n")
    .filter(Boolean);

  const selected = lines.slice(-n);
  const entries: AuditLogEntry[] = [];

  for (const line of selected) {
    try {
      entries.push(JSON.parse(line) as AuditLogEntry);
    } catch {}
  }

  return entries;
}

export function printAuditTerminalReport(verifyOnly: boolean, tailCount: number = 20): boolean {
  const logPath = getDefaultAuditLogPath();
  console.log("\n" + pc.bold(pc.blue("=== mcp-shield Audit Log Inspection ===")));
  console.log(pc.gray(`Log File: ${logPath}\n`));

  const verifyResult = verifyAuditLog(logPath);

  if (!verifyResult.valid) {
    console.log(
      pc.bgRed(pc.white(" AUDIT INTEGRITY FAILURE ")) +
        pc.red(` Tamper detected: ${verifyResult.errorReason}\n`)
    );
    return false;
  }

  console.log(
    pc.green(
      `✓ Cryptographic SHA-256 Hash Chain Verified (${verifyResult.totalEntries} entries intact with sequence tracking)`
    )
  );

  if (verifyOnly) {
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
