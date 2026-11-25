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

export function generateAuditKeyPair(outDir?: string): {
  privateKeyPath: string;
  publicKeyPath: string;
  keyId: string;
} {
  const targetDir = path.resolve(outDir || process.cwd());
  fs.mkdirSync(targetDir, { recursive: true });

  const { privateKey, publicKey } = crypto.generateKeyPairSync("ed25519", {
    publicKeyEncoding: { type: "spki", format: "pem" },
    privateKeyEncoding: { type: "pkcs8", format: "pem" },
  });

  const keyId = crypto.createHash("sha256").update(publicKey).digest("hex").slice(0, 16);

  const privateKeyPath = path.join(targetDir, "audit-signing.key");
  const publicKeyPath = path.join(targetDir, "audit-signing.pub");

  fs.writeFileSync(privateKeyPath, privateKey, {
    mode: process.platform === "win32" ? undefined : 0o600,
    encoding: "utf-8",
  });

  fs.writeFileSync(publicKeyPath, publicKey, {
    mode: process.platform === "win32" ? undefined : 0o644,
    encoding: "utf-8",
  });

  return { privateKeyPath, publicKeyPath, keyId };
}

export function signCheckpointPayload(
  payload: { eventCount: number; headHash: string; keyId: string; sequence: number },
  privateKeyPem: string
): string {
  const canonical = canonicalJsonStringify(payload);
  return crypto.sign(null, Buffer.from(canonical), privateKeyPem).toString("base64");
}

export function verifyCheckpointPayload(
  payload: { eventCount: number; headHash: string; keyId: string; sequence: number },
  signatureBase64: string,
  publicKeyPem: string
): boolean {
  try {
    const canonical = canonicalJsonStringify(payload);
    return crypto.verify(
      null,
      Buffer.from(canonical),
      publicKeyPem,
      Buffer.from(signatureBase64, "base64")
    );
  } catch {
    return false;
  }
}

export function createAuditCheckpoint(options?: {
  logPath?: string | undefined;
  privateKeyPath?: string | undefined;
  privateKeyContent?: string | undefined;
}): AuditLogEntry {
  const logPath = options?.logPath || getDefaultAuditLogPath();
  const dir = path.dirname(logPath);

  fs.mkdirSync(dir, {
    recursive: true,
    mode: process.platform === "win32" ? undefined : 0o700,
  });

  // Resolve private key content
  let privateKeyPem: string;
  if (options?.privateKeyContent) {
    privateKeyPem = options.privateKeyContent;
  } else {
    const keyPath =
      options?.privateKeyPath ||
      process.env.MCP_SHIELD_AUDIT_PRIVATE_KEY ||
      path.join(process.cwd(), "audit-signing.key");

    let content: string;
    try {
      content = fs.readFileSync(path.resolve(keyPath), "utf-8");
    } catch {
      throw new Error(`Audit signing private key not found at: ${keyPath}`);
    }
    privateKeyPem = content;
  }

  // Derive public key and deterministic keyId
  const privKeyObj = crypto.createPrivateKey(privateKeyPem);
  const pubKeyObj = crypto.createPublicKey(privKeyObj);
  const pubKeyPem = pubKeyObj.export({ type: "spki", format: "pem" }).toString();
  const keyId = crypto.createHash("sha256").update(pubKeyPem).digest("hex").slice(0, 16);

  // Read current log state
  let prevHash = GENESIS_PREV_HASH;
  let seq = 1;
  let eventCount = 0;

  try {
    const lines = fs
      .readFileSync(logPath, "utf-8")
      .trim()
      .split("\n")
      .filter(Boolean);

    if (lines.length > 0) {
      eventCount = lines.length;
      const lastLine = lines[lines.length - 1];
      if (lastLine) {
        const parsed = JSON.parse(lastLine) as AuditLogEntry;
        if (parsed.entryHash) {
          prevHash = parsed.entryHash;
        }
        if (typeof parsed.seq === "number") {
          seq = parsed.seq + 1;
        } else {
          seq = lines.length + 1;
        }
      }
    }
  } catch (err) {
    const code = (err as NodeJS.ErrnoException).code;
    if (code !== "ENOENT" && code !== "EPERM" && code !== "EACCES") {
      throw err;
    }
  }

  const headHash = prevHash;
  const sequence = seq;

  const checkpointPayload = {
    eventCount,
    headHash,
    keyId,
    sequence,
  };

  const signature = signCheckpointPayload(checkpointPayload, privateKeyPem);

  const baseEntry = {
    schemaVersion: 1,
    seq,
    timestamp: new Date().toISOString(),
    eventType: "checkpoint" as const,
    action: "CHECKPOINT" as const,
    details: checkpointPayload,
    prevHash,
  };

  const entryHash = computeCanonicalEntryHash(prevHash, baseEntry);

  const checkpointEntry: AuditLogEntry = {
    ...baseEntry,
    entryHash,
    signature,
    keyId,
    headHash,
    eventCount,
    sequence,
  };

  const lineToWrite = canonicalJsonStringify(checkpointEntry) + "\n";
  fs.appendFileSync(logPath, lineToWrite, {
    mode: process.platform === "win32" ? undefined : 0o600,
    encoding: "utf-8",
  });

  if (process.platform !== "win32") {
    try {
      fs.chmodSync(dir, 0o700);
      fs.chmodSync(logPath, 0o600);
    } catch {}
  }

  return checkpointEntry;
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
  fs.mkdirSync(dir, {
    recursive: true,
    mode: process.platform === "win32" ? undefined : 0o700,
  });
  try {
    const dStat = fs.lstatSync(dir);
    if (dStat.isSymbolicLink()) {
      throw new Error("SYMLINK_DETECTED: Audit directory cannot be a symbolic link");
    }
  } catch (err) {
    if ((err as Error).message.startsWith("SYMLINK_DETECTED")) throw err;
  }

  // 2. Check file symlink
  try {
    const fStat = fs.lstatSync(logPath);
    if (fStat.isSymbolicLink()) {
      throw new Error("SYMLINK_DETECTED: Audit log file cannot be a symbolic link");
    }
  } catch (err) {
    if ((err as Error).message.startsWith("SYMLINK_DETECTED")) throw err;
    // File does not exist yet, which is safe
  }

  let prevHash = GENESIS_PREV_HASH;
  let seq = 1;

  try {
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
  } catch (err) {
    const code = (err as NodeJS.ErrnoException).code;
    if (code !== "ENOENT" && code !== "EPERM" && code !== "EACCES") {
      throw err;
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
  hmacKey?: string,
  publicKeyPathOrContent?: string
): AuditVerifyResult {
  const logPath = customLogPath || getDefaultAuditLogPath();
  const dir = path.dirname(logPath);

  // Check symlinks
  try {
    if (fs.lstatSync(dir).isSymbolicLink()) {
      return {
        valid: false,
        totalEntries: 0,
        code: "SYMLINK_DETECTED",
        errorReason: "Audit directory is a symbolic link",
      };
    }
  } catch (err) {
    const code = (err as NodeJS.ErrnoException).code;
    if (code !== "ENOENT" && code !== "EPERM" && code !== "EACCES") throw err;
  }

  try {
    if (fs.lstatSync(logPath).isSymbolicLink()) {
      return {
        valid: false,
        totalEntries: 0,
        code: "SYMLINK_DETECTED",
        errorReason: "Audit log file is a symbolic link",
      };
    }
  } catch (err) {
    const code = (err as NodeJS.ErrnoException).code;
    if (code !== "ENOENT" && code !== "EPERM" && code !== "EACCES") throw err;
  }

  let content: string;
  try {
    content = fs.readFileSync(logPath, "utf-8");
  } catch (err) {
    const code = (err as NodeJS.ErrnoException).code;
    if (code === "ENOENT" || code === "EPERM" || code === "EACCES") {
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
    throw err;
  }

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

  // Resolve Ed25519 public key if specified or available
  let publicKeyPem: string | undefined;
  if (publicKeyPathOrContent) {
    if (publicKeyPathOrContent.includes("BEGIN PUBLIC KEY")) {
      publicKeyPem = publicKeyPathOrContent;
    } else {
      try {
        publicKeyPem = fs.readFileSync(path.resolve(publicKeyPathOrContent), "utf-8");
      } catch {
        return {
          valid: false,
          totalEntries: 0,
          code: "INVALID_SIGNATURE",
          errorReason: `Public key file not found: ${publicKeyPathOrContent}`,
        };
      }
    }
  } else if (process.env.MCP_SHIELD_AUDIT_PUBLIC_KEY) {
    const envKey = process.env.MCP_SHIELD_AUDIT_PUBLIC_KEY;
    if (envKey.includes("BEGIN PUBLIC KEY")) {
      publicKeyPem = envKey;
    } else {
      try {
        publicKeyPem = fs.readFileSync(path.resolve(envKey), "utf-8");
      } catch {}
    }
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

    // Verify checkpoint integrity if checkpoint entry
    const isCheckpoint = parsed.eventType === "checkpoint" || parsed.action === "CHECKPOINT";
    if (isCheckpoint) {
      const headHash =
        parsed.headHash ?? (parsed.details?.["headHash"] as string | undefined);
      const eventCount =
        parsed.eventCount ?? (parsed.details?.["eventCount"] as number | undefined);
      const keyId =
        parsed.keyId ?? (parsed.details?.["keyId"] as string | undefined);
      const sequence =
        parsed.sequence ??
        (parsed.details?.["sequence"] as number | undefined) ??
        parsed.seq;

      if (headHash && headHash !== expectedPrevHash) {
        return {
          valid: false,
          totalEntries: lines.length,
          code: "CHECKPOINT_MISMATCH",
          errorLine: i + 1,
          errorReason: `Checkpoint mismatch at line ${i + 1}: headHash does not match actual log head`,
        };
      }

      if (eventCount !== undefined && eventCount !== i) {
        return {
          valid: false,
          totalEntries: lines.length,
          code: "CHECKPOINT_MISMATCH",
          errorLine: i + 1,
          errorReason: `Checkpoint mismatch at line ${i + 1}: eventCount ${eventCount} does not match actual event count ${i}`,
        };
      }

      if (publicKeyPem) {
        if (!parsed.signature) {
          return {
            valid: false,
            totalEntries: lines.length,
            code: "INVALID_SIGNATURE",
            errorLine: i + 1,
            errorReason: `Missing Ed25519 signature on checkpoint at line ${i + 1}`,
          };
        }
        const isValid = verifyCheckpointPayload(
          {
            eventCount: eventCount ?? i,
            headHash: headHash ?? expectedPrevHash,
            keyId: keyId ?? "",
            sequence,
          },
          parsed.signature,
          publicKeyPem
        );
        if (!isValid) {
          return {
            valid: false,
            totalEntries: lines.length,
            code: "INVALID_SIGNATURE",
            errorLine: i + 1,
            errorReason: `Invalid Ed25519 signature on checkpoint at line ${i + 1}`,
          };
        }
      }
    }

    // Verify HMAC signature if active
    if (activeHmacKey && !isCheckpoint) {
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
  let content: string;
  try {
    content = fs.readFileSync(logPath, "utf-8");
  } catch {
    return [];
  }

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
  checkpoint?: boolean | undefined;
  privateKey?: string | undefined;
  publicKey?: string | undefined;
}): boolean {
  const logPath = getDefaultAuditLogPath();
  const tailCount = options.tailCount ?? 20;

  if (options.checkpoint) {
    try {
      const entry = createAuditCheckpoint({
        logPath,
        privateKeyPath: options.privateKey,
      });

      if (options.isJson) {
        process.stdout.write(JSON.stringify(entry, null, 2) + "\n");
      } else {
        console.log(
          pc.bold(
            pc.green(`\n✓ Cryptographic Audit Checkpoint Created (Seq #${entry.seq})`)
          )
        );
        console.log(`  Key ID:     ${pc.cyan(entry.keyId || "")}`);
        console.log(`  Head Hash:  ${pc.dim(entry.headHash || "")}`);
        console.log(`  Events:     ${entry.eventCount}`);
        console.log(`  Entry Hash: ${pc.dim(entry.entryHash)}\n`);
      }
      return true;
    } catch (err) {
      if (options.isJson) {
        process.stdout.write(
          JSON.stringify({ error: (err as Error).message, success: false }) + "\n"
        );
      } else {
        process.stderr.write(pc.red(`Checkpoint error: ${(err as Error).message}\n`));
      }
      return false;
    }
  }

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

  const verifyResult = verifyAuditLog(
    logPath,
    undefined,
    options.hmacKey,
    options.publicKey
  );

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
      entry.action === "CHECKPOINT"
        ? pc.bgMagenta(pc.white(" CHECKPOINT "))
        : entry.action === "BLOCK"
        ? pc.bgRed(pc.white(" BLOCK "))
        : entry.action === "ALLOW"
        ? pc.green(" ALLOW ")
        : pc.cyan(" SCAN  ");

    console.log(
      `#${entry.seq} ${pc.dim(entry.timestamp)} ${badge} ${pc.bold(entry.eventType.toUpperCase())} ${entry.ruleId ? pc.yellow(entry.ruleId) : ""}`
    );
    if (entry.action === "CHECKPOINT") {
      console.log(
        `  Key ID: ${pc.cyan(entry.keyId || "")} | Events: ${entry.eventCount} | Head: ${pc.dim((entry.headHash || "").slice(0, 16))}...`
      );
    } else {
      console.log(
        `  Hash: ${pc.dim(entry.entryHash.slice(0, 16))}... <- Prev: ${pc.dim(entry.prevHash.slice(0, 16))}...`
      );
    }
  }
  console.log();
  return true;
}
