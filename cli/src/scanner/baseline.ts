import * as fs from "node:fs";
import * as path from "node:path";
import * as crypto from "node:crypto";
import type { BaselineFile, BaselineFinding, ScanFinding } from "../types/index.js";

/**
 * Load baseline JSON file safely.
 * Returns undefined if file does not exist or parse fails.
 */
export function loadBaseline(filePath: string): BaselineFile | undefined {
  try {
    const resolvedPath = path.resolve(filePath);
    const content = fs.readFileSync(resolvedPath, "utf-8");
    const parsed = JSON.parse(content) as unknown;
    if (
      typeof parsed === "object" &&
      parsed !== null &&
      "findings" in parsed &&
      Array.isArray((parsed as { findings: unknown }).findings)
    ) {
      return parsed as BaselineFile;
    }
    return undefined;
  } catch {
    return undefined;
  }
}

/**
 * Filter findings using baseline file and flags.
 * Returns active findings and suppressed findings.
 */
export function filterWithBaseline(
  findings: readonly ScanFinding[],
  baseline: BaselineFile | undefined,
  changedOnly: boolean = false
): { active: ScanFinding[]; suppressed: ScanFinding[] } {
  if (!baseline) {
    const active = findings.map((f) => ({
      ...f,
      baselineState: "new" as const,
      suppressed: false,
    }));
    return { active, suppressed: [] };
  }

  const baselineMap = new Map<string, BaselineFinding>();
  for (const b of baseline.findings) {
    if (b.fingerprint) {
      baselineMap.set(b.fingerprint, b);
    }
    // Secondary key for fallback match
    const compositeKey = `${b.ruleId}::${b.server}::${b.file}`;
    if (!baselineMap.has(compositeKey)) {
      baselineMap.set(compositeKey, b);
    }
  }

  const now = Date.now();
  const active: ScanFinding[] = [];
  const suppressed: ScanFinding[] = [];

  for (const f of findings) {
    const match =
      (f.fingerprint ? baselineMap.get(f.fingerprint) : undefined) ||
      baselineMap.get(`${f.ruleId}::${f.serverName}::${f.file}`);

    let isExpired = false;
    if (match?.expiresAt) {
      const expTime = new Date(match.expiresAt).getTime();
      if (!Number.isNaN(expTime) && expTime <= now) {
        isExpired = true;
      }
    }

    if (match && !isExpired) {
      const suppressedFinding: ScanFinding = {
        ...f,
        baselineState: "unchanged",
        suppressed: true,
        suppressionReason: match.reason || "Suppressed by baseline entry",
      };
      suppressed.push(suppressedFinding);
      if (!changedOnly) {
        // When not changedOnly, finding is recorded in suppressed, not active
      }
    } else {
      const activeFinding: ScanFinding = {
        ...f,
        baselineState: "new",
        suppressed: false,
      };
      active.push(activeFinding);
    }
  }

  return { active, suppressed };
}

/**
 * Save current findings to baseline file.
 * Uses atomic temporary file write and replace.
 */
export function updateBaseline(
  filePath: string,
  findings: readonly ScanFinding[],
  options?: { reason?: string; owner?: string; expiresAt?: string }
): void {
  const resolvedPath = path.resolve(filePath);
  const baselineFindings: BaselineFinding[] = findings.map((f) => ({
    fingerprint: f.fingerprint || `${f.ruleId}:${f.serverName}:${f.file}`,
    ruleId: f.ruleId,
    server: f.serverName,
    file: f.file,
    reason: options?.reason || "Accepted baseline risk",
    ...(options?.owner ? { owner: options.owner } : {}),
    ...(options?.expiresAt ? { expiresAt: options.expiresAt } : {}),
  }));

  const baselineData: BaselineFile = {
    version: "1.0",
    generatedAt: new Date().toISOString(),
    findings: baselineFindings,
  };

  const dir = path.dirname(resolvedPath);
  fs.mkdirSync(dir, { recursive: true });

  const tempPath = `${resolvedPath}.tmp.${crypto.randomBytes(16).toString("hex")}`;
  fs.writeFileSync(tempPath, JSON.stringify(baselineData, null, 2) + "\n", "utf-8");
  fs.renameSync(tempPath, resolvedPath);
}
