import type {
  NormalizedMcpServer,
  ScanResult,
  ScanFinding,
  SecurityGrade,
  PolicyConfig,
} from "../types/index.js";
import { evaluateServerRules } from "./rules.js";

export function calculateGrade(score: number): SecurityGrade {
  if (score >= 90) return "A";
  if (score >= 75) return "B";
  if (score >= 60) return "C";
  if (score >= 40) return "D";
  return "F";
}

export function calculateSecurityScore(findings: readonly ScanFinding[]): {
  score: number;
  grade: SecurityGrade;
} {
  let score = 100;

  for (const finding of findings) {
    switch (finding.severity) {
      case "critical":
        score -= 35;
        break;
      case "high":
        score -= 20;
        break;
      case "medium":
        score -= 10;
        break;
      case "low":
        score -= 5;
        break;
    }
  }

  score = Math.max(0, score);
  return {
    score,
    grade: calculateGrade(score),
  };
}

export function runScanEngine(
  servers: readonly NormalizedMcpServer[],
  scannedFiles: readonly string[],
  policy?: PolicyConfig
): ScanResult {
  const allFindings: ScanFinding[] = [];

  for (const server of servers) {
    const findings = evaluateServerRules(server, policy);
    allFindings.push(...findings);
  }

  const { score, grade } = calculateSecurityScore(allFindings);

  return {
    scannedFiles,
    serversCount: servers.length,
    findings: allFindings,
    score,
    grade,
    timestamp: new Date().toISOString(),
  };
}
