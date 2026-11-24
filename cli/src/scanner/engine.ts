import type {
  NormalizedMcpServer,
  ScanResult,
  ScanFinding,
  SecurityGrade,
  PolicyConfig,
  ScoreBreakdown,
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
  breakdown: ScoreBreakdown;
} {
  let score = 100;
  const breakdown = {
    secrets: 0,
    paths: 0,
    promptInjection: 0,
    supplyChain: 0,
    commands: 0,
    transport: 0,
    shadowMcp: 0,
  };

  for (const finding of findings) {
    let penalty = 0;
    switch (finding.severity) {
      case "critical":
        penalty = 35;
        break;
      case "high":
        penalty = 20;
        break;
      case "medium":
        penalty = 10;
        break;
      case "low":
        penalty = 5;
        break;
    }
    score -= penalty;

    switch (finding.ruleId) {
      case "MS-001":
        breakdown.secrets += penalty;
        break;
      case "MS-002":
        breakdown.paths += penalty;
        break;
      case "MS-003":
        breakdown.promptInjection += penalty;
        break;
      case "MS-004":
        breakdown.supplyChain += penalty;
        break;
      case "MS-005":
        breakdown.commands += penalty;
        break;
      case "MS-006":
        breakdown.transport += penalty;
        break;
      case "MS-007":
        breakdown.shadowMcp += penalty;
        break;
    }
  }

  score = Math.max(0, score);
  return {
    score,
    grade: calculateGrade(score),
    breakdown,
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

  const { score, grade, breakdown } = calculateSecurityScore(allFindings);

  return {
    scannedFiles,
    serversCount: servers.length,
    findings: allFindings,
    score,
    grade,
    scoreBreakdown: breakdown,
    timestamp: new Date().toISOString(),
  };
}
