/**
 * Core type definitions for mcp-shield.
 * Follows ASD-STE100 rules: strict, typed, zero any.
 */

export const ExitCode = {
  SUCCESS: 0,
  BLOCKING_FINDINGS: 1,
  USAGE_ERROR: 2,
  CONFIG_ERROR: 3,
  AUDIT_VERIFICATION_FAILURE: 4,
  PROXY_PROCESS_FAILURE: 5,
  INTERNAL_ERROR: 6,
} as const;

export type ExitCodeType = (typeof ExitCode)[keyof typeof ExitCode];

export type McpClientType =
  | "antigravity"
  | "cursor"
  | "claude-desktop"
  | "claude-code"
  | "vscode"
  | "windsurf"
  | "gemini"
  | "zed"
  | "cline"
  | "custom";

export type McpTransportType = "stdio" | "sse" | "http";

export interface NormalizedMcpServer {
  readonly client: McpClientType;
  readonly configPath: string;
  readonly serverName: string;
  readonly transport: McpTransportType;
  readonly command?: string;
  readonly args?: readonly string[];
  readonly env?: Readonly<Record<string, string>>;
  readonly url?: string;
  readonly headers?: Readonly<Record<string, string>>;
}

export type RuleSeverity = "critical" | "high" | "medium" | "low";
export type FindingConfidence = "high" | "medium" | "low";

export type RuleId =
  | "MS-001"
  | "MS-002"
  | "MS-003"
  | "MS-004"
  | "MS-005"
  | "MS-006"
  | "MS-007"
  | string;

export type OwaspMcpId =
  | "MCP01:2025"
  | "MCP02:2025"
  | "MCP03:2025"
  | "MCP04:2025"
  | "MCP05:2025"
  | "MCP07:2025"
  | "MCP09:2025"
  | string;

export interface ScanFinding {
  readonly ruleId: RuleId;
  readonly owaspId: OwaspMcpId;
  readonly severity: RuleSeverity;
  readonly title: string;
  readonly message: string;
  readonly file: string;
  readonly serverName: string;
  readonly maskedEvidence?: string;
  readonly fixSuggestion: string;
  readonly confidence?: FindingConfidence;
  readonly reason?: string;
  readonly fingerprint?: string;
  readonly baselineState?: "new" | "unchanged";
  readonly suppressed?: boolean;
  readonly suppressionReason?: string;
}

export type SecurityGrade = "A" | "B" | "C" | "D" | "F";

export interface ScoreBreakdown {
  readonly secrets: number;
  readonly paths: number;
  readonly promptInjection: number;
  readonly supplyChain: number;
  readonly commands: number;
  readonly transport: number;
  readonly shadowMcp: number;
}

export interface ScanResult {
  readonly scannedFiles: readonly string[];
  readonly serversCount: number;
  readonly findings: readonly ScanFinding[];
  readonly activeFindings?: readonly ScanFinding[];
  readonly suppressedFindings?: readonly ScanFinding[];
  readonly score: number;
  readonly grade: SecurityGrade;
  readonly scoreBreakdown?: ScoreBreakdown;
  readonly timestamp: string;
}

export type PolicyMode = "monitor" | "enforce" | "baseline" | "quarantine" | "audit-only";
export type SecretSensitivity = "low" | "balanced" | "strict";
export type FramingMode = "line" | "content-length" | "auto";
export type RugPullMode = "off" | "monitor" | "approve" | "enforce";
export type RugPullPersistence = "local" | "memory";

export interface RugPullConfig {
  readonly mode?: RugPullMode | undefined;
  readonly persistence?: RugPullPersistence | undefined;
  readonly baselinePath?: string | undefined;
  readonly immutableFields?: readonly string[] | undefined;
}

export interface SecretDetectionConfig {
  readonly sensitivity?: SecretSensitivity | undefined;
  readonly exclude?: readonly string[] | undefined;
}

export interface PolicyConfig {
  readonly version: string;
  readonly mode: PolicyMode;
  readonly inherit?: readonly string[] | undefined;
  readonly denyPaths: readonly string[];
  readonly allowPaths: readonly string[];
  readonly blockedCommands: readonly string[];
  readonly disabledRules: readonly string[];
  readonly allowedServers?: readonly string[] | undefined;
  readonly failOnSeverity: RuleSeverity;
  readonly secretDetection?: SecretDetectionConfig | undefined;
  readonly blockedMethods?: readonly string[] | undefined;
  readonly allowedTools?: readonly string[] | undefined;
  readonly deniedTools?: readonly string[] | undefined;
  readonly allowedHosts?: readonly string[] | undefined;
  readonly deniedHosts?: readonly string[] | undefined;
  readonly processAllowlist?: readonly string[] | undefined;
  readonly rugPull?: RugPullConfig | undefined;
}

export interface RuleDefinition {
  readonly id: RuleId;
  readonly owaspId: OwaspMcpId;
  readonly severity: RuleSeverity;
  readonly title: string;
  readonly description: string;
  readonly remediation: string;
}

export const JsonRpcErrorCode = {
  PARSE_ERROR: -32700,
  INVALID_REQUEST: -32600,
  METHOD_NOT_FOUND: -32601,
  INVALID_PARAMS: -32602,
  INTERNAL_ERROR: -32603,
  POLICY_BLOCK: -32001,
  POLICY_EVAL_FAILURE: -32002,
  OVERSIZED_FRAME: -32009,
} as const;

export type JsonRpcErrorCodeType = (typeof JsonRpcErrorCode)[keyof typeof JsonRpcErrorCode];

export type ProxyAction = "ALLOW" | "BLOCK";

export interface ProxyDecision {
  readonly action: ProxyAction;
  readonly ruleId?: string;
  readonly owaspId?: string;
  readonly reason?: string;
  readonly redactedTarget?: string;
  readonly errorCode?: number;
}

export type JsonRpcId = string | number | null;

export interface JsonRpcRequest {
  readonly jsonrpc: "2.0";
  readonly id?: JsonRpcId;
  readonly method: string;
  readonly params?: unknown;
}

export interface JsonRpcError {
  readonly code: number;
  readonly message: string;
  readonly data?: unknown;
}

export interface JsonRpcResponse {
  readonly jsonrpc: "2.0";
  readonly id: JsonRpcId;
  readonly result?: unknown;
  readonly error?: JsonRpcError;
}

export type AuditVerificationCode =
  | "SUCCESS"
  | "MISSING_LOG"
  | "INVALID_HASH"
  | "SEQUENCE_GAP"
  | "REORDERED_ENTRY"
  | "TRUNCATED_ENTRY"
  | "INVALID_SIGNATURE"
  | "SYMLINK_DETECTED"
  | "CORRUPT_JSON";

export interface AuditLogEntry {
  readonly schemaVersion?: number;
  readonly seq: number;
  readonly timestamp: string;
  readonly eventType: "scan" | "proxy";
  readonly action: "SCAN_COMPLETE" | "ALLOW" | "BLOCK";
  readonly ruleId?: string | undefined;
  readonly owaspId?: string | undefined;
  readonly details: Readonly<Record<string, unknown>>;
  readonly prevHash: string;
  readonly entryHash: string;
  readonly signature?: string;
}

export interface BaselineFinding {
  readonly fingerprint: string;
  readonly ruleId: string;
  readonly server: string;
  readonly file: string;
  readonly reason?: string;
  readonly owner?: string;
  readonly expiresAt?: string;
  readonly policyHash?: string;
}

export interface BaselineFile {
  readonly version: string;
  readonly generatedAt: string;
  readonly findings: readonly BaselineFinding[];
}
