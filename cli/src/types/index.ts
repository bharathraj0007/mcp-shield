/**
 * Core type definitions for mcp-shield.
 * Follows ASD-STE100 rules: strict, typed, zero any.
 */

export type McpClientType =
  | "antigravity"
  | "cursor"
  | "claude-desktop"
  | "claude-code"
  | "vscode"
  | "windsurf"
  | "gemini"
  | "zed"
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
}

export type SecurityGrade = "A" | "B" | "C" | "D" | "F";

export interface ScanResult {
  readonly scannedFiles: readonly string[];
  readonly serversCount: number;
  readonly findings: readonly ScanFinding[];
  readonly score: number;
  readonly grade: SecurityGrade;
  readonly timestamp: string;
}

export type PolicyMode = "enforce" | "monitor";

export interface PolicyConfig {
  readonly version: string;
  readonly mode: PolicyMode;
  readonly denyPaths: readonly string[];
  readonly allowPaths: readonly string[];
  readonly blockedCommands: readonly string[];
  readonly disabledRules: readonly string[];
  readonly allowedServers?: readonly string[];
  readonly failOnSeverity: RuleSeverity;
}

export type ProxyAction = "ALLOW" | "BLOCK";

export interface ProxyDecision {
  readonly action: ProxyAction;
  readonly ruleId?: string;
  readonly owaspId?: string;
  readonly reason?: string;
  readonly redactedTarget?: string;
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

export interface AuditLogEntry {
  readonly seq: number;
  readonly timestamp: string;
  readonly eventType: "scan" | "proxy";
  readonly action: "SCAN_COMPLETE" | "ALLOW" | "BLOCK";
  readonly ruleId?: string | undefined;
  readonly owaspId?: string | undefined;
  readonly details: Readonly<Record<string, unknown>>;
  readonly prevHash: string;
  readonly entryHash: string;
}
