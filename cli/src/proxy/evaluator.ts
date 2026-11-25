import * as path from "node:path";
import * as os from "node:os";
import * as fs from "node:fs";
import { fileURLToPath } from "node:url";
import type {
  JsonRpcRequest,
  ProxyDecision,
  PolicyConfig,
} from "../types/index.js";
import { JsonRpcErrorCode } from "../types/index.js";
import * as crypto from "node:crypto";
import { defaultRugPullManager, type ToolDefinition } from "./rugpull.js";

export { defaultRugPullManager, type ToolDefinition };

export class RugPullDetector {
  private toolHashes = new Map<string, string>();

  public computeToolHash(tool: ToolDefinition): string {
    const raw = `${tool.name}:${tool.description || ""}:${JSON.stringify(tool.inputSchema || {})}`;
    return crypto.createHash("sha256").update(raw).digest("hex");
  }

  public registerTools(tools: readonly ToolDefinition[]): {
    hasMutation: boolean;
    mutatedTool?: string;
  } {
    for (const tool of tools) {
      if (!tool.name) continue;
      const hash = this.computeToolHash(tool);
      if (this.toolHashes.has(tool.name)) {
        const prevHash = this.toolHashes.get(tool.name);
        if (prevHash !== hash) {
          return { hasMutation: true, mutatedTool: tool.name };
        }
      } else {
        this.toolHashes.set(tool.name, hash);
      }
    }
    return { hasMutation: false };
  }

  public hasTool(name: string): boolean {
    return this.toolHashes.has(name);
  }

  public clear(): void {
    this.toolHashes.clear();
  }
}

export const defaultRugPullDetector = new RugPullDetector();

const SENSITIVE_FILENAME_PATTERNS: readonly { readonly regex: RegExp; readonly name: string }[] = [
  { regex: /(?:^|[\\/])\.env(?:\..*)?$/i, name: ".env file" },
  { regex: /(?:^|[\\/])id_rsa(?:\.pub)?$/i, name: "SSH private key (id_rsa)" },
  { regex: /(?:^|[\\/])id_ed25519(?:\.pub)?$/i, name: "SSH private key (id_ed25519)" },
  { regex: /(?:^|[\\/])\.ssh(?:[\\/]|$)/i, name: "SSH directory (.ssh)" },
  { regex: /(?:^|[\\/])\.aws(?:[\\/]|$)/i, name: "AWS credentials directory (.aws)" },
  { regex: /(?:^|[\\/])\.gnupg(?:[\\/]|$)/i, name: "GnuPG keyring (.gnupg)" },
  { regex: /(?:^|[\\/])\.kube(?:[\\/]|$)/i, name: "Kubernetes config (.kube)" },
  { regex: /(?:^|[\\/])credentials\.json$/i, name: "Cloud credentials file" },
  { regex: /(?:^|[\\/])\.npmrc$/i, name: "NPM auth configuration (.npmrc)" },
  { regex: /(?:^|[\\/])\.netrc$/i, name: "Netrc credentials (.netrc)" },
  { regex: /(?:^|[\\/])etc[\\/]passwd$/i, name: "System user registry (/etc/passwd)" },
  { regex: /(?:^|[\\/])etc[\\/]shadow$/i, name: "System password hashes (/etc/shadow)" },
];

const DESTRUCTIVE_COMMAND_PATTERNS: readonly { readonly regex: RegExp; readonly name: string }[] = [
  { regex: /\brm\s+-[a-zA-Z]*r[a-zA-Z]*f\b/i, name: "Recursive directory deletion (rm -rf)" },
  { regex: /(?:curl|wget)\s+[^|]+\|\s*(?:sh|bash|zsh)/i, name: "Remote script pipe to shell" },
  { regex: /\bchmod\s+777\b/i, name: "Insecure full permissions (chmod 777)" },
  { regex: /\b(?:mkfs\b|dd\s+if=)/i, name: "Disk/partition overwrite (mkfs/dd)" },
  { regex: /\bnc\s+-[a-zA-Z]*e\b/i, name: "Reverse shell listener (nc -e)" },
  { regex: /(?:powershell|pwsh).*(?:-enc|-encodedcommand)\b/i, name: "Encoded PowerShell execution" },
  { regex: /[;&|`]|(?:\$\([^)]+\))/, name: "Unescaped shell command chaining" },
];

/**
 * Decode URL encodings (%2e, %2f, %5c) and Unicode escape sequences.
 * Normalizes Unicode via NFKC and removes null bytes.
 */
export function decodePathEscapes(input: string): string {
  if (!input) return input;
  let decoded = input;

  // 1. Decode Unicode escape sequences if \u is present
  if (decoded.includes("\\u")) {
    try {
      decoded = decoded.replace(/\\u([0-9a-fA-F]{4})/g, (_, hex: string) =>
        String.fromCharCode(parseInt(hex, 16))
      );
    } catch {}
  }

  // 2. Decode percent encoding if % is present
  if (decoded.includes("%")) {
    for (let i = 0; i < 3; i++) {
      try {
        const next = decodeURIComponent(decoded);
        if (next === decoded) break;
        decoded = next;
      } catch {
        break;
      }
    }

    decoded = decoded
      .replace(/%2e/gi, ".")
      .replace(/%2f/gi, "/")
      .replace(/%5c/gi, "\\");
  }

  // 3. Normalize Unicode (NFKC) if non-ASCII characters exist
  if (/[^\x00-\x7F]/.test(decoded)) {
    try {
      decoded = decoded.normalize("NFKC");
    } catch {}
  }

  // 4. Strip null bytes (\0) to defeat null-byte poisoning
  if (decoded.includes("\0")) {
    decoded = decoded.replace(/\0/g, "");
  }

  return decoded;
}

/**
 * Check for Windows UNC paths (\\server\share, //server/share, \\?\UNC\...).
 */
export function isUncPath(p: string): boolean {
  const trimmed = p.trim();
  return (
    /^[\\/]{2}[^\\/]+[\\/]+[^\\/]+/i.test(trimmed) ||
    /^[\\/]{2}\?[\\/]/i.test(trimmed) ||
    /^[\\/]{2}\.[\\/]/i.test(trimmed)
  );
}

/**
 * Expand tilde (~) to user home directory.
 */
export function expandHome(p: string): string {
  if (p.startsWith("~")) {
    return path.join(os.homedir(), p.slice(1));
  }
  return p;
}

const REALPATH_CACHE_LIMIT = 500;
const realpathCache = new Map<string, string>();

/**
 * Resolve canonical real path on disk, resolving symlinks to prevent escapes.
 * Uses an in-memory cache to maintain sub-5ms latency under heavy I/O contention.
 */
export function resolveCanonicalPath(rawPath: string): string {
  let decoded = decodePathEscapes(rawPath);

  // If path is a file:// URI, convert or strip
  if (decoded.startsWith("file://")) {
    try {
      decoded = fileURLToPath(decoded);
    } catch {
      decoded = decoded.replace(/^file:\/\/[a-zA-Z0-9_\-.]*/i, "");
    }
  }

  const expanded = expandHome(decoded);
  const absolute = path.resolve(process.cwd(), expanded);

  const cached = realpathCache.get(absolute);
  if (cached !== undefined) {
    return cached;
  }

  let resolved = absolute;

  try {
    resolved = fs.realpathSync(absolute);
  } catch {
    let current = path.dirname(absolute);
    const childSegments: string[] = [path.basename(absolute)];

    while (current && current !== path.dirname(current)) {
      try {
        const realParent = fs.realpathSync(current);
        resolved = path.join(realParent, ...[...childSegments].reverse());
        break;
      } catch {
        childSegments.push(path.basename(current));
        current = path.dirname(current);
      }
    }
  }

  if (realpathCache.size >= REALPATH_CACHE_LIMIT) {
    const firstKey = realpathCache.keys().next().value;
    if (firstKey) realpathCache.delete(firstKey);
  }
  realpathCache.set(absolute, resolved);

  return resolved;
}

/**
 * Tokenize shell command line safely.
 */
export function tokenizeShellCommand(commandLine: string): string[] {
  const tokens: string[] = [];
  const regex = /[^\s"']+|"([^"]*)"|'([^']*)'/g;
  let match: RegExpExecArray | null;
  while ((match = regex.exec(commandLine)) !== null) {
    const val = match[1] ?? match[2] ?? match[0];
    if (val !== undefined) tokens.push(val);
  }
  return tokens;
}

/**
 * Mask sensitive file target for log output.
 */
function redactTarget(target: string): string {
  const base = path.basename(target);
  if (base.startsWith(".env")) {
    return "**/.env";
  }
  if (base.includes("id_rsa") || base.includes("id_ed25519")) {
    return "~/.ssh/**";
  }
  return `**/${base}`;
}

/**
 * Check if a host represents an internal SSRF target (localhost, private network, link-local).
 */
export function isInternalOrPrivateHost(hostname: string): boolean {
  const host = hostname.toLowerCase().trim();

  // Localhost aliases
  if (
    host === "localhost" ||
    host === "127.0.0.1" ||
    host === "0.0.0.0" ||
    host === "::1" ||
    host === "[::1]" ||
    host.endsWith(".localhost") ||
    host.endsWith(".local") ||
    host.endsWith(".internal")
  ) {
    return true;
  }

  // IPv4 Private ranges
  // 10.0.0.0/8
  if (/^10\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(host)) return true;
  // 192.168.0.0/16
  if (/^192\.168\.\d{1,3}\.\d{1,3}$/.test(host)) return true;
  // 172.16.0.0/12 (172.16.x.x - 172.31.x.x)
  const match172 = /^172\.(\d{1,3})\.\d{1,3}\.\d{1,3}$/.exec(host);
  if (match172 && match172[1]) {
    const octet = parseInt(match172[1], 10);
    if (octet >= 16 && octet <= 31) return true;
  }
  // 169.254.0.0/16 (Link-local / Cloud metadata: 169.254.169.254)
  if (/^169\.254\.\d{1,3}\.\d{1,3}$/.test(host)) return true;

  // IPv6 link-local
  if (host.startsWith("fe80:") || host.startsWith("[fe80:")) return true;

  return false;
}

export interface StructuredToolArguments {
  paths: string[];
  commands: string[];
  urls: string[];
  toolNames: string[];
  rawStrings: string[];
}

/**
 * Recursively walk request params to extract all paths, commands, URLs, and tool names.
 */
export function extractStructuredArguments(request: JsonRpcRequest): StructuredToolArguments {
  const result: StructuredToolArguments = {
    paths: [],
    commands: [],
    urls: [],
    toolNames: [],
    rawStrings: [],
  };

  if (!request.params || typeof request.params !== "object") {
    return result;
  }

  const pathKeyRegex = /(?:path|file|dir|uri|target|dest|source|folder|root)/i;
  const cmdKeyRegex = /(?:command|cmd|script|exec|shell|binary|process|run)/i;

  const urlRegex = /\b(?:https?|wss?|ftp):\/\/([a-zA-Z0-9_\-\.:]+)/gi;

  function walk(val: unknown, keyName?: string, depth: number = 0) {
    if (depth > 32) return;

    if (typeof val === "string") {
      result.rawStrings.push(val);

      // Check for URLs
      let urlMatch: RegExpExecArray | null;
      while ((urlMatch = urlRegex.exec(val)) !== null) {
        if (urlMatch[1]) result.urls.push(urlMatch[1]);
      }

      // Check key name for paths or commands
      if (keyName && pathKeyRegex.test(keyName)) {
        result.paths.push(val);
      } else if (
        val.startsWith("./") ||
        val.startsWith("../") ||
        val.startsWith("/") ||
        val.startsWith("~") ||
        val.startsWith("file://") ||
        /^[a-zA-Z]:[\\/]/.test(val) ||
        isUncPath(val)
      ) {
        result.paths.push(val);
      }

      if (keyName && cmdKeyRegex.test(keyName)) {
        result.commands.push(val);
      }

      if (keyName === "name" && request.method === "tools/call") {
        result.toolNames.push(val);
      }
    } else if (Array.isArray(val)) {
      for (const item of val) {
        walk(item, keyName, depth + 1);
      }
    } else if (val && typeof val === "object") {
      for (const [k, v] of Object.entries(val as Record<string, unknown>)) {
        walk(v, k, depth + 1);
      }
    }
  }

  walk(request.params);

  // Directly extract method-specific targets
  const paramsRecord = request.params as Record<string, unknown>;
  if (typeof paramsRecord["uri"] === "string") {
    result.paths.push(paramsRecord["uri"]);
  }
  if (typeof paramsRecord["name"] === "string" && request.method === "tools/call") {
    result.toolNames.push(paramsRecord["name"]);
  }

  return result;
}

/**
 * Evaluates an incoming JSON-RPC request before passing to child MCP process.
 */
export function evaluateRequest(
  request: JsonRpcRequest,
  policy?: PolicyConfig
): ProxyDecision {
  const method = request.method;

  // 1. Blocked Methods Check
  if (policy?.blockedMethods && policy.blockedMethods.length > 0) {
    for (const blocked of policy.blockedMethods) {
      if (method === blocked || (blocked.endsWith("*") && method.startsWith(blocked.slice(0, -1)))) {
        return {
          action: "BLOCK",
          ruleId: "MS-007",
          owaspId: "MCP07:2025",
          reason: `Blocked by mcp-shield policy: Method "${method}" is forbidden by blockedMethods`,
          redactedTarget: method,
          errorCode: JsonRpcErrorCode.METHOD_NOT_FOUND,
        };
      }
    }
  }

  const structured = extractStructuredArguments(request);

  // 2. Tools Allowlist / Denylist Check (tools/call)
  if (method === "tools/call") {
    for (const toolName of structured.toolNames) {
      if (policy?.deniedTools && policy.deniedTools.includes(toolName)) {
        return {
          action: "BLOCK",
          ruleId: "MS-007",
          owaspId: "MCP07:2025",
          reason: `Blocked by mcp-shield policy: Tool "${toolName}" is forbidden by deniedTools`,
          redactedTarget: toolName,
          errorCode: JsonRpcErrorCode.POLICY_BLOCK,
        };
      }

      if (policy?.allowedTools && policy.allowedTools.length > 0) {
        if (!policy.allowedTools.includes(toolName)) {
          return {
            action: "BLOCK",
            ruleId: "MS-007",
            owaspId: "MCP07:2025",
            reason: `Blocked by mcp-shield policy: Tool "${toolName}" is not on allowedTools list`,
            redactedTarget: toolName,
            errorCode: JsonRpcErrorCode.POLICY_BLOCK,
          };
        }
      }
    }
  }

  // 3. Hosts & SSRF Check
  for (const hostWithPort of structured.urls) {
    const hostname = hostWithPort.split(":")[0] || hostWithPort;

    // Check deniedHosts in policy
    if (policy?.deniedHosts && policy.deniedHosts.length > 0) {
      for (const denied of policy.deniedHosts) {
        if (hostname.toLowerCase() === denied.toLowerCase() || hostname.toLowerCase().endsWith(`.${denied.toLowerCase()}`)) {
          return {
            action: "BLOCK",
            ruleId: "MS-006",
            owaspId: "MCP06:2025",
            reason: `Blocked by mcp-shield policy (MS-006): Access to host "${hostname}" forbidden by deniedHosts`,
            redactedTarget: hostname,
            errorCode: JsonRpcErrorCode.POLICY_BLOCK,
          };
        }
      }
    }

    // SSRF private network check
    if (isInternalOrPrivateHost(hostname)) {
      // If allowedHosts explicitly allows it, allow; otherwise block SSRF
      const explicitlyAllowed = policy?.allowedHosts?.some(
        (h) => h.toLowerCase() === hostname.toLowerCase()
      );
      if (!explicitlyAllowed) {
        return {
          action: "BLOCK",
          ruleId: "MS-006",
          owaspId: "MCP06:2025",
          reason: `Blocked by mcp-shield (MS-006): SSRF risk — request accesses private/internal network host "${hostname}"`,
          redactedTarget: hostname,
          errorCode: JsonRpcErrorCode.POLICY_BLOCK,
        };
      }
    }

    // AllowedHosts enforcement
    if (policy?.allowedHosts && policy.allowedHosts.length > 0) {
      const isAllowed = policy.allowedHosts.some(
        (h) => hostname.toLowerCase() === h.toLowerCase() || hostname.toLowerCase().endsWith(`.${h.toLowerCase()}`)
      );
      if (!isAllowed) {
        return {
          action: "BLOCK",
          ruleId: "MS-006",
          owaspId: "MCP06:2025",
          reason: `Blocked by mcp-shield policy (MS-006): Host "${hostname}" is not on allowedHosts list`,
          redactedTarget: hostname,
          errorCode: JsonRpcErrorCode.POLICY_BLOCK,
        };
      }
    }
  }

  // 4. Shell Commands & Process Allowlist
  const explicitCommands = structured.commands;
  const allCandidateCommands = Array.from(new Set([...explicitCommands, ...structured.rawStrings]));

  for (const rawCmd of allCandidateCommands) {
    const trimmed = rawCmd.trim();
    if (!trimmed) continue;

    for (const pat of DESTRUCTIVE_COMMAND_PATTERNS) {
      // Check shell chaining metacharacters only on explicit command arguments
      if (pat.name === "Unescaped shell command chaining" && !explicitCommands.includes(rawCmd)) {
        continue;
      }

      if (pat.regex.test(trimmed)) {
        return {
          action: "BLOCK",
          ruleId: "MS-005",
          owaspId: "MCP05:2025",
          reason: `Blocked by mcp-shield (MS-005): Dangerous shell pattern detected (${pat.name})`,
          redactedTarget: trimmed.slice(0, 40),
          errorCode: JsonRpcErrorCode.POLICY_BLOCK,
        };
      }
    }

    if (policy?.blockedCommands) {
      for (const blockedCmd of policy.blockedCommands) {
        if (trimmed.includes(blockedCmd)) {
          return {
            action: "BLOCK",
            ruleId: "MS-005",
            owaspId: "MCP05:2025",
            reason: `Blocked by mcp-shield policy: Command "${blockedCmd}" is forbidden by policy.yaml`,
            redactedTarget: blockedCmd,
            errorCode: JsonRpcErrorCode.POLICY_BLOCK,
          };
        }
      }
    }
  }

  if (policy?.processAllowlist && policy.processAllowlist.length > 0) {
    for (const rawCmd of explicitCommands) {
      const trimmed = rawCmd.trim();
      if (!trimmed) continue;
      const tokens = tokenizeShellCommand(trimmed);
      const binary = tokens[0] ? path.basename(tokens[0]) : "";
      if (binary && !policy.processAllowlist.includes(binary)) {
        return {
          action: "BLOCK",
          ruleId: "MS-005",
          owaspId: "MCP05:2025",
          reason: `Blocked by mcp-shield policy: Command binary "${binary}" is not in processAllowlist`,
          redactedTarget: binary,
          errorCode: JsonRpcErrorCode.POLICY_BLOCK,
        };
      }
    }
  }

  // 5. File Paths & Sensitive Locations
  const allCandidatePaths = Array.from(new Set([...structured.paths, ...structured.rawStrings]));
  for (const rawPath of allCandidatePaths) {
    const trimmed = rawPath.trim();
    if (!trimmed) continue;

    if (isUncPath(trimmed)) {
      return {
        action: "BLOCK",
        ruleId: "MS-002",
        owaspId: "MCP02:2025",
        reason: `Blocked by mcp-shield (MS-002): Unauthorized Windows UNC network path detected`,
        redactedTarget: trimmed.slice(0, 30),
        errorCode: JsonRpcErrorCode.POLICY_BLOCK,
      };
    }

    const decoded = decodePathEscapes(trimmed);

    for (const pat of SENSITIVE_FILENAME_PATTERNS) {
      if (pat.regex.test(decoded)) {
        return {
          action: "BLOCK",
          ruleId: "MS-001",
          owaspId: "MCP01:2025",
          reason: `Blocked by mcp-shield (MS-001): Unauthorized access to sensitive file (${pat.name})`,
          redactedTarget: redactTarget(decoded),
          errorCode: JsonRpcErrorCode.POLICY_BLOCK,
        };
      }
    }

    const canonical = resolveCanonicalPath(decoded);

    for (const pat of SENSITIVE_FILENAME_PATTERNS) {
      if (pat.regex.test(canonical)) {
        return {
          action: "BLOCK",
          ruleId: "MS-001",
          owaspId: "MCP01:2025",
          reason: `Blocked by mcp-shield (MS-001): Symlink or traversal access to sensitive target (${pat.name})`,
          redactedTarget: redactTarget(canonical),
          errorCode: JsonRpcErrorCode.POLICY_BLOCK,
        };
      }
    }

    if (policy?.denyPaths) {
      for (const denyPattern of policy.denyPaths) {
        try {
          const normalizedPat = denyPattern.replace(/\\/g, "/");
          const escaped = normalizedPat.replace(/[.+^${}()|[\]\\]/g, "\\$&");
          const cleanPattern = escaped
            .replace(/\*\*/g, ".*")
            .replace(/\*(?!\*)/g, "[^/]*")
            .replace(/\?/g, "[^/]");
          const reg = new RegExp(cleanPattern, "i");
          if (reg.test(trimmed) || reg.test(decoded) || reg.test(canonical)) {
            return {
              action: "BLOCK",
              ruleId: "MS-002",
              owaspId: "MCP02:2025",
              reason: `Blocked by mcp-shield policy: Path matches denyPaths rule "${denyPattern}"`,
              redactedTarget: redactTarget(canonical),
              errorCode: JsonRpcErrorCode.POLICY_BLOCK,
            };
          }
        } catch {
          if (
            trimmed.toLowerCase().includes(denyPattern.toLowerCase()) ||
            decoded.toLowerCase().includes(denyPattern.toLowerCase()) ||
            canonical.toLowerCase().includes(denyPattern.toLowerCase())
          ) {
            return {
              action: "BLOCK",
              ruleId: "MS-002",
              owaspId: "MCP02:2025",
              reason: `Blocked by mcp-shield policy: Path matches denyPaths rule "${denyPattern}"`,
              redactedTarget: redactTarget(canonical),
              errorCode: JsonRpcErrorCode.POLICY_BLOCK,
            };
          }
        }
      }
    }
  }

  return { action: "ALLOW" };
}
