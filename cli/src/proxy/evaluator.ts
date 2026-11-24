import * as path from "node:path";
import * as os from "node:os";
import * as fs from "node:fs";
import * as crypto from "node:crypto";
import { fileURLToPath } from "node:url";
import type {
  JsonRpcRequest,
  ProxyDecision,
  PolicyConfig,
} from "../types/index.js";

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

  // If path exists on disk, resolve its real symlink target
  if (fs.existsSync(absolute)) {
    try {
      resolved = fs.realpathSync(absolute);
    } catch {
      resolved = absolute;
    }
  } else {
    // If file does not exist, resolve realpath of nearest parent directory
    let current = absolute;
    const childSegments: string[] = [];

    while (current && current !== path.dirname(current)) {
      if (fs.existsSync(current)) {
        try {
          const realParent = fs.realpathSync(current);
          resolved = path.join(realParent, ...[...childSegments].reverse());
        } catch {
          resolved = absolute;
        }
        break;
      }
      childSegments.push(path.basename(current));
      current = path.dirname(current);
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
 * Rug-pull detector tracking tool definitions across sessions.
 */
export interface ToolDefinition {
  readonly name: string;
  readonly description?: string;
  readonly inputSchema?: unknown;
}

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

export interface StructuredToolArguments {
  paths: string[];
  commands: string[];
  rawStrings: string[];
}

export function extractStructuredArguments(request: JsonRpcRequest): StructuredToolArguments {
  const result: StructuredToolArguments = {
    paths: [],
    commands: [],
    rawStrings: [],
  };

  if (!request.params || typeof request.params !== "object") {
    return result;
  }

  const params = request.params as Record<string, unknown>;

  // Check resources/read
  if (typeof params["uri"] === "string") {
    result.paths.push(params["uri"]);
  }

  // Check tools/call arguments
  const args = params["arguments"];
  if (args && typeof args === "object") {
    const argsObj = args as Record<string, unknown>;

    const pathKeys = ["path", "filePath", "dirPath", "target", "file", "uri", "destination", "source"];
    for (const key of pathKeys) {
      const val = argsObj[key];
      if (typeof val === "string") {
        result.paths.push(val);
      } else if (Array.isArray(val)) {
        for (const item of val) {
          if (typeof item === "string") result.paths.push(item);
        }
      }
    }

    const cmdKeys = ["command", "cmd", "script", "exec"];
    for (const key of cmdKeys) {
      const val = argsObj[key];
      if (typeof val === "string") {
        result.commands.push(val);
      }
    }

    for (const val of Object.values(argsObj)) {
      if (typeof val === "string") {
        result.rawStrings.push(val);
      }
    }
  } else {
    // If no nested arguments block, walk all string values in params
    function walk(val: unknown) {
      if (typeof val === "string") {
        result.rawStrings.push(val);
      } else if (Array.isArray(val)) {
        for (const item of val) walk(item);
      } else if (val && typeof val === "object") {
        for (const v of Object.values(val as Record<string, unknown>)) walk(v);
      }
    }
    walk(params);
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
  const inspectableMethods = new Set(["tools/call", "resources/read", "prompts/get"]);

  if (!inspectableMethods.has(method)) {
    return { action: "ALLOW" };
  }

  const structured = extractStructuredArguments(request);

  // 1. Inspect Shell Commands
  const allCommands = Array.from(new Set([...structured.commands, ...structured.rawStrings]));
  for (const rawCmd of allCommands) {
    const trimmed = rawCmd.trim();
    if (!trimmed) continue;

    for (const pat of DESTRUCTIVE_COMMAND_PATTERNS) {
      if (pat.regex.test(trimmed)) {
        return {
          action: "BLOCK",
          ruleId: "MS-005",
          owaspId: "MCP05:2025",
          reason: `Blocked by mcp-shield (MS-005): Dangerous shell pattern detected (${pat.name})`,
          redactedTarget: trimmed.slice(0, 40),
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
          };
        }
      }
    }
  }

  // 2. Inspect File Paths
  const allCandidatePaths = Array.from(new Set([...structured.paths, ...structured.rawStrings]));
  for (const rawPath of allCandidatePaths) {
    const trimmed = rawPath.trim();
    if (!trimmed) continue;

    // Check Windows UNC paths
    if (isUncPath(trimmed)) {
      return {
        action: "BLOCK",
        ruleId: "MS-002",
        owaspId: "MCP02:2025",
        reason: `Blocked by mcp-shield (MS-002): Unauthorized Windows UNC network path detected`,
        redactedTarget: trimmed.slice(0, 30),
      };
    }

    const decoded = decodePathEscapes(trimmed);

    // Check decoded string against sensitive targets
    for (const pat of SENSITIVE_FILENAME_PATTERNS) {
      if (pat.regex.test(decoded)) {
        return {
          action: "BLOCK",
          ruleId: "MS-001",
          owaspId: "MCP01:2025",
          reason: `Blocked by mcp-shield (MS-001): Unauthorized access to sensitive file (${pat.name})`,
          redactedTarget: redactTarget(decoded),
        };
      }
    }

    // Resolve canonical real path on disk
    const canonical = resolveCanonicalPath(decoded);

    for (const pat of SENSITIVE_FILENAME_PATTERNS) {
      if (pat.regex.test(canonical)) {
        return {
          action: "BLOCK",
          ruleId: "MS-001",
          owaspId: "MCP01:2025",
          reason: `Blocked by mcp-shield (MS-001): Symlink or traversal access to sensitive target (${pat.name})`,
          redactedTarget: redactTarget(canonical),
        };
      }
    }

    // Custom policy denyPaths
    if (policy?.denyPaths) {
      for (const denyPattern of policy.denyPaths) {
        const cleanPattern = denyPattern.replace(/\*\*/g, ".*").replace(/\*/g, "[^/]*");
        const reg = new RegExp(cleanPattern, "i");
        if (reg.test(trimmed) || reg.test(decoded) || reg.test(canonical)) {
          return {
            action: "BLOCK",
            ruleId: "MS-002",
            owaspId: "MCP02:2025",
            reason: `Blocked by mcp-shield policy: Path matches denyPaths rule "${denyPattern}"`,
            redactedTarget: redactTarget(canonical),
          };
        }
      }
    }
  }

  return { action: "ALLOW" };
}
