import type {
  NormalizedMcpServer,
  ScanFinding,
  PolicyConfig,
} from "../types/index.js";

/**
 * Calculate Shannon entropy of a string.
 */
export function calculateShannonEntropy(str: string): number {
  if (str.length === 0) return 0;
  const frequencies = new Map<string, number>();
  for (const char of str) {
    frequencies.set(char, (frequencies.get(char) || 0) + 1);
  }
  let entropy = 0;
  const len = str.length;
  for (const count of frequencies.values()) {
    const p = count / len;
    entropy -= p * Math.log2(p);
  }
  return entropy;
}

/**
 * Mask secret string for safe display.
 * Example: "sk-proj-1234567890abcdef" -> "sk-proj-***...cdef"
 */
export function maskSecret(secret: string): string {
  if (secret.length <= 8) {
    return "***";
  }
  const prefix = secret.slice(0, 7);
  const suffix = secret.slice(-4);
  return `${prefix}***...${suffix}`;
}

const KNOWN_SECRET_PATTERNS: readonly { readonly name: string; readonly regex: RegExp }[] = [
  { name: "OpenAI API Key", regex: /\b(sk-[a-zA-Z0-9_\-]{20,})\b/ },
  { name: "Anthropic API Key", regex: /\b(sk-ant-[a-zA-Z0-9_\-]{20,})\b/ },
  { name: "GitHub Personal Access Token", regex: /\b(ghp_[a-zA-Z0-9]{36})\b/ },
  { name: "GitHub Fine-Grained Token", regex: /\b(github_pat_[a-zA-Z0-9_]{22,})\b/ },
  { name: "AWS Access Key ID", regex: /\b(AKIA[0-9A-Z]{16})\b/ },
  { name: "Google Cloud API Key", regex: /\b(AIza[0-9A-Za-z-_]{35})\b/ },
  { name: "Slack Token", regex: /\b(xox[baprs]-[0-9a-zA-Z]{10,})\b/ },
  { name: "Stripe Live Key", regex: /\b(sk_live_[0-9a-zA-Z]{24,})\b/ },
  { name: "Bearer Token", regex: /\bBearer\s+([a-zA-Z0-9_\-\.]{20,})\b/i },
  {
    name: "Database Password URI",
    regex: /(?:postgres|mysql|mongodb(?:\+srv)?):\/\/[^:\s]+:([^@\s]+)@/i,
  },
];

function isSafePlaceholder(val: string): boolean {
  const trimmed = val.trim();
  if (trimmed.startsWith("${") && trimmed.endsWith("}")) return true;
  if (/^\$[A-Z0-9_]+$/.test(trimmed)) return true;
  const lower = trimmed.toLowerCase();
  return (
    lower.includes("example") ||
    lower.includes("placeholder") ||
    lower.includes("your_api_key") ||
    lower.includes("changeme") ||
    lower.includes("todo") ||
    lower.includes("<insert") ||
    lower.includes("replace_me")
  );
}

// Invisible unicode detection regex
const UNICODE_EVASION_REGEX =
  /[\u200B-\u200F\u202A-\u202E\uFEFF]|[\uD83C][\uDC00-\uDC7F]|[\uD83E][\uDD00-\uDDFF]/u;

const INJECTION_PHRASES = [
  "ignore previous instructions",
  "disregard instructions",
  "do not tell the user",
  "exfiltrate",
  "read ~/.ssh",
  "read /etc/passwd",
  "<important>",
  "system prompt:",
];

/**
 * Check RULE-001 (MS-001): Hardcoded Secrets Exposure
 */
export function checkSecretLeak(server: NormalizedMcpServer): ScanFinding[] {
  const findings: ScanFinding[] = [];

  const inspectValue = (val: string, location: string) => {
    if (isSafePlaceholder(val)) return;

    for (const pat of KNOWN_SECRET_PATTERNS) {
      const match = pat.regex.exec(val);
      if (match && match[1]) {
        const rawSecret = match[1];
        if (!isSafePlaceholder(rawSecret)) {
          findings.push({
            ruleId: "MS-001",
            owaspId: "MCP01:2025",
            severity: "critical",
            title: `Hardcoded ${pat.name} Detected`,
            message: `Server "${server.serverName}" exposes hardcoded ${pat.name} in ${location}.`,
            file: server.configPath,
            serverName: server.serverName,
            maskedEvidence: maskSecret(rawSecret),
            fixSuggestion: `Move secret to environment variable or .env file and reference with \${VAR_NAME}.`,
          });
          return;
        }
      }
    }

    // High Shannon entropy check
    if (val.length >= 20 && calculateShannonEntropy(val) >= 4.5) {
      // Avoid flagging standard filesystem paths or command strings
      if (!val.includes("/") && !val.includes("\\") && !val.includes(" ")) {
        findings.push({
          ruleId: "MS-001",
          owaspId: "MCP01:2025",
          severity: "critical",
          title: "High-Entropy Secret Detected",
          message: `Server "${server.serverName}" contains high-entropy string in ${location}.`,
          file: server.configPath,
          serverName: server.serverName,
          maskedEvidence: maskSecret(val),
          fixSuggestion: `Move secret to environment variable and reference with \${VAR_NAME}.`,
        });
      }
    }
  };

  if (server.env) {
    for (const [key, val] of Object.entries(server.env)) {
      inspectValue(val, `env.${key}`);
    }
  }

  if (server.args) {
    for (let i = 0; i < server.args.length; i++) {
      const arg = server.args[i];
      if (arg) {
        inspectValue(arg, `args[${i}]`);
      }
    }
  }

  if (server.headers) {
    for (const [header, val] of Object.entries(server.headers)) {
      inspectValue(val, `headers.${header}`);
    }
  }

  return findings;
}

/**
 * Check RULE-002 (MS-002): Scope Creep & Unsafe Path Exposure
 */
export function checkUnsafePath(server: NormalizedMcpServer): ScanFinding[] {
  const findings: ScanFinding[] = [];
  const args = server.args || [];

  const dangerousPaths = [
    /^(?:\/|C:\\|C:\/)$/i,
    /^(?:~|\$HOME|%USERPROFILE%)(?:\/|\\)?$/i,
    /(?:~|\/home\/[^/]+|\$HOME)\/\.ssh\b/i,
    /(?:~|\/home\/[^/]+|\$HOME)\/\.aws\b/i,
    /(?:~|\/home\/[^/]+|\$HOME)\/\.gnupg\b/i,
    /(?:~|\/home\/[^/]+|\$HOME)\/\.kube\b/i,
    /^\/etc(?:\/.*)?$/i,
    /(?:^|\/|\\)\.env(?:\..*)?$/i,
  ];

  for (let i = 0; i < args.length; i++) {
    const arg = args[i];
    if (!arg) continue;

    for (const pat of dangerousPaths) {
      if (pat.test(arg.trim())) {
        findings.push({
          ruleId: "MS-002",
          owaspId: "MCP02:2025",
          severity: "high",
          title: "Unsafe Path Scope Exposure",
          message: `Server "${server.serverName}" grants access to sensitive root, user, or credential path "${arg}".`,
          file: server.configPath,
          serverName: server.serverName,
          maskedEvidence: arg,
          fixSuggestion: `Restrict filesystem server scope to a designated project subfolder (e.g. "./docs" or "./workspace").`,
        });
        break;
      }
    }
  }

  return findings;
}

/**
 * Check RULE-003 (MS-003): Tool Poisoning & Hidden Injection
 */
export function checkPromptInjection(server: NormalizedMcpServer): ScanFinding[] {
  const findings: ScanFinding[] = [];
  const textsToScan: string[] = [];

  if (server.args) textsToScan.push(...server.args);
  if (server.env) textsToScan.push(...Object.values(server.env));

  for (const text of textsToScan) {
    const lower = text.toLowerCase();
    for (const phrase of INJECTION_PHRASES) {
      if (lower.includes(phrase)) {
        findings.push({
          ruleId: "MS-003",
          owaspId: "MCP03:2025",
          severity: "critical",
          title: "Prompt Injection Instruction Detected",
          message: `Server "${server.serverName}" contains override phrase "${phrase}".`,
          file: server.configPath,
          serverName: server.serverName,
          maskedEvidence: phrase,
          fixSuggestion: `Remove override instructions and untrusted prompt text from server arguments.`,
        });
        break;
      }
    }

    if (UNICODE_EVASION_REGEX.test(text)) {
      findings.push({
        ruleId: "MS-003",
        owaspId: "MCP03:2025",
        severity: "critical",
        title: "Invisible Unicode Obfuscation Detected",
        message: `Server "${server.serverName}" contains zero-width or BiDi override characters.`,
        file: server.configPath,
        serverName: server.serverName,
        maskedEvidence: "[Invisible Unicode Control Characters]",
        fixSuggestion: `Strip zero-width and control characters from configuration parameters.`,
      });
      break;
    }
  }

  return findings;
}

/**
 * Check RULE-004 (MS-004): Unpinned Dependency Tampering
 */
export function checkUnpinnedPackage(server: NormalizedMcpServer): ScanFinding[] {
  const findings: ScanFinding[] = [];
  const cmd = (server.command || "").toLowerCase();
  const args = server.args || [];

  const isRunner = cmd === "npx" || cmd === "pnpx" || cmd === "uvx" || cmd === "bunx";
  if (!isRunner) return findings;

  // Find target package in args
  for (const arg of args) {
    if (arg.startsWith("-")) continue; // flags like -y, --yes
    if (arg.startsWith("./") || arg.startsWith("../") || arg.startsWith("/")) continue;

    // Check if package has version pin (e.g. pkg@1.2.3 or @scope/pkg@1.2.3)
    const hasPin = /@[0-9]+\.[0-9]+\.[0-9]+/.test(arg);
    const hasLatest = arg.endsWith("@latest");

    if (!hasPin || hasLatest) {
      findings.push({
        ruleId: "MS-004",
        owaspId: "MCP04:2025",
        severity: "medium",
        title: "Unpinned Remote Package Execution",
        message: `Server "${server.serverName}" runs unpinned package "${arg}" via ${cmd}.`,
        file: server.configPath,
        serverName: server.serverName,
        maskedEvidence: arg,
        fixSuggestion: `Pin package to an exact semver version (e.g. "${arg}@1.0.0") instead of floating tags.`,
      });
      break;
    }
  }

  return findings;
}

/**
 * Check RULE-005 (MS-005): Dangerous Shell Command Injection
 */
export function checkDangerousCommand(server: NormalizedMcpServer): ScanFinding[] {
  const findings: ScanFinding[] = [];
  const fullCommandString = [server.command || "", ...(server.args || [])].join(" ");

  const dangerousShellPatterns: readonly { readonly name: string; readonly regex: RegExp }[] = [
    { name: "Recursive Deletion", regex: /\brm\s+-[a-zA-Z]*r[a-zA-Z]*f\b/i },
    { name: "Remote Shell Pipe", regex: /(?:curl|wget)\s+[^|]+\|\s*(?:sh|bash|zsh)/i },
    { name: "Global Permission Escalation", regex: /\bchmod\s+777\b/i },
    { name: "Filesystem Formatting", regex: /\b(?:mkfs|dd\s+if=)\b/i },
    { name: "Reverse Shell Listener", regex: /\bnc\s+-[a-zA-Z]*e\b/i },
    { name: "Encoded PowerShell Execution", regex: /(?:powershell|pwsh).*(?:-enc|-encodedcommand)\b/i },
    { name: "Unescaped Shell Chaining", regex: /[;&|`]|(?:\$\([^)]+\))/ },
  ];

  for (const pat of dangerousShellPatterns) {
    if (pat.regex.test(fullCommandString)) {
      findings.push({
        ruleId: "MS-005",
        owaspId: "MCP05:2025",
        severity: "critical",
        title: `Destructive Command Execution: ${pat.name}`,
        message: `Server "${server.serverName}" contains risky shell pattern matching ${pat.name}.`,
        file: server.configPath,
        serverName: server.serverName,
        maskedEvidence: fullCommandString.slice(0, 80),
        fixSuggestion: `Avoid executing shell wrappers or destructive commands in MCP server definitions.`,
      });
      break;
    }
  }

  return findings;
}

/**
 * Check RULE-006 (MS-006): Insecure Plaintext HTTP Transport
 */
export function checkInsecureTransport(server: NormalizedMcpServer): ScanFinding[] {
  const findings: ScanFinding[] = [];
  if (!server.url) return findings;

  try {
    const parsed = new URL(server.url);
    if (parsed.protocol === "http:") {
      const hostname = parsed.hostname.toLowerCase();
      const isLocal =
        hostname === "localhost" ||
        hostname === "127.0.0.1" ||
        hostname === "::1" ||
        hostname === "[::1]";

      if (!isLocal) {
        findings.push({
          ruleId: "MS-006",
          owaspId: "MCP07:2025",
          severity: "high",
          title: "Insecure Plaintext HTTP Transport",
          message: `Server "${server.serverName}" connects over unencrypted HTTP to remote endpoint "${parsed.hostname}".`,
          file: server.configPath,
          serverName: server.serverName,
          maskedEvidence: server.url,
          fixSuggestion: `Use encrypted HTTPS transport for remote MCP servers.`,
        });
      }
    }
  } catch {
    // Malformed URL, skip transport check
  }

  return findings;
}

/**
 * Check RULE-007 (MS-007): Shadow MCP Server Detection
 */
export function checkShadowServer(
  server: NormalizedMcpServer,
  policy?: PolicyConfig
): ScanFinding[] {
  const findings: ScanFinding[] = [];
  if (!policy?.allowedServers || policy.allowedServers.length === 0) {
    return findings;
  }

  if (!policy.allowedServers.includes(server.serverName)) {
    findings.push({
      ruleId: "MS-007",
      owaspId: "MCP09:2025",
      severity: "medium",
      title: "Shadow MCP Server Detected",
      message: `Server "${server.serverName}" is not listed in policy allowedServers.`,
      file: server.configPath,
      serverName: server.serverName,
      maskedEvidence: server.serverName,
      fixSuggestion: `Register "${server.serverName}" in policy.yaml allowedServers or disable the server.`,
    });
  }

  return findings;
}

/**
 * Execute all security checks on a server instance.
 */
export function evaluateServerRules(
  server: NormalizedMcpServer,
  policy?: PolicyConfig
): ScanFinding[] {
  const disabled = new Set(policy?.disabledRules || []);
  const allFindings: ScanFinding[] = [];

  const runCheck = (ruleId: string, fn: () => ScanFinding[]) => {
    if (!disabled.has(ruleId)) {
      allFindings.push(...fn());
    }
  };

  runCheck("MS-001", () => checkSecretLeak(server));
  runCheck("MS-002", () => checkUnsafePath(server));
  runCheck("MS-003", () => checkPromptInjection(server));
  runCheck("MS-004", () => checkUnpinnedPackage(server));
  runCheck("MS-005", () => checkDangerousCommand(server));
  runCheck("MS-006", () => checkInsecureTransport(server));
  runCheck("MS-007", () => checkShadowServer(server, policy));

  return allFindings;
}
