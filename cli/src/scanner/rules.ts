import * as crypto from "node:crypto";
import type {
  NormalizedMcpServer,
  ScanFinding,
  PolicyConfig,
  FindingConfidence,
  RuleDefinition,
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

export function computeFindingFingerprint(
  ruleId: string,
  filePath: string,
  serverName: string,
  location: string,
  discriminator: string
): string {
  const normalizedFile = filePath.replace(/\\/g, "/");
  const raw = `${ruleId}:${normalizedFile}:${serverName}:${location}:${discriminator}`;
  return crypto.createHash("sha256").update(raw).digest("hex");
}

export function isSafePlaceholder(val: string): boolean {
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

interface SecretPatternDef {
  readonly name: string;
  readonly type: string;
  readonly regex: RegExp;
  readonly confidence: FindingConfidence;
}

const KNOWN_SECRET_PATTERNS: readonly SecretPatternDef[] = [
  {
    name: "Anthropic API Key",
    type: "anthropic",
    regex: /\b(sk-ant-[a-zA-Z0-9_\-]{20,})\b/,
    confidence: "high",
  },
  {
    name: "OpenAI API Key",
    type: "openai",
    regex: /\b(sk-[a-zA-Z0-9_\-]{20,})\b/,
    confidence: "high",
  },
  {
    name: "GitHub Personal Access Token (Classic)",
    type: "github_pat_classic",
    regex: /\b(ghp_[a-zA-Z0-9]{36})\b/,
    confidence: "high",
  },
  {
    name: "GitHub Fine-Grained Token",
    type: "github_pat_fine",
    regex: /\b(github_pat_[a-zA-Z0-9_]{22,})\b/,
    confidence: "high",
  },
  {
    name: "AWS Access Key ID",
    type: "aws_access_key",
    regex: /\b(AKIA[0-9A-Z]{16})\b/,
    confidence: "high",
  },
  {
    name: "Google Cloud API Key",
    type: "google_api_key",
    regex: /\b(AIza[0-9A-Za-z-_]{35})\b/,
    confidence: "high",
  },
  {
    name: "Slack Token",
    type: "slack_token",
    regex: /\b(xox[baprs]-[0-9a-zA-Z]{10,})\b/,
    confidence: "high",
  },
  {
    name: "Stripe Live Key",
    type: "stripe_live",
    regex: /\b(sk_live_[0-9a-zA-Z]{24,})\b/,
    confidence: "high",
  },
  {
    name: "npm Access Token",
    type: "npm_token",
    regex: /\b(npm_[a-zA-Z0-9]{36})\b/,
    confidence: "high",
  },
  {
    name: "Azure Access / Connection Key",
    type: "azure_key",
    regex: /(?:AccountKey|SharedAccessSignature)=([a-zA-Z0-9+/=]{20,})/i,
    confidence: "high",
  },
  {
    name: "Twilio API Key",
    type: "twilio_key",
    regex: /\b(SK[0-9a-fA-F]{32})\b/,
    confidence: "high",
  },
  {
    name: "JSON Web Token (JWT)",
    type: "jwt",
    regex: /\b(ey[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,})\b/,
    confidence: "high",
  },
  {
    name: "PEM Private Key",
    type: "pem_private_key",
    regex: /-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----/,
    confidence: "high",
  },
  {
    name: "Database Password URI",
    type: "db_password_uri",
    regex: /(?:postgres|postgresql|mysql|mongodb|mongodb\+srv|redis|amqp|mssql):\/\/[^:\s]+:([^@\s]+)@/i,
    confidence: "high",
  },
  {
    name: "Bearer Token",
    type: "bearer_token",
    regex: /\bBearer\s+([a-zA-Z0-9_\-\.]{20,})\b/i,
    confidence: "high",
  },
  {
    name: "Basic Auth Token",
    type: "basic_token",
    regex: /\bBasic\s+([a-zA-Z0-9+/=]{16,})\b/i,
    confidence: "high",
  },
];

const SENSITIVE_KEY_NAME_REGEX =
  /(?:api[_-]?key|secret|token|auth|password|passwd|credential|private[_-]?key|access[_-]?key)/i;

function matchesExcludePattern(filePath: string, patterns: readonly string[]): boolean {
  const normalized = filePath.replace(/\\/g, "/");
  for (const pat of patterns) {
    try {
      const normalizedPat = pat.replace(/\\/g, "/");
      const escaped = normalizedPat.replace(/[.+^${}()|[\]\\]/g, "\\$&");
      const clean = escaped
        .replace(/\*\*/g, ".*")
        .replace(/\*(?!\*)/g, "[^/]*")
        .replace(/\?/g, "[^/]");
      const reg = new RegExp(clean, "i");
      if (reg.test(normalized)) return true;
    } catch {
      if (normalized.toLowerCase().includes(pat.toLowerCase())) return true;
    }
  }
  return false;
}

/**
 * Check RULE-001 (MS-001): Hardcoded Secrets Exposure
 */
export function checkSecretLeak(
  server: NormalizedMcpServer,
  policy?: PolicyConfig
): ScanFinding[] {
  const findings: ScanFinding[] = [];

  if (policy?.secretDetection?.exclude && matchesExcludePattern(server.configPath, policy.secretDetection.exclude)) {
    return findings;
  }

  const sensitivity = policy?.secretDetection?.sensitivity || "balanced";

  const inspectValue = (val: string, location: string, keyName?: string) => {
    if (isSafePlaceholder(val)) return;

    // 1. Check known provider signature patterns (High Confidence)
    for (const pat of KNOWN_SECRET_PATTERNS) {
      const match = pat.regex.exec(val);
      if (match) {
        const rawSecret = match[1] || match[0];
        if (rawSecret && !isSafePlaceholder(rawSecret)) {
          const fingerprint = computeFindingFingerprint(
            "MS-001",
            server.configPath,
            server.serverName,
            location,
            pat.type
          );

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
            confidence: pat.confidence,
            reason: `Matches known ${pat.name} signature format.`,
            fingerprint,
          });
          return;
        }
      }
    }

    // 2. AWS Secret Access Key contextual check (40 alphanumeric/slash chars in AWS key context)
    if (keyName && /(?:aws|amazon).*(?:secret|key)/i.test(keyName)) {
      const match = /\b([0-9a-zA-Z/+=]{40})\b/.exec(val);
      if (match && match[1] && !isSafePlaceholder(match[1])) {
        const rawSecret = match[1];
        const fingerprint = computeFindingFingerprint(
          "MS-001",
          server.configPath,
          server.serverName,
          location,
          "aws_secret_key"
        );
        findings.push({
          ruleId: "MS-001",
          owaspId: "MCP01:2025",
          severity: "critical",
          title: "Hardcoded AWS Secret Access Key Detected",
          message: `Server "${server.serverName}" exposes hardcoded AWS Secret Access Key in ${location}.`,
          file: server.configPath,
          serverName: server.serverName,
          maskedEvidence: maskSecret(rawSecret),
          fixSuggestion: `Move secret to environment variable or .env file and reference with \${VAR_NAME}.`,
          confidence: "high",
          reason: "Matches 40-character AWS secret access key in AWS credential context.",
          fingerprint,
        });
        return;
      }
    }

    // 3. Contextual scoring: Sensitive Key Name + High Entropy (Medium Confidence)
    const hasSensitiveKeyName = keyName ? SENSITIVE_KEY_NAME_REGEX.test(keyName) : false;
    const entropy = calculateShannonEntropy(val);

    if (hasSensitiveKeyName && val.length >= 20 && entropy >= 4.0) {
      if (!val.includes("/") && !val.includes("\\") && !val.includes(" ")) {
        if (sensitivity === "balanced" || sensitivity === "strict") {
          const fingerprint = computeFindingFingerprint(
            "MS-001",
            server.configPath,
            server.serverName,
            location,
            "high_entropy_key"
          );
          findings.push({
            ruleId: "MS-001",
            owaspId: "MCP01:2025",
            severity: "critical",
            title: "High-Entropy Credential Detected",
            message: `Server "${server.serverName}" contains high-entropy credential string in ${location}.`,
            file: server.configPath,
            serverName: server.serverName,
            maskedEvidence: maskSecret(val),
            fixSuggestion: `Move secret to environment variable and reference with \${VAR_NAME}.`,
            confidence: "medium",
            reason: `High Shannon entropy (${entropy.toFixed(2)}) assigned to sensitive key name "${keyName}".`,
            fingerprint,
          });
          return;
        }
      }
    }

    // 4. Strict Mode: standalone high entropy without sensitive key name (Low Confidence)
    if (sensitivity === "strict" && val.length >= 28 && entropy >= 4.8) {
      if (!val.includes("/") && !val.includes("\\") && !val.includes(" ")) {
        const fingerprint = computeFindingFingerprint(
          "MS-001",
          server.configPath,
          server.serverName,
          location,
          "standalone_entropy"
        );
        findings.push({
          ruleId: "MS-001",
          owaspId: "MCP01:2025",
          severity: "high",
          title: "Suspicious High-Entropy String Detected",
          message: `Server "${server.serverName}" contains high-entropy value in ${location}.`,
          file: server.configPath,
          serverName: server.serverName,
          maskedEvidence: maskSecret(val),
          fixSuggestion: `Verify if value is a credential and migrate to environment variable if sensitive.`,
          confidence: "low",
          reason: `High Shannon entropy (${entropy.toFixed(2)}) detected under strict inspection mode.`,
          fingerprint,
        });
      }
    }
  };

  if (server.env) {
    for (const [key, val] of Object.entries(server.env)) {
      inspectValue(val, `env.${key}`, key);
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
      inspectValue(val, `headers.${header}`, header);
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
        const fingerprint = computeFindingFingerprint(
          "MS-002",
          server.configPath,
          server.serverName,
          `args[${i}]`,
          arg
        );
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
          confidence: "high",
          reason: `Path matches dangerous directory pattern (${pat.source}).`,
          fingerprint,
        });
        break;
      }
    }
  }

  return findings;
}

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
 * Check RULE-003 (MS-003): Tool Poisoning & Hidden Injection
 */
export function checkPromptInjection(server: NormalizedMcpServer): ScanFinding[] {
  const findings: ScanFinding[] = [];
  const textsToScan: { text: string; loc: string }[] = [];

  if (server.args) {
    server.args.forEach((a, i) => textsToScan.push({ text: a, loc: `args[${i}]` }));
  }
  if (server.env) {
    Object.entries(server.env).forEach(([k, v]) => textsToScan.push({ text: v, loc: `env.${k}` }));
  }

  for (const { text, loc } of textsToScan) {
    const lower = text.toLowerCase();
    for (const phrase of INJECTION_PHRASES) {
      if (lower.includes(phrase)) {
        const fingerprint = computeFindingFingerprint(
          "MS-003",
          server.configPath,
          server.serverName,
          loc,
          phrase
        );
        findings.push({
          ruleId: "MS-003",
          owaspId: "MCP03:2025",
          severity: "critical",
          title: "Prompt Injection Instruction Detected",
          message: `Server "${server.serverName}" contains override phrase "${phrase}".`,
          file: server.configPath,
          serverName: server.serverName,
          maskedEvidence: phrase,
          fixSuggestion: `Remove natural-language prompt instructions from MCP server execution arguments.`,
          confidence: "high",
          reason: `Contains prompt injection phrase "${phrase}".`,
          fingerprint,
        });
      }
    }
  }

  return findings;
}

/**
 * Check RULE-004 (MS-004): Supply Chain Execution Tampering
 */
export function checkUnpinnedPackage(server: NormalizedMcpServer): ScanFinding[] {
  const findings: ScanFinding[] = [];
  const args = server.args || [];
  const cmd = (server.command || "").toLowerCase();

  const isRunner = cmd.includes("npx") || cmd.includes("uvx") || cmd.includes("bunx");

  if (isRunner) {
    for (let i = 0; i < args.length; i++) {
      const arg = args[i];
      if (!arg || arg.startsWith("-")) continue;

      const isPinned = arg.includes("@") && (!arg.startsWith("@") || arg.slice(1).includes("@"));
      if (!isPinned) {
        const fingerprint = computeFindingFingerprint(
          "MS-004",
          server.configPath,
          server.serverName,
          `args[${i}]`,
          arg
        );
        findings.push({
          ruleId: "MS-004",
          owaspId: "MCP04:2025",
          severity: "medium",
          title: "Unpinned Package Execution",
          message: `Server "${server.serverName}" runs unpinned package "${arg}" without exact version.`,
          file: server.configPath,
          serverName: server.serverName,
          maskedEvidence: `${server.command || "npx"} ${args.join(" ")}`,
          fixSuggestion: `Pin package to an exact version (e.g. ${arg}@1.0.0).`,
          confidence: "high",
          reason: `Package execution without explicit semver tag (@version).`,
          fingerprint,
        });
      }
      // Only the first non-flag argument is the runner's target package
      break;
    }
  }

  const isContainerRunner = cmd.includes("docker") || cmd.includes("podman");
  if (isContainerRunner) {
    const runIdx = args.findIndex((a) => a === "run");
    if (runIdx !== -1) {
      let i = runIdx + 1;
      while (i < args.length) {
        const a = args[i];
        if (!a) {
          i += 1;
          continue;
        }
        if (a.startsWith("-")) {
          if (
            [
              "-v",
              "-e",
              "-p",
              "-u",
              "-w",
              "--name",
              "--network",
              "--env",
              "--volume",
              "--workdir",
              "--user",
            ].includes(a)
          ) {
            i += 2;
          } else {
            i += 1;
          }
        } else {
          const image = a;
          const isPinned =
            (image.includes(":") && !image.endsWith(":latest")) || image.includes("@sha256:");
          if (!isPinned) {
            const fingerprint = computeFindingFingerprint(
              "MS-004",
              server.configPath,
              server.serverName,
              `args[${i}]`,
              image
            );
            findings.push({
              ruleId: "MS-004",
              owaspId: "MCP04:2025",
              severity: "medium",
              title: "Unpinned Container Image Execution",
              message: `Server "${server.serverName}" runs unpinned container image "${image}" without exact tag/digest.`,
              file: server.configPath,
              serverName: server.serverName,
              maskedEvidence: `${server.command || "docker"} ${args.join(" ")}`,
              fixSuggestion: `Pin container image to an exact tag or digest (e.g. ${image}:1.0.0 or ${image}@sha256:...).`,
              confidence: "high",
              reason: `Container image without explicit pinned tag (ends with :latest or lacks tag).`,
              fingerprint,
            });
          }
          break;
        }
      }
    }
  }

  return findings;
}

const DANGEROUS_COMMANDS = [
  /\brm\s+-[a-zA-Z]*r[a-zA-Z]*f\b/i,
  /(?:curl|wget)\s+[^|]+\|\s*(?:sh|bash|zsh)/i,
  /\bchmod\s+777\b/i,
  /\b(?:mkfs\b|dd\s+if=)/i,
  /\bnc\s+-[a-zA-Z]*e\b/i,
  /(?:powershell|pwsh).*(?:-enc|-encodedcommand)\b/i,
];

/**
 * Check RULE-005 (MS-005): Dangerous Command Execution Patterns
 */
export function checkDangerousCommand(server: NormalizedMcpServer): ScanFinding[] {
  const findings: ScanFinding[] = [];
  const fullCommand = [server.command, ...(server.args || [])].filter(Boolean).join(" ");

  for (const pat of DANGEROUS_COMMANDS) {
    if (pat.test(fullCommand)) {
      const fingerprint = computeFindingFingerprint(
        "MS-005",
        server.configPath,
        server.serverName,
        "command",
        pat.source
      );
      findings.push({
        ruleId: "MS-005",
        owaspId: "MCP05:2025",
        severity: "critical",
        title: "Destructive Shell Command Detected",
        message: `Server "${server.serverName}" executes dangerous command pattern.`,
        file: server.configPath,
        serverName: server.serverName,
        maskedEvidence: fullCommand.slice(0, 60),
        fixSuggestion: `Replace dangerous inline shell command with an isolated, dedicated MCP binary.`,
        confidence: "high",
        reason: `Command line matches destructive pattern (${pat.source}).`,
        fingerprint,
      });
      break;
    }
  }

  return findings;
}

/**
 * Check RULE-006 (MS-006): Insecure Transport
 */
export function checkInsecureTransport(server: NormalizedMcpServer): ScanFinding[] {
  const findings: ScanFinding[] = [];
  if (!server.url) return findings;

  try {
    const parsed = new URL(server.url);
    if (parsed.protocol === "http:") {
      const host = parsed.hostname.toLowerCase();
      if (host !== "localhost" && host !== "127.0.0.1" && host !== "::1") {
        const fingerprint = computeFindingFingerprint(
          "MS-006",
          server.configPath,
          server.serverName,
          "url",
          server.url
        );
        findings.push({
          ruleId: "MS-006",
          owaspId: "MCP07:2025",
          severity: "high",
          title: "Insecure Plaintext Transport Detected",
          message: `Server "${server.serverName}" uses unencrypted HTTP transport (${server.url}).`,
          file: server.configPath,
          serverName: server.serverName,
          maskedEvidence: server.url,
          fixSuggestion: `Use encrypted HTTPS transport for remote MCP servers.`,
          confidence: "high",
          reason: `Plaintext HTTP endpoint on remote host ${host}.`,
          fingerprint,
        });
      }
    }
  } catch {}

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
    const fingerprint = computeFindingFingerprint(
      "MS-007",
      server.configPath,
      server.serverName,
      "serverName",
      server.serverName
    );
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
      confidence: "high",
      reason: "Server name missing from policy.yaml allowedServers list.",
      fingerprint,
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

  runCheck("MS-001", () => checkSecretLeak(server, policy));
  runCheck("MS-002", () => checkUnsafePath(server));
  runCheck("MS-003", () => checkPromptInjection(server));
  runCheck("MS-004", () => checkUnpinnedPackage(server));
  runCheck("MS-005", () => checkDangerousCommand(server));
  runCheck("MS-006", () => checkInsecureTransport(server));
  runCheck("MS-007", () => checkShadowServer(server, policy));

  return allFindings;
}

export const RULE_DEFINITIONS: readonly RuleDefinition[] = [
  {
    id: "MS-001",
    owaspId: "MCP01:2025",
    severity: "critical",
    title: "Secret Leak Detection",
    description: "Detects plaintext API keys, tokens, and credentials in MCP configurations.",
    remediation: "Extract hardcoded secrets into environment variables or a protected .env.mcp file.",
  },
  {
    id: "MS-002",
    owaspId: "MCP02:2025",
    severity: "high",
    title: "Unsafe Path Traversal",
    description: "Detects path traversal sequences (../), references to sensitive directories (.ssh, .aws, .env), or Windows UNC paths.",
    remediation: "Constrain paths within approved workspace roots and avoid parent directory traversal.",
  },
  {
    id: "MS-003",
    owaspId: "MCP03:2025",
    severity: "critical",
    title: "Prompt Injection Instruction",
    description: "Detects natural-language override commands embedded inside MCP arguments.",
    remediation: "Remove natural-language prompt instructions from executable CLI arguments.",
  },
  {
    id: "MS-004",
    owaspId: "MCP04:2025",
    severity: "medium",
    title: "Supply Chain Execution Tampering",
    description: "Detects execution of unpinned packages (npx/uvx) or container images without explicit semver tags/digests.",
    remediation: "Pin package versions (e.g. package@1.0.0) or container image tags/digests.",
  },
  {
    id: "MS-005",
    owaspId: "MCP05:2025",
    severity: "critical",
    title: "Destructive Shell Command",
    description: "Detects destructive shell commands (rm -rf, curl | sh, chmod 777) in server definitions.",
    remediation: "Replace raw destructive shell command strings with isolated, dedicated MCP binaries.",
  },
  {
    id: "MS-006",
    owaspId: "MCP07:2025",
    severity: "high",
    title: "Insecure Plaintext Transport",
    description: "Detects remote MCP connections over unencrypted HTTP protocol.",
    remediation: "Enforce HTTPS encryption for all remote MCP endpoints.",
  },
  {
    id: "MS-007",
    owaspId: "MCP09:2025",
    severity: "medium",
    title: "Shadow MCP Server Detection",
    description: "Detects active MCP servers that are not explicitly approved in policy allowedServers.",
    remediation: "Register the server in policy.yaml allowedServers or disable the unapproved server.",
  },
];
