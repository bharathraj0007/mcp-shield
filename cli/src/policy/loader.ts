import * as fs from "node:fs";
import * as path from "node:path";
import * as os from "node:os";
import { parse as parseYaml } from "yaml";
import { z } from "zod";
import type { PolicyConfig } from "../types/index.js";

const RuleIdRegex = /^MS-\d{3}$/;

export const SecretDetectionSchema = z
  .object({
    sensitivity: z.enum(["low", "balanced", "strict"]).default("balanced"),
    exclude: z.array(z.string()).default([]),
  })
  .strict();

export const RugPullPolicySchema = z
  .object({
    mode: z.enum(["off", "monitor", "approve", "enforce"]).default("enforce"),
    persistence: z.enum(["local", "memory"]).default("local"),
    baselinePath: z.string().optional(),
    immutableFields: z.array(z.string()).default(["description", "inputSchema"]),
  })
  .strict();

export const PolicySchema = z
  .object({
    version: z.string().default("1.0"),
    mode: z
      .enum(["monitor", "enforce", "baseline", "quarantine", "audit-only"])
      .default("enforce"),
    inherit: z.array(z.string()).default([]),
    denyPaths: z
      .array(z.string())
      .default([
        "**/.env",
        "**/.env.*",
        "~/.ssh/**",
        "~/.aws/**",
        "~/.gnupg/**",
        "/etc/passwd",
      ]),
    allowPaths: z.array(z.string()).default(["./src/**"]),
    blockedCommands: z
      .array(z.string())
      .default(["rm -rf", "curl * | sh", "wget * | bash", "chmod 777"]),
    disabledRules: z
      .array(z.string().regex(RuleIdRegex, "Must be valid Rule ID (e.g. MS-001)"))
      .default([]),
    allowedServers: z.array(z.string()).optional(),
    failOnSeverity: z.enum(["critical", "high", "medium", "low"]).default("high"),
    secretDetection: SecretDetectionSchema.optional(),
    blockedMethods: z.array(z.string()).default([]),
    allowedTools: z.array(z.string()).optional(),
    deniedTools: z.array(z.string()).default([]),
    allowedHosts: z.array(z.string()).optional(),
    deniedHosts: z.array(z.string()).default([]),
    processAllowlist: z.array(z.string()).optional(),
    rugPull: RugPullPolicySchema.optional(),
  })
  .strict()
  .superRefine((val, ctx) => {
    // Check conflicting tool rules
    if (val.allowedTools && val.deniedTools) {
      for (const t of val.allowedTools) {
        if (val.deniedTools.includes(t)) {
          ctx.addIssue({
            code: z.ZodIssueCode.custom,
            message: `Conflicting rule: Tool "${t}" is present in both allowedTools and deniedTools`,
            path: ["allowedTools"],
          });
        }
      }
    }
    // Check conflicting host rules
    if (val.allowedHosts && val.deniedHosts) {
      for (const h of val.allowedHosts) {
        if (val.deniedHosts.includes(h)) {
          ctx.addIssue({
            code: z.ZodIssueCode.custom,
            message: `Conflicting rule: Host "${h}" is present in both allowedHosts and deniedHosts`,
            path: ["allowedHosts"],
          });
        }
      }
    }
    // Check conflicting path rules
    if (val.allowPaths && val.denyPaths) {
      for (const p of val.allowPaths) {
        if (val.denyPaths.includes(p)) {
          ctx.addIssue({
            code: z.ZodIssueCode.custom,
            message: `Conflicting rule: Path pattern "${p}" is present in both allowPaths and denyPaths`,
            path: ["allowPaths"],
          });
        }
      }
    }
  });

export const DEFAULT_POLICY: PolicyConfig = {
  version: "1.0",
  mode: "enforce",
  inherit: [],
  denyPaths: [
    "**/.env",
    "**/.env.*",
    "~/.ssh/**",
    "~/.aws/**",
    "~/.gnupg/**",
    "/etc/passwd",
  ],
  allowPaths: ["./src/**"],
  blockedCommands: ["rm -rf", "curl * | sh", "wget * | bash", "chmod 777"],
  disabledRules: [],
  failOnSeverity: "high",
  secretDetection: {
    sensitivity: "balanced",
    exclude: [],
  },
  blockedMethods: [],
  deniedTools: [],
  deniedHosts: [],
  rugPull: {
    mode: "enforce",
    persistence: "local",
    immutableFields: ["description", "inputSchema"],
  },
};

export const STRICT_POLICY: PolicyConfig = {
  version: "1.0",
  mode: "enforce",
  inherit: [],
  denyPaths: [
    "**/.env*",
    "~/.ssh/**",
    "~/.aws/**",
    "~/.gnupg/**",
    "~/.kube/**",
    "/etc/**",
    "C:\\Windows\\System32\\**",
  ],
  allowPaths: ["./src/**"],
  blockedCommands: [
    "rm -rf",
    "curl * | sh",
    "wget * | bash",
    "chmod 777",
    "dd if=",
    "nc -e",
    "powershell -enc",
  ],
  disabledRules: [],
  failOnSeverity: "medium",
  secretDetection: {
    sensitivity: "strict",
    exclude: [],
  },
  blockedMethods: ["sampling/createMessage"],
  deniedTools: [],
  deniedHosts: [
    "localhost",
    "127.0.0.1",
    "0.0.0.0",
    "169.254.169.254",
    "10.*",
    "192.168.*",
  ],
  processAllowlist: ["node", "git", "npm", "npx"],
  rugPull: {
    mode: "enforce",
    persistence: "local",
    immutableFields: ["description", "inputSchema", "outputSchema", "annotations"],
  },
};

function expandHome(p: string): string {
  if (p.startsWith("~")) {
    return path.join(os.homedir(), p.slice(1));
  }
  return p;
}

export function mergePolicyConfigs(
  base: PolicyConfig,
  override: Partial<PolicyConfig>
): PolicyConfig {
  return {
    version: override.version ?? base.version,
    mode: override.mode ?? base.mode,
    failOnSeverity: override.failOnSeverity ?? base.failOnSeverity,
    inherit: override.inherit
      ? Array.from(new Set([...(base.inherit || []), ...override.inherit]))
      : base.inherit,
    denyPaths: Array.from(
      new Set([...(base.denyPaths || []), ...(override.denyPaths || [])])
    ),
    allowPaths: Array.from(
      new Set([...(base.allowPaths || []), ...(override.allowPaths || [])])
    ),
    blockedCommands: Array.from(
      new Set([...(base.blockedCommands || []), ...(override.blockedCommands || [])])
    ),
    disabledRules: Array.from(
      new Set([...(base.disabledRules || []), ...(override.disabledRules || [])])
    ),
    allowedServers: override.allowedServers ?? base.allowedServers,
    blockedMethods: Array.from(
      new Set([...(base.blockedMethods || []), ...(override.blockedMethods || [])])
    ),
    allowedTools: override.allowedTools ?? base.allowedTools,
    deniedTools: Array.from(
      new Set([...(base.deniedTools || []), ...(override.deniedTools || [])])
    ),
    allowedHosts: override.allowedHosts ?? base.allowedHosts,
    deniedHosts: Array.from(
      new Set([...(base.deniedHosts || []), ...(override.deniedHosts || [])])
    ),
    processAllowlist: override.processAllowlist ?? base.processAllowlist,
    secretDetection: {
      sensitivity:
        override.secretDetection?.sensitivity ??
        base.secretDetection?.sensitivity ??
        "balanced",
      exclude: Array.from(
        new Set([
          ...(base.secretDetection?.exclude || []),
          ...(override.secretDetection?.exclude || []),
        ])
      ),
    },
    rugPull: {
      mode: override.rugPull?.mode ?? base.rugPull?.mode ?? "enforce",
      persistence:
        override.rugPull?.persistence ?? base.rugPull?.persistence ?? "local",
      baselinePath: override.rugPull?.baselinePath ?? base.rugPull?.baselinePath,
      immutableFields: Array.from(
        new Set([
          ...(base.rugPull?.immutableFields || ["description", "inputSchema"]),
          ...(override.rugPull?.immutableFields || []),
        ])
      ),
    },
  };
}

/**
 * Validate a policy file strictly using Zod schema.
 */
export function validatePolicyFile(filePath: string): {
  valid: boolean;
  errors: string[];
  policy?: PolicyConfig;
} {
  const resolved = path.resolve(expandHome(filePath));

  let content: string;
  try {
    content = fs.readFileSync(resolved, "utf-8");
  } catch (err: unknown) {
    const code = (err as NodeJS.ErrnoException).code;
    if (code === "ENOENT") {
      return { valid: false, errors: [`Policy file not found: ${filePath}`] };
    }
    return {
      valid: false,
      errors: [`Failed to read policy file: ${(err as Error).message}`],
    };
  }

  let rawParsed: unknown;
  try {
    rawParsed = parseYaml(content);
  } catch (err) {
    return {
      valid: false,
      errors: [`Invalid YAML syntax: ${(err as Error).message}`],
    };
  }

  const parsed = PolicySchema.safeParse(rawParsed);
  if (!parsed.success) {
    const errorDetails = parsed.error.issues.map(
      (i) => `${i.path.join(".") || "root"}: ${i.message}`
    );
    return { valid: false, errors: errorDetails };
  }

  return { valid: true, errors: [], policy: parsed.data as PolicyConfig };
}

/**
 * Load policy configuration honoring precedence:
 * Built-in defaults < global policy < workspace policy < repository policy < inherited files < CLI overrides < environment overrides
 */
export function loadPolicy(
  explicitPath?: string,
  cliOverrides?: Partial<PolicyConfig>
): PolicyConfig {
  let effectivePolicy = DEFAULT_POLICY;

  // 1. Check Global Policy: ~/.mcp-shield/policy.yaml
  const globalPath = path.join(os.homedir(), ".mcp-shield", "policy.yaml");
  const resGlobal = validatePolicyFile(globalPath);
  if (resGlobal.valid && resGlobal.policy) {
    effectivePolicy = mergePolicyConfigs(effectivePolicy, resGlobal.policy);
  }

  // 2. Check Workspace Policy: ./policy.yaml or ./.mcp-shield/policy.yaml
  let workspacePath: string | undefined;
  const local1 = path.resolve(process.cwd(), "policy.yaml");
  const local2 = path.resolve(process.cwd(), ".mcp-shield", "policy.yaml");
  const resLocal1 = validatePolicyFile(local1);
  if (resLocal1.valid && resLocal1.policy) {
    workspacePath = local1;
  } else {
    const resLocal2 = validatePolicyFile(local2);
    if (resLocal2.valid && resLocal2.policy) {
      workspacePath = local2;
    }
  }

  // 3. Explicit CLI/Target Path
  const targetPath = explicitPath ? path.resolve(expandHome(explicitPath)) : workspacePath;

  if (targetPath) {
    const res = validatePolicyFile(targetPath);
    if (!res.valid) {
      throw new Error(
        `Policy validation error in ${targetPath}:\n${res.errors.map((e) => `  - ${e}`).join("\n")}`
      );
    }
    if (res.policy) {
      // 4. Resolve Inherited Policies Recursively
      const activeStack = new Set<string>([targetPath]);
      const visited = new Set<string>();
      const loadInherited = (inheritList: readonly string[], baseDir: string) => {
        for (const relInherit of inheritList) {
          const inheritPath = path.resolve(baseDir, expandHome(relInherit));
          if (activeStack.has(inheritPath)) {
            throw new Error(
              `Circular policy inheritance detected: "${inheritPath}" is already in active inheritance chain.`
            );
          }
          if (visited.has(inheritPath)) continue;
          visited.add(inheritPath);
          activeStack.add(inheritPath);

          const iRes = validatePolicyFile(inheritPath);
          if (!iRes.valid) {
            throw new Error(
              `Inherited policy validation error in ${inheritPath}:\n${iRes.errors.map((e) => `  - ${e}`).join("\n")}`
            );
          }
          if (iRes.policy) {
            if (iRes.policy.inherit && iRes.policy.inherit.length > 0) {
              loadInherited(iRes.policy.inherit, path.dirname(inheritPath));
            }
            effectivePolicy = mergePolicyConfigs(effectivePolicy, iRes.policy);
          }
          activeStack.delete(inheritPath);
        }
      };

      if (res.policy.inherit && res.policy.inherit.length > 0) {
        loadInherited(res.policy.inherit, path.dirname(targetPath));
      }

      effectivePolicy = mergePolicyConfigs(effectivePolicy, res.policy);
    }
  }

  // 5. Apply CLI overrides
  if (cliOverrides) {
    effectivePolicy = mergePolicyConfigs(effectivePolicy, cliOverrides);
  }

  // 6. Apply Environment variable overrides
  if (process.env["MCP_SHIELD_MODE"]) {
    const envMode = process.env["MCP_SHIELD_MODE"] as PolicyConfig["mode"];
    if (["monitor", "enforce", "baseline", "quarantine", "audit-only"].includes(envMode)) {
      effectivePolicy = { ...effectivePolicy, mode: envMode };
    }
  }
  if (process.env["MCP_SHIELD_FAIL_ON"]) {
    const envFailOn = process.env["MCP_SHIELD_FAIL_ON"] as PolicyConfig["failOnSeverity"];
    if (["critical", "high", "medium", "low"].includes(envFailOn)) {
      effectivePolicy = { ...effectivePolicy, failOnSeverity: envFailOn };
    }
  }

  return effectivePolicy;
}

/**
 * Return JSON Schema describing the policy.yaml specification.
 */
export function getPolicyJsonSchema(): Record<string, unknown> {
  return {
    $schema: "http://json-schema.org/draft-07/schema#",
    title: "McpShieldPolicy",
    type: "object",
    additionalProperties: false,
    properties: {
      version: { type: "string", default: "1.0" },
      mode: {
        type: "string",
        enum: ["monitor", "enforce", "baseline", "quarantine", "audit-only"],
        default: "enforce",
      },
      inherit: {
        type: "array",
        items: { type: "string" },
        default: [],
      },
      denyPaths: {
        type: "array",
        items: { type: "string" },
      },
      allowPaths: {
        type: "array",
        items: { type: "string" },
      },
      blockedCommands: {
        type: "array",
        items: { type: "string" },
      },
      disabledRules: {
        type: "array",
        items: { type: "string", pattern: "^MS-\\d{3}$" },
      },
      allowedServers: {
        type: "array",
        items: { type: "string" },
      },
      failOnSeverity: {
        type: "string",
        enum: ["critical", "high", "medium", "low"],
        default: "high",
      },
      secretDetection: {
        type: "object",
        additionalProperties: false,
        properties: {
          sensitivity: { type: "string", enum: ["low", "balanced", "strict"], default: "balanced" },
          exclude: { type: "array", items: { type: "string" } },
        },
      },
      blockedMethods: {
        type: "array",
        items: { type: "string" },
      },
      allowedTools: {
        type: "array",
        items: { type: "string" },
      },
      deniedTools: {
        type: "array",
        items: { type: "string" },
      },
      allowedHosts: {
        type: "array",
        items: { type: "string" },
      },
      deniedHosts: {
        type: "array",
        items: { type: "string" },
      },
      processAllowlist: {
        type: "array",
        items: { type: "string" },
      },
      rugPull: {
        type: "object",
        additionalProperties: false,
        properties: {
          mode: { type: "string", enum: ["off", "monitor", "approve", "enforce"], default: "enforce" },
          persistence: { type: "string", enum: ["local", "memory"], default: "local" },
          baselinePath: { type: "string" },
          immutableFields: { type: "array", items: { type: "string" } },
        },
      },
    },
    required: ["version", "mode"],
  };
}

/**
 * Return starter policy.yaml content by template name.
 */
export function getStarterPolicyContent(template: "default" | "strict" = "default"): string {
  if (template === "strict") {
    return `# mcp-shield Strict Security Policy
version: "1.0"
mode: "enforce" # "enforce" | "monitor" | "baseline" | "quarantine" | "audit-only"
failOnSeverity: "medium" # "critical" | "high" | "medium" | "low"

denyPaths:
  - "**/.env*"
  - "~/.ssh/**"
  - "~/.aws/**"
  - "~/.gnupg/**"
  - "~/.kube/**"
  - "/etc/**"
  - "C:\\\\Windows\\\\System32\\\\**"

allowPaths:
  - "./src/**"

blockedCommands:
  - "rm -rf"
  - "curl * | sh"
  - "wget * | bash"
  - "chmod 777"
  - "dd if="
  - "nc -e"
  - "powershell -enc"

blockedMethods:
  - "sampling/createMessage"

deniedHosts:
  - "localhost"
  - "127.0.0.1"
  - "0.0.0.0"
  - "169.254.169.254"

processAllowlist:
  - "node"
  - "git"
  - "npm"
  - "npx"

secretDetection:
  sensitivity: "strict" # "low" | "balanced" | "strict"
  exclude: []

rugPull:
  mode: "enforce"
  persistence: "local"
  immutableFields:
    - "description"
    - "inputSchema"
    - "outputSchema"
    - "annotations"
`;
  }

  return `# mcp-shield Starter Security Policy
version: "1.0"
mode: "enforce" # "enforce" | "monitor" | "baseline" | "quarantine" | "audit-only"
failOnSeverity: "high" # "critical" | "high" | "medium" | "low"

denyPaths:
  - "**/.env"
  - "**/.env.*"
  - "~/.ssh/**"
  - "~/.aws/**"
  - "~/.gnupg/**"
  - "/etc/passwd"

allowPaths:
  - "./src/**"

blockedCommands:
  - "rm -rf"
  - "curl * | sh"
  - "wget * | bash"
  - "chmod 777"

disabledRules: []
allowedServers: []

secretDetection:
  sensitivity: "balanced" # "low" | "balanced" | "strict"
  exclude: []

rugPull:
  mode: "enforce"
  persistence: "local"
  immutableFields:
    - "description"
    - "inputSchema"
`;
}
