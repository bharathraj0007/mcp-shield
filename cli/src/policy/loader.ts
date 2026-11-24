import * as fs from "node:fs";
import * as path from "node:path";
import * as os from "node:os";
import { parse as parseYaml } from "yaml";
import { z } from "zod";
import type { PolicyConfig } from "../types/index.js";

export const PolicySchema = z.object({
  version: z.string().default("1.0"),
  mode: z.enum(["enforce", "monitor"]).default("enforce"),
  denyPaths: z.array(z.string()).default([
    "**/.env",
    "**/.env.*",
    "~/.ssh/**",
    "~/.aws/**",
    "~/.gnupg/**",
    "/etc/passwd",
  ]),
  allowPaths: z.array(z.string()).default(["./src/**"]),
  blockedCommands: z.array(z.string()).default([
    "rm -rf",
    "curl * | sh",
    "wget * | bash",
    "chmod 777",
  ]),
  disabledRules: z.array(z.string()).default([]),
  allowedServers: z.array(z.string()).optional(),
  failOnSeverity: z.enum(["critical", "high", "medium", "low"]).default("high"),
});

export const DEFAULT_POLICY: PolicyConfig = {
  version: "1.0",
  mode: "enforce",
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
};

function expandHome(p: string): string {
  if (p.startsWith("~")) {
    return path.join(os.homedir(), p.slice(1));
  }
  return p;
}

export function loadPolicy(explicitPath?: string): PolicyConfig {
  let targetPath: string | undefined;

  if (explicitPath) {
    const resolved = path.resolve(expandHome(explicitPath));
    if (!fs.existsSync(resolved)) {
      throw new Error(`Policy file not found at: ${explicitPath}`);
    }
    targetPath = resolved;
  } else {
    // Check ./policy.yaml
    const localPolicy = path.resolve(process.cwd(), "policy.yaml");
    if (fs.existsSync(localPolicy)) {
      targetPath = localPolicy;
    } else {
      // Check ~/.mcp-shield/policy.yaml
      const userPolicy = path.join(os.homedir(), ".mcp-shield", "policy.yaml");
      if (fs.existsSync(userPolicy)) {
        targetPath = userPolicy;
      }
    }
  }

  if (!targetPath) {
    return DEFAULT_POLICY;
  }

  let content: string;
  try {
    content = fs.readFileSync(targetPath, "utf-8");
  } catch (err) {
    throw new Error(`Failed to read policy file at ${targetPath}: ${(err as Error).message}`);
  }

  let rawParsed: unknown;
  try {
    rawParsed = parseYaml(content);
  } catch (err) {
    throw new Error(`Invalid YAML syntax in policy file at ${targetPath}: ${(err as Error).message}`);
  }

  const parsed = PolicySchema.safeParse(rawParsed);
  if (!parsed.success) {
    const errorDetails = parsed.error.issues
      .map((i) => `  - ${i.path.join(".")}: ${i.message}`)
      .join("\n");
    throw new Error(`Policy validation error in ${targetPath}:\n${errorDetails}`);
  }

  return parsed.data as PolicyConfig;
}
