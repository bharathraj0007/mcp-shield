import * as fs from "node:fs";
import * as path from "node:path";
import * as os from "node:os";
import { parse as parseJsonc } from "jsonc-parser";
import { parse as parseYaml } from "yaml";
import type { NormalizedMcpServer, McpClientType, McpTransportType } from "../types/index.js";

interface KnownLocation {
  readonly client: McpClientType;
  readonly scope: "global" | "workspace";
  readonly getPath: () => string;
  readonly serverKey: "mcpServers" | "servers" | "context_servers";
  readonly urlKeys: readonly string[];
}

function expandHome(p: string): string {
  if (p.startsWith("~")) {
    return path.join(os.homedir(), p.slice(1));
  }
  return p;
}

function getAppdataDir(): string {
  if (process.platform === "win32") {
    return process.env["APPDATA"] || path.join(os.homedir(), "AppData", "Roaming");
  }
  if (process.platform === "darwin") {
    return path.join(os.homedir(), "Library", "Application Support");
  }
  return path.join(os.homedir(), ".config");
}

export function isBackupFile(filenameOrPath: string): boolean {
  const base = path.basename(filenameOrPath);
  return /\.bak(?:\.|$)/i.test(base);
}

export function getKnownLocations(): readonly KnownLocation[] {
  const home = os.homedir();
  const appdata = getAppdataDir();

  return [
    // Google Antigravity
    {
      client: "antigravity",
      scope: "global",
      getPath: () => path.join(home, ".gemini", "config", "mcp_config.json"),
      serverKey: "mcpServers",
      urlKeys: ["url", "serverUrl"],
    },
    {
      client: "antigravity",
      scope: "workspace",
      getPath: () => path.join(process.cwd(), ".agents", "mcp_config.json"),
      serverKey: "mcpServers",
      urlKeys: ["url", "serverUrl"],
    },
    // Cursor
    {
      client: "cursor",
      scope: "global",
      getPath: () => path.join(home, ".cursor", "mcp.json"),
      serverKey: "mcpServers",
      urlKeys: ["url"],
    },
    {
      client: "cursor",
      scope: "workspace",
      getPath: () => path.join(process.cwd(), ".cursor", "mcp.json"),
      serverKey: "mcpServers",
      urlKeys: ["url"],
    },
    // Claude Desktop
    {
      client: "claude-desktop",
      scope: "global",
      getPath: () => path.join(appdata, "Claude", "claude_desktop_config.json"),
      serverKey: "mcpServers",
      urlKeys: ["url"],
    },
    // Claude Code
    {
      client: "claude-code",
      scope: "global",
      getPath: () => path.join(home, ".claude.json"),
      serverKey: "mcpServers",
      urlKeys: ["url"],
    },
    {
      client: "claude-code",
      scope: "workspace",
      getPath: () => path.join(process.cwd(), ".mcp.json"),
      serverKey: "mcpServers",
      urlKeys: ["url"],
    },
    // VS Code (outlier key: servers)
    {
      client: "vscode",
      scope: "global",
      getPath: () => path.join(appdata, "Code", "User", "mcp.json"),
      serverKey: "servers",
      urlKeys: ["url"],
    },
    {
      client: "vscode",
      scope: "workspace",
      getPath: () => path.join(process.cwd(), ".vscode", "mcp.json"),
      serverKey: "servers",
      urlKeys: ["url"],
    },
    // Windsurf / Devin
    {
      client: "windsurf",
      scope: "global",
      getPath: () => path.join(appdata, "devin", "mcp_config.json"),
      serverKey: "mcpServers",
      urlKeys: ["serverUrl", "url"],
    },
    {
      client: "windsurf",
      scope: "global",
      getPath: () => path.join(home, ".codeium", "windsurf", "mcp_config.json"),
      serverKey: "mcpServers",
      urlKeys: ["serverUrl", "url"],
    },
    // Gemini CLI
    {
      client: "gemini",
      scope: "global",
      getPath: () => path.join(home, ".gemini", "settings.json"),
      serverKey: "mcpServers",
      urlKeys: ["httpUrl", "url"],
    },
    {
      client: "gemini",
      scope: "workspace",
      getPath: () => path.join(process.cwd(), ".gemini", "settings.json"),
      serverKey: "mcpServers",
      urlKeys: ["httpUrl", "url"],
    },
    // Zed (outlier key: context_servers)
    {
      client: "zed",
      scope: "global",
      getPath: () => path.join(home, ".config", "zed", "settings.json"),
      serverKey: "context_servers",
      urlKeys: ["url"],
    },
    // Cline
    {
      client: "cline",
      scope: "global",
      getPath: () =>
        path.join(
          appdata,
          "Code",
          "User",
          "globalStorage",
          "saoudrizwan.claude-dev",
          "settings",
          "cline_mcp_settings.json"
        ),
      serverKey: "mcpServers",
      urlKeys: ["url"],
    },
    {
      client: "cline",
      scope: "workspace",
      getPath: () => path.join(process.cwd(), ".cline", "mcp_settings.json"),
      serverKey: "mcpServers",
      urlKeys: ["url"],
    },
    {
      client: "cline",
      scope: "workspace",
      getPath: () => path.join(process.cwd(), "cline_mcp_settings.json"),
      serverKey: "mcpServers",
      urlKeys: ["url"],
    },
  ];
}

interface RawServerConfig {
  readonly command?: unknown;
  readonly args?: unknown;
  readonly env?: unknown;
  readonly url?: unknown;
  readonly serverUrl?: unknown;
  readonly httpUrl?: unknown;
  readonly headers?: unknown;
  readonly type?: unknown;
}

export function expandEnvVars(text: string): string {
  return text.replace(/\$\{([A-Za-z0-9_]+)\}|\$([A-Za-z0-9_]+)/g, (match, p1, p2) => {
    const varName = p1 || p2;
    if (varName && process.env[varName] !== undefined) {
      return process.env[varName]!;
    }
    return match;
  });
}

export function parseSimpleToml(content: string): Record<string, unknown> {
  const root: Record<string, any> = {};
  let current = root;
  const lines = content.split(/\r?\n/);

  for (let line of lines) {
    line = line.trim();
    if (!line || line.startsWith("#")) continue;

    // Table header [a.b.c]
    const headerMatch = line.match(/^\[([A-Za-z0-9_.\-]+)\]$/);
    const tablePath = headerMatch ? headerMatch[1] : undefined;
    if (tablePath) {
      const parts = tablePath.split(".");
      current = root;
      for (const part of parts) {
        if (!current[part] || typeof current[part] !== "object") {
          current[part] = {};
        }
        current = current[part];
      }
      continue;
    }

    // Key-value pair
    const eqIdx = line.indexOf("=");
    if (eqIdx !== -1) {
      const rawKey = line.slice(0, eqIdx).trim();
      const rawVal = line.slice(eqIdx + 1).trim();
      const key = rawKey.replace(/^["']|["']$/g, "");
      current[key] = parseTomlValue(rawVal);
    }
  }

  return root;
}

function parseTomlValue(val: string): unknown {
  const v = val.trim();
  if ((v.startsWith('"') && v.endsWith('"')) || (v.startsWith("'") && v.endsWith("'"))) {
    return v.slice(1, -1);
  }
  if (v === "true") return true;
  if (v === "false") return false;
  if (/^-?\d+$/.test(v)) return parseInt(v, 10);
  if (/^-?\d+\.\d+$/.test(v)) return parseFloat(v);
  if (v.startsWith("[") && v.endsWith("]")) {
    const inner = v.slice(1, -1).trim();
    if (!inner) return [];
    const items: string[] = [];
    let cur = "";
    let inQuote = false;
    let quoteChar = "";
    for (let i = 0; i < inner.length; i++) {
      const ch = inner[i];
      const prevCh = i > 0 ? inner[i - 1] : undefined;
      if ((ch === '"' || ch === "'") && prevCh !== "\\") {
        if (!inQuote) {
          inQuote = true;
          quoteChar = ch;
        } else if (quoteChar === ch) {
          inQuote = false;
        }
      }
      if (ch === "," && !inQuote) {
        items.push(cur.trim());
        cur = "";
      } else {
        cur += ch;
      }
    }
    if (cur.trim()) items.push(cur.trim());
    return items.map((item) => parseTomlValue(item));
  }
  return v;
}

export function parseConfigContent(
  content: string,
  filePath: string
): Record<string, unknown> | undefined {
  const ext = path.extname(filePath).toLowerCase();

  if (ext === ".yaml" || ext === ".yml") {
    try {
      const parsed = parseYaml(content);
      if (parsed && typeof parsed === "object") {
        return parsed as Record<string, unknown>;
      }
    } catch {
      return undefined;
    }
  }

  if (ext === ".toml") {
    try {
      const parsed = parseSimpleToml(content);
      if (parsed && typeof parsed === "object") {
        return parsed;
      }
    } catch {
      return undefined;
    }
  }

  // Try JSON / JSONC
  const errors: { error: number; offset: number; length: number }[] = [];
  const parsed = parseJsonc(content, errors, { allowTrailingComma: true });
  if (errors.length === 0 && parsed && typeof parsed === "object") {
    return parsed as Record<string, unknown>;
  }

  // Fallback 1: YAML parser handles many non-strict formats
  try {
    const yamlParsed = parseYaml(content);
    if (yamlParsed && typeof yamlParsed === "object") {
      return yamlParsed as Record<string, unknown>;
    }
  } catch {}

  // Fallback 2: TOML parser
  try {
    const tomlParsed = parseSimpleToml(content);
    if (tomlParsed && Object.keys(tomlParsed).length > 0) {
      return tomlParsed;
    }
  } catch {}

  return undefined;
}

export function parseConfigFile(
  filePath: string,
  client: McpClientType = "custom"
): NormalizedMcpServer[] {
  const resolvedPath = path.resolve(expandHome(filePath));

  try {
    const stat = fs.lstatSync(resolvedPath);
    if (!stat.isFile()) {
      return [];
    }
    if (stat.size > 5 * 1024 * 1024) {
      process.stderr.write(`Warning: Config file ${resolvedPath} exceeds 5 MB limit. Skipping.\n`);
      return [];
    }
  } catch {
    return [];
  }

  let content: string;
  try {
    content = fs.readFileSync(resolvedPath, "utf-8");
  } catch {
    return [];
  }

  const parsed = parseConfigContent(content, resolvedPath);
  if (!parsed || typeof parsed !== "object") {
    return [];
  }

  const record = parsed as Record<string, unknown>;
  let serversBlock: Record<string, unknown> | undefined;

  if (record["mcpServers"] && typeof record["mcpServers"] === "object") {
    serversBlock = record["mcpServers"] as Record<string, unknown>;
  } else if (record["servers"] && typeof record["servers"] === "object") {
    serversBlock = record["servers"] as Record<string, unknown>;
  } else if (record["context_servers"] && typeof record["context_servers"] === "object") {
    serversBlock = record["context_servers"] as Record<string, unknown>;
  }

  if (!serversBlock) {
    return [];
  }

  const results: NormalizedMcpServer[] = [];
  const configDir = path.dirname(resolvedPath);

  for (const [serverName, rawServer] of Object.entries(serversBlock)) {
    if (!rawServer || typeof rawServer !== "object") continue;

    const s = rawServer as RawServerConfig;
    let command = typeof s.command === "string" ? s.command : undefined;
    if (command) {
      command = expandEnvVars(command);
      if (
        command.startsWith("./") ||
        command.startsWith("../") ||
        command.startsWith(".\\") ||
        command.startsWith("..\\")
      ) {
        command = path.resolve(configDir, command);
      }
    }

    const args = Array.isArray(s.args)
      ? s.args
          .filter((a): a is string => typeof a === "string")
          .map((a) => {
            const expanded = expandEnvVars(a);
            return expanded;
          })
      : undefined;

    let env: Record<string, string> | undefined;
    if (s.env && typeof s.env === "object") {
      env = {};
      for (const [k, v] of Object.entries(s.env as Record<string, unknown>)) {
        if (typeof v === "string") {
          env[k] = v;
        } else if (typeof v === "number" || typeof v === "boolean") {
          env[k] = String(v);
        }
      }
    }

    const rawUrlCandidate =
      (typeof s.url === "string" && s.url) ||
      (typeof s.serverUrl === "string" && s.serverUrl) ||
      (typeof s.httpUrl === "string" && s.httpUrl) ||
      undefined;

    const urlCandidate = rawUrlCandidate ? expandEnvVars(rawUrlCandidate) : undefined;

    let headers: Record<string, string> | undefined;
    if (s.headers && typeof s.headers === "object") {
      headers = {};
      for (const [k, v] of Object.entries(s.headers as Record<string, unknown>)) {
        if (typeof v === "string") {
          headers[k] = v;
        }
      }
    }

    let transport: McpTransportType = "stdio";
    if (urlCandidate) {
      if (urlCandidate.includes("/sse") || s.type === "sse") {
        transport = "sse";
      } else {
        transport = "http";
      }
    }

    results.push({
      client,
      configPath: resolvedPath,
      serverName,
      transport,
      ...(command !== undefined ? { command } : {}),
      ...(args !== undefined ? { args } : {}),
      ...(env !== undefined ? { env } : {}),
      ...(urlCandidate !== undefined ? { url: urlCandidate } : {}),
      ...(headers !== undefined ? { headers } : {}),
    });
  }

  return results;
}

export function discoverConfigs(customPath?: string): {
  servers: NormalizedMcpServer[];
  scannedFiles: string[];
} {
  const scannedFiles = new Set<string>();
  const servers: NormalizedMcpServer[] = [];

  if (customPath) {
    const resolved = path.resolve(expandHome(customPath));
    try {
      const stat = fs.statSync(resolved);
      if (stat.isFile()) {
        scannedFiles.add(resolved);
        servers.push(...parseConfigFile(resolved, "custom"));
      } else if (stat.isDirectory()) {
        const candidateNames = [
          "mcp.json",
          "mcp_config.json",
          ".mcp.json",
          ".cursor/mcp.json",
          ".vscode/mcp.json",
          ".agents/mcp_config.json",
          "cline_mcp_settings.json",
          ".cline/mcp_settings.json",
          "mcp.yaml",
          "mcp.yml",
          "mcp.toml",
        ];
        for (const rel of candidateNames) {
          const target = path.join(resolved, rel);
          try {
            const targetStat = fs.statSync(target);
            if (targetStat.isFile() && !isBackupFile(target)) {
              scannedFiles.add(target);
              servers.push(...parseConfigFile(target, "custom"));
            }
          } catch {}
        }
        if (scannedFiles.size === 0) {
          try {
            const entries = fs.readdirSync(resolved, { withFileTypes: true });
            const validExts = [".json", ".jsonc", ".yaml", ".yml", ".toml"];
            for (const entry of entries) {
              if (
                entry.isFile() &&
                validExts.some((ext) => entry.name.endsWith(ext)) &&
                !isBackupFile(entry.name)
              ) {
                const target = path.join(resolved, entry.name);
                const parsed = parseConfigFile(target, "custom");
                if (parsed.length > 0) {
                  scannedFiles.add(target);
                  servers.push(...parsed);
                }
              }
            }
          } catch {}
        }
      }
    } catch {}
    return { servers, scannedFiles: Array.from(scannedFiles) };
  }

  // Scan known standard locations
  for (const loc of getKnownLocations()) {
    try {
      const p = loc.getPath();
      if (!isBackupFile(p)) {
        try {
          const stat = fs.statSync(p);
          if (stat.isFile()) {
            scannedFiles.add(p);
            servers.push(...parseConfigFile(p, loc.client));
          }
        } catch {}
      }
    } catch {
      // Skip inaccessible locations cleanly
    }
  }

  return { servers, scannedFiles: Array.from(scannedFiles) };
}
