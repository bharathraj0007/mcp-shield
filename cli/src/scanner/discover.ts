import * as fs from "node:fs";
import * as path from "node:path";
import * as os from "node:os";
import { parse as parseJsonc, printParseErrorCode } from "jsonc-parser";
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
      getPath: () => path.join(appdata, "zed", "settings.json"),
      serverKey: "context_servers",
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

export function parseConfigFile(
  filePath: string,
  client: McpClientType = "custom"
): NormalizedMcpServer[] {
  const resolvedPath = path.resolve(expandHome(filePath));
  if (!fs.existsSync(resolvedPath)) {
    return [];
  }

  let content: string;
  try {
    content = fs.readFileSync(resolvedPath, "utf-8");
  } catch {
    return [];
  }

  const errors: { error: number; offset: number; length: number }[] = [];
  const parsed = parseJsonc(content, errors, { allowTrailingComma: true });

  if (errors.length > 0 && parsed === undefined) {
    const firstErr = errors[0];
    const codeMsg = firstErr ? printParseErrorCode(firstErr.error) : "Unknown JSON error";
    process.stderr.write(`Warning: Failed to parse JSONC at ${resolvedPath}: ${codeMsg}\n`);
    return [];
  }

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

  for (const [serverName, rawServer] of Object.entries(serversBlock)) {
    if (!rawServer || typeof rawServer !== "object") continue;

    const s = rawServer as RawServerConfig;
    const command = typeof s.command === "string" ? s.command : undefined;
    const args = Array.isArray(s.args)
      ? s.args.filter((a): a is string => typeof a === "string")
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

    const urlCandidate =
      (typeof s.url === "string" && s.url) ||
      (typeof s.serverUrl === "string" && s.serverUrl) ||
      (typeof s.httpUrl === "string" && s.httpUrl) ||
      undefined;

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
      command,
      args,
      env,
      url: urlCandidate,
      headers,
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
    if (fs.existsSync(resolved)) {
      const stat = fs.statSync(resolved);
      if (stat.isFile()) {
        scannedFiles.add(resolved);
        servers.push(...parseConfigFile(resolved, "custom"));
      } else if (stat.isDirectory()) {
        // Search directory for standard config names
        const candidateNames = [
          "mcp.json",
          "mcp_config.json",
          ".mcp.json",
          ".cursor/mcp.json",
          ".vscode/mcp.json",
          ".agents/mcp_config.json",
        ];
        for (const rel of candidateNames) {
          const target = path.join(resolved, rel);
          if (fs.existsSync(target) && fs.statSync(target).isFile()) {
            scannedFiles.add(target);
            servers.push(...parseConfigFile(target, "custom"));
          }
        }
        // Also look for any .json files in root of the custom directory if none found
        if (scannedFiles.size === 0) {
          try {
            const entries = fs.readdirSync(resolved, { withFileTypes: true });
            for (const entry of entries) {
              if (entry.isFile() && entry.name.endsWith(".json")) {
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
    }
    return { servers, scannedFiles: Array.from(scannedFiles) };
  }

  // Scan known standard locations
  for (const loc of getKnownLocations()) {
    try {
      const p = loc.getPath();
      if (fs.existsSync(p)) {
        scannedFiles.add(p);
        servers.push(...parseConfigFile(p, loc.client));
      }
    } catch {
      // Skip inaccessible locations cleanly
    }
  }

  return { servers, scannedFiles: Array.from(scannedFiles) };
}
