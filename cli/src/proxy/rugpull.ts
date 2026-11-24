import * as fs from "node:fs";
import * as path from "node:path";
import * as os from "node:os";
import * as crypto from "node:crypto";
import { canonicalJsonStringify } from "../audit/logWriter.js";
import type { RugPullConfig, RugPullMode, RugPullPersistence } from "../types/index.js";

export interface ToolDefinition {
  readonly name: string;
  readonly description?: string | undefined;
  readonly inputSchema?: unknown;
  readonly outputSchema?: unknown;
  readonly annotations?: unknown;
  readonly instructions?: string | undefined;
}

export interface StoredToolSnapshot {
  readonly hash: string;
  readonly name: string;
  readonly description?: string | undefined;
  readonly canonicalJson: string;
  readonly recordedAt: string;
}

export interface RugPullBaselineFile {
  readonly version: "1.0";
  readonly updatedAt: string;
  readonly tools: Record<string, StoredToolSnapshot>;
}

export interface MutationDetail {
  readonly toolName: string;
  readonly changedFields: readonly string[];
  readonly previousHash: string;
  readonly newHash: string;
}

export function getDefaultRugPullBaselinePath(): string {
  return path.join(os.homedir(), ".mcp-shield", "rugpull-baseline.json");
}

/**
 * Computes canonical SHA-256 hash of a tool definition.
 */
export function computeCanonicalToolHash(tool: ToolDefinition): {
  hash: string;
  canonicalJson: string;
} {
  const canonicalObj = {
    annotations: tool.annotations ?? null,
    description: tool.description ?? "",
    inputSchema: tool.inputSchema ?? {},
    instructions: tool.instructions ?? "",
    name: tool.name,
    outputSchema: tool.outputSchema ?? null,
  };
  const canonicalJson = canonicalJsonStringify(canonicalObj);
  const hash = crypto.createHash("sha256").update(canonicalJson).digest("hex");
  return { hash, canonicalJson };
}

export class RugPullManager {
  private mode: RugPullMode;
  private persistence: RugPullPersistence;
  private baselinePath: string;
  private immutableFields: readonly string[];
  private activeTools = new Map<string, StoredToolSnapshot>();
  private mutatedTools = new Map<string, MutationDetail>();

  constructor(config?: RugPullConfig) {
    this.mode = config?.mode || "enforce";
    this.persistence = config?.persistence || "local";
    this.baselinePath = config?.baselinePath || getDefaultRugPullBaselinePath();
    this.immutableFields = config?.immutableFields || ["description", "inputSchema"];

    if (this.persistence === "local" && this.mode !== "off") {
      this.loadBaseline();
    }
  }

  public getMode(): RugPullMode {
    return this.mode;
  }

  public setMode(mode: RugPullMode): void {
    this.mode = mode;
  }

  private loadBaseline(): void {
    try {
      if (fs.existsSync(this.baselinePath)) {
        const content = fs.readFileSync(this.baselinePath, "utf-8");
        const parsed = JSON.parse(content) as RugPullBaselineFile;
        if (parsed?.tools && typeof parsed.tools === "object") {
          for (const [name, snapshot] of Object.entries(parsed.tools)) {
            this.activeTools.set(name, snapshot);
          }
        }
      }
    } catch {
      // Continue if baseline file is missing or unreadable
    }
  }

  public saveBaseline(): void {
    if (this.persistence !== "local") return;

    try {
      const dir = path.dirname(this.baselinePath);
      if (!fs.existsSync(dir)) {
        fs.mkdirSync(dir, { recursive: true, mode: process.platform === "win32" ? undefined : 0o700 });
      }

      const toolsObj: Record<string, StoredToolSnapshot> = {};
      for (const [name, snapshot] of this.activeTools.entries()) {
        toolsObj[name] = snapshot;
      }

      const fileData: RugPullBaselineFile = {
        version: "1.0",
        updatedAt: new Date().toISOString(),
        tools: toolsObj,
      };

      const tmpPath = `${this.baselinePath}.tmp.${Date.now()}`;
      fs.writeFileSync(tmpPath, JSON.stringify(fileData, null, 2) + "\n", "utf-8");
      fs.renameSync(tmpPath, this.baselinePath);
    } catch {
      // Fallback gracefully on disk restriction
    }
  }

  /**
   * Inspect a list of tools from tools/list response.
   */
  public registerTools(tools: readonly ToolDefinition[]): {
    hasMutation: boolean;
    mutations: readonly MutationDetail[];
  } {
    if (this.mode === "off") {
      return { hasMutation: false, mutations: [] };
    }

    const mutations: MutationDetail[] = [];
    const now = new Date().toISOString();

    for (const tool of tools) {
      if (!tool.name) continue;
      const { hash, canonicalJson } = computeCanonicalToolHash(tool);

      if (this.activeTools.has(tool.name)) {
        const existing = this.activeTools.get(tool.name)!;
        if (existing.hash !== hash) {
          // Detect which specific fields changed
          const changedFields: string[] = [];
          if (existing.description !== tool.description) {
            changedFields.push("description");
          }
          if (
            canonicalJsonStringify(existing.canonicalJson) !==
            canonicalJsonStringify(canonicalJson)
          ) {
            changedFields.push("inputSchema");
          }

          const detail: MutationDetail = {
            toolName: tool.name,
            changedFields: changedFields.length > 0 ? changedFields : ["definition"],
            previousHash: existing.hash,
            newHash: hash,
          };

          this.mutatedTools.set(tool.name, detail);
          mutations.push(detail);

          if (this.mode === "approve") {
            // In approve mode, update active tool to new hash once approved
          }
        }
      } else {
        // Record initial tool baseline
        const snapshot: StoredToolSnapshot = {
          name: tool.name,
          description: tool.description,
          canonicalJson,
          hash,
          recordedAt: now,
        };
        this.activeTools.set(tool.name, snapshot);
      }
    }

    if (mutations.length === 0 && this.persistence === "local") {
      this.saveBaseline();
    }

    return {
      hasMutation: mutations.length > 0,
      mutations,
    };
  }

  public isToolMutated(toolName: string): boolean {
    if (this.mode === "off" || this.mode === "monitor") {
      return false;
    }
    return this.mutatedTools.has(toolName);
  }

  public getMutationDetail(toolName: string): MutationDetail | undefined {
    return this.mutatedTools.get(toolName);
  }

  public approveToolMutation(toolName?: string): void {
    if (toolName) {
      this.mutatedTools.delete(toolName);
    } else {
      this.mutatedTools.clear();
    }
    this.saveBaseline();
  }

  public clear(): void {
    this.activeTools.clear();
    this.mutatedTools.clear();
  }
}

export const defaultRugPullManager = new RugPullManager();
