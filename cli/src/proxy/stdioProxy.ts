import { spawn, type ChildProcess } from "node:child_process";
import pc from "picocolors";
import type { JsonRpcRequest, JsonRpcResponse, PolicyConfig } from "../types/index.js";
import { evaluateRequest, defaultRugPullDetector, type ToolDefinition } from "./evaluator.js";

export const MAX_FRAME_SIZE = 1024 * 1024; // 1 MB limit

/**
 * LineBuffer buffers raw binary chunks across data events and extracts complete lines.
 * Enforces MAX_FRAME_SIZE to prevent buffer exhaustion and memory denial of service.
 */
export class LineBuffer {
  private buffer: Buffer = Buffer.alloc(0);
  private readonly maxFrameSize: number;

  constructor(maxFrameSize: number = MAX_FRAME_SIZE) {
    this.maxFrameSize = maxFrameSize;
  }

  public push(
    chunk: Buffer,
    onLine: (line: string) => void,
    onOversized: (size: number) => void
  ): void {
    this.buffer = Buffer.concat([this.buffer, chunk]);

    let newlineIndex: number;
    while ((newlineIndex = this.buffer.indexOf(0x0a)) !== -1) {
      if (newlineIndex > this.maxFrameSize) {
        onOversized(newlineIndex);
        this.buffer = this.buffer.subarray(newlineIndex + 1);
        continue;
      }

      let lineBuffer = this.buffer.subarray(0, newlineIndex);
      // Strip trailing \r if present
      if (lineBuffer.length > 0 && lineBuffer[lineBuffer.length - 1] === 0x0d) {
        lineBuffer = lineBuffer.subarray(0, lineBuffer.length - 1);
      }

      const line = lineBuffer.toString("utf-8");
      this.buffer = this.buffer.subarray(newlineIndex + 1);
      onLine(line);
    }

    // Fail-closed immediately if un-terminated buffer exceeds max frame size
    if (this.buffer.length > this.maxFrameSize) {
      onOversized(this.buffer.length);
      this.buffer = Buffer.alloc(0);
    }
  }

  public flush(onLine: (line: string) => void): void {
    if (this.buffer.length > 0) {
      let lineBuffer = this.buffer;
      if (lineBuffer.length > 0 && lineBuffer[lineBuffer.length - 1] === 0x0d) {
        lineBuffer = lineBuffer.subarray(0, lineBuffer.length - 1);
      }
      const line = lineBuffer.toString("utf-8");
      this.buffer = Buffer.alloc(0);
      if (line.trim().length > 0) {
        onLine(line);
      }
    }
  }

  public getBufferedLength(): number {
    return this.buffer.length;
  }
}

export interface ProxyOptions {
  readonly command: string;
  readonly args: readonly string[];
  readonly policy?: PolicyConfig;
  readonly onBlock?: (decision: ReturnType<typeof evaluateRequest>, req: JsonRpcRequest) => void;
}

/**
 * Runs the live stdio JSON-RPC 2.0 runtime firewall.
 */
export function startStdioProxy(options: ProxyOptions): Promise<number> {
  return new Promise((resolve, reject) => {
    const { command, args, policy, onBlock } = options;

    let child: ChildProcess;
    try {
      child = spawn(command, [...args], {
        stdio: ["pipe", "pipe", "pipe"],
        env: process.env,
        shell: false,
      });
    } catch (err) {
      process.stderr.write(
        pc.red(`Error: Failed to spawn MCP child process "${command}": ${(err as Error).message}\n`)
      );
      return reject(err);
    }

    if (!child.stdin || !child.stdout || !child.stderr) {
      process.stderr.write(pc.red("Error: Child process standard streams are unavailable.\n"));
      return resolve(1);
    }

    // Forward child stderr directly to host stderr
    child.stderr.on("data", (chunk: Buffer) => {
      process.stderr.write(chunk);
    });

    const mutatedToolsSet = new Set<string>();

    const childOutBuffer = new LineBuffer(MAX_FRAME_SIZE);

    const handleChildStdoutLine = (line: string) => {
      const trimmed = line.trim();
      if (!trimmed) return;

      try {
        const parsed = JSON.parse(trimmed) as {
          result?: { tools?: readonly ToolDefinition[] };
        };
        if (parsed?.result?.tools && Array.isArray(parsed.result.tools)) {
          const check = defaultRugPullDetector.registerTools(parsed.result.tools);
          if (check.hasMutation && check.mutatedTool) {
            mutatedToolsSet.add(check.mutatedTool);
            process.stderr.write(
              `${pc.bgRed(pc.white(" MCP-SHIELD RUG-PULL "))} Detected tool mutation for "${check.mutatedTool}". Future invocations will be blocked.\n`
            );
          }
        }
      } catch {
        // Forward non-JSON or other responses normally
      }

      process.stdout.write(line + "\n");
    };

    child.stdout.on("data", (chunk: Buffer) => {
      childOutBuffer.push(
        chunk,
        handleChildStdoutLine,
        (size: number) => {
          process.stderr.write(
            `${pc.bgRed(pc.white(" MCP-SHIELD "))} Child stdout frame exceeded 1 MB limit (${size} bytes).\n`
          );
        }
      );
    });

    child.stdout.on("end", () => {
      childOutBuffer.flush(handleChildStdoutLine);
    });

    const stdinBuffer = new LineBuffer(MAX_FRAME_SIZE);

    const handleOversizedStdin = (size: number, rawSnippet?: string) => {
      process.stderr.write(
        `${pc.bgRed(pc.white(" MCP-SHIELD FAIL-CLOSED "))} Frame exceeded maximum 1 MB limit (${size} bytes). Dropping payload.\n`
      );

      let extractedId: string | number | null = null;
      if (rawSnippet) {
        const idMatch = /"id"\s*:\s*(\d+|"[^"]+")/.exec(rawSnippet.slice(0, 500));
        if (idMatch && idMatch[1]) {
          try {
            extractedId = JSON.parse(idMatch[1]);
          } catch {}
        }
      }

      const oversizedError: JsonRpcResponse = {
        jsonrpc: "2.0",
        id: extractedId,
        error: {
          code: -32001,
          message: "Blocked by mcp-shield: Frame size exceeds maximum allowed 1 MB limit",
          data: { action: "BLOCK", reason: "OVERSIZED_FRAME" },
        },
      };
      process.stdout.write(JSON.stringify(oversizedError) + "\n");
    };

    const handleStdinLine = (line: string) => {
      const trimmed = line.trim();
      if (!trimmed) return;

      // 1. Frame Size Enforcement (1 MB max) -> Fail Closed
      if (Buffer.byteLength(line, "utf-8") > MAX_FRAME_SIZE) {
        handleOversizedStdin(Buffer.byteLength(line, "utf-8"), line);
        return;
      }

      // 2. Malformed JSON Enforcement -> Fail Closed
      let req: JsonRpcRequest | undefined;
      try {
        req = JSON.parse(trimmed) as JsonRpcRequest;
      } catch {
        process.stderr.write(
          `${pc.bgRed(pc.white(" MCP-SHIELD FAIL-CLOSED "))} Malformed JSON frame received. Failing closed without forwarding.\n`
        );
        const malformedError: JsonRpcResponse = {
          jsonrpc: "2.0",
          id: null,
          error: {
            code: -32001,
            message: "Blocked by mcp-shield: Malformed JSON-RPC frame rejected",
            data: { action: "BLOCK", reason: "PARSE_ERROR" },
          },
        };
        process.stdout.write(JSON.stringify(malformedError) + "\n");
        return;
      }

      if (!req || typeof req !== "object" || req.jsonrpc !== "2.0" || typeof req.method !== "string") {
        process.stderr.write(
          `${pc.bgRed(pc.white(" MCP-SHIELD FAIL-CLOSED "))} Non-conforming JSON-RPC frame rejected.\n`
        );
        const invalidProtoError: JsonRpcResponse = {
          jsonrpc: "2.0",
          id: (req as JsonRpcRequest)?.id ?? null,
          error: {
            code: -32001,
            message: "Blocked by mcp-shield: Invalid JSON-RPC 2.0 structure",
            data: { action: "BLOCK", reason: "INVALID_PROTOCOL" },
          },
        };
        process.stdout.write(JSON.stringify(invalidProtoError) + "\n");
        return;
      }

      // 3. Rug-Pull Tool Call Block
      if (req.method === "tools/call") {
        const toolName = (req.params as { name?: string })?.name;
        if (toolName && mutatedToolsSet.has(toolName)) {
          process.stderr.write(
            `${pc.bgRed(pc.white(" MCP-SHIELD BLOCK "))} MS-003: Rug-pull blocked for mutated tool "${toolName}".\n`
          );
          if (req.id !== undefined && req.id !== null) {
            const rugPullError: JsonRpcResponse = {
              jsonrpc: "2.0",
              id: req.id,
              error: {
                code: -32001,
                message: `Blocked by mcp-shield (MS-003): Tool "${toolName}" description or schema mutated mid-session (rug-pull protection)`,
                data: { ruleId: "MS-003", action: "BLOCK", tool: toolName },
              },
            };
            process.stdout.write(JSON.stringify(rugPullError) + "\n");
          }
          return;
        }
      }

      // 4. Policy & Argument Evaluation with Fail-Closed Error Boundary
      let decision: ReturnType<typeof evaluateRequest>;
      try {
        decision = evaluateRequest(req, policy);
      } catch (evalErr) {
        process.stderr.write(
          `${pc.bgRed(pc.white(" MCP-SHIELD FAIL-CLOSED "))} Policy evaluation error: ${(evalErr as Error).message}\n`
        );
        if (req.id !== undefined && req.id !== null) {
          const evalError: JsonRpcResponse = {
            jsonrpc: "2.0",
            id: req.id,
            error: {
              code: -32001,
              message: "Blocked by mcp-shield: Policy evaluation failed safely",
              data: { action: "BLOCK", reason: "EVALUATION_ERROR" },
            },
          };
          process.stdout.write(JSON.stringify(evalError) + "\n");
        }
        return;
      }

      if (decision.action === "ALLOW") {
        if (child.stdin && !child.stdin.destroyed) {
          child.stdin.write(line + "\n");
        }
      } else {
        // Block notice strictly on stderr
        process.stderr.write(
          `${pc.bgRed(pc.white(" MCP-SHIELD BLOCK "))} ${pc.bold(decision.ruleId || "MS-BLOCK")}: ${decision.reason}\n`
        );

        if (onBlock) {
          onBlock(decision, req);
        }

        // Return valid JSON-RPC 2.0 error frame on stdout ONLY if request has an id
        if (req.id !== undefined && req.id !== null) {
          const errorResponse: JsonRpcResponse = {
            jsonrpc: "2.0",
            id: req.id,
            error: {
              code: -32001,
              message: decision.reason || "Request blocked by mcp-shield policy",
              data: {
                ruleId: decision.ruleId,
                owaspId: decision.owaspId,
                action: "BLOCK",
                redactedTarget: decision.redactedTarget,
              },
            },
          };
          process.stdout.write(JSON.stringify(errorResponse) + "\n");
        }
      }
    };

    process.stdin.on("data", (chunk: Buffer) => {
      stdinBuffer.push(
        chunk,
        handleStdinLine,
        (size: number) => handleOversizedStdin(size)
      );
    });

    process.stdin.on("end", () => {
      stdinBuffer.flush(handleStdinLine);
      if (child.stdin && !child.stdin.destroyed) {
        child.stdin.end();
      }
    });

    const cleanup = () => {
      process.stdin.removeAllListeners("data");
      process.stdin.removeAllListeners("end");
    };

    child.on("error", (err) => {
      process.stderr.write(pc.red(`Child process error: ${err.message}\n`));
      cleanup();
      reject(err);
    });

    child.on("close", (code) => {
      cleanup();
      resolve(code ?? 0);
    });

    // Clean signal forwarding
    const onSignal = (signal: NodeJS.Signals) => {
      if (child && !child.killed) {
        child.kill(signal);
      }
    };

    process.on("SIGINT", () => onSignal("SIGINT"));
    process.on("SIGTERM", () => onSignal("SIGTERM"));
  });
}
