import { spawn, type ChildProcess } from "node:child_process";
import * as readline from "node:readline";
import pc from "picocolors";
import type { JsonRpcRequest, JsonRpcResponse, PolicyConfig } from "../types/index.js";
import { evaluateRequest, defaultRugPullDetector, type ToolDefinition } from "./evaluator.js";

export const MAX_FRAME_SIZE = 1024 * 1024; // 1 MB limit

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

    // Forward child stdout line-by-line to host stdout and inspect for tools/list responses
    const childOutRl = readline.createInterface({
      input: child.stdout,
      terminal: false,
    });

    childOutRl.on("line", (line: string) => {
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
        // Continue forwarding
      }

      process.stdout.write(line + "\n");
    });

    // Intercept host stdin line-by-line
    const stdinRl = readline.createInterface({
      input: process.stdin,
      terminal: false,
    });

    stdinRl.on("line", (line: string) => {
      const trimmed = line.trim();
      if (!trimmed) return;

      // 1. Frame Size Enforcement (1 MB max) -> Fail Closed
      if (Buffer.byteLength(line, "utf-8") > MAX_FRAME_SIZE) {
        process.stderr.write(
          `${pc.bgRed(pc.white(" MCP-SHIELD FAIL-CLOSED "))} Frame exceeded maximum 1 MB limit (${line.length} bytes). Dropping payload.\n`
        );

        // Attempt to extract an id if possible, otherwise null
        let extractedId: string | number | null = null;
        const idMatch = /"id"\s*:\s*(\d+|"[^"]+")/.exec(line.slice(0, 500));
        if (idMatch && idMatch[1]) {
          try {
            extractedId = JSON.parse(idMatch[1]);
          } catch {}
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
    });

    stdinRl.on("close", () => {
      if (child.stdin && !child.stdin.destroyed) {
        child.stdin.end();
      }
    });

    const cleanup = () => {
      stdinRl.close();
      childOutRl.close();
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
