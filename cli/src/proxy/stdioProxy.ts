import { spawn, spawnSync, type ChildProcess } from "node:child_process";
import pc from "picocolors";
import type {
  JsonRpcRequest,
  JsonRpcResponse,
  PolicyConfig,
  FramingMode,
} from "../types/index.js";
import { JsonRpcErrorCode } from "../types/index.js";
import { MessageFramingParser, encodeFrame, DEFAULT_MAX_FRAME_SIZE } from "./framing.js";
import {
  validateJsonRpcPayload,
  createJsonRpcError,
  extractIdSafely,
} from "./jsonValidator.js";
import { evaluateRequest } from "./evaluator.js";
import { RugPullManager, type ToolDefinition } from "./rugpull.js";

export const MAX_FRAME_SIZE = DEFAULT_MAX_FRAME_SIZE;

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
      if (lineBuffer.length > 0 && lineBuffer[lineBuffer.length - 1] === 0x0d) {
        lineBuffer = lineBuffer.subarray(0, lineBuffer.length - 1);
      }

      const line = lineBuffer.toString("utf-8");
      this.buffer = this.buffer.subarray(newlineIndex + 1);
      onLine(line);
    }

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
  readonly policy?: PolicyConfig | undefined;
  readonly framing?: FramingMode | undefined;
  readonly maxFrameSize?: number | undefined;
  readonly shutdownTimeoutMs?: number | undefined;
  readonly approveRugPull?: boolean | undefined;
  readonly onBlock?: ((decision: ReturnType<typeof evaluateRequest>, req: JsonRpcRequest) => void) | undefined;
}

/**
 * Terminate child process tree cleanly across platforms.
 */
function terminateProcessTree(child: ChildProcess, timeoutMs: number = 2000): void {
  if (!child || child.killed || child.exitCode !== null) return;
  const pid = child.pid;
  if (!pid) return;

  if (process.platform === "win32") {
    try {
      spawnSync("taskkill", ["/pid", String(pid), "/T", "/F"], { stdio: "ignore" });
    } catch {
      try {
        child.kill();
      } catch {}
    }
  } else {
    try {
      process.kill(-pid, "SIGTERM");
    } catch {
      try {
        child.kill("SIGTERM");
      } catch {}
    }

    const timer = setTimeout(() => {
      try {
        if (!child.killed && child.exitCode === null) {
          process.kill(-pid, "SIGKILL");
        }
      } catch {
        try {
          child.kill("SIGKILL");
        } catch {}
      }
    }, timeoutMs);
    timer.unref();
  }
}

/**
 * Runs the live stdio JSON-RPC 2.0 runtime firewall.
 */
export function startStdioProxy(options: ProxyOptions): Promise<number> {
  return new Promise((resolve, reject) => {
    const {
      command,
      args,
      policy,
      framing = "auto",
      maxFrameSize = MAX_FRAME_SIZE,
      shutdownTimeoutMs = 2000,
      approveRugPull = false,
      onBlock,
    } = options;

    const rugPullManager = new RugPullManager(policy?.rugPull);
    if (approveRugPull) {
      rugPullManager.approveToolMutation();
      process.stderr.write(pc.green("✓ Approved all current tool mutations and updated baseline.\n"));
    }

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

    // Dual Framing Parsers
    const hostInParser = new MessageFramingParser(framing, maxFrameSize);
    const childOutParser = new MessageFramingParser("auto", maxFrameSize);

    // Track active request IDs (bounded to 1000)
    const MAX_CONCURRENT_REQUESTS = 1000;
    const pendingRequestIds = new Set<string | number>();

    let isCleanedUp = false;

    // Helper to write framed response to host stdout with backpressure
    const writeToHostStdout = (payload: string) => {
      if (process.stdout.destroyed) return;
      const hostFraming = hostInParser.getFramingMode();
      const encoded = encodeFrame(payload, hostFraming);

      const canWrite = process.stdout.write(encoded);
      if (!canWrite && child.stdout && !child.stdout.destroyed) {
        child.stdout.pause();
        process.stdout.once("drain", () => {
          if (child.stdout && !child.stdout.destroyed) {
            child.stdout.resume();
          }
        });
      }
    };

    // Helper to write to child stdin with backpressure
    const writeToChildStdin = (payload: string) => {
      if (!child.stdin || child.stdin.destroyed) return;
      const childFraming = childOutParser.getFramingMode();
      const encoded = encodeFrame(payload, childFraming);

      const canWrite = child.stdin.write(encoded);
      if (!canWrite && !process.stdin.destroyed) {
        process.stdin.pause();
        child.stdin.once("drain", () => {
          if (!process.stdin.destroyed) {
            process.stdin.resume();
          }
        });
      }
    };

    // Handle incoming frames from child stdout
    const handleChildStdoutFrame = ({ payload }: { payload: string }) => {
      const trimmed = payload.trim();
      if (!trimmed) return;

      try {
        const parsed = JSON.parse(trimmed) as {
          id?: string | number | null;
          result?: { tools?: readonly ToolDefinition[] };
        };

        if (parsed?.id !== undefined && parsed.id !== null) {
          pendingRequestIds.delete(parsed.id);
        }

        // Rug-Pull Snapshot inspection on tools/list responses
        if (parsed?.result?.tools && Array.isArray(parsed.result.tools)) {
          const check = rugPullManager.registerTools(parsed.result.tools);
          if (check.hasMutation) {
            for (const mutation of check.mutations) {
              process.stderr.write(
                `${pc.bgRed(pc.white(" MCP-SHIELD RUG-PULL "))} Detected tool mutation for "${mutation.toolName}" [changed: ${mutation.changedFields.join(", ")}]. Future invocations will be blocked in enforce mode.\n`
              );
            }
          }
        }
      } catch {
        // Forward non-JSON lines directly
      }

      writeToHostStdout(payload);
    };

    child.stdout.on("data", (chunk: Buffer) => {
      childOutParser.push(
        chunk,
        handleChildStdoutFrame,
        (size: number) => {
          process.stderr.write(
            `${pc.bgRed(pc.white(" MCP-SHIELD "))} Child stdout frame exceeded limit (${size} bytes). Dropping.\n`
          );
        }
      );
    });

    child.stdout.on("end", () => {
      childOutParser.flush(handleChildStdoutFrame);
    });

    // Handle oversized frames from host stdin
    const handleOversizedStdin = (size: number, rawSnippet?: string) => {
      process.stderr.write(
        `${pc.bgRed(pc.white(" MCP-SHIELD FAIL-CLOSED "))} Frame exceeded maximum 1 MB limit (${size} bytes). Dropping payload.\n`
      );

      const extractedId = rawSnippet ? extractIdSafely(rawSnippet) : null;
      const oversizedError = createJsonRpcError(
        extractedId,
        JsonRpcErrorCode.OVERSIZED_FRAME,
        `Blocked by mcp-shield: Frame size exceeds maximum allowed 1 MB limit (${maxFrameSize} bytes)`,
        { action: "BLOCK", reason: "OVERSIZED_FRAME", size }
      );
      writeToHostStdout(JSON.stringify(oversizedError));
    };

    // Evaluate single request
    const evaluateSingleReq = (
      req: JsonRpcRequest
    ): { allow: true } | { allow: false; errorResponse?: JsonRpcResponse } => {
      const isNotification = req.id === undefined;

      // 1. Rug-Pull Tool Call Block
      if (req.method === "tools/call") {
        const toolName = (req.params as { name?: string })?.name;
        if (toolName && rugPullManager.isToolMutated(toolName)) {
          const detail = rugPullManager.getMutationDetail(toolName);
          const reason = `Tool "${toolName}" description or schema mutated mid-session (rug-pull protection)`;
          process.stderr.write(
            `${pc.bgRed(pc.white(" MCP-SHIELD BLOCK "))} MS-003: Rug-pull blocked for mutated tool "${toolName}".\n`
          );

          if (isNotification) {
            return { allow: false };
          }

          const rugPullError = createJsonRpcError(
            req.id ?? null,
            JsonRpcErrorCode.POLICY_BLOCK,
            `Blocked by mcp-shield (MS-003): ${reason}`,
            { ruleId: "MS-003", action: "BLOCK", tool: toolName, mutation: detail }
          );
          return { allow: false, errorResponse: rugPullError };
        }
      }

      // 2. Policy & Argument Evaluation
      let decision: ReturnType<typeof evaluateRequest>;
      try {
        decision = evaluateRequest(req, policy);
      } catch (evalErr) {
        process.stderr.write(
          `${pc.bgRed(pc.white(" MCP-SHIELD FAIL-CLOSED "))} Policy evaluation error: ${(evalErr as Error).message}\n`
        );
        if (isNotification) {
          return { allow: false };
        }
        const evalError = createJsonRpcError(
          req.id ?? null,
          JsonRpcErrorCode.POLICY_EVAL_FAILURE,
          "Blocked by mcp-shield: Policy evaluation failed safely",
          { action: "BLOCK", reason: "EVALUATION_ERROR" }
        );
        return { allow: false, errorResponse: evalError };
      }

      if (decision.action === "ALLOW") {
        return { allow: true };
      }

      // Blocked by policy
      process.stderr.write(
        `${pc.bgRed(pc.white(" MCP-SHIELD BLOCK "))} ${pc.bold(decision.ruleId || "MS-BLOCK")}: ${decision.reason}\n`
      );

      if (onBlock) {
        onBlock(decision, req);
      }

      if (isNotification) {
        return { allow: false };
      }

      const errorCode = decision.errorCode || JsonRpcErrorCode.POLICY_BLOCK;
      const errorResponse = createJsonRpcError(
        req.id ?? null,
        errorCode,
        decision.reason || "Request blocked by mcp-shield policy",
        {
          ruleId: decision.ruleId,
          owaspId: decision.owaspId,
          action: "BLOCK",
          redactedTarget: decision.redactedTarget,
        }
      );
      return { allow: false, errorResponse };
    };

    // Handle validated incoming frames from host stdin
    const handleHostStdinFrame = ({ payload }: { payload: string }) => {
      const validation = validateJsonRpcPayload(payload);

      if (!validation.valid) {
        process.stderr.write(
          `${pc.bgRed(pc.white(" MCP-SHIELD FAIL-CLOSED "))} ${validation.errorMessage}\n`
        );
        const errResp = createJsonRpcError(
          validation.extractedId,
          validation.errorCode,
          `Blocked by mcp-shield: ${validation.errorMessage}`,
          { action: "BLOCK" }
        );
        writeToHostStdout(JSON.stringify(errResp));
        return;
      }

      // Check concurrency bound
      if (pendingRequestIds.size >= MAX_CONCURRENT_REQUESTS) {
        process.stderr.write(
          `${pc.bgRed(pc.white(" MCP-SHIELD "))} Bounded pending requests limit reached (${MAX_CONCURRENT_REQUESTS}). Dropping.\n`
        );
        const errResp = createJsonRpcError(
          validation.requests[0]?.id ?? null,
          JsonRpcErrorCode.INTERNAL_ERROR,
          "Blocked by mcp-shield: Server overloaded (maximum concurrent requests exceeded)"
        );
        writeToHostStdout(JSON.stringify(errResp));
        return;
      }

      // Handle Batch vs Single
      if (validation.isBatch) {
        const batchResults: (JsonRpcResponse | undefined)[] = [];
        const allowedRequests: JsonRpcRequest[] = [];

        for (const req of validation.requests) {
          const evalRes = evaluateSingleReq(req);
          if (evalRes.allow) {
            allowedRequests.push(req);
            if (req.id !== undefined && req.id !== null) {
              pendingRequestIds.add(req.id);
            }
          } else {
            if (evalRes.errorResponse) {
              batchResults.push(evalRes.errorResponse);
            }
          }
        }

        // If some allowed, forward them as a batch to child
        if (allowedRequests.length > 0) {
          writeToChildStdin(JSON.stringify(allowedRequests));
        }

        // If there are blocked responses to return, return them
        const responsesToSend = batchResults.filter((r): r is JsonRpcResponse => r !== undefined);
        if (responsesToSend.length > 0) {
          writeToHostStdout(JSON.stringify(responsesToSend));
        }
      } else {
        const singleReq = validation.requests[0]!;
        const evalRes = evaluateSingleReq(singleReq);

        if (evalRes.allow) {
          if (singleReq.id !== undefined && singleReq.id !== null) {
            pendingRequestIds.add(singleReq.id);
          }
          writeToChildStdin(payload);
        } else if (evalRes.errorResponse) {
          writeToHostStdout(JSON.stringify(evalRes.errorResponse));
        }
      }
    };

    process.stdin.on("data", (chunk: Buffer) => {
      hostInParser.push(
        chunk,
        handleHostStdinFrame,
        (size: number, rawSnippet?: string) => handleOversizedStdin(size, rawSnippet)
      );
    });

    const cleanup = () => {
      if (isCleanedUp) return;
      isCleanedUp = true;

      process.stdin.removeAllListeners("data");
      process.stdin.removeAllListeners("end");

      process.removeListener("SIGINT", onSigInt);
      process.removeListener("SIGTERM", onSigTerm);
      process.removeListener("SIGHUP", onSigHup);

      terminateProcessTree(child, shutdownTimeoutMs);
    };

    process.stdin.on("end", () => {
      hostInParser.flush(handleHostStdinFrame);
      if (child.stdin && !child.stdin.destroyed) {
        child.stdin.end();
      }
      cleanup();
    });

    child.on("error", (err) => {
      process.stderr.write(pc.red(`Child process error: ${err.message}\n`));
      cleanup();
      reject(err);
    });

    child.on("close", (code) => {
      cleanup();
      resolve(code ?? 0);
    });

    child.on("exit", (code) => {
      cleanup();
      resolve(code ?? 0);
    });

    const onSigInt = () => {
      cleanup();
      process.exit(130);
    };
    const onSigTerm = () => {
      cleanup();
      process.exit(143);
    };
    const onSigHup = () => {
      cleanup();
      process.exit(129);
    };

    process.on("SIGINT", onSigInt);
    process.on("SIGTERM", onSigTerm);
    process.on("SIGHUP", onSigHup);
  });
}
