import { describe, it, expect } from "vitest";
import * as path from "node:path";
import { spawn } from "node:child_process";

const mockServerPath = path.resolve(__dirname, "mockServer.mjs");
const binPath = path.resolve(__dirname, "../dist/index.js");

function sendRawToProxy(lines: readonly string[]): Promise<{ stdout: string; stderr: string; exitCode: number | null }> {
  return new Promise((resolve) => {
    const proc = spawn(process.execPath, [binPath, "proxy", "--", process.execPath, mockServerPath], {
      stdio: ["pipe", "pipe", "pipe"],
    });

    let stdout = "";
    let stderr = "";

    proc.stdout.on("data", (chunk: Buffer) => {
      stdout += chunk.toString();
    });

    proc.stderr.on("data", (chunk: Buffer) => {
      stderr += chunk.toString();
    });

    for (const line of lines) {
      proc.stdin.write(line + "\n");
    }

    setTimeout(() => {
      proc.stdin.end();
      proc.kill("SIGTERM");
      setTimeout(() => {
        resolve({ stdout, stderr, exitCode: proc.exitCode });
      }, 400);
    }, 1200);
  });
}

describe("Malformed & Oversized JSON-RPC Fuzz Suite (Fail-Closed Guarantees)", () => {
  it("fails closed with code -32001 when receiving malformed JSON", async () => {
    const malformedPayloads = [
      "not json at all",
      "{ jsonrpc: 2.0, missing quotes }",
      "{\"jsonrpc\": \"2.0\", \"id\": 1, \"method\":",
      "{\"jsonrpc\": \"1.0\", \"method\": \"tools/call\"}",
      "{\"jsonrpc\": \"2.0\", \"id\": 2, \"params\": null, \"method\": 123}",
      "null",
      "12345",
      "true",
    ];

    const { stdout, stderr } = await sendRawToProxy(malformedPayloads);
    const outLines = stdout.trim().split("\n").filter(Boolean);

    // Assert proxy did not crash and returned valid error frames
    expect(outLines.length).toBeGreaterThan(0);
    for (const line of outLines) {
      const parsed = JSON.parse(line);
      expect(parsed.jsonrpc).toBe("2.0");
      expect([-32001, -32600, -32700]).toContain(parsed.error?.code);
    }

    expect(stderr).toContain("MCP-SHIELD FAIL-CLOSED");
  });

  it("fails closed and rejects oversized frames exceeding 1 MB limit", async () => {
    // Generate an oversized frame (> 1 MB, e.g. 1.2 MB)
    const largeData = "A".repeat(1024 * 1024 + 1000);
    const oversizedFrame = JSON.stringify({
      jsonrpc: "2.0",
      id: 999,
      method: "tools/call",
      params: { arguments: { data: largeData } },
    });

    const { stdout, stderr } = await sendRawToProxy([oversizedFrame]);
    const outLines = stdout.trim().split("\n").filter(Boolean);

    expect(outLines.length).toBeGreaterThan(0);
    const parsed = JSON.parse(outLines[0] || "{}");

    expect(parsed.jsonrpc).toBe("2.0");
    expect(parsed.error).toBeDefined();
    expect([-32001, -32009]).toContain(parsed.error.code);
    expect(parsed.error.message).toContain("1 MB");

    expect(stderr).toContain("MCP-SHIELD FAIL-CLOSED");
    expect(stderr).toContain("1 MB limit");
  });

  it("handles empty lines and whitespace without crashing", async () => {
    const blankPayloads = ["", "   ", "\t", "\r\n"];
    const validReq = JSON.stringify({
      jsonrpc: "2.0",
      id: 100,
      method: "tools/call",
      params: { arguments: { path: "./src/index.ts" } },
    });

    const { stdout } = await sendRawToProxy([...blankPayloads, validReq]);
    const outLines = stdout.trim().split("\n").filter(Boolean);

    expect(outLines.length).toBeGreaterThan(0);
    const parsed = JSON.parse(outLines[0] || "{}");
    expect(parsed.id).toBe(100);
    expect(parsed.result?.status).toBe("MOCK_SUCCESS");
  });
});
