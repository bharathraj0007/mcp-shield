import { describe, it, expect, beforeEach, afterEach } from "vitest";
import * as fs from "node:fs";
import * as path from "node:path";
import * as os from "node:os";
import { LineBuffer, MAX_FRAME_SIZE } from "../src/proxy/stdioProxy.js";
import {
  evaluateRequest,
  decodePathEscapes,
  isUncPath,
  resolveCanonicalPath,
} from "../src/proxy/evaluator.js";
import type { JsonRpcRequest } from "../src/types/index.js";

describe("Regression & Bypass Hardening Test Suite", () => {
  let tempDir: string;

  beforeEach(() => {
    tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "mcp-shield-bypass-"));
  });

  afterEach(() => {
    try {
      fs.rmSync(tempDir, { recursive: true, force: true });
    } catch {}
  });

  describe("LineBuffer Split & Chunked Stream Framing", () => {
    it("safely reassembles messages split across tiny 1-byte chunks", () => {
      const lineBuffer = new LineBuffer(MAX_FRAME_SIZE);
      const receivedLines: string[] = [];
      const oversizedSizes: number[] = [];

      const rawMessage = '{"jsonrpc":"2.0","id":1,"method":"ping"}\n';
      const buffer = Buffer.from(rawMessage, "utf-8");

      for (let i = 0; i < buffer.length; i++) {
        lineBuffer.push(
          buffer.subarray(i, i + 1),
          (line) => receivedLines.push(line),
          (size) => oversizedSizes.push(size)
        );
      }

      expect(receivedLines).toEqual(['{"jsonrpc":"2.0","id":1,"method":"ping"}']);
      expect(oversizedSizes.length).toBe(0);
      expect(lineBuffer.getBufferedLength()).toBe(0);
    });

    it("handles multiple JSON-RPC frames delivered in a single buffer chunk", () => {
      const lineBuffer = new LineBuffer(MAX_FRAME_SIZE);
      const receivedLines: string[] = [];

      const chunk = Buffer.from(
        '{"id":1}\n{"id":2}\r\n{"id":3}\n',
        "utf-8"
      );

      lineBuffer.push(
        chunk,
        (line) => receivedLines.push(line),
        () => {}
      );

      expect(receivedLines).toEqual(['{"id":1}', '{"id":2}', '{"id":3}']);
      expect(lineBuffer.getBufferedLength()).toBe(0);
    });

    it("flushes remaining buffer on stream close even without trailing newline", () => {
      const lineBuffer = new LineBuffer(MAX_FRAME_SIZE);
      const receivedLines: string[] = [];

      lineBuffer.push(
        Buffer.from('{"id":42}', "utf-8"),
        (line) => receivedLines.push(line),
        () => {}
      );

      expect(receivedLines.length).toBe(0);
      expect(lineBuffer.getBufferedLength()).toBeGreaterThan(0);

      lineBuffer.flush((line) => receivedLines.push(line));
      expect(receivedLines).toEqual(['{"id":42}']);
      expect(lineBuffer.getBufferedLength()).toBe(0);
    });

    it("fails closed and purges buffer immediately when un-terminated stream exceeds 1 MB", () => {
      const smallLimit = 100; // test with 100 bytes limit
      const lineBuffer = new LineBuffer(smallLimit);
      const receivedLines: string[] = [];
      const oversizedSizes: number[] = [];

      const largeChunkWithoutNewline = Buffer.alloc(150, "x");

      lineBuffer.push(
        largeChunkWithoutNewline,
        (line) => receivedLines.push(line),
        (size) => oversizedSizes.push(size)
      );

      expect(oversizedSizes).toEqual([150]);
      expect(receivedLines.length).toBe(0);
      expect(lineBuffer.getBufferedLength()).toBe(0);
    });
  });

  describe("Path Traversal & Evasion Normalization", () => {
    it("decodes URL-encoded traversal (%2e%2e%2f and double-encoded %252e%252e%252f)", () => {
      expect(decodePathEscapes("%2e%2e%2f.env")).toBe("../.env");
      expect(decodePathEscapes("%252e%252e%252f.env")).toBe("../.env");
      expect(decodePathEscapes("..%2f.env")).toBe("../.env");
      expect(decodePathEscapes("..%5c.env")).toBe("..\\.env");
      expect(decodePathEscapes("%2e%2e%2f%2e%2e%2f.env")).toBe("../../.env");
    });

    it("normalizes Unicode escape sequences and fullwidth characters (NFKC)", () => {
      expect(decodePathEscapes("\\u002e\\u002e/.env")).toBe("../.env");
      // Fullwidth dots \uFF0E\uFF0E/
      expect(decodePathEscapes("\uFF0E\uFF0E/.env")).toBe("../.env");
      // Fullwidth slash \uFF0F
      expect(decodePathEscapes("..\uFF0F.env")).toBe("../.env");
      expect(decodePathEscapes("\uFF0E\uFF0E/\uFF0E\uFF0E/.env")).toBe("../../.env");
    });

    it("strips null-byte injections to defeat filename truncation bypasses", () => {
      expect(decodePathEscapes(".env\0.png")).toBe(".env.png");
      expect(decodePathEscapes("credentials.json\0.txt")).toBe("credentials.json.txt");
    });

    it("identifies Windows UNC paths across diverse prefix patterns", () => {
      expect(isUncPath("\\\\server\\share")).toBe(true);
      expect(isUncPath("//127.0.0.1/c$")).toBe(true);
      expect(isUncPath("\\\\?\\UNC\\fileserver\\secret")).toBe(true);
      expect(isUncPath("\\\\.\\pipe\\docker")).toBe(true);
      expect(isUncPath("./src/index.ts")).toBe(false);
      expect(isUncPath("/usr/local/bin")).toBe(false);
    });

    it("blocks file:// URI protocol paths targeting sensitive files", () => {
      const req: JsonRpcRequest = {
        jsonrpc: "2.0",
        id: 1,
        method: "tools/call",
        params: {
          name: "read_file",
          arguments: {
            path: "file:///workspace/.env",
          },
        },
      };

      const decision = evaluateRequest(req);
      expect(decision.action).toBe("BLOCK");
      expect(decision.ruleId).toBe("MS-001");
    });

    it("resolves realpath of symlinks escaping project directory to sensitive files", () => {
      const realSecret = path.join(tempDir, ".env");
      fs.writeFileSync(realSecret, "SECRET=123", "utf-8");

      const subDir = path.join(tempDir, "workspace");
      fs.mkdirSync(subDir);

      const symlinkPath = path.join(subDir, "link_to_env");
      try {
        fs.symlinkSync(realSecret, symlinkPath, "file");
      } catch {
        // Skip symlink creation if OS privileges restrict
        return;
      }

      const canonical = resolveCanonicalPath(symlinkPath);
      expect(canonical.toLowerCase()).toContain(".env");

      const req: JsonRpcRequest = {
        jsonrpc: "2.0",
        id: 2,
        method: "tools/call",
        params: {
          name: "read_file",
          arguments: {
            path: symlinkPath,
          },
        },
      };

      const decision = evaluateRequest(req);
      expect(decision.action).toBe("BLOCK");
      expect(decision.ruleId).toBe("MS-001");
    });
  });
});
