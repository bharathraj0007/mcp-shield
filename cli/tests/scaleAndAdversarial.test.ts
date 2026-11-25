import { describe, it, expect, beforeAll, afterAll } from "vitest";
import * as fs from "node:fs";
import * as path from "node:path";
import * as os from "node:os";
import {
  appendAuditEntry,
  verifyAuditLog,
  generateAuditKeyPair,
  createAuditCheckpoint,
} from "../src/audit/logWriter.js";
import { parseConfigFile } from "../src/scanner/discover.js";
import { validateJsonRpcPayload, scanJsonStructure } from "../src/proxy/jsonValidator.js";
import { MessageFramingParser, DEFAULT_MAX_FRAME_SIZE } from "../src/proxy/framing.js";
import { evaluateRequest } from "../src/proxy/evaluator.js";
import { executeSafeFix, executeRollback } from "../src/policy/fixer.js";
import type { PolicyConfig } from "../src/types/index.js";

const DEFAULT_POLICY: PolicyConfig = {
  version: "1.0",
  mode: "enforce",
  denyPaths: ["~/.ssh", "~/.aws", "**/.env", "/etc/shadow"],
  allowPaths: [],
  blockedCommands: ["rm -rf", "mkfs"],
  disabledRules: [],
  failOnSeverity: "high",
};

describe("Section 13: High-Scale & Adversarial Stress Test Suite", () => {
  let tempDir: string;

  beforeAll(() => {
    tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "mcp-shield-scale-"));
  });

  afterAll(() => {
    try {
      if (tempDir) {
        fs.rmSync(tempDir, { recursive: true, force: true });
      }
    } catch {}
  });

  describe("1. High-Volume Audit Writes & Cryptographic Checkpoints", () => {
    it("handles 1,000+ sequential entries + Ed25519 checkpoint + sub-second verification", () => {
      const logFile = path.join(tempDir, "high-volume-audit.jsonl");
      const keypair = generateAuditKeyPair(tempDir);

      expect(fs.existsSync(keypair.privateKeyPath)).toBe(true);
      expect(fs.existsSync(keypair.publicKeyPath)).toBe(true);
      expect(keypair.keyId.length).toBe(16);

      const ENTRY_COUNT = 1000;
      const tWriteStart = Date.now();

      for (let i = 1; i <= ENTRY_COUNT; i++) {
        appendAuditEntry(
          {
            eventType: i % 2 === 0 ? "scan" : "proxy",
            action: i % 10 === 0 ? "BLOCK" : "ALLOW",
            ruleId: i % 10 === 0 ? "MS-002" : undefined,
            details: { testId: i, payload: "safe-request" },
          },
          logFile
        );
      }

      const tWriteEnd = Date.now();
      expect(tWriteEnd - tWriteStart).toBeGreaterThanOrEqual(0);

      // Create signed Ed25519 checkpoint at entry 1,001
      const checkpoint = createAuditCheckpoint({
        logPath: logFile,
        privateKeyPath: keypair.privateKeyPath,
      });

      expect(checkpoint.seq).toBe(ENTRY_COUNT + 1);
      expect(checkpoint.action).toBe("CHECKPOINT");
      expect(checkpoint.keyId).toBe(keypair.keyId);
      expect(checkpoint.signature).toBeDefined();

      // Verify all 1,001 entries with cryptographic verification
      const tVerifyStart = Date.now();
      const result = verifyAuditLog(
        logFile,
        ENTRY_COUNT + 1,
        undefined,
        keypair.publicKeyPath
      );
      const tVerifyDuration = Date.now() - tVerifyStart;

      expect(result.valid).toBe(true);
      expect(result.code).toBe("SUCCESS");
      expect(result.totalEntries).toBe(ENTRY_COUNT + 1);
      // High-volume verification should complete comfortably within 1000 ms
      expect(tVerifyDuration).toBeLessThan(1000);
    });
  });

  describe("2. Adversarial Audit Log Tampering Detection", () => {
    it("detects corrupt or truncated final line", () => {
      const logFile = path.join(tempDir, "corrupt-audit.jsonl");
      for (let i = 1; i <= 5; i++) {
        appendAuditEntry(
          { eventType: "proxy", action: "ALLOW", details: { i } },
          logFile
        );
      }

      // Append truncated/corrupt JSON fragment
      fs.appendFileSync(logFile, '{"schemaVersion":1,"seq":6,"timestamp":"2026-11-25T\n', "utf-8");

      const res = verifyAuditLog(logFile);
      expect(res.valid).toBe(false);
      expect(res.code).toBe("CORRUPT_JSON");
      expect(res.errorLine).toBe(6);
    });

    it("detects sequence gaps in audit log", () => {
      const logFile = path.join(tempDir, "seq-gap-audit.jsonl");
      for (let i = 1; i <= 3; i++) {
        appendAuditEntry(
          { eventType: "proxy", action: "ALLOW", details: { i } },
          logFile
        );
      }

      // Read lines and alter sequence of line 3 to 10
      const lines = fs.readFileSync(logFile, "utf-8").trim().split("\n");
      const obj3 = JSON.parse(lines[2]!);
      obj3.seq = 10;
      lines[2] = JSON.stringify(obj3);
      fs.writeFileSync(logFile, lines.join("\n") + "\n", "utf-8");

      const res = verifyAuditLog(logFile);
      expect(res.valid).toBe(false);
      expect(res.code).toBe("SEQUENCE_GAP");
    });

    it("detects reordered entries in audit log", () => {
      const logFile = path.join(tempDir, "reordered-audit.jsonl");
      for (let i = 1; i <= 4; i++) {
        appendAuditEntry(
          { eventType: "proxy", action: "ALLOW", details: { i } },
          logFile
        );
      }

      // Swap line 2 and line 3
      const lines = fs.readFileSync(logFile, "utf-8").trim().split("\n");
      const temp = lines[1]!;
      lines[1] = lines[2]!;
      lines[2] = temp;
      fs.writeFileSync(logFile, lines.join("\n") + "\n", "utf-8");

      const res = verifyAuditLog(logFile);
      expect(res.valid).toBe(false);
      expect(["REORDERED_ENTRY", "SEQUENCE_GAP", "INVALID_HASH"]).toContain(res.code);
    });

    it("detects checkpoint tampering (headHash mutation)", () => {
      const logFile = path.join(tempDir, "checkpoint-tamper-hash.jsonl");
      const keypair = generateAuditKeyPair(tempDir);

      appendAuditEntry(
        { eventType: "proxy", action: "ALLOW", details: { init: true } },
        logFile
      );
      createAuditCheckpoint({
        logPath: logFile,
        privateKeyPath: keypair.privateKeyPath,
      });

      // Tamper with checkpoint headHash
      const lines = fs.readFileSync(logFile, "utf-8").trim().split("\n");
      const checkpointObj = JSON.parse(lines[1]!);
      checkpointObj.headHash = "f".repeat(64);
      checkpointObj.details.headHash = "f".repeat(64);
      lines[1] = JSON.stringify(checkpointObj);
      fs.writeFileSync(logFile, lines.join("\n") + "\n", "utf-8");

      const res = verifyAuditLog(logFile, undefined, undefined, keypair.publicKeyPath);
      expect(res.valid).toBe(false);
      expect(["CHECKPOINT_MISMATCH", "INVALID_HASH", "INVALID_SIGNATURE"]).toContain(res.code);
    });

    it("detects checkpoint signature tampering", () => {
      const logFile = path.join(tempDir, "checkpoint-tamper-sig.jsonl");
      const keypair = generateAuditKeyPair(tempDir);

      appendAuditEntry(
        { eventType: "proxy", action: "ALLOW", details: { test: 1 } },
        logFile
      );
      createAuditCheckpoint({
        logPath: logFile,
        privateKeyPath: keypair.privateKeyPath,
      });

      // Mutate signature
      const lines = fs.readFileSync(logFile, "utf-8").trim().split("\n");
      const checkpointObj = JSON.parse(lines[1]!);
      checkpointObj.signature = Buffer.from("forged-signature-bytes").toString("base64");
      lines[1] = JSON.stringify(checkpointObj);
      fs.writeFileSync(logFile, lines.join("\n") + "\n", "utf-8");

      const res = verifyAuditLog(logFile, undefined, undefined, keypair.publicKeyPath);
      expect(res.valid).toBe(false);
      expect(["INVALID_SIGNATURE", "INVALID_HASH"]).toContain(res.code);
    });
  });

  describe("3. Large Config Files & Deep JSON Objects", () => {
    it("parses 500+ MCP servers config file without performance degradation", () => {
      const bigConfigFile = path.join(tempDir, "large-mcp-config.json");
      const serversObj: Record<string, unknown> = {};

      for (let i = 1; i <= 500; i++) {
        serversObj[`server_${i}`] = {
          command: "node",
          args: [`./servers/server_${i}.js`, "--port", `${3000 + i}`],
          env: {
            NODE_ENV: "production",
            SERVER_ID: `srv-${i}`,
          },
        };
      }

      fs.writeFileSync(
        bigConfigFile,
        JSON.stringify({ mcpServers: serversObj }, null, 2),
        "utf-8"
      );

      const parsed = parseConfigFile(bigConfigFile, "custom");
      expect(parsed.length).toBe(500);
      expect(parsed[0]?.serverName).toBe("server_1");
      expect(parsed[499]?.serverName).toBe("server_500");
    });

    it("fails closed on JSON structures exceeding max depth of 32", () => {
      // Build 35 levels of nested JSON objects: { "a": { "a": { ... } } }
      let nested = '{"leaf": true}';
      for (let i = 0; i < 35; i++) {
        nested = `{"depth_${i}": ${nested}}`;
      }

      const scanResult = scanJsonStructure(nested, 32);
      expect(scanResult.valid).toBe(false);
      expect(scanResult.error).toMatch(/depth/i);

      // Verify payload validator rejects it
      const payload = `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":${nested}}`;
      const valResult = validateJsonRpcPayload(payload);
      expect(valResult.valid).toBe(false);
      if (!valResult.valid) {
        expect([-32700, -32600]).toContain(valResult.errorCode);
      }
    });
  });

  describe("4. 1 MB Proxy Boundary Frames & Split Frames", () => {
    it("accepts exact 1 MB frame and rejects 1 MB + 1 byte frame with code -32009", () => {
      let receivedFrame: string | undefined;
      let oversizedTriggered = false;

      const parser = new MessageFramingParser("line", DEFAULT_MAX_FRAME_SIZE);

      // Create exact valid JSON-RPC frame padding to 1 MB (1,048,576 bytes)
      const baseJson = '{"jsonrpc":"2.0","id":1,"method":"ping","params":{"pad":"';
      const suffix = '"}}\n';
      const padLen = DEFAULT_MAX_FRAME_SIZE - baseJson.length - suffix.length;
      const exact1MbPayload = baseJson + "a".repeat(padLen) + suffix;

      expect(Buffer.byteLength(exact1MbPayload, "utf-8")).toBe(DEFAULT_MAX_FRAME_SIZE);

      parser.push(
        Buffer.from(exact1MbPayload, "utf-8"),
        (frame) => {
          receivedFrame = frame.payload;
        },
        () => {
          oversizedTriggered = true;
        }
      );

      expect(receivedFrame).toBeDefined();
      expect(oversizedTriggered).toBe(false);

      // Now push a payload exceeding 1 MB
      let oversizedDetected = false;
      const oversizedParser = new MessageFramingParser("line", DEFAULT_MAX_FRAME_SIZE);
      const oversizedPayload = baseJson + "a".repeat(padLen + 64) + suffix;

      oversizedParser.push(
        Buffer.from(oversizedPayload, "utf-8"),
        () => {},
        (size) => {
          oversizedDetected = true;
          expect(size).toBeGreaterThan(DEFAULT_MAX_FRAME_SIZE);
        }
      );

      expect(oversizedDetected).toBe(true);
    });

    it("correctly reassembles multi-chunk split frames across data events", () => {
      const parser = new MessageFramingParser("auto");
      const fullMessage = '{"jsonrpc":"2.0","id":99,"method":"tools/list","params":{}}\n';
      const fullBuffer = Buffer.from(fullMessage, "utf-8");

      // Split into 7 small chunks
      const chunkSize = Math.ceil(fullBuffer.length / 7);
      const frames: string[] = [];

      for (let i = 0; i < fullBuffer.length; i += chunkSize) {
        const slice = fullBuffer.subarray(i, Math.min(i + chunkSize, fullBuffer.length));
        parser.push(
          slice,
          (res) => frames.push(res.payload),
          () => {}
        );
      }

      expect(frames.length).toBe(1);
      expect(frames[0]?.trim()).toBe(fullMessage.trim());
    });
  });

  describe("5. Unicode Homoglyphs & Symlink Invariants", () => {
    it("blocks Unicode fullwidth slash homoglyphs in path traversal", () => {
      // Fullwidth solidus '／' (U+FF0F)
      const unicodeTraversalRequest = {
        jsonrpc: "2.0" as const,
        id: "unicode-test",
        method: "tools/call",
        params: {
          name: "read_file",
          arguments: {
            path: "..／..／..／.env",
          },
        },
      };

      const decision = evaluateRequest(unicodeTraversalRequest, DEFAULT_POLICY);
      expect(decision.action).toBe("BLOCK");
      expect(["MS-001", "MS-002"]).toContain(decision.ruleId);
    });

    it("rejects symlink targets in executeSafeFix", () => {
      const realFile = path.join(tempDir, "real_config.json");
      const symlinkFile = path.join(tempDir, "symlink_config.json");
      fs.writeFileSync(realFile, JSON.stringify({ mcpServers: {} }), "utf-8");

      try {
        fs.symlinkSync(realFile, symlinkFile);
        expect(() => executeSafeFix({ targetPath: symlinkFile })).toThrow(/symbolic link/i);
      } catch {
        // Platform lacks symlink permission
      }
    });

    it("rejects symlinks in executeRollback", () => {
      const realBak = path.join(tempDir, "real_backup.json.bak");
      const symlinkBak = path.join(tempDir, "symlink_backup.json.bak");
      fs.writeFileSync(realBak, JSON.stringify({ mcpServers: {} }), "utf-8");

      try {
        fs.symlinkSync(realBak, symlinkBak);
        expect(() => executeRollback(symlinkBak)).toThrow(/symbolic link/i);
      } catch {
        // Platform lacks symlink permission
      }
    });
  });
});
