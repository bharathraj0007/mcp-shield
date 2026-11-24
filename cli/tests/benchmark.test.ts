import { describe, it, expect } from "vitest";
import { performance } from "node:perf_hooks";
import { evaluateRequest } from "../src/proxy/evaluator.js";
import type { JsonRpcRequest } from "../src/types/index.js";

describe("Proxy Latency Benchmark Gate", () => {
  it("verifies p99 firewall inspection latency is under 5 ms per message", () => {
    const testCases: readonly JsonRpcRequest[] = [
      {
        jsonrpc: "2.0",
        id: 1,
        method: "tools/call",
        params: { name: "read_file", arguments: { path: "./src/index.ts" } },
      },
      {
        jsonrpc: "2.0",
        id: 2,
        method: "tools/call",
        params: { name: "read_file", arguments: { path: "./docs/ssh-setup.md" } },
      },
      {
        jsonrpc: "2.0",
        id: 3,
        method: "tools/call",
        params: { name: "read_file", arguments: { path: "./src/environment.ts" } },
      },
      {
        jsonrpc: "2.0",
        id: 4,
        method: "tools/call",
        params: { name: "execute_command", arguments: { command: "git status" } },
      },
      {
        jsonrpc: "2.0",
        id: 5,
        method: "tools/call",
        params: { name: "read_file", arguments: { path: "../../.env" } },
      },
      {
        jsonrpc: "2.0",
        id: 6,
        method: "tools/call",
        params: { name: "read_file", arguments: { path: "%2e%2e/%2e%2e/.env" } },
      },
      {
        jsonrpc: "2.0",
        id: 7,
        method: "tools/call",
        params: { name: "execute_command", arguments: { command: "rm -rf /" } },
      },
      {
        jsonrpc: "2.0",
        id: 8,
        method: "resources/read",
        params: { uri: "file:///safe/project/README.md" },
      },
    ];

    const iterations = 500;
    const durations: number[] = [];

    // Warm-up run
    for (let i = 0; i < 50; i++) {
      const sample = testCases[i % testCases.length]!;
      evaluateRequest(sample);
    }

    // Benchmark measurement
    for (let i = 0; i < iterations; i++) {
      const sample = testCases[i % testCases.length]!;
      const start = performance.now();
      evaluateRequest(sample);
      const end = performance.now();
      durations.push(end - start);
    }

    durations.sort((a, b) => a - b);

    const p50Index = Math.floor(durations.length * 0.5);
    const p90Index = Math.floor(durations.length * 0.9);
    const p95Index = Math.floor(durations.length * 0.95);
    const p99Index = Math.floor(durations.length * 0.99);

    const p50 = durations[p50Index]!;
    const p90 = durations[p90Index]!;
    const p95 = durations[p95Index]!;
    const p99 = durations[p99Index]!;

    const avg = durations.reduce((acc, v) => acc + v, 0) / durations.length;

    console.log("\n==================================================");
    console.log("MCP-SHIELD PROXY LATENCY BENCHMARK RESULTS (500 runs)");
    console.log("==================================================");
    console.log(`  Average: ${avg.toFixed(4)} ms`);
    console.log(`  p50:     ${p50.toFixed(4)} ms`);
    console.log(`  p90:     ${p90.toFixed(4)} ms`);
    console.log(`  p95:     ${p95.toFixed(4)} ms`);
    console.log(`  p99:     ${p99.toFixed(4)} ms (Target: < 5.0 ms)`);
    console.log("==================================================\n");

    expect(p99).toBeLessThan(5.0);
  });
});
