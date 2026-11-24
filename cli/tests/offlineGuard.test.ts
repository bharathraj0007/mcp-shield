import { describe, it, expect } from "vitest";
import * as fs from "node:fs";
import * as path from "node:path";

describe("Phase 4: Offline Guard & Allowlist Verification", () => {
  const cliRoot = path.resolve(__dirname, "..");
  const srcDir = path.join(cliRoot, "src");

  function getFilesRecursively(dir: string): string[] {
    let results: string[] = [];
    if (!fs.existsSync(dir)) return results;
    const list = fs.readdirSync(dir, { withFileTypes: true });
    for (const item of list) {
      const fullPath = path.join(dir, item.name);
      if (item.isDirectory()) {
        results = results.concat(getFilesRecursively(fullPath));
      } else if (item.isFile() && item.name.endsWith(".ts")) {
        results.push(fullPath);
      }
    }
    return results;
  }

  it("verifies zero outbound network, HTTP, or socket calls in src/", () => {
    const tsFiles = getFilesRecursively(srcDir);
    expect(tsFiles.length).toBeGreaterThan(0);

    const forbiddenPatterns: readonly { readonly name: string; readonly regex: RegExp }[] = [
      { name: "fetch API", regex: /\bfetch\s*\(/ },
      { name: "http module import/call", regex: /\bfrom\s*["']node:http["']|\brequire\(["']http["']\)/ },
      { name: "https module import/call", regex: /\bfrom\s*["']node:https["']|\brequire\(["']https["']\)/ },
      { name: "net socket module", regex: /\bfrom\s*["']node:net["']|\brequire\(["']net["']\)/ },
      { name: "dgram UDP module", regex: /\bfrom\s*["']node:dgram["']|\brequire\(["']dgram["']\)/ },
      { name: "tls module", regex: /\bfrom\s*["']node:tls["']|\brequire\(["']tls["']\)/ },
      { name: "WebSocket API", regex: /\bnew\s+WebSocket\b/ },
      { name: "axios client", regex: /\baxios\b/ },
      { name: "telemetry SDK", regex: /\btelemetry\b/i },
    ];

    for (const file of tsFiles) {
      const content = fs.readFileSync(file, "utf-8");
      for (const pattern of forbiddenPatterns) {
        const matches = pattern.regex.test(content);
        expect(
          matches,
          `File ${path.relative(cliRoot, file)} violates offline invariant: matches ${pattern.name}`
        ).toBe(false);
      }
    }
  });

  it("verifies package.json contains zero unapproved runtime dependencies", () => {
    const pkgPath = path.join(cliRoot, "package.json");
    const pkg = JSON.parse(fs.readFileSync(pkgPath, "utf-8")) as {
      dependencies?: Record<string, string>;
      devDependencies?: Record<string, string>;
    };

    const allowedRuntime = new Set([
      "commander",
      "picocolors",
      "jsonc-parser",
      "yaml",
      "zod",
    ]);

    const runtimeDeps = Object.keys(pkg.dependencies || {});
    for (const dep of runtimeDeps) {
      expect(
        allowedRuntime.has(dep),
        `Unapproved runtime dependency found: "${dep}". mcp-shield must remain 100% offline.`
      ).toBe(true);
    }
  });

  it("verifies package.json contains zero unapproved dev dependencies", () => {
    const pkgPath = path.join(cliRoot, "package.json");
    const pkg = JSON.parse(fs.readFileSync(pkgPath, "utf-8")) as {
      devDependencies?: Record<string, string>;
    };

    const allowedDev = new Set([
      "typescript",
      "tsup",
      "vitest",
      "@types/node",
    ]);

    const devDeps = Object.keys(pkg.devDependencies || {});
    for (const dep of devDeps) {
      expect(
        allowedDev.has(dep),
        `Unapproved dev dependency found: "${dep}".`
      ).toBe(true);
    }
  });

  it("verifies self-test script is configured in package.json scripts", () => {
    const pkgPath = path.join(cliRoot, "package.json");
    const pkg = JSON.parse(fs.readFileSync(pkgPath, "utf-8")) as {
      scripts?: Record<string, string>;
    };

    expect(pkg.scripts?.["self-test"]).toBe(
      "npm run build && node scripts/agent-self-test.mjs"
    );
  });
});
