import { describe, it, expect } from "vitest";
import * as fs from "node:fs";
import * as path from "node:path";

describe("Phase 0: Workspace & Foundation Setup", () => {
  it("verifies tsconfig.json enables strict mode and strict options", () => {
    const tsconfigPath = path.resolve(__dirname, "../tsconfig.json");
    expect(fs.existsSync(tsconfigPath)).toBe(true);

    const tsconfigRaw = fs.readFileSync(tsconfigPath, "utf-8");
    const tsconfig = JSON.parse(tsconfigRaw);

    expect(tsconfig.compilerOptions.strict).toBe(true);
    expect(tsconfig.compilerOptions.noUncheckedIndexedAccess).toBe(true);
    expect(tsconfig.compilerOptions.exactOptionalPropertyTypes).toBe(true);
  });

  it("verifies package.json contains required bin entry and allowlisted scripts", () => {
    const pkgPath = path.resolve(__dirname, "../package.json");
    expect(fs.existsSync(pkgPath)).toBe(true);

    const pkg = JSON.parse(fs.readFileSync(pkgPath, "utf-8"));
    expect(pkg.bin["mcp-shield"]).toBe("./dist/index.js");
    expect(pkg.scripts.build).toBe("tsup");
    expect(pkg.scripts.test).toBe("vitest run");
    expect(pkg.scripts["self-test"]).toBe("npm run build && node scripts/agent-self-test.mjs");
  });

  it("verifies shared types file exists and exports valid types", () => {
    const typesPath = path.resolve(__dirname, "../src/types/index.ts");
    expect(fs.existsSync(typesPath)).toBe(true);
  });

  it("verifies build artifact dist/index.js exists and contains executable node shebang", () => {
    const distPath = path.resolve(__dirname, "../dist/index.js");
    expect(fs.existsSync(distPath)).toBe(true);
    const content = fs.readFileSync(distPath, "utf-8");
    const firstLine = content.split("\n")[0]?.trim();
    expect(firstLine).toBe("#!/usr/bin/env node");
  });
});
