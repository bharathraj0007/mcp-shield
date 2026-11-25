#!/usr/bin/env node
/**
 * Offline Release Artifacts Generator for mcp-shield
 *
 * 1. Generates CycloneDX 1.5 JSON Software Bill of Materials (SBOM) from package-lock.json
 * 2. Packages production tarball via npm pack
 * 3. Computes cryptographic SHA-256 digests in SHA256SUMS.txt
 *
 * Invariant: 100% offline, zero network imports, native node:crypto only.
 */

import * as fs from "node:fs";
import * as path from "node:path";
import * as os from "node:os";
import * as crypto from "node:crypto";
import { execFileSync } from "node:child_process";
import { fileURLToPath } from "node:url";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const cliRoot = path.resolve(__dirname, "..");

console.log("Generating mcp-shield release artifacts (offline)...");

// 1. Read package.json and package-lock.json
const pkgJsonPath = path.join(cliRoot, "package.json");
const lockJsonPath = path.join(cliRoot, "package-lock.json");

const pkg = JSON.parse(fs.readFileSync(pkgJsonPath, "utf-8"));
const lock = JSON.parse(fs.readFileSync(lockJsonPath, "utf-8"));

// 2. Generate CycloneDX 1.5 JSON SBOM
const components = [];
if (lock.packages) {
  for (const [pkgPath, meta] of Object.entries(lock.packages)) {
    if (!pkgPath || pkgPath === "") continue; // skip root
    const cleanName = pkgPath.replace(/^node_modules\//, "");
    if (!cleanName || cleanName.startsWith(".")) continue;

    const purl = cleanName.startsWith("@")
      ? `pkg:npm/${cleanName.split("/")[0]}%2F${cleanName.split("/")[1]}@${meta.version}`
      : `pkg:npm/${cleanName}@${meta.version}`;

    components.push({
      type: "library",
      name: cleanName,
      version: meta.version || "unknown",
      scope: meta.dev ? "excluded" : "required",
      ...(meta.license ? { licenses: [{ license: { id: meta.license } }] } : {}),
      purl,
    });
  }
}

const sbom = {
  $schema: "http://cyclonedx.org/schema/bom-1.5.schema.json",
  bomFormat: "CycloneDX",
  specVersion: "1.5",
  serialNumber: `urn:uuid:${crypto.randomUUID()}`,
  version: 1,
  metadata: {
    timestamp: new Date().toISOString(),
    tools: [
      {
        vendor: "mcp-shield",
        name: "release-artifacts",
        version: pkg.version,
      },
    ],
    component: {
      type: "application",
      name: pkg.name,
      version: pkg.version,
      description: pkg.description || "",
      licenses: [{ license: { id: pkg.license || "Apache-2.0" } }],
      purl: `pkg:npm/%40bharathraj_07/mcp-shield@${pkg.version}`,
    },
  },
  components,
};

const sbomPath = path.join(cliRoot, "sbom.cdx.json");
fs.writeFileSync(sbomPath, JSON.stringify(sbom, null, 2) + "\n", "utf-8");
console.log(`✓ Generated CycloneDX 1.5 SBOM: ${path.basename(sbomPath)} (${components.length} components)`);

// 3. Package npm tarball via npm pack using secure temp cache and execFileSync
console.log("Packaging npm tarball via npm pack...");
const cacheDir = fs.mkdtempSync(path.join(os.tmpdir(), "mcp-shield-npm-cache-"));
let tarballFilename = "";

try {
  const packOutput =
    process.platform === "win32"
      ? execFileSync(
          process.env.ComSpec || "cmd.exe",
          ["/d", "/s", "/c", "npm", "pack", "--cache", cacheDir],
          { cwd: cliRoot, encoding: "utf-8", shell: false }
        )
      : execFileSync("npm", ["pack", "--cache", cacheDir], {
          cwd: cliRoot,
          encoding: "utf-8",
          shell: false,
        });

  const lines = packOutput.trim().split("\n");
  for (const line of lines) {
    const trimmed = line.trim();
    if (trimmed.endsWith(".tgz")) {
      tarballFilename = trimmed;
    }
  }

  if (!tarballFilename) {
    const files = fs.readdirSync(cliRoot).filter((f) => f.endsWith(".tgz"));
    if (files.length > 0) {
      tarballFilename = files[files.length - 1] || "";
    }
  }

  if (
    !tarballFilename ||
    path.basename(tarballFilename) !== tarballFilename ||
    !tarballFilename.endsWith(".tgz")
  ) {
    throw new Error(`Failed to produce or validate npm pack tarball: ${tarballFilename}`);
  }
} finally {
  try {
    fs.rmSync(cacheDir, { recursive: true, force: true });
  } catch {}
}

console.log(`✓ Packaged release tarball: ${tarballFilename}`);

// 4. Compute SHA-256 digests for release artifacts using atomic file reads
const artifactsToDigest = [tarballFilename, "sbom.cdx.json"];
const sumLines = [];

for (const artifact of artifactsToDigest) {
  if (path.basename(artifact) !== artifact) {
    throw new Error(`Invalid artifact path: ${artifact}`);
  }
  const artifactPath = path.join(cliRoot, artifact);
  try {
    const fileBytes = fs.readFileSync(artifactPath);
    const hash = crypto.createHash("sha256").update(fileBytes).digest("hex");
    sumLines.push(`${hash}  ${artifact}`);
  } catch (readErr) {
    const errMsg = readErr instanceof Error ? readErr.message : String(readErr);
    throw new Error(`Failed to read artifact for digest calculation: ${errMsg}`);
  }
}

const sumsPath = path.join(cliRoot, "SHA256SUMS.txt");
fs.writeFileSync(sumsPath, sumLines.join("\n") + "\n", "utf-8");
console.log(`✓ Generated SHA256SUMS.txt (${sumLines.length} artifacts hashed)`);

console.log("\nArtifacts summary:");
for (const line of sumLines) {
  console.log(`  ${line}`);
}
console.log("\nRelease artifacts build completed successfully.");
