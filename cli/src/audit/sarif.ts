import type { ScanResult, RuleSeverity } from "../types/index.js";

export interface SarifRule {
  readonly id: string;
  readonly name: string;
  readonly shortDescription: { readonly text: string };
  readonly defaultConfiguration?: { readonly level: "error" | "warning" | "note" };
  readonly properties?: { readonly tags: readonly string[] };
}

export interface SarifResult {
  readonly ruleId: string;
  readonly level: "error" | "warning" | "note";
  readonly message: { readonly text: string };
  readonly locations: readonly [
    {
      readonly physicalLocation: {
        readonly artifactLocation: {
          readonly uri: string;
        };
      };
    },
  ];
}

export interface SarifDocument {
  readonly $schema: string;
  readonly version: string;
  readonly runs: readonly [
    {
      readonly tool: {
        readonly driver: {
          readonly name: string;
          readonly version: string;
          readonly informationUri: string;
          readonly rules: readonly SarifRule[];
        };
      };
      readonly results: readonly SarifResult[];
    },
  ];
}

function mapSeverityToSarifLevel(severity: RuleSeverity): "error" | "warning" | "note" {
  switch (severity) {
    case "critical":
    case "high":
      return "error";
    case "medium":
      return "warning";
    case "low":
      return "note";
  }
}

export function generateSarifReport(scanResult: ScanResult): SarifDocument {
  const ruleMap = new Map<string, SarifRule>();

  for (const finding of scanResult.findings) {
    if (!ruleMap.has(finding.ruleId)) {
      ruleMap.set(finding.ruleId, {
        id: finding.ruleId,
        name: finding.title,
        shortDescription: { text: finding.title },
        defaultConfiguration: {
          level: mapSeverityToSarifLevel(finding.severity),
        },
        properties: {
          tags: ["security", finding.owaspId, "mcp-shield"],
        },
      });
    }
  }

  const sarifResults: SarifResult[] = scanResult.findings.map((f) => ({
    ruleId: f.ruleId,
    level: mapSeverityToSarifLevel(f.severity),
    message: { text: f.message },
    locations: [
      {
        physicalLocation: {
          artifactLocation: {
            uri: f.file.replace(/\\/g, "/"),
          },
        },
      },
    ],
  }));

  return {
    $schema: "https://json.schemastore.org/sarif-2.1.0.json",
    version: "2.1.0",
    runs: [
      {
        tool: {
          driver: {
            name: "mcp-shield",
            version: "1.0.0",
            informationUri: "https://github.com/mcp-shield/mcp-shield",
            rules: Array.from(ruleMap.values()),
          },
        },
        results: sarifResults,
      },
    ],
  };
}
