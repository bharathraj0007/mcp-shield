import type { ScanResult, RuleSeverity, ScanFinding } from "../types/index.js";

export interface SarifRule {
  readonly id: string;
  readonly name: string;
  readonly shortDescription: { readonly text: string };
  readonly fullDescription?: { readonly text: string };
  readonly help?: { readonly text: string };
  readonly helpUri?: string;
  readonly defaultConfiguration?: { readonly level: "error" | "warning" | "note" };
  readonly properties?: {
    readonly "security-severity"?: string;
    readonly tags: readonly string[];
  };
}

export interface SarifSuppression {
  readonly kind: "external" | "inSource";
  readonly status?: "accepted" | "underReview" | "rejected";
  readonly justification?: string;
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
  readonly partialFingerprints?: Readonly<Record<string, string>>;
  readonly baselineState?: "new" | "unchanged" | "updated" | "absent";
  readonly suppressions?: readonly SarifSuppression[];
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

function mapSeverityToScore(severity: RuleSeverity): string {
  switch (severity) {
    case "critical":
      return "9.0";
    case "high":
      return "7.5";
    case "medium":
      return "5.0";
    case "low":
      return "2.0";
  }
}

export function generateSarifReport(
  scanResult: ScanResult,
  version: string = "0.2.0"
): SarifDocument {
  const ruleMap = new Map<string, SarifRule>();

  const allFindings: readonly ScanFinding[] = [
    ...(scanResult.findings || []),
    ...(scanResult.suppressedFindings || []),
  ];

  for (const finding of allFindings) {
    if (!ruleMap.has(finding.ruleId)) {
      ruleMap.set(finding.ruleId, {
        id: finding.ruleId,
        name: finding.title,
        shortDescription: { text: finding.title },
        fullDescription: { text: `${finding.title} (${finding.owaspId})` },
        help: { text: finding.fixSuggestion },
        helpUri: `https://github.com/bharathraj0007/mcp-shield#rules-${finding.ruleId.toLowerCase()}`,
        defaultConfiguration: {
          level: mapSeverityToSarifLevel(finding.severity),
        },
        properties: {
          "security-severity": mapSeverityToScore(finding.severity),
          tags: ["security", finding.owaspId, "mcp-shield"],
        },
      });
    }
  }

  const sarifResults: SarifResult[] = allFindings.map((f) => {
    const res: {
      ruleId: string;
      level: "error" | "warning" | "note";
      message: { text: string };
      locations: readonly [
        {
          readonly physicalLocation: {
            readonly artifactLocation: {
              readonly uri: string;
            };
          };
        },
      ];
      partialFingerprints?: Record<string, string>;
      baselineState?: "new" | "unchanged";
      suppressions?: SarifSuppression[];
    } = {
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
    };

    if (f.fingerprint) {
      res.partialFingerprints = {
        "mcpShield/v1": f.fingerprint,
      };
    }

    if (f.baselineState) {
      res.baselineState = f.baselineState;
    }

    if (f.suppressed) {
      res.suppressions = [
        {
          kind: "external",
          status: "accepted",
          justification: f.suppressionReason || "Suppressed by baseline",
        },
      ];
    }

    return res as SarifResult;
  });

  return {
    $schema: "https://json.schemastore.org/sarif-2.1.0.json",
    version: "2.1.0",
    runs: [
      {
        tool: {
          driver: {
            name: "mcp-shield",
            version,
            informationUri: "https://github.com/bharathraj0007/mcp-shield",
            rules: Array.from(ruleMap.values()),
          },
        },
        results: sarifResults,
      },
    ],
  };
}
