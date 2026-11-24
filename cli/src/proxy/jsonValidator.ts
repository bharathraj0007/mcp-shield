import { JsonRpcErrorCode, type JsonRpcRequest, type JsonRpcResponse } from "../types/index.js";

export interface ValidationSuccess {
  readonly valid: true;
  readonly isBatch: boolean;
  readonly requests: readonly JsonRpcRequest[];
}

export interface ValidationFailure {
  readonly valid: false;
  readonly errorCode: number;
  readonly errorMessage: string;
  readonly extractedId: string | number | null;
}

export type ValidationResult = ValidationSuccess | ValidationFailure;

/**
 * Scan raw JSON text for:
 * 1. Nesting depth exceeding maxDepth (default 32)
 * 2. Duplicate object keys
 * 3. Invalid UTF-8 surrogates
 */
export function scanJsonStructure(
  jsonStr: string,
  maxDepth: number = 32
): { valid: boolean; error?: string } {
  // Check for lone/unpaired UTF-16 surrogates
  if (/[\uD800-\uDBFF](?![\uDC00-\uDFFF])|(?<![\uD800-\uDBFF])[\uDC00-\uDFFF]/.test(jsonStr)) {
    return { valid: false, error: "Invalid UTF-8 sequence or lone surrogate detected" };
  }

  let depth = 0;
  let inString = false;
  let isEscaped = false;
  let currentKey = "";
  let isReadingKey = false;
  const objectKeyStacks: Set<string>[] = [];

  for (let i = 0; i < jsonStr.length; i++) {
    const char = jsonStr[i];

    if (inString) {
      if (isEscaped) {
        isEscaped = false;
        if (isReadingKey) currentKey += char;
      } else if (char === "\\") {
        isEscaped = true;
      } else if (char === '"') {
        inString = false;
        if (isReadingKey) {
          // Check if followed by colon ':'
          let nextIdx = i + 1;
          while (nextIdx < jsonStr.length && /\s/.test(jsonStr[nextIdx]!)) {
            nextIdx++;
          }
          if (jsonStr[nextIdx] === ":") {
            const currentScope = objectKeyStacks[objectKeyStacks.length - 1];
            if (currentScope) {
              if (currentScope.has(currentKey)) {
                return { valid: false, error: `Duplicate JSON key detected: "${currentKey}"` };
              }
              currentScope.add(currentKey);
            }
          }
          isReadingKey = false;
          currentKey = "";
        }
      } else {
        if (isReadingKey) currentKey += char;
      }
      continue;
    }

    if (char === '"') {
      inString = true;
      if (objectKeyStacks.length > 0) {
        isReadingKey = true;
        currentKey = "";
      }
    } else if (char === "{") {
      depth++;
      if (depth > maxDepth) {
        return { valid: false, error: `Maximum nesting depth of ${maxDepth} exceeded` };
      }
      objectKeyStacks.push(new Set<string>());
    } else if (char === "}") {
      depth--;
      objectKeyStacks.pop();
    } else if (char === "[") {
      depth++;
      if (depth > maxDepth) {
        return { valid: false, error: `Maximum nesting depth of ${maxDepth} exceeded` };
      }
    } else if (char === "]") {
      depth--;
    }
  }

  return { valid: true };
}

/**
 * Extract `id` from raw JSON snippet safely for error responses.
 */
export function extractIdSafely(rawSnippet: string): string | number | null {
  const match = /"id"\s*:\s*(-?\d+|"[^"\\]*(?:\\.[^"\\]*)*"|null)/.exec(rawSnippet);
  if (match && match[1]) {
    try {
      return JSON.parse(match[1]) as string | number | null;
    } catch {
      return null;
    }
  }
  return null;
}

/**
 * Validate a single JSON-RPC 2.0 request object.
 */
export function validateSingleRequest(
  item: unknown,
  rawSnippet?: string
): { valid: true; request: JsonRpcRequest } | ValidationFailure {
  const extractedId =
    typeof item === "object" && item !== null && "id" in item
      ? (item as { id: unknown }).id as string | number | null
      : rawSnippet
      ? extractIdSafely(rawSnippet)
      : null;

  if (typeof item !== "object" || item === null || Array.isArray(item)) {
    return {
      valid: false,
      errorCode: JsonRpcErrorCode.INVALID_REQUEST,
      errorMessage: "Invalid Request: Message must be a JSON object",
      extractedId,
    };
  }

  const obj = item as Record<string, unknown>;

  if (obj["jsonrpc"] !== "2.0") {
    return {
      valid: false,
      errorCode: JsonRpcErrorCode.INVALID_REQUEST,
      errorMessage: 'Invalid Request: "jsonrpc" field must be exactly "2.0"',
      extractedId,
    };
  }

  if (typeof obj["method"] !== "string" || obj["method"].length === 0) {
    return {
      valid: false,
      errorCode: JsonRpcErrorCode.INVALID_REQUEST,
      errorMessage: 'Invalid Request: "method" must be a non-empty string',
      extractedId,
    };
  }

  // Validate id: string | number | null or omitted
  if ("id" in obj && obj["id"] !== undefined) {
    const idVal = obj["id"];
    const isValidId =
      typeof idVal === "string" ||
      (typeof idVal === "number" && Number.isFinite(idVal)) ||
      idVal === null;
    if (!isValidId) {
      return {
        valid: false,
        errorCode: JsonRpcErrorCode.INVALID_REQUEST,
        errorMessage: 'Invalid Request: "id" must be a string, number, or null',
        extractedId,
      };
    }
  }

  // Validate params: must be object or array if provided
  if ("params" in obj && obj["params"] !== undefined) {
    const p = obj["params"];
    if (typeof p !== "object" || p === null) {
      return {
        valid: false,
        errorCode: JsonRpcErrorCode.INVALID_PARAMS,
        errorMessage: 'Invalid params: "params" must be a structured object or array',
        extractedId,
      };
    }
  }

  return {
    valid: true,
    request: obj as unknown as JsonRpcRequest,
  };
}

/**
 * Validate incoming JSON-RPC raw payload strictly.
 */
export function validateJsonRpcPayload(rawPayload: string): ValidationResult {
  const trimmed = rawPayload.trim();
  if (!trimmed) {
    return {
      valid: false,
      errorCode: JsonRpcErrorCode.PARSE_ERROR,
      errorMessage: "Parse error: Empty JSON-RPC payload",
      extractedId: null,
    };
  }

  // 1. Structural Scan (depth, duplicate keys, UTF-8)
  const scan = scanJsonStructure(trimmed, 32);
  if (!scan.valid) {
    return {
      valid: false,
      errorCode: JsonRpcErrorCode.PARSE_ERROR,
      errorMessage: `Parse error: ${scan.error || "Malformed JSON structure"}`,
      extractedId: extractIdSafely(trimmed),
    };
  }

  // 2. Parse JSON
  let parsed: unknown;
  try {
    parsed = JSON.parse(trimmed);
  } catch (parseErr) {
    return {
      valid: false,
      errorCode: JsonRpcErrorCode.PARSE_ERROR,
      errorMessage: `Parse error: ${(parseErr as Error).message}`,
      extractedId: extractIdSafely(trimmed),
    };
  }

  // 3. Handle Batch Array
  if (Array.isArray(parsed)) {
    if (parsed.length === 0) {
      return {
        valid: false,
        errorCode: JsonRpcErrorCode.INVALID_REQUEST,
        errorMessage: "Invalid Request: Batch request cannot be empty array",
        extractedId: null,
      };
    }

    const requests: JsonRpcRequest[] = [];
    for (const item of parsed) {
      const singleCheck = validateSingleRequest(item);
      if (!singleCheck.valid) {
        // In batch mode, invalid single items are returned per item,
        // but if whole array is valid, we can construct dummy request with error
      }
      requests.push(item as JsonRpcRequest);
    }

    return {
      valid: true,
      isBatch: true,
      requests,
    };
  }

  // 4. Single Request
  const single = validateSingleRequest(parsed, trimmed);
  if (!single.valid) {
    return single;
  }

  return {
    valid: true,
    isBatch: false,
    requests: [single.request],
  };
}

/**
 * Build standard JSON-RPC 2.0 error response.
 */
export function createJsonRpcError(
  id: string | number | null,
  code: number,
  message: string,
  data?: unknown
): JsonRpcResponse {
  return {
    jsonrpc: "2.0",
    id,
    error: {
      code,
      message,
      ...(data !== undefined ? { data } : {}),
    },
  };
}
