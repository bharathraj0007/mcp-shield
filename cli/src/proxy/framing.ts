import type { FramingMode } from "../types/index.js";

export const DEFAULT_MAX_FRAME_SIZE = 1024 * 1024; // 1 MB

export interface FrameResult {
  readonly payload: string;
  readonly framing: "line" | "content-length";
}

/**
 * MessageFramingParser handles dual framing:
 * 1. Line-delimited JSON-RPC (separated by \n or \r\n)
 * 2. Header-framed JSON-RPC (Content-Length: <bytes>\r\n\r\n<payload>)
 * 3. Auto-detection mode
 */
export class MessageFramingParser {
  private buffer: Buffer = Buffer.alloc(0);
  private mode: FramingMode;
  private detectedMode: "line" | "content-length" | undefined;
  private readonly maxFrameSize: number;

  constructor(mode: FramingMode = "auto", maxFrameSize: number = DEFAULT_MAX_FRAME_SIZE) {
    this.mode = mode;
    this.maxFrameSize = maxFrameSize;
    if (mode === "line" || mode === "content-length") {
      this.detectedMode = mode;
    }
  }

  public getFramingMode(): "line" | "content-length" {
    return this.detectedMode || (this.mode === "content-length" ? "content-length" : "line");
  }

  public push(
    chunk: Buffer,
    onFrame: (result: FrameResult) => void,
    onOversized: (size: number, rawSnippet?: string) => void
  ): void {
    this.buffer = Buffer.concat([this.buffer, chunk]);

    let continueParsing = true;
    while (continueParsing && this.buffer.length > 0) {
      if (this.mode === "auto" && !this.detectedMode) {
        // Inspect beginning of buffer
        const preview = this.buffer.subarray(0, Math.min(this.buffer.length, 128)).toString("utf-8");
        const trimmed = preview.trimStart();
        if (/^content-length:/i.test(trimmed)) {
          this.detectedMode = "content-length";
        } else if (trimmed.startsWith("{") || trimmed.startsWith("[")) {
          this.detectedMode = "line";
        } else if (this.buffer.indexOf(0x0a) !== -1) {
          // If we see newline first without header, default to line
          this.detectedMode = "line";
        } else if (this.buffer.length > 256) {
          // Fallback if no header seen
          this.detectedMode = "line";
        } else {
          // Wait for more bytes to detect
          break;
        }
      }

      const activeFraming = this.detectedMode || (this.mode === "content-length" ? "content-length" : "line");

      if (activeFraming === "content-length") {
        continueParsing = this.parseContentLength(onFrame, onOversized);
      } else {
        continueParsing = this.parseLine(onFrame, onOversized);
      }
    }
  }

  private parseLine(
    onFrame: (result: FrameResult) => void,
    onOversized: (size: number, rawSnippet?: string) => void
  ): boolean {
    const newlineIndex = this.buffer.indexOf(0x0a);
    if (newlineIndex === -1) {
      if (this.buffer.length > this.maxFrameSize) {
        onOversized(this.buffer.length);
        this.buffer = Buffer.alloc(0);
      }
      return false;
    }

    if (newlineIndex > this.maxFrameSize) {
      onOversized(newlineIndex);
      this.buffer = this.buffer.subarray(newlineIndex + 1);
      return true;
    }

    let lineBuffer = this.buffer.subarray(0, newlineIndex);
    if (lineBuffer.length > 0 && lineBuffer[lineBuffer.length - 1] === 0x0d) {
      lineBuffer = lineBuffer.subarray(0, lineBuffer.length - 1);
    }

    const payload = lineBuffer.toString("utf-8");
    this.buffer = this.buffer.subarray(newlineIndex + 1);

    if (payload.trim().length > 0) {
      onFrame({ payload, framing: "line" });
    }
    return true;
  }

  private parseContentLength(
    onFrame: (result: FrameResult) => void,
    onOversized: (size: number, rawSnippet?: string) => void
  ): boolean {
    // Look for double CRLF or double LF indicating end of headers: \r\n\r\n or \n\n
    let headerEndIndex = -1;
    let headerDelimiterLength = 4;

    const crlfIndex = this.buffer.indexOf("\r\n\r\n");
    const lfIndex = this.buffer.indexOf("\n\n");

    if (crlfIndex !== -1 && (lfIndex === -1 || crlfIndex < lfIndex)) {
      headerEndIndex = crlfIndex;
      headerDelimiterLength = 4;
    } else if (lfIndex !== -1) {
      headerEndIndex = lfIndex;
      headerDelimiterLength = 2;
    }

    if (headerEndIndex === -1) {
      if (this.buffer.length > 8192) {
        // Headers abnormally large
        onOversized(this.buffer.length);
        this.buffer = Buffer.alloc(0);
      }
      return false;
    }

    const headerStr = this.buffer.subarray(0, headerEndIndex).toString("utf-8");
    const match = /content-length:\s*(\d+)/i.exec(headerStr);
    if (!match || !match[1]) {
      // Malformed header, skip past delimiter
      this.buffer = this.buffer.subarray(headerEndIndex + headerDelimiterLength);
      return true;
    }

    const contentLength = parseInt(match[1], 10);
    if (Number.isNaN(contentLength) || contentLength < 0) {
      this.buffer = this.buffer.subarray(headerEndIndex + headerDelimiterLength);
      return true;
    }

    if (contentLength > this.maxFrameSize) {
      onOversized(contentLength, headerStr);
      // Consume header and whatever of the payload is buffered
      const totalToConsume = Math.min(
        this.buffer.length,
        headerEndIndex + headerDelimiterLength + contentLength
      );
      this.buffer = this.buffer.subarray(totalToConsume);
      return true;
    }

    const payloadStartIndex = headerEndIndex + headerDelimiterLength;
    const requiredTotalLength = payloadStartIndex + contentLength;

    if (this.buffer.length < requiredTotalLength) {
      // Complete payload has not arrived yet
      return false;
    }

    const payloadBuffer = this.buffer.subarray(payloadStartIndex, requiredTotalLength);
    const payload = payloadBuffer.toString("utf-8");
    this.buffer = this.buffer.subarray(requiredTotalLength);

    onFrame({ payload, framing: "content-length" });
    return true;
  }

  public flush(onFrame: (result: FrameResult) => void): void {
    if (this.buffer.length > 0) {
      let lineBuffer = this.buffer;
      if (lineBuffer.length > 0 && lineBuffer[lineBuffer.length - 1] === 0x0d) {
        lineBuffer = lineBuffer.subarray(0, lineBuffer.length - 1);
      }
      const payload = lineBuffer.toString("utf-8");
      this.buffer = Buffer.alloc(0);
      if (payload.trim().length > 0) {
        onFrame({
          payload,
          framing: this.detectedMode || (this.mode === "content-length" ? "content-length" : "line"),
        });
      }
    }
  }

  public getBufferedLength(): number {
    return this.buffer.length;
  }
}

/**
 * Format message into selected framing.
 */
export function encodeFrame(payload: string, framing: "line" | "content-length"): string {
  if (framing === "content-length") {
    const bytes = Buffer.byteLength(payload, "utf-8");
    return `Content-Length: ${bytes}\r\n\r\n${payload}`;
  }
  return payload.endsWith("\n") ? payload : payload + "\n";
}
