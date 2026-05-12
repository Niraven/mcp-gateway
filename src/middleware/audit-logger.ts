import { appendFile, mkdir } from "node:fs/promises";
import { dirname } from "node:path";
import type { AuditEntry, AuditConfig } from "../types/index.js";

export class AuditLogger {
  private logPath: string;
  private includeArgs: boolean;
  private includeResults: boolean;
  private buffer: string[] = [];
  private flushTimer: ReturnType<typeof setTimeout> | null = null;

  constructor(config: AuditConfig) {
    this.logPath = config.logPath ?? "./mcp-gateway-audit.jsonl";
    this.includeArgs = config.includeArgs ?? false;
    this.includeResults = config.includeResults ?? false;
  }

  async log(entry: AuditEntry): Promise<void> {
    const sanitized: AuditEntry = {
      ...entry,
      args: this.includeArgs ? redactSecrets(entry.args) : undefined,
      result: this.includeResults ? redactSecrets(entry.result) : undefined,
    };

    const line = JSON.stringify(sanitized) + "\n";
    this.buffer.push(line);

    if (!this.flushTimer) {
      this.flushTimer = setTimeout(() => this.flush(), 1000);
    }
  }

  private async flush(): Promise<void> {
    if (this.buffer.length === 0) return;
    this.flushTimer = null;

    const lines = this.buffer.join("");
    this.buffer = [];

    try {
      await mkdir(dirname(this.logPath), { recursive: true });
      await appendFile(this.logPath, lines);
    } catch (err) {
      process.stderr.write(`[mcp-gateway] Audit write failed: ${err}\n`);
    }
  }

  async close(): Promise<void> {
    if (this.flushTimer) clearTimeout(this.flushTimer);
    await this.flush();
  }

  formatSummary(entries: AuditEntry[]): string {
    const byAction: Record<string, number> = {};
    const byServer: Record<string, number> = {};
    const byTool: Record<string, number> = {};

    for (const e of entries) {
      byAction[e.action] = (byAction[e.action] ?? 0) + 1;
      byServer[e.server] = (byServer[e.server] ?? 0) + 1;
      byTool[e.tool] = (byTool[e.tool] ?? 0) + 1;
    }

    const lines = [
      `Audit Summary (${entries.length} entries)`,
      `  By action: ${Object.entries(byAction).map(([k, v]) => `${k}=${v}`).join(", ")}`,
      `  By server: ${Object.entries(byServer).map(([k, v]) => `${k}=${v}`).join(", ")}`,
      `  Top tools: ${Object.entries(byTool).sort((a, b) => b[1] - a[1]).slice(0, 5).map(([k, v]) => `${k}=${v}`).join(", ")}`,
    ];
    return lines.join("\n");
  }
}

function redactSecrets(value: unknown): unknown {
  if (value === null || value === undefined) return value;
  if (Array.isArray(value)) return value.map(redactSecrets);
  if (typeof value === "object") {
    const result: Record<string, unknown> = {};
    for (const [key, nestedValue] of Object.entries(value as Record<string, unknown>)) {
      if (isSecretKey(key)) {
        result[key] = "[REDACTED]";
      } else {
        result[key] = redactSecrets(nestedValue);
      }
    }
    return result;
  }
  if (typeof value === "string" && looksLikeSecret(value)) {
    return "[REDACTED]";
  }
  return value;
}

function isSecretKey(key: string): boolean {
  return /token|secret|password|passwd|api[_-]?key|authorization|credential/i.test(key);
}

function looksLikeSecret(value: string): boolean {
  return /\b(sk-[A-Za-z0-9_-]{20,}|gh[pousr]_[A-Za-z0-9_]{20,}|xox[baprs]-[A-Za-z0-9-]{20,})\b/.test(value);
}
