import { createHash } from "node:crypto";
import { mkdir, readFile, writeFile } from "node:fs/promises";
import { dirname, resolve } from "node:path";
import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StdioClientTransport } from "@modelcontextprotocol/sdk/client/stdio.js";
import {
  CallToolRequestSchema,
  ListToolsRequestSchema,
} from "@modelcontextprotocol/sdk/types.js";
import type {
  GatewayConfig,
  Middleware,
  ToolCallContext,
  MiddlewareResult,
  AuditEntry,
  SecurityFinding,
} from "../types/index.js";
import { createRateLimiter } from "../middleware/rate-limiter.js";
import { createSecurityScanner, scanToolDescription } from "../middleware/security-scanner.js";
import { createApprovalGate } from "../middleware/approval.js";
import { AuditLogger } from "../middleware/audit-logger.js";

interface UpstreamConnection {
  client: Client;
  transport: StdioClientTransport;
  name: string;
}

interface DescriptorRecord {
  hash: string;
  firstSeen: string;
  lastSeen: string;
}

interface DescriptorBaseline {
  version: 1;
  tools: Record<string, DescriptorRecord>;
}

export class McpGateway {
  private server: Server;
  private upstreams: Map<string, UpstreamConnection> = new Map();
  private middlewares: Middleware[] = [];
  private auditLogger: AuditLogger | null = null;
  private config: GatewayConfig;
  private toolToServer: Map<string, string> = new Map();
  private toolAnnotations: Map<string, ToolCallContext["annotations"]> = new Map();
  private descriptorBaseline: DescriptorBaseline | null = null;
  private descriptorBaselineDirty = false;

  constructor(config: GatewayConfig) {
    this.config = config;
    this.server = new Server(
      { name: "mcp-gateway", version: "0.1.0" },
      { capabilities: { tools: {} } }
    );

    if (config.policies?.rateLimit) {
      this.middlewares.push(createRateLimiter(config.policies.rateLimit));
    }

    if (config.policies?.security) {
      this.middlewares.push(createSecurityScanner(config.policies.security));
    }

    if (config.policies?.approval) {
      this.middlewares.push(createApprovalGate(config.policies.approval));
    }

    if (config.audit?.enabled) {
      this.auditLogger = new AuditLogger(config.audit);
    }

    this.setupHandlers();
  }

  private setupHandlers(): void {
    this.server.setRequestHandler(ListToolsRequestSchema, async () => {
      const allTools: Array<{ name: string; description?: string; inputSchema: unknown }> = [];
      this.toolToServer.clear();
      this.toolAnnotations.clear();

      for (const [serverName, upstream] of this.upstreams) {
        try {
          const response = await upstream.client.listTools();
          for (const tool of response.tools) {
            const prefixedName = `${serverName}__${tool.name}`;

            const descFindings = this.config.policies?.security?.scanDescriptions
              ? scanToolDescription(tool.description ?? "")
              : [];
            const descriptorFindings = await this.checkDescriptor(prefixedName, {
              name: tool.name,
              description: tool.description ?? "",
              inputSchema: tool.inputSchema,
              annotations: tool.annotations,
            });
            const findings = [...descFindings, ...descriptorFindings];
            const shouldBlock = this.shouldBlockDescriptor(findings);
            if (shouldBlock) {
              process.stderr.write(`[mcp-gateway] Blocked unsafe descriptor for ${prefixedName}: ${findings.map(f => f.ruleId).join(", ")}\n`);
              await this.audit({
                server: serverName,
                tool: tool.name,
                args: undefined,
                findings,
              }, "blocked", "Unsafe tool descriptor blocked", undefined, findings);
              continue;
            }

            this.toolToServer.set(prefixedName, serverName);
            this.toolAnnotations.set(prefixedName, normalizeAnnotations(tool.annotations));

            let description = tool.description ?? "";
            if (findings.length > 0) {
              description = `[GATEWAY WARNING: ${findings.length} security findings] ${description}`;
            }

            allTools.push({
              name: prefixedName,
              description,
              inputSchema: tool.inputSchema,
            });
          }
        } catch (err) {
          process.stderr.write(`[mcp-gateway] Failed to list tools from ${serverName}: ${err}\n`);
        }
      }

      await this.saveDescriptorBaseline();
      return { tools: allTools };
    });

    this.server.setRequestHandler(CallToolRequestSchema, async (request) => {
      const toolName = request.params.name;
      const serverName = this.toolToServer.get(toolName);

      if (!serverName) {
        return {
          content: [{ type: "text", text: `Unknown tool: ${toolName}` }],
          isError: true,
        };
      }

      const upstream = this.upstreams.get(serverName);
      if (!upstream) {
        return {
          content: [{ type: "text", text: `Server not connected: ${serverName}` }],
          isError: true,
        };
      }

      const originalToolName = toolName.replace(`${serverName}__`, "");
      const ctx: ToolCallContext = {
        server: serverName,
        tool: originalToolName,
        args: request.params.arguments,
        annotations: this.toolAnnotations.get(toolName),
      };

      const middlewareResult = await this.runMiddlewares(ctx);

      if (middlewareResult.action === "block") {
        await this.audit(ctx, "blocked", middlewareResult.reason, undefined, middlewareResult.findings);
        return {
          content: [{
            type: "text",
            text: `[BLOCKED by mcp-gateway] ${middlewareResult.reason}`,
          }],
          isError: true,
        };
      }

      if (middlewareResult.action === "require-approval") {
        await this.audit(ctx, "pending-approval", middlewareResult.reason);
        return {
          content: [{
            type: "text",
            text: `[APPROVAL REQUIRED] ${middlewareResult.reason}\n\nThis tool call requires human approval. The action has been logged and is pending review.`,
          }],
          isError: true,
        };
      }

      const start = Date.now();
      try {
        const result = await upstream.client.callTool({
          name: originalToolName,
          arguments: request.params.arguments ?? {},
        });

        await this.audit(ctx, "allowed", undefined, Date.now() - start);
        return result;
      } catch (err) {
        const errMsg = err instanceof Error ? err.message : String(err);
        await this.audit(ctx, "allowed", `error: ${errMsg}`, Date.now() - start);
        return {
          content: [{ type: "text", text: `Tool execution failed: ${errMsg}` }],
          isError: true,
        };
      }
    });
  }

  private shouldBlockDescriptor(findings: SecurityFinding[]): boolean {
    const policy = this.config.policies?.security;
    if (!policy || findings.length === 0) return false;
    const hasCritical = findings.some(f => f.severity === "critical");
    const hasHigh = findings.some(f => f.severity === "high");
    return (hasCritical && policy.blockOnCritical) || (hasHigh && policy.blockOnHigh);
  }

  private getDescriptorBaselinePath(): string {
    return resolve(this.config.policies?.security?.descriptorBaselinePath ?? ".mcp-gateway-descriptors.json");
  }

  private async loadDescriptorBaseline(): Promise<DescriptorBaseline> {
    if (this.descriptorBaseline) return this.descriptorBaseline;
    const path = this.getDescriptorBaselinePath();
    try {
      const raw = await readFile(path, "utf-8");
      this.descriptorBaseline = JSON.parse(raw) as DescriptorBaseline;
    } catch {
      this.descriptorBaseline = { version: 1, tools: {} };
      this.descriptorBaselineDirty = true;
    }
    return this.descriptorBaseline;
  }

  private async saveDescriptorBaseline(): Promise<void> {
    if (!this.descriptorBaselineDirty || !this.descriptorBaseline) return;
    const path = this.getDescriptorBaselinePath();
    await mkdir(dirname(path), { recursive: true });
    await writeFile(path, JSON.stringify(this.descriptorBaseline, null, 2) + "\n");
    this.descriptorBaselineDirty = false;
  }

  private async checkDescriptor(prefixedName: string, descriptor: unknown): Promise<SecurityFinding[]> {
    const policy = this.config.policies?.security;
    if (!policy?.scanDescriptions) return [];

    const baseline = await this.loadDescriptorBaseline();
    const hash = createHash("sha256").update(stableStringify(descriptor)).digest("hex");
    const now = new Date().toISOString();
    const existing = baseline.tools[prefixedName];

    if (!existing) {
      baseline.tools[prefixedName] = { hash, firstSeen: now, lastSeen: now };
      this.descriptorBaselineDirty = true;
      return [];
    }

    existing.lastSeen = now;
    this.descriptorBaselineDirty = true;

    if (existing.hash !== hash) {
      const severity = policy.descriptorChangeAction === "block" ? "high" : "medium";
      return [{
        ruleId: "descriptor-changed",
        severity,
        message: `Tool descriptor changed since baseline for ${prefixedName}`,
      }];
    }

    return [];
  }

  private async runMiddlewares(ctx: ToolCallContext): Promise<MiddlewareResult> {
    for (const mw of this.middlewares) {
      const result = await mw(ctx);
      if (result.action !== "allow") return result;
    }
    return { action: "allow" };
  }

  private async audit(
    ctx: ToolCallContext,
    action: AuditEntry["action"],
    reason?: string,
    duration?: number,
    findings?: import("../types/index.js").SecurityFinding[]
  ): Promise<void> {
    if (!this.auditLogger) return;
    await this.auditLogger.log({
      timestamp: new Date().toISOString(),
      server: ctx.server,
      tool: ctx.tool,
      action,
      reason,
      args: ctx.args,
      duration,
      findings,
    });
  }

  async connectUpstreams(): Promise<void> {
    for (const [name, serverConfig] of Object.entries(this.config.servers)) {
      if (!serverConfig.command) continue;

      try {
        const transport = new StdioClientTransport({
          command: serverConfig.command,
          args: serverConfig.args,
          env: serverConfig.env as Record<string, string> | undefined,
        });

        const client = new Client(
          { name: `mcp-gateway-client-${name}`, version: "0.1.0" },
          { capabilities: {} }
        );

        await client.connect(transport);
        this.upstreams.set(name, { client, transport, name });

        transport.onclose = () => {
          process.stderr.write(`[mcp-gateway] Upstream disconnected: ${name}\n`);
          this.upstreams.delete(name);
        };

        process.stderr.write(`[mcp-gateway] Connected to upstream: ${name}\n`);
      } catch (err) {
        process.stderr.write(`[mcp-gateway] Failed to connect to ${name}: ${err}\n`);
      }
    }
  }

  async start(): Promise<void> {
    await this.connectUpstreams();
    const transport = new StdioServerTransport();
    await this.server.connect(transport);
    process.stderr.write(`[mcp-gateway] Gateway running (${this.upstreams.size} upstream servers)\n`);
  }

  getStatus(): { servers: Array<{ name: string; tools: number }>; rateLimits: Array<{ tool: string; count: number; limit: number }> } {
    const servers = Array.from(this.upstreams.entries()).map(([name]) => {
      const toolCount = Array.from(this.toolToServer.values()).filter(s => s === name).length;
      return { name, tools: toolCount };
    });

    const rateLimits: Array<{ tool: string; count: number; limit: number }> = [];
    const limit = this.config.policies?.rateLimit?.maxCallsPerMinute ?? 30;
    const toolCounts = new Map<string, number>();
    for (const [prefixed, server] of this.toolToServer) {
      const tool = prefixed.replace(`${server}__`, "");
      const perTool = this.config.policies?.rateLimit?.perTool?.[tool]?.maxCallsPerMinute ?? limit;
      toolCounts.set(tool, perTool);
    }
    for (const [tool, toolLimit] of toolCounts) {
      rateLimits.push({ tool, count: 0, limit: toolLimit });
    }

    return { servers, rateLimits };
  }

  getAuditLogPath(): string {
    return this.config.audit?.logPath ?? "./mcp-gateway-audit.jsonl";
  }

  async stop(): Promise<void> {
    for (const [name, upstream] of this.upstreams) {
      try {
        await upstream.client.close();
      } catch {}
    }
    await this.auditLogger?.close();
    await this.server.close();
  }
}

function stableStringify(value: unknown): string {
  if (value === null || typeof value !== "object") {
    return JSON.stringify(value);
  }
  if (Array.isArray(value)) {
    return `[${value.map(stableStringify).join(",")}]`;
  }
  const record = value as Record<string, unknown>;
  return `{${Object.keys(record).sort().map(key => `${JSON.stringify(key)}:${stableStringify(record[key])}`).join(",")}}`;
}

function normalizeAnnotations(value: unknown): ToolCallContext["annotations"] {
  if (!value || typeof value !== "object") return undefined;
  const record = value as Record<string, unknown>;
  return {
    readOnlyHint: typeof record.readOnlyHint === "boolean" ? record.readOnlyHint : undefined,
    destructiveHint: typeof record.destructiveHint === "boolean" ? record.destructiveHint : undefined,
    idempotentHint: typeof record.idempotentHint === "boolean" ? record.idempotentHint : undefined,
  };
}
