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

export class McpGateway {
  private server: Server;
  private upstreams: Map<string, UpstreamConnection> = new Map();
  private middlewares: Middleware[] = [];
  private auditLogger: AuditLogger | null = null;
  private config: GatewayConfig;
  private toolToServer: Map<string, string> = new Map();

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

      for (const [serverName, upstream] of this.upstreams) {
        try {
          const response = await upstream.client.listTools();
          for (const tool of response.tools) {
            const prefixedName = `${serverName}__${tool.name}`;
            this.toolToServer.set(prefixedName, serverName);

            const descFindings = scanToolDescription(tool.description ?? "");
            let description = tool.description ?? "";
            if (descFindings.length > 0) {
              description = `[GATEWAY WARNING: ${descFindings.length} security findings] ${description}`;
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
