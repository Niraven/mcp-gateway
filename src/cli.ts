#!/usr/bin/env node
import { readFile, writeFile } from "node:fs/promises";
import { resolve } from "node:path";
import { Command } from "commander";
import { McpGateway } from "./proxy/gateway.js";
import { startDashboard } from "./dashboard/server.js";
import { createRunReport, markdownReportRenderer } from "./reporting/report.js";
import type { GatewayConfig } from "./types/index.js";

const program = new Command();

program
  .name("mcp-gateway")
  .description("Security-first gateway proxy for MCP servers")
  .version("0.1.0");

program
  .command("start")
  .description("Start the gateway proxy")
  .option("-c, --config <path>", "Path to gateway config file", "mcp-gateway.json")
  .option("-v, --verbose", "Enable verbose debug logging")
  .action(async (opts) => {
    try {
      const configPath = resolve(opts.config);
      const raw = await readFile(configPath, "utf-8");
      let config: GatewayConfig;
      try {
        config = JSON.parse(raw);
      } catch {
        process.stderr.write(`Error: Invalid JSON in ${configPath}\n`);
        process.exit(1);
      }

      if (!config.servers || Object.keys(config.servers).length === 0) {
        process.stderr.write(`Error: No servers defined in config\n`);
        process.exit(1);
      }

      for (const [name, srv] of Object.entries(config.servers)) {
        if (!srv.command && !srv.url) {
          process.stderr.write(`Error: Server "${name}" needs either command or url\n`);
          process.exit(1);
        }
      }

      if (opts.verbose) {
        process.stderr.write(`[mcp-gateway] Config: ${Object.keys(config.servers).length} servers\n`);
        process.stderr.write(`[mcp-gateway] Policies: rate=${!!config.policies?.rateLimit} security=${!!config.policies?.security} approval=${!!config.policies?.approval}\n`);
        process.stderr.write(`[mcp-gateway] Audit: ${config.audit?.enabled ? config.audit.logPath : "disabled"}\n`);
      }

      const gateway = new McpGateway(config);

      process.on("SIGINT", async () => {
        process.stderr.write("\n[mcp-gateway] Shutting down...\n");
        await gateway.stop();
        process.exit(0);
      });

      process.on("SIGTERM", async () => {
        await gateway.stop();
        process.exit(0);
      });

      await gateway.start();
    } catch (error) {
      const msg = error instanceof Error ? error.message : String(error);
      process.stderr.write(`Error: ${msg}\n`);
      process.exit(1);
    }
  });

program
  .command("init")
  .description("Generate a sample gateway configuration")
  .action(() => {
    const sample: GatewayConfig = {
      servers: {
        filesystem: {
          command: "npx",
          args: ["-y", "@modelcontextprotocol/server-filesystem", "./project"],
        },
        github: {
          command: "npx",
          args: ["-y", "@modelcontextprotocol/server-github"],
          env: { GITHUB_PERSONAL_ACCESS_TOKEN: "${GITHUB_TOKEN}" },
        },
      },
      policies: {
        rateLimit: {
          maxCallsPerMinute: 30,
          maxCallsPerHour: 500,
          perTool: {
            write_file: { maxCallsPerMinute: 5 },
            delete_file: { maxCallsPerMinute: 2 },
          },
        },
        approval: {
          requireApprovalFor: [
            { type: "destructive" },
            { type: "pattern", match: "delete|drop|remove|push" },
          ],
          approvalTimeout: 30000,
          defaultAction: "deny",
        },
        security: {
          blockOnCritical: true,
          blockOnHigh: false,
          scanDescriptions: true,
          scanInputs: true,
          descriptorBaselinePath: "./.mcp-gateway-descriptors.json",
          descriptorChangeAction: "warn",
        },
      },
      audit: {
        enabled: true,
        logPath: "./mcp-audit.jsonl",
        includeArgs: true,
        includeResults: false,
      },
    };

    process.stdout.write(JSON.stringify(sample, null, 2) + "\n");
  });

program
  .command("validate")
  .description("Validate a gateway configuration file")
  .argument("<config-path>", "Path to gateway config")
  .action(async (configPath: string) => {
    try {
      const raw = await readFile(resolve(configPath), "utf-8");
      const config: GatewayConfig = JSON.parse(raw);

      const serverCount = Object.keys(config.servers).length;
      const hasRateLimit = !!config.policies?.rateLimit;
      const hasApproval = !!config.policies?.approval;
      const hasSecurity = !!config.policies?.security;
      const hasAudit = !!config.audit?.enabled;

      console.log(`\n  Configuration Valid\n`);
      console.log(`  Servers:       ${serverCount}`);
      console.log(`  Rate Limiting: ${hasRateLimit ? "enabled" : "disabled"}`);
      console.log(`  Approval Gate: ${hasApproval ? "enabled" : "disabled"}`);
      console.log(`  Security Scan: ${hasSecurity ? "enabled" : "disabled"}`);
      console.log(`  Audit Log:     ${hasAudit ? "enabled" : "disabled"}`);
      console.log();
    } catch (error) {
      const msg = error instanceof Error ? error.message : String(error);
      process.stderr.write(`Invalid config: ${msg}\n`);
      process.exit(1);
    }
  });

program
  .command("report")
  .description("Generate a local run report from MCP Gateway audit logs")
  .requiredOption("--audit <path>", "Path to MCP Gateway audit JSONL")
  .option("-c, --config <path>", "Path to gateway config file")
  .option("--baseline <path>", "Path to descriptor baseline JSON")
  .option("--diff <path>", "Path to a git diff/patch file for the run")
  .option("--metadata <path>", "Path to run metadata JSON")
  .option("--out <path>", "Write Markdown report to this path instead of stdout")
  .option("--json <path>", "Write JSON report summary to this path")
  .option("--public", "Redact secrets and generate a share-safe report")
  .action(async (opts) => {
    try {
      const report = await createRunReport({
        auditPath: resolve(opts.audit),
        configPath: opts.config ? resolve(opts.config) : undefined,
        baselinePath: opts.baseline ? resolve(opts.baseline) : undefined,
        diffPath: opts.diff ? resolve(opts.diff) : undefined,
        metadataPath: opts.metadata ? resolve(opts.metadata) : undefined,
        publicMode: !!opts.public,
      });

      const markdown = markdownReportRenderer.renderMarkdown(report);
      if (opts.out) {
        await writeFile(resolve(opts.out), markdown);
      } else {
        process.stdout.write(markdown);
      }

      if (opts.json) {
        await writeFile(resolve(opts.json), markdownReportRenderer.renderJson(report));
      }
    } catch (error) {
      const msg = error instanceof Error ? error.message : String(error);
      process.stderr.write(`Error: ${msg}\n`);
      process.exit(1);
    }
  });

program
  .command("dashboard")
  .description("Start the monitoring dashboard")
  .option("-c, --config <path>", "Path to gateway config file", "mcp-gateway.json")
  .option("-p, --port <port>", "Dashboard port", "3100")
  .action(async (opts) => {
    try {
      const configPath = resolve(opts.config);
      const raw = await readFile(configPath, "utf-8");
      const config: GatewayConfig = JSON.parse(raw);

      const auditLogPath = resolve(config.audit?.logPath ?? "./mcp-gateway-audit.jsonl");
      const serverNames = Object.keys(config.servers);
      const limit = config.policies?.rateLimit?.maxCallsPerMinute ?? 30;

      await startDashboard({
        port: parseInt(opts.port, 10),
        auditLogPath,
        getStatus: () => ({
          servers: serverNames.map(name => ({ name, tools: 0 })),
          rateLimits: Object.entries(config.policies?.rateLimit?.perTool ?? {}).map(
            ([tool, conf]) => ({ tool, count: 0, limit: (conf as {maxCallsPerMinute: number}).maxCallsPerMinute ?? limit })
          ),
        }),
      });

      await new Promise(() => {});
    } catch (error) {
      const msg = error instanceof Error ? error.message : String(error);
      process.stderr.write(`Error: ${msg}\n`);
      process.exit(1);
    }
  });

program.parse();
