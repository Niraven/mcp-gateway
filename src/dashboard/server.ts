import { createServer } from "node:http";
import { readFile } from "node:fs/promises";
import { resolve, dirname } from "node:path";
import { fileURLToPath } from "node:url";

const __dirname = dirname(fileURLToPath(import.meta.url));

interface DashboardOptions {
  port: number;
  auditLogPath: string;
  getStatus: () => {
    servers: Array<{ name: string; tools: number }>;
    rateLimits: Array<{ tool: string; count: number; limit: number }>;
  };
}

export async function startDashboard(opts: DashboardOptions): Promise<void> {
  const htmlPath = resolve(__dirname, "index.html");
  let htmlContent: string;

  try {
    htmlContent = await readFile(htmlPath, "utf-8");
  } catch {
    const srcHtmlPath = resolve(__dirname, "../../src/dashboard/index.html");
    htmlContent = await readFile(srcHtmlPath, "utf-8");
  }

  const server = createServer(async (req, res) => {
    const url = new URL(req.url ?? "/", `http://localhost:${opts.port}`);

    if (url.pathname === "/api/status") {
      res.setHeader("Content-Type", "application/json");
      res.setHeader("Access-Control-Allow-Origin", "*");

      try {
        const logContent = await readFile(opts.auditLogPath, "utf-8").catch(() => "");
        const entries = logContent
          .trim()
          .split("\n")
          .filter(Boolean)
          .map(line => {
            try { return JSON.parse(line); }
            catch { return null; }
          })
          .filter(Boolean);

        const status = opts.getStatus();
        res.end(JSON.stringify({
          entries,
          servers: status.servers,
          rateLimits: status.rateLimits,
        }));
      } catch (err) {
        res.statusCode = 500;
        res.end(JSON.stringify({ error: "Failed to read audit log" }));
      }
      return;
    }

    res.setHeader("Content-Type", "text/html");
    res.end(htmlContent);
  });

  server.listen(opts.port, () => {
    process.stderr.write(`[mcp-gateway] Dashboard: http://localhost:${opts.port}\n`);
  });
}
