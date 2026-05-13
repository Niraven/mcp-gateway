import { readFile } from "node:fs/promises";
import { basename } from "node:path";
import type {
  AuditEntry,
  GatewayConfig,
  ReliabilityScore,
  ReliabilityScoreCategory,
  ReportRenderer,
  RunReport,
  RunReportOptions,
  RunRiskFinding,
} from "../types/index.js";
import { redactSecrets, redactSecretText } from "./redaction.js";

interface ParsedAudit {
  entries: AuditEntry[];
  malformedLines: number;
}

const RISKY_TOOL_PATTERN = /delete|drop|remove|write|push|deploy|exec|shell|command|upload|send|email|payment|charge|transfer/i;
const AUDIT_ACTIONS = new Set(["allowed", "blocked", "pending-approval", "approved", "denied", "rate-limited"]);

export async function createRunReport(options: RunReportOptions): Promise<RunReport> {
  const publicMode = options.publicMode ?? false;
  const parsedAudit = await readAuditLog(options.auditPath, options.publicMode ?? false);
  const config = options.configPath ? await readJsonFile<GatewayConfig>(options.configPath) : undefined;
  const baseline = options.baselinePath ? await readOptionalJsonFile(options.baselinePath) : undefined;
  const diff = options.diffPath ? await readFile(options.diffPath, "utf-8").catch(() => "") : "";
  const metadata = options.metadataPath
    ? await readOptionalJsonFile<Record<string, unknown>>(options.metadataPath)
    : undefined;

  const summary = summarize(parsedAudit.entries, parsedAudit.malformedLines, diff);
  const risks = buildRisks(parsedAudit, config, baseline, publicMode);
  const reliability = scoreReliability(parsedAudit.entries, config, risks, metadata);

  return {
    generatedAt: new Date().toISOString(),
    input: {
      auditPath: formatRequiredInputPath(options.auditPath, publicMode),
      configPath: formatInputPath(options.configPath, publicMode),
      baselinePath: formatInputPath(options.baselinePath, publicMode),
      diffPath: formatInputPath(options.diffPath, publicMode),
      metadataPath: formatInputPath(options.metadataPath, publicMode),
      publicMode,
    },
    summary,
    risks,
    reliability,
    metadata: formatMetadata(metadata, publicMode),
  };
}

export const markdownReportRenderer: ReportRenderer = {
  renderMarkdown,
  renderJson(report: RunReport): string {
    return JSON.stringify(redactSecrets(report), null, 2) + "\n";
  },
};

async function readAuditLog(path: string, publicMode: boolean): Promise<ParsedAudit> {
  const raw = await readFile(path, "utf-8").catch((err) => {
    throw new Error(`Could not read audit log at ${path}: ${err instanceof Error ? err.message : String(err)}`);
  });
  const entries: AuditEntry[] = [];
  let malformedLines = 0;

  for (const line of raw.split(/\r?\n/)) {
    if (!line.trim()) continue;
    try {
      const parsed = JSON.parse(line) as AuditEntry;
      if (!isAuditEntry(parsed)) {
        malformedLines += 1;
        continue;
      }
      entries.push(publicMode ? redactSecrets(parsed) as AuditEntry : parsed);
    } catch {
      malformedLines += 1;
    }
  }

  return { entries, malformedLines };
}

async function readJsonFile<T>(path: string): Promise<T> {
  const raw = await readFile(path, "utf-8").catch((err) => {
    throw new Error(`Could not read JSON file at ${path}: ${err instanceof Error ? err.message : String(err)}`);
  });
  return JSON.parse(raw) as T;
}

async function readOptionalJsonFile<T = unknown>(path: string): Promise<T | undefined> {
  try {
    return await readJsonFile<T>(path);
  } catch {
    return undefined;
  }
}

function summarize(entries: AuditEntry[], malformedLines: number, diff: string): RunReport["summary"] {
  const actions: Record<string, number> = {};
  const servers: Record<string, number> = {};
  const tools: Record<string, number> = {};
  let riskyToolCalls = 0;

  for (const entry of entries) {
    actions[entry.action] = (actions[entry.action] ?? 0) + 1;
    servers[entry.server] = (servers[entry.server] ?? 0) + 1;
    tools[entry.tool] = (tools[entry.tool] ?? 0) + 1;
    if (RISKY_TOOL_PATTERN.test(entry.tool)) riskyToolCalls += 1;
  }

  return {
    totalCalls: entries.length,
    malformedAuditLines: malformedLines,
    firstTimestamp: entries[0]?.timestamp,
    lastTimestamp: entries.at(-1)?.timestamp,
    actions,
    servers,
    tools,
    riskyToolCalls,
    changedFiles: countChangedFiles(diff),
  };
}

function buildRisks(parsedAudit: ParsedAudit, config?: GatewayConfig, baseline?: unknown, publicMode = false): RunRiskFinding[] {
  const risks: RunRiskFinding[] = [];

  if (parsedAudit.entries.length === 0) {
    risks.push({
      ruleId: "audit-empty",
      severity: "high",
      message: "Audit log has no usable entries.",
      evidence: "Run visibility is missing or audit logging did not flush.",
    });
  }

  if (parsedAudit.malformedLines > 0) {
    risks.push({
      ruleId: "audit-malformed-lines",
      severity: "medium",
      message: `${parsedAudit.malformedLines} audit log line(s) could not be parsed.`,
      evidence: "Malformed audit lines reduce forensic confidence.",
    });
  }

  for (const entry of parsedAudit.entries) {
    if (entry.action === "blocked" || entry.action === "pending-approval" || entry.action === "rate-limited") {
      risks.push({
        ruleId: `tool-${entry.action}`,
        severity: entry.action === "blocked" ? "high" : "medium",
        message: `${entry.server}.${entry.tool} was ${entry.action}.`,
        evidence: entry.reason,
      });
    }

    if (entry.reason?.startsWith("error:")) {
      risks.push({
        ruleId: "tool-execution-error",
        severity: "medium",
        message: `${entry.server}.${entry.tool} failed during execution.`,
        evidence: entry.reason,
      });
    }

    if (RISKY_TOOL_PATTERN.test(entry.tool) && entry.action === "allowed") {
      risks.push({
        ruleId: "risky-tool-allowed",
        severity: "medium",
        message: `Risky-looking tool was allowed: ${entry.server}.${entry.tool}.`,
        evidence: "Tool name matches destructive or externally visible action patterns.",
      });
    }

    for (const finding of entry.findings ?? []) {
      risks.push({
        ruleId: finding.ruleId,
        severity: finding.severity,
        message: finding.message,
        evidence: `${entry.server}.${entry.tool}`,
      });
    }
  }

  if (!config?.audit?.enabled) {
    risks.push({
      ruleId: "audit-disabled",
      severity: "high",
      message: "Gateway audit logging is disabled or config was not provided.",
      evidence: "Run reports depend on audit telemetry.",
    });
  }

  if (config?.audit?.includeArgs) {
    risks.push({
      ruleId: "audit-args-enabled",
      severity: "low",
      message: "Audit logging includes tool arguments.",
      evidence: "Use --public reports or disable includeArgs for sensitive environments.",
    });
  }

  if (!config?.policies?.security?.scanInputs) {
    risks.push({
      ruleId: "input-scan-disabled",
      severity: "medium",
      message: "Tool input scanning is disabled or config was not provided.",
    });
  }

  if (!config?.policies?.security?.scanDescriptions) {
    risks.push({
      ruleId: "descriptor-scan-disabled",
      severity: "medium",
      message: "Tool descriptor scanning is disabled or config was not provided.",
    });
  }

  if (!config?.policies?.approval) {
    risks.push({
      ruleId: "approval-gate-missing",
      severity: "medium",
      message: "No approval policy was found.",
      evidence: "Destructive tools may execute without a human checkpoint.",
    });
  }

  if (!baseline && config?.policies?.security?.descriptorBaselinePath) {
    risks.push({
      ruleId: "descriptor-baseline-missing",
      severity: "medium",
      message: "Descriptor baseline could not be read.",
      evidence: formatInputPath(config.policies.security.descriptorBaselinePath, publicMode),
    });
  }

  return dedupeRisks(risks);
}

function scoreReliability(
  entries: AuditEntry[],
  config: GatewayConfig | undefined,
  risks: RunRiskFinding[],
  metadata?: Record<string, unknown>
): ReliabilityScore {
  const categories: ReliabilityScoreCategory[] = [
    scoreCategory("Goal clarity", metadata?.goal ? 2 : null, metadata?.goal ? "Run metadata includes a goal." : "No run goal metadata was provided."),
    scoreCategory("Tool permissions", scoreToolPermissions(config), config ? "Gateway config was available for policy inspection." : "No config was provided."),
    scoreCategory("Memory source", null, "MCP audit logs do not expose memory-source quality."),
    scoreCategory("Output contract", metadata?.outputContract ? 2 : null, metadata?.outputContract ? "Run metadata includes an output contract." : "No output contract metadata was provided."),
    scoreCategory("Eval/rubric", metadata?.evalRubric ? 2 : null, metadata?.evalRubric ? "Run metadata includes an eval/rubric." : "No eval/rubric metadata was provided."),
    scoreCategory("Observability", scoreObservability(entries, config), "Scored from audit entries and audit config."),
    scoreCategory("Recovery path", scoreRecovery(risks), "Scored from approval, block, and rate-limit evidence."),
    scoreCategory("Human handoff", config?.policies?.approval ? 2 : 0, config?.policies?.approval ? "Approval policy exists." : "No approval policy was found."),
    scoreCategory("Cost budget", config?.policies?.rateLimit ? 2 : 0, config?.policies?.rateLimit ? "Rate limits are configured." : "No rate-limit policy was found."),
    scoreCategory("Privacy boundary", config?.audit?.includeArgs ? 1 : config?.audit?.enabled ? 2 : 0, config?.audit?.includeArgs ? "Arguments are logged; public reports redact them." : "Audit logging avoids tool arguments or audit is disabled."),
  ];

  const known = categories.filter(category => category.score !== null);
  const knownTotal = known.reduce((sum, category) => sum + (category.score ?? 0), 0);
  return {
    total: categories.reduce((sum, category) => sum + (category.score ?? 0), 0),
    maxTotal: 20,
    knownTotal,
    knownMax: known.length * 2,
    categories,
  };
}

function scoreCategory(name: string, score: 0 | 1 | 2 | null, evidence: string): ReliabilityScoreCategory {
  return {
    name,
    score,
    status: score === null ? "unknown" : "scored",
    evidence,
  };
}

function scoreToolPermissions(config?: GatewayConfig): 0 | 1 | 2 {
  if (!config?.policies) return 0;
  const hasSecurity = !!config.policies.security?.scanInputs && !!config.policies.security?.scanDescriptions;
  const hasApproval = !!config.policies.approval;
  const hasRateLimit = !!config.policies.rateLimit;
  return hasSecurity && hasApproval && hasRateLimit ? 2 : 1;
}

function scoreObservability(entries: AuditEntry[], config?: GatewayConfig): 0 | 1 | 2 {
  if (!config?.audit?.enabled) return 0;
  return entries.length > 0 ? 2 : 1;
}

function scoreRecovery(risks: RunRiskFinding[]): 0 | 1 | 2 {
  const hasHumanGate = risks.some(risk => risk.ruleId === "tool-pending-approval");
  const hasAutomatedStop = risks.some(risk => risk.ruleId === "tool-blocked" || risk.ruleId === "tool-rate-limited");
  if (hasHumanGate && hasAutomatedStop) return 2;
  if (hasHumanGate || hasAutomatedStop) return 1;
  return 0;
}

function renderMarkdown(report: RunReport): string {
  const riskLines = report.risks.length === 0
    ? ["- No risks detected from available evidence."]
    : report.risks.map(risk => `- **${risk.severity.toUpperCase()} ${formatInline(risk.ruleId)}:** ${formatInline(risk.message)}${risk.evidence ? ` Evidence: ${formatInline(risk.evidence)}` : ""}`);

  const actionRows = Object.entries(report.summary.actions).map(([action, count]) => `| ${formatTableCell(action)} | ${count} |`);
  const toolRows = Object.entries(report.summary.tools)
    .sort((a, b) => b[1] - a[1])
    .slice(0, 10)
    .map(([tool, count]) => `| ${formatTableCell(tool)} | ${count} |`);

  const scoreRows = report.reliability.categories.map(category =>
    `| ${formatTableCell(category.name)} | ${category.score === null ? "unknown" : category.score} | ${category.status} | ${formatTableCell(category.evidence)} |`
  );

  return [
    "# MCP Gateway Run Report",
    "",
    `Generated: ${report.generatedAt}`,
    `Public mode: ${report.input.publicMode ? "yes" : "no"}`,
    "",
    "## Summary",
    "",
    `- Total tool calls: ${report.summary.totalCalls}`,
    `- Malformed audit lines: ${report.summary.malformedAuditLines}`,
    `- First event: ${report.summary.firstTimestamp ?? "unknown"}`,
    `- Last event: ${report.summary.lastTimestamp ?? "unknown"}`,
    `- Risky-looking tool calls: ${report.summary.riskyToolCalls}`,
    `- Changed files from diff: ${report.summary.changedFiles}`,
    "",
    "## Actions",
    "",
    "| Action | Count |",
    "|---|---:|",
    ...(actionRows.length > 0 ? actionRows : ["| none | 0 |"]),
    "",
    "## Top Tools",
    "",
    "| Tool | Calls |",
    "|---|---:|",
    ...(toolRows.length > 0 ? toolRows : ["| none | 0 |"]),
    "",
    "## Risks",
    "",
    ...riskLines,
    "",
    "## Reliability Score",
    "",
    `Conservative score: **${report.reliability.total}/${report.reliability.maxTotal}**`,
    `Known-evidence score: **${report.reliability.knownTotal}/${report.reliability.knownMax}**`,
    "",
    "| Category | Score | Status | Evidence |",
    "|---|---:|---|---|",
    ...scoreRows,
    "",
    "## Inputs",
    "",
    `- Audit: ${formatInline(report.input.auditPath)}`,
    `- Config: ${formatInline(report.input.configPath ?? "not provided")}`,
    `- Descriptor baseline: ${formatInline(report.input.baselinePath ?? "not provided")}`,
    `- Diff: ${formatInline(report.input.diffPath ?? "not provided")}`,
    `- Metadata: ${formatInline(report.input.metadataPath ?? "not provided")}`,
    "",
  ].join("\n");
}

function countChangedFiles(diff: string): number {
  if (!diff.trim()) return 0;
  const matches = diff.match(/^diff --git /gm);
  if (matches) return matches.length;
  const files = new Set<string>();
  for (const line of diff.split(/\r?\n/)) {
    const match = /^\+\+\+ b\/(.+)$/.exec(line);
    if (match) files.add(match[1]);
  }
  return files.size;
}

function dedupeRisks(risks: RunRiskFinding[]): RunRiskFinding[] {
  const seen = new Set<string>();
  const deduped: RunRiskFinding[] = [];
  for (const risk of risks) {
    const key = `${risk.ruleId}:${risk.message}:${risk.evidence ?? ""}`;
    if (seen.has(key)) continue;
    seen.add(key);
    deduped.push(risk);
  }
  return deduped;
}

function formatInputPath(path: string | undefined, publicMode: boolean): string | undefined {
  if (!path) return undefined;
  return publicMode ? basename(path) : path;
}

function formatRequiredInputPath(path: string, publicMode: boolean): string {
  return publicMode ? basename(path) : path;
}

function formatMetadata(metadata: Record<string, unknown> | undefined, publicMode: boolean): Record<string, unknown> | undefined {
  if (!metadata) return undefined;
  const redacted = redactSecrets(metadata) as Record<string, unknown>;
  if (!publicMode) return redacted;

  const publicMetadata: Record<string, unknown> = {};
  for (const key of ["goal", "outputContract", "evalRubric"]) {
    if (typeof redacted[key] === "string") {
      publicMetadata[key] = formatInline(redacted[key]);
    }
  }
  return Object.keys(publicMetadata).length > 0 ? publicMetadata : undefined;
}

function isAuditEntry(value: unknown): value is AuditEntry {
  if (!value || typeof value !== "object") return false;
  const record = value as Record<string, unknown>;
  return typeof record.timestamp === "string" &&
    typeof record.server === "string" &&
    typeof record.tool === "string" &&
    typeof record.action === "string" &&
    AUDIT_ACTIONS.has(record.action);
}

function formatInline(value: string): string {
  return redactSecretText(value).replace(/\s+/g, " ").trim();
}

function formatTableCell(value: string): string {
  return formatInline(value).replace(/\|/g, "\\|");
}
