import { strict as assert } from "node:assert";
import { mkdir, readFile, rm, writeFile } from "node:fs/promises";
import { resolve } from "node:path";
import { createRunReport, markdownReportRenderer, redactSecrets, redactSecretText } from "../src/index.js";

const TMP_DIR = resolve("test/.tmp/report");
const AUDIT_PATH = resolve(TMP_DIR, "audit.jsonl");
const CONFIG_PATH = resolve(TMP_DIR, "config.json");
const BASELINE_PATH = resolve(TMP_DIR, "baseline.json");
const DIFF_PATH = resolve(TMP_DIR, "run.diff");
const METADATA_PATH = resolve(TMP_DIR, "metadata.json");

async function setup() {
  await rm(TMP_DIR, { recursive: true, force: true });
  await mkdir(TMP_DIR, { recursive: true });

  await writeFile(AUDIT_PATH, [
    JSON.stringify({
      timestamp: "2026-05-13T00:00:00.000Z",
      server: "filesystem",
      tool: "write_file",
      action: "allowed",
      args: { apiKey: "sk-abcdefghijklmnopqrstuvwxyz123456" },
      duration: 12,
    }),
    "{not valid json}",
    JSON.stringify({ event: "not an audit entry" }),
    JSON.stringify({
      timestamp: "2026-05-13T00:00:00.500Z",
      server: "filesystem",
      tool: "read_file",
      action: "surprised",
    }),
    JSON.stringify({
      timestamp: "2026-05-13T00:00:01.000Z",
      server: "database",
      tool: "drop_table",
      action: "blocked",
      reason: "High severity security finding in tool call",
      findings: [{ ruleId: "input-shell-chars", severity: "high", message: "Suspicious characters in input" }],
    }),
    JSON.stringify({
      timestamp: "2026-05-13T00:00:02.000Z",
      server: "filesystem",
      tool: "delete_file|with\nnewline",
      action: "pending-approval",
      reason: "Destructive tool requires approval\nwith multiline note",
    }),
  ].join("\n") + "\n");

  await writeFile(CONFIG_PATH, JSON.stringify({
    servers: {
      filesystem: { command: "node", args: ["server.js"] },
    },
    policies: {
      rateLimit: { maxCallsPerMinute: 10 },
      approval: {
        requireApprovalFor: [{ type: "destructive" }],
        approvalTimeout: 30000,
        defaultAction: "deny",
      },
      security: {
        blockOnCritical: true,
        blockOnHigh: true,
        scanDescriptions: true,
        scanInputs: true,
        descriptorBaselinePath: BASELINE_PATH,
        descriptorChangeAction: "block",
      },
    },
    audit: {
      enabled: true,
      logPath: AUDIT_PATH,
      includeArgs: true,
    },
  }, null, 2));

  await writeFile(BASELINE_PATH, JSON.stringify({ version: 1, tools: {} }, null, 2));
  await writeFile(DIFF_PATH, "diff --git a/src/a.ts b/src/a.ts\n+++ b/src/a.ts\n");
  await writeFile(METADATA_PATH, JSON.stringify({
    goal: "Check risky MCP behavior.",
    outputContract: "Markdown and JSON report.",
    evalRubric: "Risk findings are present and redacted.",
    privateNote: "/Users/niamamor/private/context.md",
  }, null, 2));
}

async function run() {
  await setup();
  const report = await createRunReport({
    auditPath: AUDIT_PATH,
    configPath: CONFIG_PATH,
    baselinePath: BASELINE_PATH,
    diffPath: DIFF_PATH,
    metadataPath: METADATA_PATH,
    publicMode: true,
  });

  assert.equal(report.summary.totalCalls, 3);
  assert.equal(report.summary.malformedAuditLines, 3);
  assert.equal(report.summary.changedFiles, 1);
  assert.equal(report.summary.actions.allowed, 1);
  assert.equal(report.summary.actions.blocked, 1);
  assert.equal(report.summary.actions["pending-approval"], 1);
  assert.ok(report.risks.some(risk => risk.ruleId === "input-shell-chars"));
  assert.ok(report.risks.some(risk => risk.ruleId === "tool-blocked"));
  assert.ok(report.risks.some(risk => risk.ruleId === "tool-pending-approval"));
  assert.equal(report.reliability.total, 17);
  assert.equal(report.reliability.knownMax, 18);

  const markdown = markdownReportRenderer.renderMarkdown(report);
  assert.match(markdown, /MCP Gateway Run Report/);
  assert.match(markdown, /Reliability Score/);
  assert.match(markdown, /input-shell-chars/);
  assert.match(markdown, /delete_file\\\|with newline/);
  assert.doesNotMatch(markdown, /sk-abcdefghijklmnopqrstuvwxyz123456/);
  assert.doesNotMatch(markdown, /\nwith multiline note/);

  const json = markdownReportRenderer.renderJson(report);
  assert.doesNotMatch(json, /sk-abcdefghijklmnopqrstuvwxyz123456/);
  assert.doesNotMatch(json, /\/Users\//);
  assert.equal(report.input.auditPath, "audit.jsonl");
  assert.equal(report.metadata?.privateNote, undefined);

  assert.deepEqual(redactSecrets({ token: "abc", nested: { ok: "value" } }), {
    token: "[REDACTED]",
    nested: { ok: "value" },
  });
  assert.deepEqual(redactSecrets({ "tool_sk-abcdefghijklmnopqrstuvwxyz123456": "value" }), {
    "tool_[REDACTED]": "value",
  });
  assert.equal(redactSecretText("key sk-abcdefghijklmnopqrstuvwxyz123456"), "key [REDACTED]");

  await readFile(AUDIT_PATH, "utf-8");
  console.log("report tests passed");
}

run().catch(err => {
  console.error(err);
  process.exit(1);
});
