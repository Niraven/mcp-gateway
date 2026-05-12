import type { Middleware, ToolCallContext, MiddlewareResult, SecurityPolicy, SecurityFinding } from "../types/index.js";

const POISONING_PATTERNS = [
  { pattern: /\bIMPORTANT\b.*?\b(ignore|override|bypass|forget|disregard)\b/i, id: "poison-override" },
  { pattern: /\b(do not|don't|never)\s+(tell|inform|reveal|show|display|mention)\s+(the\s+)?(user|human)/i, id: "poison-conceal" },
  { pattern: /\b(instead|actually|secretly|silently|quietly)\s+(send|transmit|exfiltrate|upload|post|forward)/i, id: "poison-exfil" },
  { pattern: /\bignore\s+(all\s+)?(previous|prior|above|earlier)\s+(instructions?|context|rules?)/i, id: "poison-hijack" },
  { pattern: /\byou\s+(are|must|should|will)\s+(now|actually|really)/i, id: "poison-role" },
  { pattern: /<!--[\s\S]*?-->/g, id: "poison-hidden-html" },
  { pattern: /\u200b|\u200c|\u200d|\ufeff|\u00ad/g, id: "poison-invisible" },
];

const INJECTION_PATTERNS = [
  { pattern: /[;&|`$]/, id: "input-shell-chars", severity: "high" as const },
  { pattern: /\.\.[\/\\]/, id: "input-path-traversal", severity: "high" as const },
  { pattern: /<script/i, id: "input-xss", severity: "medium" as const },
];

export function createSecurityScanner(policy: SecurityPolicy): Middleware {
  return (ctx: ToolCallContext): MiddlewareResult => {
    const findings: SecurityFinding[] = [];

    if (policy.scanInputs && ctx.args) {
      const inputStr = JSON.stringify(ctx.args);
      for (const { pattern, id, severity } of INJECTION_PATTERNS) {
        if (pattern.test(inputStr)) {
          findings.push({
            ruleId: id,
            severity,
            message: `Suspicious characters in tool input for ${ctx.tool}`,
          });
        }
      }
    }

    const hasCritical = findings.some(f => f.severity === "critical");
    const hasHigh = findings.some(f => f.severity === "high");

    if (hasCritical && policy.blockOnCritical) {
      return { action: "block", reason: "Critical security finding in tool call", findings };
    }

    if (hasHigh && policy.blockOnHigh) {
      return { action: "block", reason: "High severity security finding in tool call", findings };
    }

    return { action: "allow", findings: findings.length > 0 ? findings : undefined };
  };
}

export function scanToolDescription(description: string): SecurityFinding[] {
  const findings: SecurityFinding[] = [];

  for (const { pattern, id } of POISONING_PATTERNS) {
    if (pattern.test(description)) {
      findings.push({
        ruleId: id,
        severity: "critical",
        message: `Tool description contains suspicious pattern: ${id}`,
      });
    }
  }

  return findings;
}
