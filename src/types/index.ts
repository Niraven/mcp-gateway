export interface GatewayConfig {
  servers: Record<string, UpstreamServerConfig>;
  policies?: PolicyConfig;
  audit?: AuditConfig;
  port?: number;
}

export interface UpstreamServerConfig {
  command: string;
  args?: string[];
  env?: Record<string, string>;
  url?: string;
  policies?: ServerPolicyOverrides;
}

export interface PolicyConfig {
  rateLimit?: RateLimitPolicy;
  approval?: ApprovalPolicy;
  security?: SecurityPolicy;
}

export interface RateLimitPolicy {
  maxCallsPerMinute: number;
  maxCallsPerHour?: number;
  maxGlobalCallsPerMinute?: number;
  perTool?: Record<string, { maxCallsPerMinute: number }>;
}

export interface ApprovalPolicy {
  requireApprovalFor: ApprovalTrigger[];
  approvalTimeout: number;
  defaultAction: "deny" | "allow";
}

export type ApprovalTrigger =
  | { type: "destructive" }
  | { type: "tool"; names: string[] }
  | { type: "pattern"; match: string };

export interface SecurityPolicy {
  blockOnCritical: boolean;
  blockOnHigh: boolean;
  scanDescriptions: boolean;
  scanInputs: boolean;
  descriptorBaselinePath?: string;
  descriptorChangeAction?: "warn" | "block";
}

export interface AuditConfig {
  enabled: boolean;
  logPath?: string;
  includeArgs?: boolean;
  includeResults?: boolean;
}

export interface ServerPolicyOverrides {
  rateLimit?: Partial<RateLimitPolicy>;
  approval?: Partial<ApprovalPolicy>;
  trusted?: boolean;
}

export interface AuditEntry {
  timestamp: string;
  server: string;
  tool: string;
  action: "allowed" | "blocked" | "pending-approval" | "approved" | "denied" | "rate-limited";
  reason?: string;
  args?: unknown;
  result?: unknown;
  duration?: number;
  findings?: SecurityFinding[];
}

export interface SecurityFinding {
  ruleId: string;
  severity: "critical" | "high" | "medium" | "low";
  message: string;
}

export interface ToolCallContext {
  server: string;
  tool: string;
  args: unknown;
  findings?: SecurityFinding[];
  annotations?: {
    readOnlyHint?: boolean;
    destructiveHint?: boolean;
    idempotentHint?: boolean;
  };
}

export interface MiddlewareResult {
  action: "allow" | "block" | "require-approval";
  reason?: string;
  findings?: SecurityFinding[];
}

export type Middleware = (ctx: ToolCallContext) => MiddlewareResult | Promise<MiddlewareResult>;
