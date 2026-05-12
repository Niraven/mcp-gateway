export { McpGateway } from "./proxy/gateway.js";
export { startDashboard } from "./dashboard/server.js";
export { createRateLimiter } from "./middleware/rate-limiter.js";
export { createSecurityScanner, scanToolDescription } from "./middleware/security-scanner.js";
export { createApprovalGate } from "./middleware/approval.js";
export { AuditLogger } from "./middleware/audit-logger.js";
export type {
  GatewayConfig,
  UpstreamServerConfig,
  PolicyConfig,
  RateLimitPolicy,
  ApprovalPolicy,
  SecurityPolicy,
  AuditConfig,
  AuditEntry,
  ToolCallContext,
  Middleware,
  MiddlewareResult,
  SecurityFinding,
} from "./types/index.js";
