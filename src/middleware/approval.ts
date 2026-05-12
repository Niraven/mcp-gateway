import type { Middleware, ToolCallContext, MiddlewareResult, ApprovalPolicy } from "../types/index.js";

export function createApprovalGate(policy: ApprovalPolicy): Middleware {
  return (ctx: ToolCallContext): MiddlewareResult => {
    for (const trigger of policy.requireApprovalFor) {
      switch (trigger.type) {
        case "destructive":
          if (ctx.annotations?.destructiveHint) {
            return {
              action: "require-approval",
              reason: `Tool "${ctx.tool}" is marked destructive and requires human approval`,
            };
          }
          break;

        case "tool":
          if (trigger.names.includes(ctx.tool)) {
            return {
              action: "require-approval",
              reason: `Tool "${ctx.tool}" requires explicit approval per policy`,
            };
          }
          break;

        case "pattern":
          if (new RegExp(trigger.match, "i").test(ctx.tool)) {
            return {
              action: "require-approval",
              reason: `Tool "${ctx.tool}" matches approval pattern: ${trigger.match}`,
            };
          }
          break;
      }
    }

    return { action: "allow" };
  };
}
