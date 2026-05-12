import type { Middleware, ToolCallContext, MiddlewareResult, RateLimitPolicy } from "../types/index.js";

interface BucketEntry {
  count: number;
  windowStart: number;
}

function checkBucket(
  buckets: Map<string, BucketEntry>,
  key: string,
  limit: number,
  windowMs: number,
  now: number
): string | null {
  const entry = buckets.get(key);
  if (!entry || now - entry.windowStart > windowMs) {
    buckets.set(key, { count: 1, windowStart: now });
    return null;
  }
  entry.count++;
  if (entry.count > limit) {
    return `${entry.count}/${limit}`;
  }
  return null;
}

export function createRateLimiter(policy: RateLimitPolicy): Middleware {
  const perToolMinute = new Map<string, BucketEntry>();
  const perToolHour = new Map<string, BucketEntry>();
  const globalMinute: BucketEntry = { count: 0, windowStart: Date.now() };
  const globalHour: BucketEntry = { count: 0, windowStart: Date.now() };

  return (ctx: ToolCallContext): MiddlewareResult => {
    const key = `${ctx.server}:${ctx.tool}`;
    const now = Date.now();

    const toolLimit = policy.perTool?.[ctx.tool]?.maxCallsPerMinute ?? policy.maxCallsPerMinute;
    const exceeded = checkBucket(perToolMinute, key, toolLimit, 60_000, now);
    if (exceeded) {
      return {
        action: "block",
        reason: `Rate limit exceeded: ${exceeded} calls/min for ${ctx.tool}`,
      };
    }

    if (policy.maxCallsPerHour) {
      const hourExceeded = checkBucket(perToolHour, key, policy.maxCallsPerHour, 3_600_000, now);
      if (hourExceeded) {
        return {
          action: "block",
          reason: `Hourly rate limit exceeded: ${hourExceeded} calls/hr for ${ctx.tool}`,
        };
      }
    }

    if (now - globalMinute.windowStart > 60_000) {
      globalMinute.count = 1;
      globalMinute.windowStart = now;
    } else {
      globalMinute.count++;
      const globalLimit = policy.maxGlobalCallsPerMinute ?? policy.maxCallsPerMinute * 3;
      if (globalMinute.count > globalLimit) {
        return {
          action: "block",
          reason: `Global rate limit exceeded: ${globalMinute.count}/${globalLimit} calls/min across all tools`,
        };
      }
    }

    return { action: "allow" };
  };
}
