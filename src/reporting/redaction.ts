const SECRET_KEY_PATTERN = /token|secret|password|passwd|api[_-]?key|authorization|credential/i;
const SECRET_VALUE_PATTERN = /(sk-[A-Za-z0-9_-]{20,}|gh[pousr]_[A-Za-z0-9_]{20,}|xox[baprs]-[A-Za-z0-9-]{20,}|AKIA[0-9A-Z]{16})/g;

export function redactSecrets(value: unknown): unknown {
  if (value === null || value === undefined) return value;
  if (Array.isArray(value)) return value.map(redactSecrets);
  if (typeof value === "object") {
    const result: Record<string, unknown> = {};
    for (const [key, nestedValue] of Object.entries(value as Record<string, unknown>)) {
      const safeKey = redactSecretText(key);
      result[safeKey] = SECRET_KEY_PATTERN.test(key) ? "[REDACTED]" : redactSecrets(nestedValue);
    }
    return result;
  }
  if (typeof value === "string") return redactSecretText(value);
  return value;
}

export function redactSecretText(value: string): string {
  return value.replace(SECRET_VALUE_PATTERN, "[REDACTED]");
}
