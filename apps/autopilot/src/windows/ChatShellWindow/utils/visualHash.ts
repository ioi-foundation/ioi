const VISUAL_HASH_LENGTH = 64;
const VISUAL_HASH_REGEX = /^[0-9a-f]{64}$/i;
const ZERO_VISUAL_HASH = "0".repeat(VISUAL_HASH_LENGTH);

export function normalizeVisualHash(value: unknown): string {
  if (typeof value !== "string") {
    return "";
  }

  const trimmed = value.trim();
  if (trimmed.length !== VISUAL_HASH_LENGTH) {
    return "";
  }

  if (!VISUAL_HASH_REGEX.test(trimmed)) {
    return "";
  }

  const normalized = trimmed.toLowerCase();
  if (normalized === ZERO_VISUAL_HASH) {
    return "";
  }

  return normalized;
}

export function firstMeaningfulVisualHash(...values: unknown[]): string {
  for (const value of values) {
    const normalized = normalizeVisualHash(value);
    if (normalized) {
      return normalized;
    }
  }
  return "";
}
