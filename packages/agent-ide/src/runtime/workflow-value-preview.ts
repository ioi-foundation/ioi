export interface WorkflowValuePreview {
  kind: string;
  summary: string;
  detail: string;
  keys: string[];
}

const MAX_SUMMARY_LENGTH = 180;
const MAX_DETAIL_KEYS = 8;

function truncatePreview(value: string): string {
  const normalized = value.replace(/\s+/g, " ").trim();
  return normalized.length > MAX_SUMMARY_LENGTH
    ? `${normalized.slice(0, MAX_SUMMARY_LENGTH - 1)}...`
    : normalized;
}

export function workflowConfiguredFieldNames(value: unknown): string[] {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    return [];
  }
  return Object.keys(value as Record<string, unknown>).filter((key) => {
    const fieldValue = (value as Record<string, unknown>)[key];
    if (fieldValue === undefined || fieldValue === null || fieldValue === "") {
      return false;
    }
    if (Array.isArray(fieldValue)) {
      return fieldValue.length > 0;
    }
    if (typeof fieldValue === "object") {
      return Object.keys(fieldValue as Record<string, unknown>).length > 0;
    }
    return true;
  });
}

export function workflowValuePreview(value: unknown): WorkflowValuePreview {
  if (value === undefined) {
    return {
      kind: "empty",
      summary: "No value captured.",
      detail: "Run this node to inspect its produced value.",
      keys: [],
    };
  }
  if (value === null) {
    return {
      kind: "null",
      summary: "Null value captured.",
      detail: "The node completed without a structured payload.",
      keys: [],
    };
  }
  if (Array.isArray(value)) {
    const first = value[0];
    const firstKeys = first && typeof first === "object" && !Array.isArray(first)
      ? Object.keys(first as Record<string, unknown>)
      : [];
    return {
      kind: "array",
      summary: `${value.length} item${value.length === 1 ? "" : "s"} captured.`,
      detail: firstKeys.length > 0
        ? `First item fields: ${firstKeys.slice(0, MAX_DETAIL_KEYS).join(", ")}`
        : truncatePreview(JSON.stringify(value.slice(0, 3))),
      keys: firstKeys,
    };
  }
  if (typeof value === "object") {
    const record = value as Record<string, unknown>;
    const keys = Object.keys(record);
    const explicitSummary = typeof record.summary === "string"
      ? record.summary
      : typeof record.message === "string"
        ? record.message
        : typeof record.text === "string"
          ? record.text
          : "";
    return {
      kind: "object",
      summary: explicitSummary
        ? truncatePreview(explicitSummary)
        : `${keys.length} field${keys.length === 1 ? "" : "s"} captured.`,
      detail: keys.length > 0
        ? `Fields: ${keys.slice(0, MAX_DETAIL_KEYS).join(", ")}${keys.length > MAX_DETAIL_KEYS ? `, +${keys.length - MAX_DETAIL_KEYS}` : ""}`
        : "Empty object captured.",
      keys,
    };
  }
  if (typeof value === "string") {
    return {
      kind: "text",
      summary: value ? truncatePreview(value) : "Empty text captured.",
      detail: `${value.length} character${value.length === 1 ? "" : "s"}`,
      keys: [],
    };
  }
  if (typeof value === "number" || typeof value === "boolean") {
    return {
      kind: typeof value,
      summary: String(value),
      detail: "Scalar value captured.",
      keys: [],
    };
  }
  return {
    kind: typeof value,
    summary: truncatePreview(String(value)),
    detail: "Value captured.",
    keys: [],
  };
}
