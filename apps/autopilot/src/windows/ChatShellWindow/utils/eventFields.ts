import type { AgentEvent } from "../../../types";

const TOOL_NAME_KEYS = ["tool_name", "tool", "name"] as const;

export function toEventString(value: unknown): string {
  if (typeof value === "string") {
    return value;
  }
  if (typeof value === "number" || typeof value === "boolean") {
    return String(value);
  }
  return "";
}

export function eventToolName(event: AgentEvent): string {
  const digest = event.digest || {};
  const details = event.details || {};

  for (const key of TOOL_NAME_KEYS) {
    const digestValue = toEventString(digest[key as keyof typeof digest]).trim();
    if (digestValue.length > 0) {
      return digestValue;
    }

    const detailsValue = toEventString(details[key as keyof typeof details]).trim();
    if (detailsValue.length > 0) {
      return detailsValue;
    }
  }

  return "";
}

export function eventOutputText(event: AgentEvent): string {
  const details = event.details || {};
  const digest = event.digest || {};
  const candidates = [details.output, details.chunk, details.content, digest.output_snippet];

  for (const candidate of candidates) {
    const text = toEventString(candidate).trim();
    if (text.length > 0) {
      return text;
    }
  }

  return "";
}

export function parseTimestampMs(value: string | null | undefined): number | null {
  if (!value) {
    return null;
  }
  const ms = Date.parse(value);
  return Number.isNaN(ms) ? null : ms;
}

export function isUserRequestEvent(event: AgentEvent): boolean {
  const details = event.details || {};
  const title = event.title.toLowerCase();
  return (
    toEventString(details.kind).trim().toLowerCase() === "user_input" ||
    title === "user request"
  );
}

export function eventPromptText(event: AgentEvent): string {
  const details = event.details || {};
  const digest = event.digest || {};
  return toEventString(details.text).trim() || toEventString(digest.query).trim();
}
