import type { AgentEvent } from "../../../types";
import {
  eventOutputText,
  eventToolName as normalizedEventToolName,
  toEventString,
} from "../utils/eventFields";

const URL_RE = /https?:\/\/[^\s)\]}"']+/gim;
const GOOGLE_FAVICON_BASE = "https://www.google.com/s2/favicons?domain=";

export const WEB_SEARCH_TOOL = "web__search";
export const WEB_READ_TOOL = "web__read";

export interface ParsedWebSource {
  url: string;
  title?: string;
  domain?: string;
}

export interface ParsedWebDocument {
  url: string;
  title?: string;
}

export interface ParsedWebBundle {
  query?: string;
  url?: string;
  sources: ParsedWebSource[];
  documents: ParsedWebDocument[];
}

export function toValueString(value: unknown): string {
  return toEventString(value);
}

export function hashString(input: string): string {
  let hash = 0x811c9dc5;
  for (let i = 0; i < input.length; i += 1) {
    hash ^= input.charCodeAt(i);
    hash = Math.imul(hash, 0x01000193);
  }
  return (hash >>> 0).toString(16);
}

export function normalizeOutputForHash(value: string): string {
  return value
    .replace(/\s+/g, " ")
    .replace(/\|\s*\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z\s*\|/g, "|TIMESTAMP|")
    .trim();
}

export function eventOutput(event: AgentEvent): string {
  return eventOutputText(event);
}

export function eventToolName(event: AgentEvent): string | undefined {
  const value = normalizedEventToolName(event).trim();
  return value.length > 0 ? value : undefined;
}

export function isChatReplyTool(toolName?: string): boolean {
  if (!toolName) return false;
  const normalized = toolName.trim().toLowerCase();
  return normalized === "chat__reply" || normalized === "chat::reply";
}

export function extractUrls(text: string): string[] {
  const matches = text.match(URL_RE) || [];
  const unique = new Set<string>();

  for (const candidate of matches) {
    const cleaned = candidate
      .trim()
      .replace(/[),.;]+$/g, "")
      .trim();
    if (cleaned.startsWith("http://") || cleaned.startsWith("https://")) {
      unique.add(cleaned);
    }
  }

  return Array.from(unique);
}

export function asRecord(value: unknown): Record<string, unknown> | null {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    return null;
  }
  return value as Record<string, unknown>;
}

export function firstStringValue(...values: unknown[]): string | undefined {
  for (const value of values) {
    const text = toValueString(value).trim();
    if (text.length > 0) {
      return text;
    }
  }
  return undefined;
}

export function parseOutputJsonObject(output: string): Record<string, unknown> | null {
  const trimmed = output.trim();
  if (!trimmed) return null;

  const candidates = [trimmed];
  const firstBrace = trimmed.indexOf("{");
  const lastBrace = trimmed.lastIndexOf("}");
  if (firstBrace >= 0 && lastBrace > firstBrace) {
    candidates.push(trimmed.slice(firstBrace, lastBrace + 1));
  }

  for (const candidate of candidates) {
    try {
      const parsed = JSON.parse(candidate);
      const record = asRecord(parsed);
      if (record) {
        return record;
      }
    } catch {
      // Continue trying fallback candidates.
    }
  }

  return null;
}

export function parseWebBundle(event: AgentEvent): ParsedWebBundle | null {
  const output = eventOutput(event);
  const payload = parseOutputJsonObject(output);
  if (!payload) return null;

  const sourcesRaw = Array.isArray(payload.sources) ? payload.sources : [];
  const documentsRaw = Array.isArray(payload.documents) ? payload.documents : [];

  const sources: ParsedWebSource[] = [];
  for (const entry of sourcesRaw) {
    const row = asRecord(entry);
    if (!row) continue;

    const url = firstStringValue(row.url);
    if (!url) continue;

    const parsed: ParsedWebSource = { url };
    const title = firstStringValue(row.title);
    const domain = firstStringValue(row.domain);
    if (title) parsed.title = title;
    if (domain) parsed.domain = domain;
    sources.push(parsed);
  }

  const documents: ParsedWebDocument[] = [];
  for (const entry of documentsRaw) {
    const row = asRecord(entry);
    if (!row) continue;

    const url = firstStringValue(row.url);
    if (!url) continue;

    const parsed: ParsedWebDocument = { url };
    const title = firstStringValue(row.title);
    if (title) parsed.title = title;
    documents.push(parsed);
  }

  return {
    query: firstStringValue(
      payload.query,
      event.details?.query,
      event.digest?.query,
    ),
    url: firstStringValue(payload.url, event.details?.url, event.digest?.url),
    sources,
    documents,
  };
}

export function normalizedDomain(url: string): string | null {
  try {
    const host = new URL(url).hostname.trim().toLowerCase();
    if (!host) return null;
    return host.replace(/^www\./, "");
  } catch {
    return null;
  }
}

export function faviconUrlForDomain(domain: string): string {
  return `${GOOGLE_FAVICON_BASE}${encodeURIComponent(domain)}&sz=256`;
}
