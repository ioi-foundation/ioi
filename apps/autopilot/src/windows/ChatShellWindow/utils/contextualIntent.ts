type TranscriptRole = "user" | "assistant";

const TOOLCAT_MARKER_RE = /\bTOOLCAT_(?:SINGLE_TOOL|STAGE\d+_[A-Z0-9_]+)\b/i;
const TOOLCAT_TOOL_RE = /\btoolcat_tool=([a-z0-9_.]+(?:__[a-z0-9_]+)?)/i;
const TOOLCAT_SINGLE_TOOL_RE = /\bTOOLCAT_SINGLE_TOOL\s+([a-z0-9_.]+(?:__[a-z0-9_]+)?)/i;

function compactWhitespace(value: string | null | undefined): string {
  return String(value || "").replace(/\s+/g, " ").trim();
}

function humanizeToolName(value: string | null | undefined): string | null {
  const compact = compactWhitespace(value);
  if (!compact) {
    return null;
  }
  return compact
    .replace(/\./g, " ")
    .replace(/__+/g, " ")
    .replace(/_+/g, " ")
    .replace(/\s+/g, " ")
    .trim()
    .toLowerCase() || null;
}

function toolcatToolName(value: string): string | null {
  return humanizeToolName(
    value.match(TOOLCAT_TOOL_RE)?.[1] ||
      value.match(TOOLCAT_SINGLE_TOOL_RE)?.[1] ||
      null,
  );
}

export function humanizeOperationalTranscriptText(
  value: string | null | undefined,
  role: TranscriptRole = "assistant",
): string {
  const raw = String(value || "").trim();
  const trimmed = compactWhitespace(raw);
  if (!trimmed) {
    return "";
  }

  if (TOOLCAT_MARKER_RE.test(trimmed)) {
    const toolName = toolcatToolName(trimmed);
    if (role === "user") {
      return toolName
        ? `Run live Rust tool catalogue verification for ${toolName}.`
        : "Run live Rust tool catalogue verification.";
    }
    if (/\bfailed\b|\bfailure\b/i.test(trimmed)) {
      return toolName
        ? `The live Rust tool catalogue probe failed for ${toolName}. Details are in Tracing.`
        : "The live Rust tool catalogue verification step failed. Details are in Tracing.";
    }
    return toolName
      ? `The live Rust tool catalogue probe completed for ${toolName}.`
      : "The live Rust tool catalogue verification step completed.";
  }

  return raw;
}

export function extractUserRequestFromContextualIntent(value: string | null | undefined): string {
  const trimmed = (value ?? "").trim();
  if (!trimmed) {
    return "";
  }

  if (TOOLCAT_MARKER_RE.test(trimmed)) {
    return humanizeOperationalTranscriptText(trimmed, "user");
  }

  const markers = ["[User request]", "User request:"];
  for (const marker of markers) {
    const index = trimmed.lastIndexOf(marker);
    if (index >= 0) {
      const request = trimmed
        .slice(index + marker.length)
        .replace(/^[\s:-]+/, "")
        .trim();
      if (request) {
        return humanizeOperationalTranscriptText(request, "user");
      }
    }
  }

  return humanizeOperationalTranscriptText(trimmed, "user");
}
