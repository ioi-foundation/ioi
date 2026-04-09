import type {
  AgentTask,
  CapabilityRegistryEntry,
  SessionSummary,
  SkillCatalogEntry,
} from "../../../types";
import type { ConnectorSummary } from "@ioi/agent-ide";

export type SlashTokenContext = {
  query: string;
  start: number;
  end: number;
};

export function adjustTextareaHeight(textarea: HTMLTextAreaElement | null) {
  if (!textarea) {
    return;
  }
  textarea.style.height = "auto";
  textarea.style.height = `${Math.min(textarea.scrollHeight, 120)}px`;
}

export function getSlashTokenContext(
  value: string,
  caret: number,
): SlashTokenContext | null {
  const safeCaret = Math.max(0, Math.min(caret, value.length));
  const beforeCaret = value.slice(0, safeCaret);
  const leadingMatch = beforeCaret.match(/(?:^|\s)\/([^\s/]*)$/);

  if (!leadingMatch) {
    return null;
  }

  const queryBeforeCaret = leadingMatch[1] ?? "";
  const tokenStart = safeCaret - queryBeforeCaret.length - 1;
  const trailingMatch = value.slice(safeCaret).match(/^[^\s/]*/);
  const trailingQuery = trailingMatch?.[0] ?? "";

  return {
    query: `${queryBeforeCaret}${trailingQuery}`,
    start: tokenStart,
    end: safeCaret + trailingQuery.length,
  };
}

export function humanizeLabel(value: string | null | undefined) {
  if (!value) {
    return "";
  }

  return value
    .replace(/[_-]+/g, " ")
    .replace(/\b\w/g, (match) => match.toUpperCase());
}

export function matchesSlashQuery(
  query: string,
  ...parts: Array<string | null | undefined>
) {
  const normalizedQuery = query.trim().toLowerCase();
  if (!normalizedQuery) {
    return true;
  }

  return parts
    .filter(Boolean)
    .join(" ")
    .toLowerCase()
    .includes(normalizedQuery);
}

export function sourceLabelForSkill(skill: SkillCatalogEntry) {
  if (skill.source_type === "starter") {
    return "System";
  }
  if (skill.source_type === "workspace") {
    return "Personal";
  }

  return humanizeLabel(skill.source_type) || "Skill";
}

export function capabilityMetaLabel(
  entry: CapabilityRegistryEntry | null,
  fallback: string,
): string {
  if (!entry) {
    return fallback;
  }

  return [
    entry.authority.tierLabel,
    entry.lease.modeLabel ?? entry.lease.availabilityLabel,
  ]
    .filter(Boolean)
    .join(" · ");
}

export function capabilityDescriptionForSkill(
  skill: SkillCatalogEntry,
  entry: CapabilityRegistryEntry | null,
): string {
  if (!entry) {
    return (
      skill.description ||
      skill.definition?.description ||
      "Add this skill to the prompt as guidance."
    );
  }

  return [entry.whySelectable, entry.lease.summary].filter(Boolean).join(" ");
}

export function sessionLabel(session: SessionSummary) {
  const trimmedTitle = session.title.trim();
  return trimmedTitle.length > 0
    ? trimmedTitle
    : `Session ${session.session_id.slice(0, 8)}`;
}

export function sessionWorkspaceLabel(session: SessionSummary) {
  const trimmed = session.workspace_root?.trim();
  if (!trimmed) {
    return null;
  }

  const normalized = trimmed.replace(/\\/g, "/");
  const segments = normalized.split("/").filter(Boolean);
  return segments[segments.length - 1] ?? normalized;
}

export function workspaceRootFromTask(task: AgentTask | null): string | null {
  return (
    task?.build_session?.workspaceRoot ||
    task?.renderer_session?.workspaceRoot ||
    task?.studio_session?.workspaceRoot ||
    null
  );
}

function uniqueSessionParts(parts: Array<string | null | undefined>): string[] {
  const seen = new Set<string>();
  const unique: string[] = [];

  parts.forEach((part) => {
    const trimmed = part?.trim();
    if (!trimmed) {
      return;
    }
    const key = trimmed.toLowerCase();
    if (seen.has(key)) {
      return;
    }
    seen.add(key);
    unique.push(trimmed);
  });

  return unique;
}

export function sessionResumeContext(session: SessionSummary) {
  const parts = uniqueSessionParts([
    session.phase,
    session.current_step,
    session.resume_hint,
    sessionWorkspaceLabel(session),
  ]);
  return parts.length > 0 ? parts.join(" · ") : null;
}

export function stableSessionCandidate(
  sessions: SessionSummary[],
  activeSessionId: string | null,
): SessionSummary | null {
  const waitingStep = (value: string | null | undefined) => {
    const normalized = (value || "").trim().toLowerCase();
    return (
      normalized.includes("waiting for") ||
      normalized.includes("initializing") ||
      normalized.includes("routing the request") ||
      normalized.includes("sending message") ||
      normalized.includes("approval required") ||
      normalized.includes("clarification required")
    );
  };

  return (
    sessions.find((session) => {
      if (session.session_id === activeSessionId) {
        return false;
      }
      const phase = (session.phase || "").trim().toLowerCase();
      if (phase === "running" || phase === "gate") {
        return false;
      }
      return !waitingStep(session.current_step);
    }) || null
  );
}

export function connectorStatusRank(status: ConnectorSummary["status"]) {
  switch (status) {
    case "connected":
      return 0;
    case "degraded":
      return 1;
    case "needs_auth":
      return 2;
    case "disabled":
      return 3;
    default:
      return 4;
  }
}

