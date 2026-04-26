import type { AgentEvent, AgentTask } from "../../../types";
import { icons } from "../../../components/ui/icons";
import {
  eventOutputText,
  eventToolName,
  toEventString,
} from "../utils/eventFields";

type ThoughtsDrawerSurfaceProps = {
  task: AgentTask | null;
  events?: AgentEvent[];
  onCollapse: () => void;
  onSeedIntent: (intent: string) => void;
};

type ThoughtRow = {
  id: string;
  label: string;
  body: string;
  kind: "thought" | "tool" | "source" | "verify";
};

const MAX_EVENT_ROWS = 6;
const MAX_SOURCE_ROWS = 6;
const URL_RE = /https?:\/\/[^\s)"'<>]+/gi;

function compactText(value: string, maxChars = 220): string {
  const compact = value.replace(/\s+/g, " ").trim();
  if (compact.length <= maxChars) {
    return compact;
  }
  return `${compact.slice(0, maxChars - 1).trim()}…`;
}

function eventDomain(url: string): string {
  try {
    return new URL(url).hostname.replace(/^www\./, "");
  } catch {
    return url.replace(/^https?:\/\//, "").split(/[/?#]/)[0] || url;
  }
}

function collectSourceRows(events: AgentEvent[]): ThoughtRow[] {
  const seen = new Set<string>();
  const rows: ThoughtRow[] = [];

  for (const event of events) {
    const text = [
      eventOutputText(event),
      toEventString(event.digest?.url as unknown),
      toEventString(event.digest?.source_url as unknown),
      toEventString(event.digest?.href as unknown),
    ].join(" ");

    for (const match of text.matchAll(URL_RE)) {
      const url = match[0].replace(/[),.;]+$/, "");
      const domain = eventDomain(url);
      if (!domain || seen.has(domain)) {
        continue;
      }
      seen.add(domain);
      rows.push({
        id: `source:${domain}`,
        label: "Browsed",
        body: domain,
        kind: "source",
      });
      if (rows.length >= MAX_SOURCE_ROWS) {
        return rows;
      }
    }
  }

  return rows;
}

function collectEventRows(events: AgentEvent[]): ThoughtRow[] {
  return events
    .slice()
    .reverse()
    .map((event, index) => {
      const tool = eventToolName(event).trim();
      const output = compactText(eventOutputText(event), 260);
      const label = tool
        ? tool.replace(/[_:.-]+/g, " ")
        : event.event_type.replace(/[_:.-]+/g, " ");
      return {
        id: event.event_id || `event:${index}`,
        label,
        body: output,
        kind: tool ? "tool" : "thought",
      } satisfies ThoughtRow;
    })
    .filter((row) => row.body.length > 0)
    .slice(0, MAX_EVENT_ROWS)
    .reverse();
}

function taskRows(task: AgentTask | null): ThoughtRow[] {
  if (!task) {
    return [];
  }

  const rows: ThoughtRow[] = [];
  const intent = compactText(
    task.intent || task.chat_session?.title || task.current_step || "",
    180,
  );
  if (intent) {
    rows.push({
      id: "task:intent",
      label: "Intent",
      body: intent,
      kind: "thought",
    });
  }

  const currentStep = compactText(task.current_step || "", 220);
  if (currentStep && currentStep.toLowerCase() !== "initializing...") {
    rows.push({
      id: "task:current-step",
      label: "Working",
      body: currentStep,
      kind: "thought",
    });
  }

  for (const [index, item] of (task.session_checklist || []).slice(-4).entries()) {
    const title = compactText(item.label || item.detail || "", 180);
    if (!title) {
      continue;
    }
    rows.push({
      id: `task:checklist:${index}`,
      label: item.status ? `Step · ${item.status}` : "Step",
      body: title,
      kind: "verify",
    });
  }

  return rows;
}

function rowIcon(kind: ThoughtRow["kind"]) {
  switch (kind) {
    case "source":
      return icons.globe;
    case "tool":
      return icons.code;
    case "verify":
      return icons.check;
    default:
      return icons.sparkles;
  }
}

export function ThoughtsDrawerSurface({
  task,
  events = [],
  onCollapse,
  onSeedIntent,
}: ThoughtsDrawerSurfaceProps) {
  const sourceRows = collectSourceRows(events);
  const rows = [...taskRows(task), ...collectEventRows(events)];
  const title =
    task?.chat_session?.title?.trim() ||
    task?.intent?.trim() ||
    task?.current_step?.trim() ||
    "Current chat run";
  const active = task?.phase === "Running" || task?.phase === "Gate";

  return (
    <section className="chat-artifact-surface chat-thoughts-drawer">
      <header className="chat-thoughts-drawer__header">
        <div>
          <span className="chat-thoughts-drawer__eyebrow">
            {active ? "Working" : "Thoughts"}
          </span>
          <h2>Thoughts</h2>
        </div>
        <button
          type="button"
          className="chat-thoughts-drawer__close"
          onClick={onCollapse}
          title="Close thoughts"
        >
          {icons.close}
        </button>
      </header>

      <div className="chat-thoughts-drawer__summary">
        <span className="thoughts-agent-dot" />
        <div>
          <strong>{compactText(title, 92)}</strong>
          <p>
            Process, tools, sources, and verification notes for this chat turn.
          </p>
        </div>
      </div>

      {sourceRows.length > 0 ? (
        <section className="thoughts-section">
          <div className="thoughts-agent-header">
            <span className="thoughts-agent-dot" />
            <span className="thoughts-agent-name">Sources</span>
            <span className="thoughts-agent-role">Used this turn</span>
          </div>
          <div className="chat-thoughts-source-pills">
            {sourceRows.map((row) => (
              <span className="chat-thoughts-source-pill" key={row.id}>
                <span aria-hidden="true">{icons.globe}</span>
                {row.body}
              </span>
            ))}
          </div>
        </section>
      ) : null}

      {rows.length > 0 ? (
        <section className="thoughts-section">
          <div className="thoughts-agent-header">
            <span className="thoughts-agent-dot" />
            <span className="thoughts-agent-name">Autopilot</span>
            <span className="thoughts-agent-role">Process</span>
          </div>
          <div className="chat-thoughts-drawer__rows">
            {rows.map((row) => (
              <article className="chat-thoughts-row" key={row.id}>
                <span className="chat-thoughts-row__icon" aria-hidden="true">
                  {rowIcon(row.kind)}
                </span>
                <div>
                  <span className="chat-thoughts-row__label">{row.label}</span>
                  <p>{row.body}</p>
                </div>
              </article>
            ))}
          </div>
        </section>
      ) : (
        <p className="chat-thoughts-drawer__empty">
          No process entries were retained for this turn yet.
        </p>
      )}

      <div className="chat-thoughts-drawer__actions">
        <button
          type="button"
          onClick={() =>
            onSeedIntent(
              "In chat only, summarize the useful process, tool, source, and verification evidence for the current run.",
            )
          }
        >
          Summarize process
        </button>
      </div>
    </section>
  );
}
