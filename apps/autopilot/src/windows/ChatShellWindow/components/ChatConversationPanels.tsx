import type { ReactNode } from "react";
import type { ChatArtifactSelectedSkill } from "../../../types";
import { icons } from "../../../components/ui/icons";
import { formatChatExecutionPreviewPhase } from "./chatExecutionPreview";

type ChatConversationWelcomeProps = {
  onSuggestionClick: (text: string) => void;
};

type ChatRunStateCardProps = {
  tone?: "active" | "error";
  title: string;
  detail: string;
  metrics?: {
    stage?: string | null;
    activeRole?: string | null;
    progress?: string | null;
    verification?: string | null;
  } | null;
  processes?: Array<{
    id: string;
    label: string;
    status: string;
    summary: string;
    isActive?: boolean;
    iconKey?: string | null;
  }>;
  selectedSkills?: ChatArtifactSelectedSkill[];
  livePreview?: {
    label: string;
    content: string;
    status: string;
    kind?: string | null;
    language?: string | null;
    isFinal: boolean;
  } | null;
  codePreview?: {
    label: string;
    content: string;
    status: string;
    kind?: string | null;
    language?: string | null;
    isFinal: boolean;
  } | null;
};

function processIcon(iconKey: string | null | undefined) {
  switch (iconKey) {
    case "search":
      return icons.search;
    case "cube":
      return icons.cube;
    case "sparkles":
      return icons.sparkles;
    case "copy":
      return icons.copy;
    case "code":
      return icons.code;
    case "retry":
      return icons.retry;
    case "check":
      return icons.check;
    case "artifacts":
      return icons.artifacts;
    case "terminal":
      return icons.code;
    default:
      return icons.sparkles;
  }
}

function previewMode(
  preview:
    | {
        kind?: string | null;
      }
    | null
    | undefined,
) {
  return preview?.kind === "change_preview" ? "code" : "stream";
}

function formatPreviewStats(content: string) {
  const lineCount = content.split(/\r?\n/).length;
  const charCount = content.length;
  return `${lineCount.toLocaleString()} lines · ${charCount.toLocaleString()} chars`;
}

const suggestionPrompts = [
  "Review the current repo",
  "Explain the active file",
  "Find risky changes",
  "Draft a patch plan",
];

type ProgressRow = {
  id: string;
  label: string;
  detail?: string | null;
  meta?: string | null;
  icon: ReactNode;
  active?: boolean;
  tone?: "default" | "error" | "success";
};

function hasText(value: string | null | undefined): value is string {
  return Boolean(value?.trim());
}

function pushProgressRow(
  rows: ProgressRow[],
  row: ProgressRow,
  seen: Set<string>,
) {
  const normalized = [
    row.label.trim().toLowerCase(),
    row.detail?.trim().toLowerCase() ?? "",
    row.meta?.trim().toLowerCase() ?? "",
  ].join("|");
  if (seen.has(normalized)) {
    return;
  }
  seen.add(normalized);
  rows.push(row);
}

export function ChatConversationWelcome({
  onSuggestionClick,
}: ChatConversationWelcomeProps) {
  return (
    <section className="spot-chat-welcome" aria-label="Chat welcome">
      <div className="spot-chat-welcome-mark" aria-hidden="true">
        {icons.sparkles}
      </div>

      <div className="spot-chat-welcome-copy">
        <h2>Build with Agent</h2>
        <p>
          AI responses may be inaccurate. Repo, file, runtime, and evidence
          context stay attached.
        </p>
      </div>

      <span className="spot-chat-welcome-kicker">Suggested Actions</span>
      <div className="spot-chat-suggestion-row">
        {suggestionPrompts.map((prompt) => (
          <button
            key={prompt}
            type="button"
            className="spot-chat-suggestion"
            onClick={() => onSuggestionClick(prompt)}
          >
            {prompt}
          </button>
        ))}
      </div>
    </section>
  );
}


export function ChatRunStateCard({
  tone = "active",
  title,
  detail,
  metrics = null,
  processes = [],
  selectedSkills = [],
  livePreview = null,
  codePreview = null,
}: ChatRunStateCardProps) {
  const isError = tone === "error";
  const renderPreviewAriaLabel = (
    preview: NonNullable<ChatRunStateCardProps["livePreview"]>,
  ) =>
    `${preview.label}. ${formatChatExecutionPreviewPhase(preview)}.`;
  const seenRows = new Set<string>();
  const progressRows: ProgressRow[] = [];

  if (hasText(metrics?.progress)) {
    const detailParts = [metrics.stage, metrics.activeRole]
      .filter(hasText)
      .filter((part) => part !== metrics.progress);
    pushProgressRow(
      progressRows,
      {
        id: "progress",
        label: metrics.progress,
        detail: detailParts.length ? detailParts.join(" · ") : null,
        icon: icons.history,
        active: true,
      },
      seenRows,
    );
  } else if (hasText(metrics?.stage)) {
    const detail = hasText(metrics.activeRole) && metrics.activeRole !== metrics.stage
      ? metrics.activeRole
      : null;
    pushProgressRow(
      progressRows,
      {
        id: "stage",
        label: metrics.stage,
        detail,
        icon: icons.history,
        active: true,
      },
      seenRows,
    );
  } else if (hasText(metrics?.activeRole)) {
    pushProgressRow(
      progressRows,
      {
        id: "active-role",
        label: metrics.activeRole,
        icon: icons.history,
        active: true,
      },
      seenRows,
    );
  }

  processes.forEach((process) => {
    pushProgressRow(
      progressRows,
      {
        id: `process-${process.id}`,
        label: process.label,
        detail: process.summary,
        meta: process.status,
        icon: processIcon(process.iconKey),
        active: process.isActive,
      },
      seenRows,
    );
  });

  selectedSkills.forEach((skill) => {
    pushProgressRow(
      progressRows,
      {
        id: `skill-${skill.skillHash}`,
        label: `Read ${skill.name}`,
        detail: skill.matchRationale || skill.description,
        meta: skill.relativePath || null,
        icon: icons.copy,
      },
      seenRows,
    );
  });

  if (livePreview?.content) {
    pushProgressRow(
      progressRows,
      {
        id: "live-preview",
        label: livePreview.label,
        detail: formatChatExecutionPreviewPhase(livePreview),
        meta: livePreview.language || livePreview.kind || null,
        icon:
          livePreview.kind === "html" || livePreview.kind === "command_stream"
            ? icons.code
            : icons.artifacts,
        active: !livePreview.isFinal,
      },
      seenRows,
    );
  }

  if (codePreview?.content && codePreview.content !== livePreview?.content) {
    pushProgressRow(
      progressRows,
      {
        id: "code-preview",
        label: codePreview.label,
        detail: formatChatExecutionPreviewPhase(codePreview),
        meta: codePreview.language || codePreview.kind || null,
        icon:
          codePreview.kind === "html" || codePreview.kind === "command_stream"
            ? icons.code
            : icons.artifacts,
        active: !codePreview.isFinal,
      },
      seenRows,
    );
  }

  if (hasText(metrics?.verification)) {
    pushProgressRow(
      progressRows,
      {
        id: "verification",
        label: metrics.verification,
        icon: icons.check,
        tone: "success",
      },
      seenRows,
    );
  }

  if (isError) {
    const commandStreamFailed =
      livePreview?.kind === "command_stream" && livePreview.status === "failed";
    pushProgressRow(
      progressRows,
      {
        id: "repair",
        label: commandStreamFailed ? "Install blocked" : "Needs repair",
        detail: commandStreamFailed
          ? "Review the resolver or execution receipt above before retrying."
          : "This run needs operator or runtime repair before it can continue.",
        icon: icons.alert,
        tone: "error",
        active: true,
      },
      seenRows,
    );
  }

  const renderPreview = (
    preview: NonNullable<ChatRunStateCardProps["livePreview"]>,
  ) => (
    <div
      className={`spot-agent-progress-preview ${
        previewMode(preview) === "code"
          ? "is-code-preview"
          : "is-stream-preview"
      }`}
      aria-live="polite"
      aria-label={renderPreviewAriaLabel(preview)}
    >
      <div className="spot-agent-progress-preview-head">
        <span>{preview.label}</span>
        <span>{formatChatExecutionPreviewPhase(preview)}</span>
      </div>
      <div className="spot-agent-progress-preview-meta">
        <span>{formatPreviewStats(preview.content)}</span>
        {previewMode(preview) === "code" ? (
          <span>Scroll to inspect the full artifact.</span>
        ) : null}
      </div>
      <pre tabIndex={0}>
        <code>{preview.content}</code>
      </pre>
    </div>
  );

  const terminalOnly =
    livePreview?.kind === "command_stream" &&
    !!livePreview.content &&
    progressRows.length === 0 &&
    !codePreview?.content;

  if (terminalOnly) {
    return (
      <section
        className={`spot-chat-status-card spot-agent-progress ${
          isError ? "is-error" : "is-active"
        } is-terminal-only`}
        aria-live="polite"
      >
        <div className="spot-agent-progress-previews">
          {renderPreview(livePreview)}
        </div>
      </section>
    );
  }

  return (
    <section
      className={`spot-chat-status-card spot-agent-progress ${
        isError ? "is-error" : "is-active"
      }`}
      aria-live="polite"
    >
      <div className="spot-agent-progress-row spot-agent-progress-row--lead">
        <span className="spot-agent-progress-icon" aria-hidden="true">
          {isError ? icons.alert : icons.spinner}
        </span>
        <div className="spot-agent-progress-body">
          <strong>{title}</strong>
          {hasText(detail) ? <p>{detail}</p> : null}
        </div>
      </div>
      {progressRows.length ? (
        <div className="spot-agent-progress-rail" aria-label="Agent work steps">
          {progressRows.map((row) => (
            <div
              key={row.id}
              className={`spot-agent-progress-row ${
                row.active ? "is-active" : ""
              } ${row.tone ? `is-${row.tone}` : ""}`}
            >
              <span className="spot-agent-progress-icon" aria-hidden="true">
                {row.icon}
              </span>
              <div className="spot-agent-progress-body">
                <strong>{row.label}</strong>
                {hasText(row.detail) ? <p>{row.detail}</p> : null}
              </div>
              {hasText(row.meta) ? (
                <span className="spot-agent-progress-meta">{row.meta}</span>
              ) : null}
            </div>
          ))}
        </div>
      ) : null}
      <div className="spot-agent-progress-previews">
        {livePreview?.content ? renderPreview(livePreview) : null}
        {codePreview?.content && codePreview.content !== livePreview?.content ? (
          renderPreview(codePreview)
        ) : null}
      </div>
    </section>
  );
}
