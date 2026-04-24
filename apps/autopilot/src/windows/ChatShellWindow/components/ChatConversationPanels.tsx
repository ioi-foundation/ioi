import { invoke } from "@tauri-apps/api/core";
import { useEffect, useMemo, useState } from "react";
import type {
  SkillDetailView,
  ChatArtifactSelectedSkill,
} from "../../../types";
import { icons } from "./Icons";
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

function clipSkillMarkdown(markdown: string | null | undefined): string | null {
  const trimmed = (markdown || "").trim();
  if (!trimmed) {
    return null;
  }
  if (trimmed.length <= 1500) {
    return trimmed;
  }
  return `${trimmed.slice(0, 1500).trimEnd()}\n...`;
}

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
  const isThinkingRail = processes.length > 0 && !metrics;
  const [activeSkillHash, setActiveSkillHash] = useState<string | null>(
    selectedSkills[0]?.skillHash ?? null,
  );
  const [skillDetailLookup, setSkillDetailLookup] = useState<
    Record<string, { detail: SkillDetailView | null; error: string | null }>
  >({});
  const [skillDetailsLoading, setSkillDetailsLoading] = useState(false);
  const selectedSkillKey = useMemo(
    () => selectedSkills.map((skill) => skill.skillHash).join("|"),
    [selectedSkills],
  );

  useEffect(() => {
    setActiveSkillHash((current) => {
      if (current && selectedSkills.some((skill) => skill.skillHash === current)) {
        return current;
      }
      return selectedSkills[0]?.skillHash ?? null;
    });
  }, [selectedSkillKey]);

  useEffect(() => {
    let cancelled = false;

    if (selectedSkills.length === 0) {
      setSkillDetailLookup({});
      setSkillDetailsLoading(false);
      return () => {
        cancelled = true;
      };
    }

    setSkillDetailsLoading(true);
    void Promise.all(
      selectedSkills.map(async (skill) => {
        try {
          const detail = await invoke<SkillDetailView>("get_skill_detail", {
            skillHash: skill.skillHash,
          });
          return [skill.skillHash, { detail, error: null }] as const;
        } catch (error) {
          return [
            skill.skillHash,
            {
              detail: null,
              error: error instanceof Error ? error.message : String(error ?? ""),
            },
          ] as const;
        }
      }),
    ).then((entries) => {
      if (cancelled) {
        return;
      }
      setSkillDetailLookup(Object.fromEntries(entries));
      setSkillDetailsLoading(false);
    });

    return () => {
      cancelled = true;
    };
  }, [selectedSkillKey]);

  const renderPreviewAriaLabel = (
    preview: NonNullable<ChatRunStateCardProps["livePreview"]>,
  ) =>
    `${preview.label}. ${formatChatExecutionPreviewPhase(preview)}.`;
  const activeSkill = useMemo(
    () =>
      selectedSkills.find((skill) => skill.skillHash === activeSkillHash) ??
      selectedSkills[0] ??
      null,
    [activeSkillHash, selectedSkills],
  );
  const activeSkillContext = activeSkill
    ? skillDetailLookup[activeSkill.skillHash] ?? null
    : null;
  const activeSkillDetail = activeSkillContext?.detail ?? null;
  const activeSkillMarkdown = clipSkillMarkdown(
    activeSkillDetail?.markdown ?? activeSkill?.guidanceMarkdown ?? null,
  );
  const activeSkillMeta = activeSkill
    ? [
        activeSkill.relativePath || activeSkillDetail?.relative_path || null,
        activeSkillDetail?.used_tools?.length
          ? `${activeSkillDetail.used_tools.length} tools`
          : null,
        activeSkillDetail?.steps?.length
          ? `${activeSkillDetail.steps.length} steps`
          : null,
      ].filter(Boolean)
    : [];

  return (
    <section
      className={`spot-chat-status-card ${
        isThinkingRail ? "is-thinking" : isError ? "is-error" : "is-active"
      }`}
      aria-live="polite"
    >
      <div className="spot-chat-status-icon">
        {isThinkingRail ? icons.sparkles : isError ? icons.alert : icons.spinner}
      </div>
      <div className="spot-chat-status-copy">
        <strong>{title}</strong>
        <p>{detail}</p>
        {metrics ? (
          <div className="spot-chat-status-metrics">
            {metrics.stage ? (
              <span className="spot-chat-status-chip">{metrics.stage}</span>
            ) : null}
            {metrics.activeRole ? (
              <span className="spot-chat-status-chip is-muted">
                {metrics.activeRole}
              </span>
            ) : null}
            {metrics.progress ? (
              <span className="spot-chat-status-chip is-muted">
                {metrics.progress}
              </span>
            ) : null}
            {metrics.verification ? (
              <span className="spot-chat-status-chip is-muted">
                {metrics.verification}
              </span>
            ) : null}
          </div>
        ) : null}
        {processes.length ? (
          <div className="spot-chat-status-process-list" aria-label="Thinking processes">
            {processes.map((process) => (
              <div
                key={process.id}
                className={`spot-chat-status-process ${
                  process.isActive ? "is-active" : ""
                }`}
                aria-label={`${process.label}. ${process.status}. ${process.summary}`}
              >
                <div className="spot-chat-status-process-row">
                  <div className="spot-chat-status-process-head">
                    <span className="spot-chat-status-process-icon" aria-hidden="true">
                      {processIcon(process.iconKey)}
                    </span>
                    <strong>{process.label}</strong>
                  </div>
                  <span>{process.status}</span>
                </div>
                <p>{process.summary}</p>
              </div>
            ))}
          </div>
        ) : null}
        {selectedSkills.length ? (
          <div className="spot-chat-status-skill-shell" aria-label="Selected skill guidance">
            <div className="spot-chat-status-skill-copy">
              <span>Skill guidance</span>
              <p>
                Skill guidance was resolved before authoring. Open a skill to inspect
                the exact procedure attached to this run.
              </p>
            </div>
            <div className="spot-chat-status-skill-row">
              {selectedSkills.map((skill) => (
                <button
                  key={skill.skillHash}
                  type="button"
                  className={`spot-chat-status-skill-chip ${
                    activeSkill?.skillHash === skill.skillHash ? "is-active" : ""
                  }`}
                  onClick={() => setActiveSkillHash(skill.skillHash)}
                >
                  {skill.name}
                </button>
              ))}
            </div>
            {activeSkill ? (
              <div className="spot-chat-status-skill-detail">
                <div className="spot-chat-status-skill-detail-head">
                  <div>
                    <strong>{activeSkill.name}</strong>
                    <p>{activeSkill.description}</p>
                  </div>
                  {activeSkillMeta.length ? (
                    <span className="spot-chat-status-chip is-muted">
                      {activeSkillMeta.join(" · ")}
                    </span>
                  ) : null}
                </div>
                <p className="spot-chat-status-skill-note">
                  {activeSkill.matchRationale}
                </p>
                {skillDetailsLoading && !activeSkillContext ? (
                  <p className="spot-chat-status-skill-note">
                    Loading live skill detail...
                  </p>
                ) : null}
                {activeSkillContext?.error ? (
                  <p className="spot-chat-status-skill-note">
                    Live skill detail unavailable: {activeSkillContext.error}
                  </p>
                ) : null}
                {activeSkillMarkdown ? (
                  <pre className="spot-chat-status-skill-markdown">
                    {activeSkillMarkdown}
                  </pre>
                ) : null}
              </div>
            ) : null}
          </div>
        ) : null}
        {livePreview?.content ? (
          <div
            className={`spot-chat-status-preview ${
              previewMode(livePreview) === "code"
                ? "is-code-preview"
                : "is-stream-preview"
            }`}
            aria-live="polite"
            aria-label={renderPreviewAriaLabel(livePreview)}
          >
            <div className="spot-chat-status-preview-head">
              <span>{livePreview.label}</span>
              <span>
                {formatChatExecutionPreviewPhase(livePreview)}
              </span>
            </div>
            <div className="spot-chat-status-preview-meta">
              <span>{formatPreviewStats(livePreview.content)}</span>
              {previewMode(livePreview) === "code" ? (
                <span>Scroll to inspect the full artifact.</span>
              ) : null}
            </div>
            <pre tabIndex={0}>
              <code>{livePreview.content}</code>
            </pre>
          </div>
        ) : null}
        {codePreview?.content && codePreview.content !== livePreview?.content ? (
          <div
            className={`spot-chat-status-preview ${
              previewMode(codePreview) === "code"
                ? "is-code-preview"
                : "is-stream-preview"
            }`}
            aria-live="polite"
            aria-label={renderPreviewAriaLabel(codePreview)}
          >
            <div className="spot-chat-status-preview-head">
              <span>{codePreview.label}</span>
              <span>
                {formatChatExecutionPreviewPhase(codePreview)}
              </span>
            </div>
            <div className="spot-chat-status-preview-meta">
              <span>{formatPreviewStats(codePreview.content)}</span>
              {previewMode(codePreview) === "code" ? (
                <span>Scroll to inspect the full artifact.</span>
              ) : null}
            </div>
            <pre tabIndex={0}>
              <code>{codePreview.content}</code>
            </pre>
          </div>
        ) : null}
      </div>
    </section>
  );
}
