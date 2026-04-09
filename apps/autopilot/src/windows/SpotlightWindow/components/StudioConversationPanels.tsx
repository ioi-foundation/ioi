import { icons } from "./Icons";
import { formatStudioExecutionPreviewPhase } from "./studioExecutionPreview";

type StudioConversationWelcomeProps = {
  onSuggestionClick: (text: string) => void;
};

type StudioRunStateCardProps = {
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
  }>;
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

const suggestionPrompts = [
  "Investigate the request first and stay conversational unless an artifact is justified",
  "Create an interactive HTML artifact that explains a product rollout with charts",
  "Create a markdown artifact that captures our launch checklist and open questions",
  "Create a workspace artifact for a billing settings experience with verification steps",
];

const operatingLenses = [
  {
    label: "Route",
    detail: "Choose conversation, widget, visualizer, or artifact from the requested outcome.",
  },
  {
    label: "Materialize",
    detail: "Turn artifact requests into renderable files and renderer sessions, not vague promises.",
  },
  {
    label: "Verify",
    detail: "Let receipts and verification decide what Studio claims back to the user.",
  },
];

export function StudioConversationWelcome({
  onSuggestionClick,
}: StudioConversationWelcomeProps) {
  return (
    <section className="spot-studio-welcome" aria-label="Studio welcome">
      <div className="spot-studio-welcome-copy">
        <span className="spot-studio-welcome-kicker">Outcome control plane</span>
        <h2>Start with the outcome, not the implementation surface.</h2>
        <p>
          Studio routes each request into the right delivery path. If the work
          should become a durable product, it opens an artifact with the proper
          renderer and evidence rail. If not, it stays in conversation.
        </p>
      </div>

      <div className="spot-studio-lens-grid">
        {operatingLenses.map((lens) => (
          <div key={lens.label} className="spot-studio-lens-card">
            <strong>{lens.label}</strong>
            <span>{lens.detail}</span>
          </div>
        ))}
      </div>

      <div className="spot-studio-suggestion-row">
        {suggestionPrompts.map((prompt) => (
          <button
            key={prompt}
            type="button"
            className="spot-studio-suggestion"
            onClick={() => onSuggestionClick(prompt)}
          >
            {prompt}
          </button>
        ))}
      </div>
    </section>
  );
}

export function StudioRunStateCard({
  tone = "active",
  title,
  detail,
  metrics = null,
  processes = [],
  livePreview = null,
  codePreview = null,
}: StudioRunStateCardProps) {
  const isError = tone === "error";

  const renderPreviewAriaLabel = (
    preview: NonNullable<StudioRunStateCardProps["livePreview"]>,
  ) =>
    `${preview.label}. ${formatStudioExecutionPreviewPhase(preview)}. ${preview.content}`;

  return (
    <section
      className={`spot-studio-status-card ${isError ? "is-error" : "is-active"}`}
      aria-live="polite"
    >
      <div className="spot-studio-status-icon">
        {isError ? icons.alert : icons.spinner}
      </div>
      <div className="spot-studio-status-copy">
        <strong>{title}</strong>
        <p>{detail}</p>
        {metrics ? (
          <div className="spot-studio-status-metrics">
            {metrics.stage ? (
              <span className="spot-studio-status-chip">{metrics.stage}</span>
            ) : null}
            {metrics.activeRole ? (
              <span className="spot-studio-status-chip is-muted">
                {metrics.activeRole}
              </span>
            ) : null}
            {metrics.progress ? (
              <span className="spot-studio-status-chip is-muted">
                {metrics.progress}
              </span>
            ) : null}
            {metrics.verification ? (
              <span className="spot-studio-status-chip is-muted">
                {metrics.verification}
              </span>
            ) : null}
          </div>
        ) : null}
        {processes.length ? (
          <div className="spot-studio-status-process-list" aria-label="Thinking processes">
            {processes.map((process) => (
              <div
                key={process.id}
                className={`spot-studio-status-process ${
                  process.isActive ? "is-active" : ""
                }`}
                aria-label={`${process.label}. ${process.status}. ${process.summary}`}
              >
                <div className="spot-studio-status-process-row">
                  <strong>{process.label}</strong>
                  <span>{process.status}</span>
                </div>
                <p>{process.summary}</p>
              </div>
            ))}
          </div>
        ) : null}
        {livePreview?.content ? (
          <div
            className="spot-studio-status-preview"
            aria-live="polite"
            aria-label={renderPreviewAriaLabel(livePreview)}
          >
            <div className="spot-studio-status-preview-head">
              <span>{livePreview.label}</span>
              <span>
                {formatStudioExecutionPreviewPhase(livePreview)}
              </span>
            </div>
            <pre>
              <code aria-label={livePreview.content}>{livePreview.content}</code>
            </pre>
          </div>
        ) : null}
        {codePreview?.content && codePreview.content !== livePreview?.content ? (
          <div
            className="spot-studio-status-preview"
            aria-live="polite"
            aria-label={renderPreviewAriaLabel(codePreview)}
          >
            <div className="spot-studio-status-preview-head">
              <span>{codePreview.label}</span>
              <span>
                {formatStudioExecutionPreviewPhase(codePreview)}
              </span>
            </div>
            <pre>
              <code aria-label={codePreview.content}>{codePreview.content}</code>
            </pre>
          </div>
        ) : null}
      </div>
    </section>
  );
}
