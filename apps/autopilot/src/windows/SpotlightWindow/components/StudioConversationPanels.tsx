import { icons } from "./Icons";

type StudioConversationWelcomeProps = {
  onSuggestionClick: (text: string) => void;
};

type StudioRunStateCardProps = {
  tone?: "active" | "error";
  title: string;
  detail: string;
};

const suggestionPrompts = [
  "Create a markdown artifact that captures our launch checklist and open questions",
  "Create an interactive HTML artifact that explains a product rollout with charts",
  "Investigate the request first and stay conversational unless an artifact is justified",
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
}: StudioRunStateCardProps) {
  const isError = tone === "error";

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
      </div>
    </section>
  );
}
