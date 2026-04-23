import clsx from "clsx";
import type { WorkspaceOperatorPaneProps, WorkspaceOperatorSurface } from "../types";

const ORDER: WorkspaceOperatorSurface[] = [
  "chat",
  "workflows",
  "runs",
  "artifacts",
  "policy",
  "connections",
];

function labelForTone(tone: "default" | "attention" | "success" | undefined) {
  return clsx("workspace-chip", tone && `is-${tone}`);
}

export function WorkspaceOperatorPane({ model = null }: WorkspaceOperatorPaneProps) {
  return (
    <section className="workspace-pane workspace-operator-pane">
      <header className="workspace-pane-header">
        <div className="workspace-pane-header-leading">
          <div>
            <span className="workspace-pane-eyebrow">IOI</span>
            <h3>IOI</h3>
          </div>
        </div>
      </header>

      {model?.views.length ? (
        <div className="workspace-operator-sections" aria-label="IOI views">
          {ORDER.map((surface) => {
            const view = model.views.find((candidate) => candidate.id === surface);
            if (!view) {
              return null;
            }
            const isActive = model.activeSurface === surface;

            return (
              <section
                key={surface}
                className={clsx(
                  "workspace-operator-section",
                  isActive && "is-active",
                )}
              >
                <button
                  type="button"
                  className="workspace-operator-section-header"
                  onClick={() => model.onSelectSurface(surface)}
                  aria-expanded={isActive}
                >
                  <div className="workspace-operator-section-copy">
                    <strong>{view.title}</strong>
                    {view.eyebrow ? (
                      <span className="workspace-pane-caption">{view.eyebrow}</span>
                    ) : null}
                  </div>
                  <span className="workspace-operator-section-indicator" aria-hidden="true">
                    {isActive ? "−" : "+"}
                  </span>
                </button>

                {isActive ? (
                  <div className="workspace-operator-view">
                    <p className="workspace-operator-description">{view.description}</p>

                    {view.summaryItems.length > 0 ? (
                      <div className="workspace-pane-meta workspace-operator-summary">
                        {view.summaryItems.map((item) => (
                          <span key={`${view.id}:${item.label}`} className={labelForTone(item.tone)}>
                            {item.label}: {item.value}
                          </span>
                        ))}
                      </div>
                    ) : null}

                    <div className="workspace-pane-action-stack">
                      {view.actions.map((action) => (
                        <button
                          key={action.id}
                          type="button"
                          className="workspace-pane-button workspace-pane-button--full"
                          onClick={action.onSelect}
                          title={action.description ?? undefined}
                        >
                          {action.label}
                        </button>
                      ))}
                    </div>
                  </div>
                ) : null}
              </section>
            );
          })}
        </div>
      ) : (
        <p className="workspace-pane-message">
          The IOI container is wired, but no runtime-backed views are available yet.
        </p>
      )}
    </section>
  );
}
