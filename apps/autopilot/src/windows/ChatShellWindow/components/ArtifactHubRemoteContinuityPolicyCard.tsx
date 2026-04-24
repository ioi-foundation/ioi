import { openReviewSettings } from "../../../services/reviewNavigation";
import type { ArtifactHubViewKey } from "../../../types";
import { humanizeStatus } from "./ArtifactHubViewHelpers";
import type { ChatRemoteContinuityLaunchRequest } from "./artifactHubRemoteContinuityModel";
import type {
  RemoteContinuityPolicyAction,
  RemoteContinuityPolicyOverview,
} from "./artifactHubRemoteContinuityPolicyModel";

export function RemoteContinuityPolicyCard({
  title,
  overview,
  onRequestReplLaunch,
  onOpenView,
  onRefreshServer,
}: {
  title: string;
  overview: RemoteContinuityPolicyOverview;
  onRequestReplLaunch?: (request: ChatRemoteContinuityLaunchRequest) => void;
  onOpenView?: (view: ArtifactHubViewKey) => void;
  onRefreshServer?: () => Promise<unknown>;
}) {
  const runAction = (action: RemoteContinuityPolicyAction) => {
    switch (action.kind) {
      case "launch_repl":
        onRequestReplLaunch?.(action.launchRequest);
        break;
      case "open_view":
        onOpenView?.(action.view);
        break;
      case "open_studio_settings":
        void openReviewSettings();
        break;
      case "refresh_server":
        void onRefreshServer?.();
        break;
      default:
        break;
    }
  };

  const canRunAction = (
    action: RemoteContinuityPolicyAction | null,
  ): boolean => {
    if (!action) {
      return false;
    }
    switch (action.kind) {
      case "launch_repl":
        return Boolean(onRequestReplLaunch);
      case "open_view":
        return Boolean(onOpenView);
      case "open_studio_settings":
        return true;
      case "refresh_server":
        return Boolean(onRefreshServer);
      default:
        return false;
    }
  };

  return (
    <section
      className={`artifact-hub-permissions-card ${
        overview.tone === "review" || overview.tone === "attention"
          ? "artifact-hub-permissions-card--alert"
          : ""
      }`}
    >
      <div className="artifact-hub-permissions-card__head">
        <strong>{title}</strong>
        <span className="artifact-hub-policy-pill">
          {humanizeStatus(overview.tone)}
        </span>
      </div>
      <p>{overview.detail}</p>
      <div className="artifact-hub-files-meta artifact-hub-permissions__meta">
        {overview.checklist.map((item) => (
          <span key={item}>{item}</span>
        ))}
        {overview.queuedActions.length > 1 ? (
          <span>{overview.queuedActions.length} queued continuity steps</span>
        ) : null}
      </div>
      {overview.primaryAction ? (
        <p className="artifact-hub-generic-summary">
          {overview.primaryAction.detail}
        </p>
      ) : null}
      {overview.queuedActions.length > 1 ? (
        <div className="artifact-hub-permissions-list">
          {overview.queuedActions.map((action, index) => (
            <div
              key={`${action.kind}:${"launchRequest" in action ? action.launchRequest.sessionId : action.label}:${index}`}
              className="artifact-hub-permissions-list__row"
            >
              <div>
                <strong>{action.label}</strong>
                <p>{action.detail}</p>
              </div>
              <button
                type="button"
                className="artifact-hub-open-btn secondary"
                disabled={!canRunAction(action)}
                onClick={() => runAction(action)}
              >
                Run step
              </button>
            </div>
          ))}
        </div>
      ) : null}
      <div className="artifact-hub-permissions-card__actions">
        {overview.primaryAction ? (
          <button
            type="button"
            className="artifact-hub-open-btn"
            disabled={!canRunAction(overview.primaryAction)}
            onClick={() => runAction(overview.primaryAction!)}
          >
            {overview.primaryAction.label}
          </button>
        ) : null}
        {overview.secondaryAction ? (
          <button
            type="button"
            className="artifact-hub-open-btn secondary"
            disabled={!canRunAction(overview.secondaryAction)}
            onClick={() => runAction(overview.secondaryAction!)}
          >
            {overview.secondaryAction.label}
          </button>
        ) : null}
      </div>
    </section>
  );
}
