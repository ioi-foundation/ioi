import type {
  LocalEngineStagedOperation,
  PlanSummary,
  SourceBrowseRow,
  SourceSearchRow,
  ThoughtAgentSummary,
} from "../../../../types";
import type { ChatPlaybookRunRecord } from "../../../ChatShellWindow/hooks/useChatPlaybookRuns";
import { icons } from "../Icons";
import { LivePlaybookRunsSection } from "../LivePlaybookRunsSection";
import { LiveStagedOperationsSection } from "../LiveStagedOperationsSection";
import { workerInsightForPlanSummary } from "../artifactHubWorkerInsight";
import { ArtifactHubEmptyState } from "./shared/ArtifactHubEmptyState";

function compactThoughtText(value: string, maxChars = 120): string {
  const compact = value.replace(/\s+/g, " ").trim();
  if (compact.length <= maxChars) {
    return compact;
  }
  return `${compact.slice(0, maxChars - 1).trim()}…`;
}

function sourceHostname(url: string): string {
  try {
    return new URL(url).hostname.replace(/^www\./, "");
  } catch {
    return url.replace(/^https?:\/\//, "").split(/[/?#]/)[0] || url;
  }
}

export function ThoughtsView({
  planSummary,
  searches,
  browses,
  thoughtAgents,
  playbookRuns,
  playbookRunsLoading,
  playbookRunsBusyRunId,
  playbookRunsMessage,
  playbookRunsError,
  stagedOperations,
  stagedOperationsLoading,
  stagedOperationsBusyId,
  stagedOperationsMessage,
  stagedOperationsError,
  onRetryPlaybookRun,
  onResumePlaybookRun,
  onDismissPlaybookRun,
  onMessageWorkerSession,
  onStopWorkerSession,
  onPromoteRunResult,
  onPromoteStepResult,
  onPromoteStagedOperation,
  onRemoveStagedOperation,
  onLoadSession,
  onOpenArtifact,
  openExternalUrl,
}: {
  planSummary: PlanSummary | null;
  searches: SourceSearchRow[];
  browses: SourceBrowseRow[];
  thoughtAgents: ThoughtAgentSummary[];
  playbookRuns: ChatPlaybookRunRecord[];
  playbookRunsLoading: boolean;
  playbookRunsBusyRunId: string | null;
  playbookRunsMessage: string | null;
  playbookRunsError: string | null;
  stagedOperations: LocalEngineStagedOperation[];
  stagedOperationsLoading: boolean;
  stagedOperationsBusyId: string | null;
  stagedOperationsMessage: string | null;
  stagedOperationsError: string | null;
  onRetryPlaybookRun?: (runId: string) => void;
  onResumePlaybookRun?: (runId: string, stepId?: string | null) => void;
  onDismissPlaybookRun?: (runId: string) => void;
  onMessageWorkerSession?: (
    runId: string,
    sessionId: string,
    message: string,
  ) => void;
  onStopWorkerSession?: (runId: string, sessionId: string) => void;
  onPromoteRunResult?: (runId: string) => void;
  onPromoteStepResult?: (runId: string, stepId: string) => void;
  onPromoteStagedOperation?: (operationId: string) => void;
  onRemoveStagedOperation?: (operationId: string) => void;
  onLoadSession?: (sessionId: string) => void;
  onOpenArtifact?: (artifactId: string) => void;
  openExternalUrl: (url: string) => Promise<void>;
}) {
  const hasLiveDelegation =
    playbookRuns.length > 0 ||
    playbookRunsLoading ||
    !!playbookRunsMessage ||
    !!playbookRunsError;
  const hasStagedOperations =
    stagedOperations.length > 0 ||
    stagedOperationsLoading ||
    !!stagedOperationsMessage ||
    !!stagedOperationsError;
  const researchRows = [
    ...searches.map((entry, index) => ({
      id: `thought-search-${index}`,
      icon: icons.search,
      kind: "Searched web",
      title: compactThoughtText(entry.query),
      meta: `${entry.resultCount} result${entry.resultCount === 1 ? "" : "s"}`,
      url: null as string | null,
    })),
    ...browses.map((entry, index) => ({
      id: `thought-browse-${index}`,
      icon: icons.globe,
      kind: "Browsed source",
      title: compactThoughtText(sourceHostname(entry.url)),
      meta: "Opened",
      url: entry.url,
    })),
  ];
  const hasContent =
    searches.length > 0 ||
    browses.length > 0 ||
    thoughtAgents.length > 0 ||
    hasLiveDelegation ||
    hasStagedOperations;

  if (!hasContent) {
    return (
      <ArtifactHubEmptyState message="No worklog entries were captured for this turn." />
    );
  }

  return (
    <div className="artifact-hub-thoughts">
      <LivePlaybookRunsSection
        runs={playbookRuns}
        loading={playbookRunsLoading}
        busyRunId={playbookRunsBusyRunId}
        message={playbookRunsMessage}
        error={playbookRunsError}
        onOpenArtifact={onOpenArtifact}
        onRetryRun={onRetryPlaybookRun}
        onResumeRun={onResumePlaybookRun}
        onDismissRun={onDismissPlaybookRun}
        onLoadSession={onLoadSession}
        onMessageWorker={onMessageWorkerSession}
        onStopWorker={onStopWorkerSession}
        onPromoteRunResult={onPromoteRunResult}
        onPromoteStepResult={onPromoteStepResult}
      />

      <LiveStagedOperationsSection
        operations={stagedOperations}
        loading={stagedOperationsLoading}
        busyOperationId={stagedOperationsBusyId}
        message={stagedOperationsMessage}
        error={stagedOperationsError}
        onPromoteOperation={onPromoteStagedOperation}
        onRemoveOperation={onRemoveStagedOperation}
      />

      {researchRows.length > 0 ? (
        <section className="thoughts-section thoughts-section--compact">
          <div className="thoughts-agent-header">
            <span className="thoughts-agent-dot" />
            <span className="thoughts-agent-name">Autopilot</span>
            <span className="thoughts-agent-role">Research</span>
          </div>
          <div className="thoughts-items thoughts-items-compact">
            {researchRows.map((entry) => (
              <div
                className="thoughts-item thoughts-item-compact"
                key={entry.id}
              >
                <span className="thoughts-item-icon">{entry.icon}</span>
                <div className="thoughts-item-main">
                  <span className="thoughts-item-kind">{entry.kind}</span>
                  {entry.url ? (
                    <button
                      className="thoughts-item-link"
                      onClick={() => void openExternalUrl(entry.url as string)}
                      type="button"
                      title={entry.url}
                    >
                      {entry.title}
                    </button>
                  ) : (
                    <span className="thoughts-item-query">{entry.title}</span>
                  )}
                </div>
                <span className="thoughts-item-count">{entry.meta}</span>
              </div>
            ))}
          </div>
        </section>
      ) : null}

      {thoughtAgents.map((agent, index) => {
        const insight = workerInsightForPlanSummary(agent, planSummary);
        const isActive = planSummary?.activeWorkerLabel === agent.agentLabel;

        return (
          <section
            className={`thoughts-section worker-card ${isActive ? "is-active" : ""}`}
            key={`thought-agent-${agent.stepIndex}-${index}`}
          >
            <div className="thoughts-agent-header">
              <span className="thoughts-agent-dot" />
              <span className="thoughts-agent-name">{agent.agentLabel}</span>
              {agent.agentRole ? (
                <span className="thoughts-agent-role">{agent.agentRole}</span>
              ) : null}
            </div>
            <div className="worker-card-meta">
              <span className="worker-card-chip">step {agent.stepIndex}</span>
              {isActive ? (
                <span className="worker-card-chip is-emphasis">Active</span>
              ) : null}
              {planSummary?.branchCount ? (
                <span className="worker-card-chip">
                  {planSummary.branchCount} branches
                </span>
              ) : null}
            </div>
            <div className="worker-card-grid">
              <div className="worker-card-block">
                <span>Objective</span>
                <p>{agent.agentRole || `Advance step ${agent.stepIndex}`}</p>
              </div>
              {agent.notes[0] ? (
                <div className="worker-card-block">
                  <span>Current action</span>
                  <p>{agent.notes[0]}</p>
                </div>
              ) : null}
              {insight ? (
                <div className="worker-card-block is-emphasis">
                  <span>{insight.label}</span>
                  <p>{insight.text}</p>
                </div>
              ) : null}
            </div>
            <div className="thoughts-notes">
              {agent.notes.slice(1).map((note, noteIndex) => (
                <div
                  className="thoughts-note"
                  key={`thought-note-${agent.stepIndex}-${noteIndex + 1}`}
                >
                  {note}
                </div>
              ))}
            </div>
          </section>
        );
      })}
    </div>
  );
}
