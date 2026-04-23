import { useCallback, useEffect, useState } from "react";
import { humanize } from "./capabilities/model";
import { formatSettingsTime } from "./ChatSettingsView.shared";
import type { SettingsViewBodyView } from "./ChatSettingsView.types";
import type {
  SessionCompactionPolicy,
  SessionCompactionPruneDecision,
  SessionCompactionSnapshot,
  TeamMemorySyncSnapshot,
} from "../../../types";

function defaultCompactionPolicy(): SessionCompactionPolicy {
  return {
    carryPinnedOnly: false,
    preserveChecklistState: true,
    preserveBackgroundTasks: true,
    preserveLatestOutputExcerpt: true,
    preserveGovernanceBlockers: true,
    aggressiveTranscriptPruning: false,
  };
}

function compactionPoliciesMatch(
  left: SessionCompactionPolicy,
  right: SessionCompactionPolicy,
): boolean {
  return (
    left.carryPinnedOnly === right.carryPinnedOnly &&
    left.preserveChecklistState === right.preserveChecklistState &&
    left.preserveBackgroundTasks === right.preserveBackgroundTasks &&
    left.preserveLatestOutputExcerpt === right.preserveLatestOutputExcerpt &&
    left.preserveGovernanceBlockers === right.preserveGovernanceBlockers &&
    left.aggressiveTranscriptPruning === right.aggressiveTranscriptPruning
  );
}

function compactionPolicySummary(policy: SessionCompactionPolicy): string {
  const bits = [
    policy.carryPinnedOnly ? "Pinned files only" : "Pinned + explicit file context",
    policy.aggressiveTranscriptPruning
      ? "Aggressive transcript pruning"
      : "Transcript summary retained",
  ];
  if (policy.preserveChecklistState) {
    bits.push("Checklist retained");
  }
  if (policy.preserveBackgroundTasks) {
    bits.push("Background tasks retained");
  }
  if (policy.preserveLatestOutputExcerpt) {
    bits.push("Latest output retained");
  }
  if (policy.preserveGovernanceBlockers) {
    bits.push("Blockers retained");
  }
  return bits.join(" · ");
}

function compactionDecisionCounts(
  decisions: SessionCompactionPruneDecision[] | undefined | null,
): Record<"carry_forward" | "retained_summary" | "pruned", number> {
  return (decisions ?? []).reduce(
    (acc: Record<"carry_forward" | "retained_summary" | "pruned", number>, decision) => {
      acc[decision.disposition] += 1;
      return acc;
    },
    {
      carry_forward: 0,
      retained_summary: 0,
      pruned: 0,
    },
  );
}

function compactionResumeSafetyLabel(status?: string | null): string {
  return status === "degraded" ? "Degraded resume" : "Protected resume";
}

export function SettingsKnowledgeSection({
  view,
}: {
  view: SettingsViewBodyView;
}) {
  const {
    runtime,
    knowledgeCollections,
    knowledgeLoading,
    knowledgeBusy,
    knowledgeError,
    setKnowledgeError,
    knowledgeMessage,
    knowledgeCollectionName,
    setKnowledgeCollectionName,
    knowledgeCollectionDescription,
    setKnowledgeCollectionDescription,
    setSelectedKnowledgeCollectionId,
    knowledgeEntryTitle,
    setKnowledgeEntryTitle,
    knowledgeEntryContent,
    setKnowledgeEntryContent,
    knowledgeImportPath,
    setKnowledgeImportPath,
    knowledgeSourceUri,
    setKnowledgeSourceUri,
    knowledgeSourceInterval,
    setKnowledgeSourceInterval,
    knowledgeSearchQuery,
    setKnowledgeSearchQuery,
    knowledgeSearchResults,
    setKnowledgeSearchResults,
    knowledgeSearchLoading,
    setKnowledgeSearchLoading,
    knowledgeEntryLoading,
    setKnowledgeEntryLoading,
    selectedKnowledgeEntryContent,
    setSelectedKnowledgeEntryContent,
    selectedKnowledgeCollection,
    runKnowledgeAction,
  } = view;

  const [teamMemorySnapshot, setTeamMemorySnapshot] =
    useState<TeamMemorySyncSnapshot | null>(null);
  const [teamMemoryStatus, setTeamMemoryStatus] = useState<
    "idle" | "loading" | "ready" | "error" | "syncing" | "forgetting"
  >("idle");
  const [teamMemoryError, setTeamMemoryError] = useState<string | null>(null);
  const [includeGovernanceCritical, setIncludeGovernanceCritical] = useState(false);
  const [compactionSnapshot, setCompactionSnapshot] =
    useState<SessionCompactionSnapshot | null>(null);
  const [compactionStatus, setCompactionStatus] = useState<
    "idle" | "loading" | "ready" | "error" | "compacting"
  >("idle");
  const [compactionError, setCompactionError] = useState<string | null>(null);
  const [compactionPolicy, setCompactionPolicy] = useState<SessionCompactionPolicy>(
    defaultCompactionPolicy,
  );

  const refreshTeamMemory = useCallback(async () => {
    setTeamMemoryStatus((current) => (current === "ready" ? "loading" : current));
    setTeamMemoryError(null);
    try {
      const snapshot = await runtime.getTeamMemorySnapshot();
      setTeamMemorySnapshot(snapshot);
      setTeamMemoryStatus("ready");
      return snapshot;
    } catch (nextError) {
      const message =
        nextError instanceof Error ? nextError.message : String(nextError ?? "");
      setTeamMemorySnapshot(null);
      setTeamMemoryStatus("error");
      setTeamMemoryError(message);
      throw nextError;
    }
  }, [runtime]);

  const syncTeamMemory = useCallback(async () => {
    setTeamMemoryStatus("syncing");
    setTeamMemoryError(null);
    try {
      const snapshot = await runtime.syncTeamMemory({
        actorLabel: "Chat",
        actorRole: "operator",
        includeGovernanceCritical,
      });
      setTeamMemorySnapshot(snapshot);
      setTeamMemoryStatus("ready");
      return snapshot;
    } catch (nextError) {
      const message =
        nextError instanceof Error ? nextError.message : String(nextError ?? "");
      setTeamMemoryStatus("error");
      setTeamMemoryError(message);
      throw nextError;
    }
  }, [includeGovernanceCritical, runtime]);

  const forgetTeamMemory = useCallback(
    async (entryId: string) => {
      setTeamMemoryStatus("forgetting");
      setTeamMemoryError(null);
      try {
        const snapshot = await runtime.forgetTeamMemoryEntry(entryId);
        setTeamMemorySnapshot(snapshot);
        setTeamMemoryStatus("ready");
        return snapshot;
      } catch (nextError) {
        const message =
          nextError instanceof Error ? nextError.message : String(nextError ?? "");
        setTeamMemoryStatus("error");
        setTeamMemoryError(message);
        throw nextError;
      }
    },
    [runtime],
  );

  const refreshCompaction = useCallback(
    async (nextPolicy?: SessionCompactionPolicy) => {
      const effectivePolicy = nextPolicy ?? compactionPolicy;
      setCompactionStatus((current) => (current === "ready" ? "loading" : current));
      setCompactionError(null);
      try {
        const snapshot = await runtime.getSessionCompactionSnapshot(effectivePolicy);
        const activePolicy = snapshot.policyForActive ?? effectivePolicy;
        setCompactionPolicy(activePolicy);
        setCompactionSnapshot(snapshot);
        setCompactionStatus("ready");
        return snapshot;
      } catch (nextError) {
        const message =
          nextError instanceof Error ? nextError.message : String(nextError ?? "");
        setCompactionSnapshot(null);
        setCompactionStatus("error");
        setCompactionError(message);
        throw nextError;
      }
    },
    [compactionPolicy, runtime],
  );

  const compactSession = useCallback(
    async (nextPolicy?: SessionCompactionPolicy) => {
      const effectivePolicy = nextPolicy ?? compactionPolicy;
      setCompactionStatus("compacting");
      setCompactionError(null);
      try {
        const snapshot = await runtime.compactSession({
          policy: effectivePolicy,
        });
        const activePolicy = snapshot.policyForActive ?? effectivePolicy;
        setCompactionPolicy(activePolicy);
        setCompactionSnapshot(snapshot);
        setCompactionStatus("ready");
        return snapshot;
      } catch (nextError) {
        const message =
          nextError instanceof Error ? nextError.message : String(nextError ?? "");
        setCompactionStatus("error");
        setCompactionError(message);
        throw nextError;
      }
    },
    [compactionPolicy, runtime],
  );

  const applyRecommendedCompactionPolicy = useCallback(async () => {
    const nextPolicy = compactionSnapshot?.recommendationForActive?.recommendedPolicy;
    if (!nextPolicy) {
      return null;
    }
    setCompactionPolicy(nextPolicy);
    return refreshCompaction(nextPolicy);
  }, [compactionSnapshot?.recommendationForActive?.recommendedPolicy, refreshCompaction]);

  const resetCompactionPolicy = useCallback(async () => {
    const nextPolicy = defaultCompactionPolicy();
    setCompactionPolicy(nextPolicy);
    return refreshCompaction(nextPolicy);
  }, [refreshCompaction]);

  useEffect(() => {
    setTeamMemoryStatus("loading");
    setTeamMemoryError(null);
    void runtime
      .getTeamMemorySnapshot()
      .then((snapshot: TeamMemorySyncSnapshot) => {
        setTeamMemorySnapshot(snapshot);
        setTeamMemoryStatus("ready");
      })
      .catch((nextError: unknown) => {
        setTeamMemorySnapshot(null);
        setTeamMemoryStatus("error");
        setTeamMemoryError(
          nextError instanceof Error ? nextError.message : String(nextError ?? ""),
        );
      });
  }, [runtime]);

  useEffect(() => {
    const initialPolicy = defaultCompactionPolicy();
    setCompactionStatus("loading");
    setCompactionError(null);
    void runtime
      .getSessionCompactionSnapshot(initialPolicy)
      .then((snapshot: SessionCompactionSnapshot) => {
        setCompactionPolicy(snapshot.policyForActive ?? initialPolicy);
        setCompactionSnapshot(snapshot);
        setCompactionStatus("ready");
      })
      .catch((nextError: unknown) => {
        setCompactionSnapshot(null);
        setCompactionStatus("error");
        setCompactionError(
          nextError instanceof Error ? nextError.message : String(nextError ?? ""),
        );
      });
  }, [runtime]);

  const compactionRecommendation = compactionSnapshot?.recommendationForActive ?? null;
  const compactionPreview = compactionSnapshot?.previewForActive ?? null;
  const latestCompaction = compactionSnapshot?.latestForActive ?? null;
  const durabilityPortfolio = compactionSnapshot?.durabilityPortfolio ?? null;
  const activeCompactionPolicy =
    compactionPreview?.policy ??
    compactionSnapshot?.policyForActive ??
    compactionPolicy;
  const recommendedCompactionPolicy =
    compactionRecommendation?.recommendedPolicy ?? null;
  const recommendedPolicyMatches = recommendedCompactionPolicy
    ? compactionPoliciesMatch(activeCompactionPolicy, recommendedCompactionPolicy)
    : false;
  const previewDecisionCounts = compactionDecisionCounts(
    compactionPreview?.pruneDecisions,
  );
  const latestDecisionCounts = compactionDecisionCounts(
    latestCompaction?.pruneDecisions,
  );
  const compactionBusy = compactionStatus === "compacting";
  const compactionAutoState = compactionRecommendation?.shouldCompact
    ? "Recommended now"
    : latestCompaction?.mode === "auto"
      ? "Recently auto-compacted"
      : "Monitoring";

  return (
    <div className="chat-settings-stack">
      <article className="chat-settings-card">
        <div className="chat-settings-card-head">
          <div>
            <span className="chat-settings-card-eyebrow">Team memory</span>
            <h2>Scoped shared sync</h2>
          </div>
          <span className="chat-settings-pill">
            {teamMemoryStatus === "syncing" || teamMemoryStatus === "forgetting"
              ? "Updating"
              : teamMemorySnapshot
                ? `${teamMemorySnapshot.entryCount} in scope`
                : "No scope"}
          </span>
        </div>
        <p className="chat-settings-body">
          Promote carried-forward session memory into a scoped multi-actor
          ledger. Governance-critical blocker context stays local by default,
          and sensitive values are redacted before shared sync.
        </p>
        <div className="chat-settings-summary-grid">
          <article className="chat-settings-subcard">
            <strong>Scope</strong>
            <span>{teamMemorySnapshot?.activeScopeLabel || "Current scope"}</span>
          </article>
          <article className="chat-settings-subcard">
            <strong>Redacted</strong>
            <span>{teamMemorySnapshot?.redactedEntryCount ?? 0}</span>
          </article>
          <article className="chat-settings-subcard">
            <strong>Review required</strong>
            <span>{teamMemorySnapshot?.reviewRequiredCount ?? 0}</span>
          </article>
          <article className="chat-settings-subcard">
            <strong>Updated</strong>
            <span>
              {teamMemorySnapshot
                ? formatSettingsTime(teamMemorySnapshot.generatedAtMs)
                : "Never"}
            </span>
          </article>
        </div>
        <p className="chat-settings-body">
          {teamMemorySnapshot?.summary ||
            "Sync the active retained session after a meaningful run to seed team memory."}
        </p>
        {teamMemoryError ? (
          <p className="chat-settings-error">{teamMemoryError}</p>
        ) : null}
        <label className="chat-settings-field">
          <span>Governance-critical sync policy</span>
          <select
            value={includeGovernanceCritical ? "include" : "keep_local"}
            onChange={(event) =>
              setIncludeGovernanceCritical(event.target.value === "include")
            }
          >
            <option value="keep_local">Keep blockers local</option>
            <option value="include">Sync blockers and mark for review</option>
          </select>
        </label>
        <div className="chat-settings-actions">
          <button
            type="button"
            className="chat-settings-secondary"
            disabled={teamMemoryStatus === "syncing" || teamMemoryStatus === "forgetting"}
            onClick={() => {
              void syncTeamMemory();
            }}
          >
            {teamMemoryStatus === "syncing" ? "Syncing..." : "Sync active session"}
          </button>
          <button
            type="button"
            className="chat-settings-secondary"
            disabled={teamMemoryStatus === "syncing" || teamMemoryStatus === "forgetting"}
            onClick={() => {
              void refreshTeamMemory();
            }}
          >
            Refresh team memory
          </button>
        </div>
        {teamMemorySnapshot?.entries.length ? (
          <div className="chat-settings-summary-grid">
            {teamMemorySnapshot.entries.map((entry) => (
              <article className="chat-settings-subcard" key={entry.entryId}>
                <strong>{entry.actorLabel}</strong>
                <span>{entry.scopeLabel}</span>
                <small>{formatSettingsTime(entry.syncedAtMs)}</small>
                <p>{entry.summary}</p>
                <small>{entry.reviewSummary}</small>
                <small>
                  Redactions: {entry.redaction.redactionCount} · Review:{" "}
                  {entry.syncStatus === "review_required" ? "yes" : "no"}
                </small>
                <div className="chat-settings-actions">
                  <button
                    type="button"
                    className="chat-settings-danger"
                    disabled={teamMemoryStatus === "syncing" || teamMemoryStatus === "forgetting"}
                    onClick={() => {
                      void forgetTeamMemory(entry.entryId);
                    }}
                  >
                    Forget entry
                  </button>
                </div>
              </article>
            ))}
          </div>
        ) : (
          <p className="chat-settings-body">
            No scoped team-memory entries are stored yet.
          </p>
        )}
      </article>

      <article className="chat-settings-card">
        <div className="chat-settings-card-head">
          <div>
            <span className="chat-settings-card-eyebrow">Compaction</span>
            <h2>Long-session durability</h2>
          </div>
          <span className="chat-settings-pill">
            {compactionBusy
              ? "Compacting"
              : compactionSnapshot
                ? `${compactionSnapshot.recordCount} records`
                : "No records"}
          </span>
        </div>
        <p className="chat-settings-body">
          Review the shared runtime compaction recommendation, inspect the
          resume-safety posture, and run the same retained-session compaction
          flow Chat now shares with the standalone REPL.
        </p>
        <div className="chat-settings-summary-grid">
          <article className="chat-settings-subcard">
            <strong>Active session</strong>
            <span>{compactionSnapshot?.activeSessionTitle || "No retained session"}</span>
          </article>
          <article className="chat-settings-subcard">
            <strong>Auto state</strong>
            <span>{compactionAutoState}</span>
          </article>
          <article className="chat-settings-subcard">
            <strong>Preview safety</strong>
            <span>
              {compactionPreview
                ? compactionResumeSafetyLabel(compactionPreview.resumeSafety.status)
                : "No preview"}
            </span>
          </article>
          <article className="chat-settings-subcard">
            <strong>Updated</strong>
            <span>
              {compactionSnapshot
                ? formatSettingsTime(compactionSnapshot.generatedAtMs)
                : "Never"}
            </span>
          </article>
        </div>
        <p className="chat-settings-body">
          {compactionRecommendation?.reasonLabels.length
            ? compactionRecommendation.reasonLabels.join(" · ")
            : "No compaction threshold is active right now. The runtime keeps watching transcript pressure, file-context size, and blocker or idle age."}
        </p>
        {durabilityPortfolio ? (
          <>
            <div className="chat-settings-summary-grid">
              <article className="chat-settings-subcard">
                <strong>Replay-ready sessions</strong>
                <span>
                  {durabilityPortfolio.replayReadySessionCount}/
                  {durabilityPortfolio.retainedSessionCount}
                </span>
              </article>
              <article className="chat-settings-subcard">
                <strong>Stale checkpoints</strong>
                <span>{durabilityPortfolio.staleCompactionCount}</span>
              </article>
              <article className="chat-settings-subcard">
                <strong>Degraded resumes</strong>
                <span>{durabilityPortfolio.degradedCompactionCount}</span>
              </article>
              <article className="chat-settings-subcard">
                <strong>Team-memory coverage</strong>
                <span>
                  {durabilityPortfolio.teamMemoryCoveredSessionCount} sessions ·{" "}
                  {durabilityPortfolio.teamMemoryReviewRequiredSessionCount} review
                </span>
              </article>
            </div>
            <p className="chat-settings-body">
              {durabilityPortfolio.coverageSummary}
            </p>
            <p className="chat-settings-body">
              {durabilityPortfolio.teamMemorySummary}
            </p>
            <p className="chat-settings-body">
              {durabilityPortfolio.attentionSummary}
            </p>
          </>
        ) : null}
        {compactionError ? (
          <p className="chat-settings-error">{compactionError}</p>
        ) : null}
        <div className="chat-settings-summary-grid">
          <article className="chat-settings-subcard">
            <strong>Current preview policy</strong>
            <span>{compactionPolicySummary(activeCompactionPolicy)}</span>
          </article>
          <article className="chat-settings-subcard">
            <strong>Recommended policy</strong>
            <span>
              {recommendedCompactionPolicy
                ? compactionPolicySummary(recommendedCompactionPolicy)
                : "Balanced default policy"}
            </span>
          </article>
          <article className="chat-settings-subcard">
            <strong>Preview shape</strong>
            <span>
              Carry {previewDecisionCounts.carry_forward} · Summary{" "}
              {previewDecisionCounts.retained_summary} · Pruned{" "}
              {previewDecisionCounts.pruned}
            </span>
          </article>
          <article className="chat-settings-subcard">
            <strong>Latest record</strong>
            <span>
              {latestCompaction
                ? `${humanize(latestCompaction.mode)} · ${compactionResumeSafetyLabel(
                    latestCompaction.resumeSafety.status,
                  )}`
                : "No retained compaction record"}
            </span>
          </article>
        </div>
        <div className="chat-settings-actions">
          <button
            type="button"
            className="chat-settings-secondary"
            disabled={
              compactionBusy || !compactionSnapshot?.activeSessionId || recommendedPolicyMatches
            }
            onClick={() => {
              void applyRecommendedCompactionPolicy();
            }}
          >
            {recommendedPolicyMatches ? "Recommended policy active" : "Apply recommended policy"}
          </button>
          <button
            type="button"
            className="chat-settings-secondary"
            disabled={compactionBusy || !compactionSnapshot?.activeSessionId}
            onClick={() => {
              void compactSession();
            }}
          >
            {compactionBusy ? "Compacting..." : "Run manual compaction"}
          </button>
          <button
            type="button"
            className="chat-settings-secondary"
            disabled={
              compactionBusy ||
              compactionPoliciesMatch(activeCompactionPolicy, defaultCompactionPolicy())
            }
            onClick={() => {
              void resetCompactionPolicy();
            }}
          >
            Reset defaults
          </button>
          <button
            type="button"
            className="chat-settings-secondary"
            disabled={compactionBusy}
            onClick={() => {
              void refreshCompaction();
            }}
          >
            Refresh compaction
          </button>
        </div>
        {compactionRecommendation?.recommendedPolicyReasonLabels.length ? (
          <div className="chat-settings-summary-grid">
            {compactionRecommendation.recommendedPolicyReasonLabels.map((reason) => (
              <article className="chat-settings-subcard" key={reason}>
                <strong>Recommendation reason</strong>
                <span>{reason}</span>
              </article>
            ))}
          </div>
        ) : null}
        {compactionRecommendation?.resumeSafeguardLabels.length ? (
          <div className="chat-settings-summary-grid">
            {compactionRecommendation.resumeSafeguardLabels.map((label) => (
              <article className="chat-settings-subcard" key={label}>
                <strong>Resume safeguard</strong>
                <span>{label}</span>
              </article>
            ))}
          </div>
        ) : null}
        {compactionPreview ? (
          <div className="chat-settings-summary-grid">
            <article className="chat-settings-subcard">
              <strong>Preview span</strong>
              <span>{compactionPreview.preCompactionSpan}</span>
            </article>
            <article className="chat-settings-subcard">
              <strong>Resume anchor</strong>
              <span>{compactionPreview.resumeAnchor}</span>
            </article>
            <article className="chat-settings-subcard">
              <strong>Preview summary</strong>
              <span>{compactionPreview.summary}</span>
            </article>
          </div>
        ) : (
          <p className="chat-settings-body">
            No retained-session compaction preview is available yet.
          </p>
        )}
        {latestCompaction ? (
          <div className="chat-settings-summary-grid">
            <article className="chat-settings-subcard">
              <strong>Last applied policy</strong>
              <span>{compactionPolicySummary(latestCompaction.policy)}</span>
            </article>
            <article className="chat-settings-subcard">
              <strong>Last run</strong>
              <span>{formatSettingsTime(latestCompaction.compactedAtMs)}</span>
            </article>
            <article className="chat-settings-subcard">
              <strong>Retained shape</strong>
              <span>
                Carry {latestDecisionCounts.carry_forward} · Summary{" "}
                {latestDecisionCounts.retained_summary} · Pruned{" "}
                {latestDecisionCounts.pruned}
              </span>
            </article>
            <article className="chat-settings-subcard">
              <strong>Last anchor</strong>
              <span>{latestCompaction.resumeAnchor}</span>
            </article>
          </div>
        ) : null}
      </article>

      <article className="chat-settings-card">
        <div className="chat-settings-card-head">
          <div>
            <span className="chat-settings-card-eyebrow">Knowledge</span>
            <h2>Collections and retrieval scopes</h2>
          </div>
          <span className="chat-settings-pill">
            {knowledgeCollections.length} collections
          </span>
        </div>
        <p className="chat-settings-body">
          Collections now land in `ioi-memory` as durable, embedding-backed
          knowledge entries. Each entry gets its own retrieval scope so agent
          IDE flows can target or exclude it cleanly.
        </p>
        {knowledgeMessage ? (
          <p className="chat-settings-success">{knowledgeMessage}</p>
        ) : null}
        {knowledgeError ? (
          <p className="chat-settings-error">{knowledgeError}</p>
        ) : null}
        <div className="chat-settings-profile-grid">
          <label className="chat-settings-field">
            <span>Collection name</span>
            <input
              value={knowledgeCollectionName}
              onChange={(event) => setKnowledgeCollectionName(event.target.value)}
              placeholder="research-notes"
            />
          </label>
          <label className="chat-settings-field chat-settings-field--wide">
            <span>Description</span>
            <input
              value={knowledgeCollectionDescription}
              onChange={(event) =>
                setKnowledgeCollectionDescription(event.target.value)
              }
              placeholder="What this collection is for"
            />
          </label>
        </div>
        <div className="chat-settings-actions">
          <button
            type="button"
            className="chat-settings-secondary"
            disabled={knowledgeBusy || knowledgeCollectionName.trim().length === 0}
            onClick={() =>
              void runKnowledgeAction(async () => {
                const created = await runtime.createKnowledgeCollection(
                  knowledgeCollectionName,
                  knowledgeCollectionDescription || null,
                );
                setKnowledgeCollectionName("");
                setKnowledgeCollectionDescription("");
                setSelectedKnowledgeCollectionId(created.collectionId);
              }, "Knowledge collection created.")
            }
          >
            {knowledgeBusy ? "Working..." : "Create collection"}
          </button>
        </div>
      </article>

      <article className="chat-settings-card">
        <div className="chat-settings-card-head">
          <div>
            <span className="chat-settings-card-eyebrow">Collections</span>
            <h2>Registry</h2>
          </div>
          <span className="chat-settings-pill">
            {knowledgeLoading ? "Loading" : `${knowledgeCollections.length} live`}
          </span>
        </div>
        {knowledgeLoading ? (
          <p className="chat-settings-body">Loading knowledge collections...</p>
        ) : knowledgeCollections.length === 0 ? (
          <p className="chat-settings-body">
            No knowledge collections exist yet. Create one above to begin
            ingesting files or durable notes.
          </p>
        ) : (
          <div className="chat-settings-summary-grid">
            {knowledgeCollections.map((collection) => (
              <button
                key={collection.collectionId}
                type="button"
                className={`chat-settings-subcard ${
                  selectedKnowledgeCollection?.collectionId ===
                  collection.collectionId
                    ? "is-live"
                    : ""
                }`}
                onClick={() => {
                  setSelectedKnowledgeCollectionId(collection.collectionId);
                  setKnowledgeSearchResults([]);
                  setSelectedKnowledgeEntryContent(null);
                }}
              >
                <strong>{collection.label}</strong>
                <span>{collection.entries.length} entries</span>
                <small>{collection.sources.length} sources</small>
                <p>{collection.description || collection.collectionId}</p>
              </button>
            ))}
          </div>
        )}
      </article>

      {selectedKnowledgeCollection ? (
        <article className="chat-settings-card">
          <div className="chat-settings-card-head">
            <div>
              <span className="chat-settings-card-eyebrow">
                Selected collection
              </span>
              <h2>{selectedKnowledgeCollection.label}</h2>
            </div>
            <span className="chat-settings-pill">
              {selectedKnowledgeCollection.entries.length} entries
            </span>
          </div>
          <p className="chat-settings-body">
            Scope root: <code>{selectedKnowledgeCollection.collectionId}</code>.
            Entries are kept as independent retrieval scopes for clean
            delete/reset semantics.
          </p>
          <div className="chat-settings-summary-grid">
            <article className="chat-settings-subcard">
              <strong>Entries</strong>
              <span>{selectedKnowledgeCollection.entries.length}</span>
            </article>
            <article className="chat-settings-subcard">
              <strong>Sources</strong>
              <span>{selectedKnowledgeCollection.sources.length}</span>
            </article>
            <article className="chat-settings-subcard">
              <strong>Updated</strong>
              <span>
                {formatSettingsTime(selectedKnowledgeCollection.updatedAtMs)}
              </span>
            </article>
            <article className="chat-settings-subcard">
              <strong>Created</strong>
              <span>
                {formatSettingsTime(selectedKnowledgeCollection.createdAtMs)}
              </span>
            </article>
          </div>
          <div className="chat-settings-actions">
            <button
              type="button"
              className="chat-settings-secondary"
              disabled={knowledgeBusy}
              onClick={() =>
                void runKnowledgeAction(
                  () =>
                    runtime.resetKnowledgeCollection(
                      selectedKnowledgeCollection.collectionId,
                    ),
                  "Knowledge collection reset.",
                )
              }
            >
              Reset collection
            </button>
            <button
              type="button"
              className="chat-settings-danger"
              disabled={knowledgeBusy}
              onClick={() =>
                void runKnowledgeAction(async () => {
                  await runtime.deleteKnowledgeCollection(
                    selectedKnowledgeCollection.collectionId,
                  );
                  setSelectedKnowledgeCollectionId(null);
                  setKnowledgeSearchResults([]);
                  setSelectedKnowledgeEntryContent(null);
                }, "Knowledge collection removed.")
              }
            >
              Delete collection
            </button>
          </div>
        </article>
      ) : null}

      {selectedKnowledgeCollection ? (
        <article className="chat-settings-card">
          <div className="chat-settings-card-head">
            <div>
              <span className="chat-settings-card-eyebrow">Ingestion</span>
              <h2>Add entries</h2>
            </div>
            <span className="chat-settings-pill">Retrieval-ready</span>
          </div>
          <div className="chat-settings-profile-grid">
            <label className="chat-settings-field">
              <span>Entry title</span>
              <input
                value={knowledgeEntryTitle}
                onChange={(event) => setKnowledgeEntryTitle(event.target.value)}
                placeholder="Q2 launch notes"
              />
            </label>
            <label className="chat-settings-field chat-settings-field--wide">
              <span>Note content</span>
              <textarea
                value={knowledgeEntryContent}
                onChange={(event) => setKnowledgeEntryContent(event.target.value)}
                placeholder="Paste durable knowledge or procedure notes here."
                rows={6}
              />
            </label>
            <div className="chat-settings-actions">
              <button
                type="button"
                className="chat-settings-secondary"
                disabled={
                  knowledgeBusy ||
                  knowledgeEntryTitle.trim().length === 0 ||
                  knowledgeEntryContent.trim().length === 0
                }
                onClick={() =>
                  void runKnowledgeAction(async () => {
                    await runtime.addKnowledgeTextEntry(
                      selectedKnowledgeCollection.collectionId,
                      knowledgeEntryTitle,
                      knowledgeEntryContent,
                    );
                    setKnowledgeEntryTitle("");
                    setKnowledgeEntryContent("");
                  }, "Knowledge note ingested.")
                }
              >
                Add text entry
              </button>
            </div>
          </div>
          <div className="chat-settings-profile-grid">
            <label className="chat-settings-field chat-settings-field--wide">
              <span>Import file path</span>
              <input
                value={knowledgeImportPath}
                onChange={(event) => setKnowledgeImportPath(event.target.value)}
                placeholder="/abs/path/to/doc.md"
              />
            </label>
            <div className="chat-settings-actions">
              <button
                type="button"
                className="chat-settings-secondary"
                disabled={knowledgeBusy || knowledgeImportPath.trim().length === 0}
                onClick={() =>
                  void runKnowledgeAction(async () => {
                    await runtime.importKnowledgeFile(
                      selectedKnowledgeCollection.collectionId,
                      knowledgeImportPath,
                    );
                    setKnowledgeImportPath("");
                  }, "Knowledge file imported.")
                }
              >
                Import file
              </button>
            </div>
          </div>
        </article>
      ) : null}

      {selectedKnowledgeCollection ? (
        <article className="chat-settings-card">
          <div className="chat-settings-card-head">
            <div>
              <span className="chat-settings-card-eyebrow">Sources</span>
              <h2>Registered source endpoints</h2>
            </div>
            <span className="chat-settings-pill">
              {selectedKnowledgeCollection.sources.length} configured
            </span>
          </div>
          <div className="chat-settings-profile-grid">
            <label className="chat-settings-field chat-settings-field--wide">
              <span>Source URI or path</span>
              <input
                value={knowledgeSourceUri}
                onChange={(event) => setKnowledgeSourceUri(event.target.value)}
                placeholder="https://docs.example.com or /data/docs"
              />
            </label>
            <label className="chat-settings-field">
              <span>Poll interval minutes</span>
              <input
                value={knowledgeSourceInterval}
                onChange={(event) =>
                  setKnowledgeSourceInterval(event.target.value)
                }
                placeholder="60"
              />
            </label>
          </div>
          <div className="chat-settings-actions">
            <button
              type="button"
              className="chat-settings-secondary"
              disabled={knowledgeBusy || knowledgeSourceUri.trim().length === 0}
              onClick={() =>
                void runKnowledgeAction(async () => {
                  await runtime.addKnowledgeCollectionSource(
                    selectedKnowledgeCollection.collectionId,
                    knowledgeSourceUri,
                    knowledgeSourceInterval.trim().length > 0
                      ? Number(knowledgeSourceInterval)
                      : null,
                  );
                  setKnowledgeSourceUri("");
                  setKnowledgeSourceInterval("");
                }, "Knowledge source registered.")
              }
            >
              Add source
            </button>
          </div>
          <div className="chat-settings-stack chat-settings-stack--compact">
            {selectedKnowledgeCollection.sources.length === 0 ? (
              <p className="chat-settings-body">
                No recurring sources are registered for this collection yet.
              </p>
            ) : (
              selectedKnowledgeCollection.sources.map((source) => (
                <article key={source.sourceId} className="chat-settings-subcard">
                  <div className="chat-settings-subcard-head">
                    <strong>{source.uri}</strong>
                    <span>{humanize(source.syncStatus)}</span>
                  </div>
                  <div className="chat-settings-chip-row">
                    <span className="chat-settings-chip">
                      {humanize(source.kind)}
                    </span>
                    <span className="chat-settings-chip">
                      {source.enabled ? "Enabled" : "Disabled"}
                    </span>
                    {source.pollIntervalMinutes ? (
                      <span className="chat-settings-chip">
                        Every {source.pollIntervalMinutes} min
                      </span>
                    ) : null}
                  </div>
                  <div className="chat-settings-actions">
                    <button
                      type="button"
                      className="chat-settings-secondary"
                      disabled={knowledgeBusy}
                      onClick={() =>
                        void runKnowledgeAction(
                          () =>
                            runtime.removeKnowledgeCollectionSource(
                              selectedKnowledgeCollection.collectionId,
                              source.sourceId,
                            ),
                          "Knowledge source removed.",
                        )
                      }
                    >
                      Remove source
                    </button>
                  </div>
                </article>
              ))
            )}
          </div>
        </article>
      ) : null}

      {selectedKnowledgeCollection ? (
        <article className="chat-settings-card">
          <div className="chat-settings-card-head">
            <div>
              <span className="chat-settings-card-eyebrow">Search</span>
              <h2>Collection retrieval check</h2>
            </div>
            <span className="chat-settings-pill">Hybrid</span>
          </div>
          <div className="chat-settings-profile-grid">
            <label className="chat-settings-field chat-settings-field--wide">
              <span>Search query</span>
              <input
                value={knowledgeSearchQuery}
                onChange={(event) => setKnowledgeSearchQuery(event.target.value)}
                placeholder="What does this collection know about..."
              />
            </label>
          </div>
          <div className="chat-settings-actions">
            <button
              type="button"
              className="chat-settings-secondary"
              disabled={
                knowledgeSearchLoading || knowledgeSearchQuery.trim().length === 0
              }
              onClick={async () => {
                setKnowledgeSearchLoading(true);
                setKnowledgeError(null);
                try {
                  const results = await runtime.searchKnowledgeCollection(
                    selectedKnowledgeCollection.collectionId,
                    knowledgeSearchQuery,
                    8,
                  );
                  setKnowledgeSearchResults(results);
                } catch (nextError) {
                  setKnowledgeError(String(nextError));
                } finally {
                  setKnowledgeSearchLoading(false);
                }
              }}
            >
              {knowledgeSearchLoading ? "Searching..." : "Search collection"}
            </button>
          </div>
          <div className="chat-settings-stack chat-settings-stack--compact">
            {knowledgeSearchResults.map((result) => (
              <article
                key={`${result.archivalRecordId}-${result.entryId}`}
                className="chat-settings-subcard"
              >
                <div className="chat-settings-subcard-head">
                  <strong>{result.title}</strong>
                  <span>{Math.round(result.score * 100)}%</span>
                </div>
                <div className="chat-settings-chip-row">
                  <span className="chat-settings-chip">{result.entryId}</span>
                  <span className="chat-settings-chip">{result.trustLevel}</span>
                  <span className="chat-settings-chip">{result.scope}</span>
                </div>
                <p>{result.snippet}</p>
              </article>
            ))}
            {!knowledgeSearchLoading &&
            knowledgeSearchQuery.trim().length > 0 &&
            knowledgeSearchResults.length === 0 ? (
              <p className="chat-settings-body">
                No hits yet for this query in the selected collection.
              </p>
            ) : null}
          </div>
        </article>
      ) : null}

      {selectedKnowledgeCollection ? (
        <article className="chat-settings-card">
          <div className="chat-settings-card-head">
            <div>
              <span className="chat-settings-card-eyebrow">Entries</span>
              <h2>Stored artifacts and scopes</h2>
            </div>
            <span className="chat-settings-pill">
              {selectedKnowledgeCollection.entries.length} stored
            </span>
          </div>
          <div className="chat-settings-stack chat-settings-stack--compact">
            {selectedKnowledgeCollection.entries.length === 0 ? (
              <p className="chat-settings-body">
                This collection does not have any entries yet.
              </p>
            ) : (
              selectedKnowledgeCollection.entries.map((entry) => (
                <article key={entry.entryId} className="chat-settings-subcard">
                  <div className="chat-settings-subcard-head">
                    <strong>{entry.title}</strong>
                    <span>{humanize(entry.kind)}</span>
                  </div>
                  <div className="chat-settings-chip-row">
                    <span className="chat-settings-chip">{entry.scope}</span>
                    <span className="chat-settings-chip">
                      {entry.chunkCount} chunks
                    </span>
                    <span className="chat-settings-chip">
                      {entry.byteCount} bytes
                    </span>
                  </div>
                  <p>{entry.contentPreview}</p>
                  <div className="chat-settings-actions">
                    <button
                      type="button"
                      className="chat-settings-secondary"
                      disabled={knowledgeEntryLoading}
                      onClick={async () => {
                        setKnowledgeEntryLoading(true);
                        setKnowledgeError(null);
                        try {
                          const content =
                            await runtime.getKnowledgeCollectionEntryContent(
                              selectedKnowledgeCollection.collectionId,
                              entry.entryId,
                            );
                          setSelectedKnowledgeEntryContent(content);
                        } catch (nextError) {
                          setKnowledgeError(String(nextError));
                        } finally {
                          setKnowledgeEntryLoading(false);
                        }
                      }}
                    >
                      {knowledgeEntryLoading ? "Opening..." : "Open entry"}
                    </button>
                    <button
                      type="button"
                      className="chat-settings-danger"
                      disabled={knowledgeBusy}
                      onClick={() =>
                        void runKnowledgeAction(
                          async () => {
                            await runtime.removeKnowledgeCollectionEntry(
                              selectedKnowledgeCollection.collectionId,
                              entry.entryId,
                            );
                            if (
                              selectedKnowledgeEntryContent?.entryId ===
                              entry.entryId
                            ) {
                              setSelectedKnowledgeEntryContent(null);
                            }
                          },
                          "Knowledge entry removed.",
                        )
                      }
                    >
                      Remove entry
                    </button>
                  </div>
                </article>
              ))
            )}
          </div>
        </article>
      ) : null}

      {selectedKnowledgeEntryContent ? (
        <article className="chat-settings-card">
          <div className="chat-settings-card-head">
            <div>
              <span className="chat-settings-card-eyebrow">Entry content</span>
              <h2>{selectedKnowledgeEntryContent.title}</h2>
            </div>
            <span className="chat-settings-pill">
              {selectedKnowledgeEntryContent.byteCount} bytes
            </span>
          </div>
          <label className="chat-settings-field chat-settings-field--wide">
            <span>Materialized artifact</span>
            <textarea
              value={selectedKnowledgeEntryContent.content}
              readOnly
              rows={12}
            />
          </label>
        </article>
      ) : null}
    </div>
  );
}
