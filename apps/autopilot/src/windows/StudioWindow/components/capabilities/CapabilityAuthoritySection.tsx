import { useEffect, useMemo, useState } from "react";
import type {
  CapabilityAuthorityDescriptor,
  CapabilityLeaseDescriptor,
  CapabilityRegistryEntry,
} from "../../../../types";
import type {
  CapabilityGovernanceProposal,
  CapabilityGovernanceRequest,
} from "../../policyCenter";

interface CapabilityAuthoritySectionProps {
  currentEntry: CapabilityRegistryEntry;
  authority: CapabilityAuthorityDescriptor;
  lease: CapabilityLeaseDescriptor;
  sourceNote?: string | null;
  comparisonPool?: CapabilityRegistryEntry[] | null;
  relatedGoverningEntries?:
    | Array<{
        entry: CapabilityRegistryEntry;
        sharedHints: string[];
      }>
    | null;
  onPlanWiderLeaseProposal?: (
    comparisonEntryId?: string | null,
  ) => Promise<CapabilityGovernanceProposal | null>;
  onRequestWiderLease?: (request?: CapabilityGovernanceRequest | null) => void;
  onReturnToBaseline?: () => void;
  onOpenPolicyCenter?: () => void;
  onOpenRelatedEntry?: (entryId: string) => void;
  onOpenRelatedPolicy?: (entryId: string) => void;
}

function humanizeCapabilityKind(value: string): string {
  return value
    .replace(/[_-]+/g, " ")
    .replace(/\b\w/g, (char) => char.toUpperCase());
}

function comparisonValue(value: string | null | undefined, fallback = "None"): string {
  const trimmed = value?.trim();
  return trimmed && trimmed.length > 0 ? trimmed : fallback;
}

function compactHintValue(value: string): string {
  const normalized = value.replace(/[_/.-]+/g, " ").trim();
  if (!normalized) {
    return "";
  }
  return normalized.length > 28 ? `${normalized.slice(0, 28).trimEnd()}...` : normalized;
}

function humanizeGoverningHint(hint: string): string {
  const [rawKind, ...rawRest] = hint.split(":");
  const kind = rawKind.trim().toLowerCase();
  const value = compactHintValue(rawRest.join(":").trim());
  const withValue = (label: string) => (value ? `${label}: ${value}` : label);

  switch (kind) {
    case "source-root":
      return withValue("Shared source root");
    case "extension-root":
      return withValue("Shared extension root");
    case "capability":
      return withValue("Shared capability");
    case "native-family":
      return withValue("Shared native family");
    case "backend":
      return withValue("Shared backend");
    case "skill-name":
      return withValue("Shared skill name");
    case "skill-path":
      return withValue("Shared skill path");
    case "connector":
      return withValue("Shared connector");
    case "manifest":
      return withValue("Shared manifest");
    default:
      return withValue(humanizeCapabilityKind(kind || "family"));
  }
}

function comparisonRows(
  currentEntry: CapabilityRegistryEntry,
  selectedEntry: CapabilityRegistryEntry,
): Array<{ label: string; currentValue: string; selectedValue: string; changed: boolean }> {
  const rows = [
    {
      label: "Why selectable",
      currentValue: comparisonValue(currentEntry.whySelectable),
      selectedValue: comparisonValue(selectedEntry.whySelectable),
    },
    {
      label: "Authority tier",
      currentValue: comparisonValue(currentEntry.authority.tierLabel),
      selectedValue: comparisonValue(selectedEntry.authority.tierLabel),
    },
    {
      label: "Governed profile",
      currentValue: comparisonValue(currentEntry.authority.governedProfileLabel),
      selectedValue: comparisonValue(selectedEntry.authority.governedProfileLabel),
    },
    {
      label: "Lease mode",
      currentValue: comparisonValue(
        currentEntry.lease.modeLabel ?? currentEntry.lease.availabilityLabel,
      ),
      selectedValue: comparisonValue(
        selectedEntry.lease.modeLabel ?? selectedEntry.lease.availabilityLabel,
      ),
    },
    {
      label: "Requires auth",
      currentValue: currentEntry.lease.requiresAuth ? "Yes" : "No",
      selectedValue: selectedEntry.lease.requiresAuth ? "Yes" : "No",
    },
    {
      label: "Runtime target",
      currentValue: comparisonValue(currentEntry.lease.runtimeTargetLabel),
      selectedValue: comparisonValue(selectedEntry.lease.runtimeTargetLabel),
    },
    {
      label: "Source",
      currentValue: comparisonValue(currentEntry.sourceLabel),
      selectedValue: comparisonValue(selectedEntry.sourceLabel),
    },
  ];

  return rows.map((row) => ({
    ...row,
    changed: row.currentValue !== row.selectedValue,
  }));
}

export function CapabilityAuthoritySection({
  currentEntry,
  authority,
  lease,
  sourceNote,
  comparisonPool,
  relatedGoverningEntries,
  onPlanWiderLeaseProposal,
  onRequestWiderLease,
  onReturnToBaseline,
  onOpenPolicyCenter,
  onOpenRelatedEntry,
  onOpenRelatedPolicy,
}: CapabilityAuthoritySectionProps) {
  const authorityBadge = authority.governedProfileLabel ?? authority.tierLabel;
  const leaseBadge = lease.modeLabel ?? lease.availabilityLabel;
  const [selectedComparisonEntryId, setSelectedComparisonEntryId] =
    useState<string>("");
  const [proposal, setProposal] = useState<CapabilityGovernanceProposal | null>(null);
  const [proposalStatus, setProposalStatus] = useState<
    "idle" | "loading" | "ready" | "error"
  >("idle");
  const [proposalError, setProposalError] = useState<string | null>(null);
  const [preferredProposalTargetEntryId, setPreferredProposalTargetEntryId] =
    useState<string>("");
  const [selectedProposalTargetEntryId, setSelectedProposalTargetEntryId] =
    useState<string>("");

  const comparisonCandidates = useMemo(() => {
    const pool = comparisonPool ?? [];
    return pool
      .filter((entry) => entry.entryId !== currentEntry.entryId)
      .map((entry) => {
        let relevanceScore = 0;
        if (entry.kind === currentEntry.kind) relevanceScore += 4;
        if (entry.sourceKind === currentEntry.sourceKind) relevanceScore += 3;
        if (
          entry.authority.governedProfileId &&
          entry.authority.governedProfileId === currentEntry.authority.governedProfileId
        ) {
          relevanceScore += 2;
        }
        if (entry.authority.tierId === currentEntry.authority.tierId) {
          relevanceScore += 1;
        }
        if (entry.sourceLabel === currentEntry.sourceLabel) {
          relevanceScore += 1;
        }
        return { entry, relevanceScore };
      })
      .sort((left, right) => {
        if (left.relevanceScore !== right.relevanceScore) {
          return right.relevanceScore - left.relevanceScore;
        }
        return left.entry.label.localeCompare(right.entry.label);
      })
      .slice(0, 12)
      .map(({ entry }) => entry);
  }, [comparisonPool, currentEntry]);

  const selectedComparisonEntry =
    comparisonCandidates.find((entry) => entry.entryId === selectedComparisonEntryId) ??
    null;
  const compareRows = selectedComparisonEntry
    ? comparisonRows(currentEntry, selectedComparisonEntry)
    : [];
  const compareSummary = selectedComparisonEntry
    ? compareRows.filter((row) => row.changed).length > 0
      ? `${selectedComparisonEntry.label} diverges on ${compareRows.filter((row) => row.changed).length} governance signals.`
      : `${selectedComparisonEntry.label} matches the current governance posture on every compared signal.`
    : null;
  const policyButtonLabel = lease.requiresAuth
    ? "Resolve in policy"
    : "Open governing policy";

  useEffect(() => {
    setSelectedComparisonEntryId("");
    setPreferredProposalTargetEntryId("");
    setSelectedProposalTargetEntryId("");
    setProposal(null);
    setProposalStatus("idle");
    setProposalError(null);
  }, [currentEntry.entryId]);

  useEffect(() => {
    if (!onPlanWiderLeaseProposal) {
      setProposal(null);
      setProposalStatus("idle");
      setProposalError(null);
      setSelectedProposalTargetEntryId("");
      return;
    }

    let cancelled = false;
    setProposalStatus("loading");
    setProposalError(null);

    void onPlanWiderLeaseProposal(selectedComparisonEntryId || null)
      .then((nextProposal) => {
        if (cancelled) {
          return;
        }
        setProposal(nextProposal);
        setProposalStatus("ready");
        setSelectedProposalTargetEntryId((currentValue) => {
          if (
            preferredProposalTargetEntryId &&
            nextProposal?.targets.some(
              (target) => target.targetEntryId === preferredProposalTargetEntryId,
            )
          ) {
            return preferredProposalTargetEntryId;
          }
          if (
            currentValue &&
            nextProposal?.targets.some(
              (target) => target.targetEntryId === currentValue,
            )
          ) {
            return currentValue;
          }
          return nextProposal?.recommendedTargetEntryId ?? "";
        });
      })
      .catch((error) => {
        if (cancelled) {
          return;
        }
        setProposal(null);
        setProposalStatus("error");
        setProposalError(String(error));
        setSelectedProposalTargetEntryId("");
      });

    return () => {
      cancelled = true;
    };
  }, [
    onPlanWiderLeaseProposal,
    preferredProposalTargetEntryId,
    selectedComparisonEntryId,
  ]);

  const selectedProposalTarget =
    proposal?.targets.find(
      (target) => target.targetEntryId === selectedProposalTargetEntryId,
    ) ??
    proposal?.targets[0] ??
    null;
  const proposalSelectionLabel =
    selectedProposalTarget?.targetKind === "policy_target"
      ? "Global runtime posture"
      : humanizeCapabilityKind(selectedProposalTarget?.targetKind ?? "target");
  const normalizedRelatedGoverningEntries = relatedGoverningEntries ?? [];

  const handleCompareRelatedEntry = (entryId: string) => {
    setSelectedComparisonEntryId(entryId);
  };

  const handleUseRelatedEntryAsTarget = (entryId: string) => {
    setPreferredProposalTargetEntryId(entryId);
    setSelectedProposalTargetEntryId(entryId);
    setSelectedComparisonEntryId((currentValue) =>
      currentValue === entryId ? currentValue : entryId,
    );
  };

  return (
    <>
      <section className="capabilities-detail-card capabilities-trust-card">
        <div className="capabilities-detail-card-head">
          <h3>Authority tier</h3>
          <span>{authorityBadge}</span>
        </div>
        <div className="capabilities-trust-tier-line">
          <div className="capabilities-trust-tier-copy">
            <strong>{authority.tierLabel}</strong>
            <span>{authority.summary}</span>
          </div>
          <span className="capabilities-trust-tier-badge">{authorityBadge}</span>
        </div>
        <p className="capabilities-trust-detail">{authority.detail}</p>
        <div className="capabilities-trust-signal-list">
          {authority.signals.map((signal) => (
            <span key={signal} className="capabilities-trust-signal">
              {signal}
            </span>
          ))}
        </div>
      </section>

      <section className="capabilities-detail-card">
        <div className="capabilities-detail-card-head">
          <h3>Lease semantics</h3>
          <span>{lease.availabilityLabel}</span>
        </div>
        <div className="capabilities-trust-tier-line">
          <div className="capabilities-trust-tier-copy">
            <strong>{lease.modeLabel ?? "Availability bound"}</strong>
            <span>{lease.summary}</span>
          </div>
          <span className="capabilities-trust-tier-badge">{leaseBadge}</span>
        </div>
        <p className="capabilities-trust-detail">{lease.detail}</p>
        <div className="capabilities-detail-inline-meta">
          <span>
            Availability <strong>{lease.availabilityLabel}</strong>
          </span>
          {lease.runtimeTargetLabel ? (
            <span>
              Runtime target <strong>{lease.runtimeTargetLabel}</strong>
            </span>
          ) : null}
          {lease.modeLabel ? (
            <span>
              Lease mode <strong>{lease.modeLabel}</strong>
            </span>
          ) : null}
          <span>
            Requires auth <strong>{lease.requiresAuth ? "Yes" : "No"}</strong>
          </span>
        </div>
        {sourceNote ? <p className="capabilities-inline-note">{sourceNote}</p> : null}
        {lease.signals.length > 0 ? (
          <div className="capabilities-trust-signal-list">
            {lease.signals.map((signal) => (
              <span key={signal} className="capabilities-trust-signal">
                {signal}
              </span>
            ))}
          </div>
        ) : null}
      </section>

      <section className="capabilities-detail-card capabilities-policy-card">
        <div className="capabilities-detail-card-head">
          <h3>Selection posture</h3>
          <span>{humanizeCapabilityKind(currentEntry.kind)}</span>
        </div>
        <div className="capabilities-trust-tier-copy">
          <strong>Why selectable</strong>
          <span>{currentEntry.whySelectable}</span>
        </div>
        <div className="capabilities-detail-inline-meta">
          <span>
            Capability kind <strong>{humanizeCapabilityKind(currentEntry.kind)}</strong>
          </span>
          <span>
            Source <strong>{currentEntry.sourceLabel}</strong>
          </span>
          <span>
            Status <strong>{currentEntry.statusLabel}</strong>
          </span>
        </div>
        {normalizedRelatedGoverningEntries.length > 0 ? (
          <div className="capabilities-related-family">
            <div className="capabilities-detail-card-head capabilities-related-family-head">
              <h4>Related governing family</h4>
              <span>
                {normalizedRelatedGoverningEntries.length} linked entr
                {normalizedRelatedGoverningEntries.length === 1 ? "y" : "ies"}
              </span>
            </div>
            <p className="capabilities-inline-note">
              These capabilities share governing provenance with the current
              entry, so you can compare them directly or steer the widening plan
              toward a narrower target.
            </p>
            <div className="capabilities-related-family-grid">
              {normalizedRelatedGoverningEntries.map(({ entry, sharedHints }) => {
                const isCompared = selectedComparisonEntryId === entry.entryId;
                const isSelectedTarget =
                  selectedProposalTargetEntryId === entry.entryId ||
                  preferredProposalTargetEntryId === entry.entryId;
                const canUseAsTarget =
                  proposal?.targets.some(
                    (target) => target.targetEntryId === entry.entryId,
                  ) ?? false;
                return (
                  <article
                    key={entry.entryId}
                    className={`capabilities-related-family-card ${
                      isCompared ? "is-compared" : ""
                    } ${isSelectedTarget ? "is-selected" : ""}`.trim()}
                  >
                    <div className="capabilities-related-family-copy">
                      <strong>{entry.label}</strong>
                      <span>
                        {humanizeCapabilityKind(entry.kind)} ·{" "}
                        {entry.authority.tierLabel}
                      </span>
                    </div>
                    <p>{entry.summary}</p>
                    <div className="capabilities-related-family-hints">
                      {sharedHints.slice(0, 3).map((hint) => (
                        <span
                          key={`${entry.entryId}:${hint}`}
                          className="capabilities-related-family-hint"
                        >
                          {humanizeGoverningHint(hint)}
                        </span>
                      ))}
                      {sharedHints.length > 3 ? (
                        <span className="capabilities-related-family-hint">
                          +{sharedHints.length - 3} more
                        </span>
                      ) : null}
                    </div>
                    <div className="capabilities-related-family-actions">
                      {onOpenRelatedEntry ? (
                        <button
                          type="button"
                          className="capabilities-secondary-button"
                          onClick={() => onOpenRelatedEntry(entry.entryId)}
                        >
                          Open details
                        </button>
                      ) : null}
                      <button
                        type="button"
                        className="capabilities-secondary-button"
                        onClick={() => handleCompareRelatedEntry(entry.entryId)}
                      >
                        {isCompared ? "Comparing" : "Compare"}
                      </button>
                      {onOpenRelatedPolicy ? (
                        <button
                          type="button"
                          className="capabilities-secondary-button"
                          onClick={() => onOpenRelatedPolicy(entry.entryId)}
                        >
                          Open governing policy
                        </button>
                      ) : null}
                      <button
                        type="button"
                        className="capabilities-secondary-button"
                        onClick={() => handleUseRelatedEntryAsTarget(entry.entryId)}
                        disabled={proposalStatus === "loading" || !canUseAsTarget}
                      >
                        {isSelectedTarget
                          ? "Using as target"
                          : !canUseAsTarget
                            ? "Compare only"
                          : "Use as governing target"}
                      </button>
                    </div>
                  </article>
                );
              })}
            </div>
          </div>
        ) : null}

        {onPlanWiderLeaseProposal ? (
          <div className="capabilities-governance-proposal">
            <div className="capabilities-detail-card-head capabilities-governance-proposal-head">
              <h4>Recommended governing target</h4>
              <span>
                {proposal ? `${proposal.targets.length} target${proposal.targets.length === 1 ? "" : "s"}` : "Planning"}
              </span>
            </div>
            {proposalStatus === "loading" ? (
              <p className="capabilities-inline-note">
                Asking the runtime to compare governing targets and propose the
                narrowest widening path.
              </p>
            ) : null}
            {proposalStatus === "error" && proposalError ? (
              <p className="capabilities-inline-note">
                Governance planner unavailable: <strong>{proposalError}</strong>
              </p>
            ) : null}
            {selectedProposalTarget ? (
              <>
                <div className="capabilities-detail-inline-meta">
                  <span>
                    Governing target <strong>{selectedProposalTarget.targetLabel}</strong>
                  </span>
                  <span>
                    Target kind <strong>{proposalSelectionLabel}</strong>
                  </span>
                  <span>
                    Policy target{" "}
                    <strong>{selectedProposalTarget.request.connectorLabel}</strong>
                  </span>
                  <span>
                    Delta{" "}
                    <strong>{selectedProposalTarget.deltaMagnitude ?? 0} field{selectedProposalTarget.deltaMagnitude === 1 ? "" : "s"}</strong>
                  </span>
                  {proposal?.comparedEntryLabel ? (
                    <span>
                      Compared against <strong>{proposal.comparedEntryLabel}</strong>
                    </span>
                  ) : null}
                </div>
                <p className="capabilities-inline-note">
                  {selectedProposalTarget.recommendationReason}
                </p>
                <p className="capabilities-inline-note">
                  {selectedProposalTarget.deltaSummary}
                </p>
                {proposal && proposal.targets.length > 1 ? (
                  <label className="capabilities-compare-picker">
                    <span>Choose a different governing target</span>
                    <select
                      value={selectedProposalTargetEntryId}
                      onChange={(event) =>
                        setSelectedProposalTargetEntryId(event.target.value)
                      }
                    >
                      {proposal.targets.map((target) => (
                        <option key={target.targetEntryId} value={target.targetEntryId}>
                          {`${target.targetLabel} · ${humanizeCapabilityKind(target.targetKind)} · ${target.deltaMagnitude ?? 0} field delta`}
                        </option>
                      ))}
                    </select>
                  </label>
                ) : null}
                <div className="capabilities-governance-proposal-grid">
                  {proposal?.targets.map((target) => (
                    <article
                      key={target.targetEntryId}
                      className={`capabilities-governance-proposal-card ${
                        target.targetEntryId ===
                        (selectedProposalTarget?.targetEntryId ?? "")
                          ? "is-selected"
                          : ""
                      }`}
                    >
                      <span>{humanizeCapabilityKind(target.targetKind)}</span>
                      <strong>{target.targetLabel}</strong>
                      <p>{target.targetSummary}</p>
                      <small>{target.deltaSummary}</small>
                    </article>
                  ))}
                </div>
              </>
            ) : null}
          </div>
        ) : null}

        <div className="capabilities-detail-actions">
          {onRequestWiderLease ? (
            <button
              type="button"
              className="capabilities-primary-button"
              onClick={() => onRequestWiderLease(selectedProposalTarget?.request ?? null)}
              disabled={proposalStatus === "loading"}
            >
              Request wider lease
            </button>
          ) : null}
          {onReturnToBaseline ? (
            <button
              type="button"
              className="capabilities-secondary-button"
              onClick={onReturnToBaseline}
            >
              Return to baseline
            </button>
          ) : null}
          {onOpenPolicyCenter ? (
            <button
              type="button"
              className="capabilities-secondary-button"
              onClick={onOpenPolicyCenter}
            >
              {policyButtonLabel}
            </button>
          ) : null}
          {selectedComparisonEntry ? (
            <button
              type="button"
              className="capabilities-secondary-button"
              onClick={() => setSelectedComparisonEntryId("")}
            >
              Clear comparison
            </button>
          ) : null}
        </div>
      </section>

      {comparisonCandidates.length > 0 ? (
        <section className="capabilities-detail-card">
          <div className="capabilities-detail-card-head">
            <h3>Compare governance</h3>
            <span>{comparisonCandidates.length} related capabilities</span>
          </div>
          <label className="capabilities-compare-picker">
            <span>Compare this capability against</span>
            <select
              value={selectedComparisonEntryId}
              onChange={(event) => setSelectedComparisonEntryId(event.target.value)}
            >
              <option value="">Choose a capability</option>
              {comparisonCandidates.map((entry) => (
                <option key={entry.entryId} value={entry.entryId}>
                  {`${entry.label} · ${humanizeCapabilityKind(entry.kind)} · ${entry.authority.tierLabel}`}
                </option>
              ))}
            </select>
          </label>
          {selectedComparisonEntry ? (
            <>
              <p className="capabilities-inline-note">{compareSummary}</p>
              {onOpenRelatedEntry || onOpenRelatedPolicy ? (
                <div className="capabilities-detail-actions">
                  {onOpenRelatedEntry ? (
                    <button
                      type="button"
                      className="capabilities-secondary-button"
                      onClick={() =>
                        onOpenRelatedEntry(selectedComparisonEntry.entryId)
                      }
                    >
                      {`Open ${selectedComparisonEntry.label} details`}
                    </button>
                  ) : null}
                  {onOpenRelatedPolicy ? (
                    <button
                      type="button"
                      className="capabilities-secondary-button"
                      onClick={() =>
                        onOpenRelatedPolicy(selectedComparisonEntry.entryId)
                      }
                    >
                      {`Open ${selectedComparisonEntry.label} policy`}
                    </button>
                  ) : null}
                </div>
              ) : null}
              <div className="capabilities-compare-grid">
                {compareRows.map((row) => (
                  <article
                    key={row.label}
                    className={`capabilities-compare-card ${row.changed ? "is-changed" : ""}`}
                  >
                    <span>{row.label}</span>
                    <strong>Current</strong>
                    <p>{row.currentValue}</p>
                    <strong>{selectedComparisonEntry.label}</strong>
                    <p>{row.selectedValue}</p>
                  </article>
                ))}
              </div>
            </>
          ) : (
            <p className="capabilities-inline-note">
              Compare authority tier, governed profile, lease posture, and
              selection reasoning before widening a capability envelope.
            </p>
          )}
        </section>
      ) : null}
    </>
  );
}
