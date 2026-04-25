import { useEffect, useMemo, useState } from "react";
import { invoke } from "@tauri-apps/api/core";

import type {
  SkillDetailView,
  ChatArtifactRenderEvaluation,
  ChatArtifactRevision,
  ChatArtifactSelectedSkill,
} from "../../../types";
import {
  resolveCapabilityRegistryEntryForSelectedArtifactSkill,
  resolveExtensionManifestForSelectedSkill,
  useChatCapabilityRegistry,
} from "../hooks/useChatCapabilityRegistry";
import {
  formatRuntimeProvenance,
  formatStatusLabel,
  type ArtifactEvidencePanelProps,
  type ArtifactRevisionComparison,
} from "./artifactSurfaceShared";
import {
  buildArtifactContextInspection,
  buildArtifactDeliveryInspection,
  buildArtifactValidationInspection,
  buildArtifactVerificationInspection,
} from "../../../services/runtimeInspection";

interface SelectedSkillRuntimeContext {
  detail: SkillDetailView | null;
  error: string | null;
}

function stripMarkdownToSummary(markdown?: string | null): string | null {
  if (!markdown) {
    return null;
  }

  const normalized = markdown
    .split(/\n+/)
    .map((line) => line.trim())
    .filter((line) => line && !line.startsWith("#"))
    .join(" ")
    .replace(/\[(.*?)\]\(.*?\)/g, "$1")
    .replace(/[`*_>~-]/g, " ")
    .replace(/\s+/g, " ")
    .trim();

  return normalized || null;
}

function formatBasisPoints(basisPoints: number): string {
  return `${Math.round(basisPoints / 100)}%`;
}

function sourceLabelForSkill(
  skill: ChatArtifactSelectedSkill,
  detail: SkillDetailView | null,
): string {
  if (detail?.source_registry_label) {
    return detail.source_registry_label;
  }
  return formatStatusLabel(skill.sourceType);
}

function sourcePathForSkill(
  skill: ChatArtifactSelectedSkill,
  detail: SkillDetailView | null,
): string | null {
  return (
    detail?.source_registry_relative_path ??
    detail?.relative_path ??
    skill.relativePath ??
    null
  );
}

function sourceLocationForSkill(
  skill: ChatArtifactSelectedSkill,
  detail: SkillDetailView | null,
): string {
  const fragments = [
    sourceLabelForSkill(skill, detail),
    detail?.source_registry_uri ?? null,
    sourcePathForSkill(skill, detail),
  ].filter((value): value is string => Boolean(value));
  return fragments.join(" · ");
}

function obligationCounts(
  evaluation?: ChatArtifactRenderEvaluation | null,
): { required: number; cleared: number; failed: number } {
  const required = evaluation?.acceptanceObligations?.filter(
    (obligation) => obligation.required,
  ) ?? [];
  return {
    required: required.length,
    cleared: required.filter((obligation) => obligation.status === "passed")
      .length,
    failed: required.filter(
      (obligation) =>
        obligation.status === "failed" || obligation.status === "blocked",
    ).length,
  };
}

export function ArtifactEvidencePanel({
  manifest,
  chatSession,
  pipelineSteps,
  notes,
  evidence,
  receipts = [],
  workspaceActivity = [],
  onOpenArtifact,
  onOpenEvidenceSession,
}: ArtifactEvidencePanelProps) {
  const revisions = [...(chatSession.revisions ?? [])].reverse();
  const activeRevisionId =
    chatSession.activeRevisionId ?? revisions[0]?.revisionId ?? null;
  const brief = chatSession.materialization.artifactBrief ?? null;
  const blueprint = chatSession.materialization.blueprint ?? null;
  const artifactIr = chatSession.materialization.artifactIr ?? null;
  const selectedSkills = chatSession.materialization.selectedSkills ?? [];
  const validation = chatSession.materialization.validation ?? null;
  const executionEnvelope = chatSession.materialization.executionEnvelope ?? null;
  const swarmPlan = chatSession.materialization.swarmPlan ?? executionEnvelope?.plan ?? null;
  const swarmExecution =
    chatSession.materialization.swarmExecution ??
    executionEnvelope?.executionSummary ??
    null;
  const swarmWorkerReceipts =
    chatSession.materialization.swarmWorkerReceipts ??
    executionEnvelope?.workerReceipts ??
    [];
  const swarmChangeReceipts =
    chatSession.materialization.swarmChangeReceipts ??
    executionEnvelope?.changeReceipts ??
    [];
  const swarmMergeReceipts =
    chatSession.materialization.swarmMergeReceipts ??
    executionEnvelope?.mergeReceipts ??
    [];
  const swarmVerificationReceipts =
    chatSession.materialization.swarmVerificationReceipts ??
    executionEnvelope?.verificationReceipts ??
    [];
  const graphMutationReceipts = executionEnvelope?.graphMutationReceipts ?? [];
  const dispatchBatches = executionEnvelope?.dispatchBatches ?? [];
  const repairReceipts = executionEnvelope?.repairReceipts ?? [];
  const replanReceipts = executionEnvelope?.replanReceipts ?? [];
  const hasSwarmExecution = Boolean(
    swarmExecution?.enabled || swarmPlan || executionEnvelope,
  );
  const candidates = chatSession.materialization.candidateSummaries ?? [];
  const tasteMemory = chatSession.tasteMemory ?? null;
  const repairPassCount = hasSwarmExecution
    ? swarmChangeReceipts.filter(
        (receipt) =>
          (receipt.workItemId.startsWith("repair-pass-") ||
            receipt.workItemId === "repair") &&
          receipt.operationCount > 0,
      ).length
    : candidates.filter(
        (candidate) =>
          candidate.convergence && candidate.convergence.passKind !== "initial",
      ).length;
  const winningCandidate =
    !hasSwarmExecution
      ? candidates.find((candidate) => candidate.selected) ??
        (chatSession.materialization.winningCandidateId
          ? (candidates.find(
              (candidate) =>
                candidate.candidateId ===
                chatSession.materialization.winningCandidateId,
            ) ?? null)
          : null)
      : null;
  const winningRenderEvaluation =
    chatSession.materialization.renderEvaluation ??
    winningCandidate?.renderEvaluation ??
    null;
  const validationCounts = obligationCounts(winningRenderEvaluation);
  const [comparison, setComparison] =
    useState<ArtifactRevisionComparison | null>(null);
  const [revisionBusy, setRevisionBusy] = useState<string | null>(null);
  const [selectedSkillRuntimeContext, setSelectedSkillRuntimeContext] =
    useState<Record<string, SelectedSkillRuntimeContext>>({});
  const [selectedSkillDetailStatus, setSelectedSkillDetailStatus] = useState<
    "idle" | "loading" | "ready"
  >("idle");
  const {
    snapshot: capabilityRegistrySnapshot,
    status: capabilityRegistryStatus,
    error: capabilityRegistryError,
    entryLookup: capabilityRegistryEntryLookup,
  } = useChatCapabilityRegistry(selectedSkills.length > 0);
  const selectedSkillNames = selectedSkills
    .map((skill) => skill.name)
    .slice(0, 3);
  const artifactId = manifest.artifactId?.trim() || null;
  const evidenceSessionId = chatSession.sessionId?.trim() || null;
  const verificationInspection = buildArtifactVerificationInspection(
    manifest,
    formatRuntimeProvenance,
  );
  const validationInspection = buildArtifactValidationInspection(
    validation,
    winningRenderEvaluation,
    formatStatusLabel,
  );
  const deliveryInspection = buildArtifactDeliveryInspection({
    hasSwarmExecution,
    adapterLabel: swarmExecution?.adapterLabel ?? null,
    completedWorkItems: swarmExecution?.completedWorkItems ?? 0,
    totalWorkItems: swarmExecution?.totalWorkItems ?? 0,
    evidenceCount: evidence.length,
    receiptCount: receipts.length,
    revisionCount: revisions.length,
    winningCandidateId: winningCandidate?.candidateId ?? null,
    winningCandidateRationale:
      chatSession.materialization.winningCandidateRationale ?? null,
    obligationLine: validationCounts.required > 0
      ? `${validationCounts.cleared}/${validationCounts.required} required obligations cleared`
      : "Execution-witness obligation counts pending",
    repairPassCount,
    activeWorkerRole: swarmExecution?.activeWorkerRole ?? null,
    workspaceDetail: workspaceActivity[0]?.detail ?? null,
    formatStatusLabel,
  });
  const contextInspection = buildArtifactContextInspection({
    selectedSkills,
    subjectDomain: brief?.subjectDomain ?? null,
    artifactThesis: brief?.artifactThesis ?? null,
    tasteSummary: tasteMemory?.summary ?? null,
  });

  useEffect(() => {
    let cancelled = false;

    if (selectedSkills.length === 0) {
      setSelectedSkillRuntimeContext({});
      setSelectedSkillDetailStatus("idle");
      return () => {
        cancelled = true;
      };
    }

    setSelectedSkillDetailStatus("loading");
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
              error:
                error instanceof Error ? error.message : String(error ?? ""),
            },
          ] as const;
        }
      }),
    ).then((detailEntries) => {
      if (cancelled) {
        return;
      }
      setSelectedSkillRuntimeContext(Object.fromEntries(detailEntries));
      setSelectedSkillDetailStatus("ready");
    });

    return () => {
      cancelled = true;
    };
  }, [selectedSkills]);

  const selectionContextStatus =
    selectedSkills.length === 0
      ? "idle"
      : capabilityRegistryStatus === "loading" ||
          selectedSkillDetailStatus === "loading"
        ? "loading"
        : "ready";

  const selectedSkillExplainability = useMemo(
    () =>
      selectedSkills.map((skill) => {
        const runtimeContext = selectedSkillRuntimeContext[skill.skillHash] ?? {
          detail: null,
          error: null,
        };
        const extension = resolveExtensionManifestForSelectedSkill(
          skill,
          runtimeContext.detail,
          capabilityRegistrySnapshot?.extensionManifests ?? [],
        );
        return {
          skill,
          detail: runtimeContext.detail,
          error: runtimeContext.error,
          extension,
          registryEntry: resolveCapabilityRegistryEntryForSelectedArtifactSkill(
            capabilityRegistrySnapshot,
            capabilityRegistryEntryLookup,
            skill,
            runtimeContext.detail,
            extension,
          ),
          guidanceSummary: stripMarkdownToSummary(skill.guidanceMarkdown),
        };
      }),
    [
      capabilityRegistryEntryLookup,
      capabilityRegistrySnapshot,
      selectedSkills,
      selectedSkillRuntimeContext,
    ],
  );

  const compareRevision = async (revision: ChatArtifactRevision) => {
    if (!activeRevisionId || activeRevisionId === revision.revisionId) {
      setComparison(null);
      return;
    }
    const result = await invoke<ArtifactRevisionComparison>(
      "chat_compare_artifact_revisions",
      {
        baseRevisionId: activeRevisionId,
        targetRevisionId: revision.revisionId,
      },
    );
    setComparison(result);
  };

  const restoreRevision = async (revision: ChatArtifactRevision) => {
    setRevisionBusy(revision.revisionId);
    try {
      await invoke("chat_restore_artifact_revision", {
        revisionId: revision.revisionId,
      });
    } finally {
      setRevisionBusy(null);
    }
  };

  const branchRevision = async (revision: ChatArtifactRevision) => {
    setRevisionBusy(revision.revisionId);
    try {
      await invoke("chat_branch_artifact_revision", {
        revisionId: revision.revisionId,
      });
    } finally {
      setRevisionBusy(null);
    }
  };

  return (
    <aside
      className="chat-artifact-inspector"
      aria-label="Artifact evidence inspector"
    >
      <section className="chat-artifact-inspector-section chat-artifact-summary-tier">
        <div className="chat-artifact-summary-copy">
          <span className="chat-artifact-panel-label">At a glance</span>
          <p>
            Summary-first trust, validation, and delivery view for the current
            artifact run.
          </p>
          {artifactId || evidenceSessionId ? (
            <div className="chat-artifact-summary-actions">
              {artifactId && onOpenArtifact ? (
                <button
                  type="button"
                  className="chat-artifact-stage-button"
                  onClick={() => onOpenArtifact(artifactId)}
                >
                  Open artifact
                </button>
              ) : null}
              {evidenceSessionId && onOpenEvidenceSession ? (
                <button
                  type="button"
                  className="chat-artifact-stage-button"
                  onClick={() => onOpenEvidenceSession(evidenceSessionId)}
                >
                  Open evidence session
                </button>
              ) : null}
            </div>
          ) : null}
        </div>
        <div className="chat-artifact-summary-grid">
          <article className="chat-artifact-summary-card">
            <span>Verification</span>
            <strong>{verificationInspection.headline}</strong>
            <p>{verificationInspection.summary}</p>
            <p>
              Production: {verificationInspection.productionLabel}
            </p>
            <p>
              Acceptance: {verificationInspection.acceptanceLabel}
            </p>
          </article>
          <article className="chat-artifact-summary-card">
            <span>Validation</span>
            <strong>{validationInspection.headline}</strong>
            <p>{validationInspection.summary}</p>
            {validationInspection.scoreLine ? (
              <p>{validationInspection.scoreLine}</p>
            ) : null}
            {validationInspection.nextPass ? (
              <p>Next pass: {validationInspection.nextPass}</p>
            ) : null}
          </article>
          <article className="chat-artifact-summary-card">
            <span>Delivery</span>
            <strong>{deliveryInspection.headline}</strong>
            <p>{deliveryInspection.summary}</p>
            <p>{deliveryInspection.revisionLine}</p>
            {deliveryInspection.repairLine ? (
              <p>{deliveryInspection.repairLine}</p>
            ) : null}
            {deliveryInspection.activeRoleLine ? (
              <p>{deliveryInspection.activeRoleLine}</p>
            ) : null}
            {deliveryInspection.workspaceDetail ? (
              <p>{deliveryInspection.workspaceDetail}</p>
            ) : null}
          </article>
          <article className="chat-artifact-summary-card">
            <span>Context</span>
            <strong>{contextInspection.headline}</strong>
            <p>{contextInspection.summary}</p>
            {selectedSkillNames.length ? (
              <p>{selectedSkillNames.join(" · ")}</p>
            ) : null}
            {blueprint ? <p>Scaffold: {blueprint.scaffoldFamily}</p> : null}
          </article>
        </div>
      </section>

      <section className="chat-artifact-inspector-section">
        <span className="chat-artifact-panel-label">Verification</span>
        <p>{manifest.verification.summary}</p>
        <div className="chat-artifact-note-list">
          <p>
            <strong>Production:</strong>{" "}
            {formatRuntimeProvenance(
              manifest.verification.productionProvenance,
            )}
          </p>
          <p>
            <strong>Acceptance:</strong>{" "}
            {formatRuntimeProvenance(
              manifest.verification.acceptanceProvenance,
            )}
          </p>
          {manifest.verification.failure ? (
            <p>
              <strong>Failure:</strong> {manifest.verification.failure.code} ·{" "}
              {manifest.verification.failure.message}
            </p>
          ) : null}
        </div>
      </section>

      {brief ? (
        <section className="chat-artifact-inspector-section">
          <span className="chat-artifact-panel-label">Artifact brief</span>
          <div className="chat-artifact-note-list">
            <p>
              <strong>Audience:</strong> {brief.audience}
            </p>
            <p>
              <strong>Thesis:</strong> {brief.artifactThesis}
            </p>
            <p>
              <strong>Domain:</strong> {brief.subjectDomain}
            </p>
            {brief.visualTone.length ? (
              <p>{brief.visualTone.join(" · ")}</p>
            ) : null}
            {brief.styleDirectives.length ? (
              <p>{brief.styleDirectives.join(" · ")}</p>
            ) : null}
          </div>
        </section>
      ) : null}

      {blueprint ? (
        <section className="chat-artifact-inspector-section">
          <span className="chat-artifact-panel-label">Blueprint</span>
          <div className="chat-artifact-note-list">
            <p>
              <strong>Scaffold:</strong> {blueprint.scaffoldFamily}
            </p>
            <p>{blueprint.narrativeArc}</p>
            <p>
              <strong>Sections:</strong>{" "}
              {blueprint.sectionPlan.map((section) => section.role).join(" · ")}
            </p>
            {blueprint.componentPlan.length ? (
              <p>
                <strong>Component plan:</strong>{" "}
                {blueprint.componentPlan
                  .map((component) => component.componentFamily)
                  .join(" · ")}
              </p>
            ) : null}
            <p>
              <strong>Interactions:</strong>{" "}
              {blueprint.interactionPlan
                .map((interaction) => interaction.family)
                .join(" · ")}
            </p>
            {blueprint.skillNeeds.length ? (
              <p>
                <strong>Skill needs:</strong>{" "}
                {blueprint.skillNeeds
                  .map(
                    (skillNeed) => `${skillNeed.kind} (${skillNeed.priority})`,
                  )
                  .join(" · ")}
              </p>
            ) : null}
            <p>
              <strong>Variation:</strong> {blueprint.variationStrategy}
            </p>
          </div>
        </section>
      ) : null}

      {artifactIr ? (
        <section className="chat-artifact-inspector-section">
          <span className="chat-artifact-panel-label">Artifact IR</span>
          <div className="chat-artifact-note-list">
            <p>
              <strong>Structure:</strong> {artifactIr.semanticStructure.length}{" "}
              nodes · {artifactIr.interactionGraph.length} interactions ·{" "}
              {artifactIr.evidenceSurfaces.length} evidence surfaces
            </p>
            {artifactIr.componentBindings.length ? (
              <p>
                <strong>Component packs:</strong>{" "}
                {artifactIr.componentBindings.join(" · ")}
              </p>
            ) : null}
            {artifactIr.staticAuditExpectations.length ? (
              <p>{artifactIr.staticAuditExpectations.join(" · ")}</p>
            ) : null}
            {artifactIr.renderEvalChecklist.length ? (
              <p>
                <strong>Render eval:</strong>{" "}
                {artifactIr.renderEvalChecklist.join(" · ")}
              </p>
            ) : null}
          </div>
        </section>
      ) : null}

      {selectedSkills.length ? (
        <section className="chat-artifact-inspector-section">
          <span className="chat-artifact-panel-label">
            Selection explainability
          </span>
          <p>
            Why the runtime selected each reusable behavior and where that
            behavior came from during this artifact run.
          </p>
          {selectionContextStatus === "loading" ? (
            <p>Loading live capability fabric, source registry, and skill detail...</p>
          ) : null}
          {capabilityRegistryStatus === "error" && !capabilityRegistrySnapshot ? (
            <p>
              Capability fabric unavailable right now:{" "}
              {capabilityRegistryError ?? "Registry snapshot failed to load."}
            </p>
          ) : null}
          <div className="chat-artifact-selection-list">
            {selectedSkillExplainability.map(
              ({
                skill,
                detail,
                error,
                extension,
                registryEntry,
                guidanceSummary,
              }) => (
                <article
                  key={skill.skillHash}
                  className="chat-artifact-selection-card"
                >
                  <div className="chat-artifact-selection-head">
                    <div>
                      <strong>{skill.name}</strong>
                      <p>{skill.description}</p>
                    </div>
                    <span className="chat-artifact-selection-pill">
                      {registryEntry?.authority.tierLabel ??
                        (extension
                          ? "Extension-backed"
                          : detail?.source_registry_label
                            ? "Source-backed"
                            : formatStatusLabel(skill.sourceType))}
                    </span>
                  </div>
                  <div className="chat-artifact-selection-meta">
                    {skill.matchedNeedKinds.length ? (
                      <span>
                        Matched{" "}
                        {skill.matchedNeedKinds
                          .map((kind) => formatStatusLabel(kind))
                          .join(" · ")}
                      </span>
                    ) : null}
                    {skill.matchedNeedIds.length ? (
                      <span>
                        Need ids {skill.matchedNeedIds.join(" · ")}
                      </span>
                    ) : null}
                    <span>
                      Reliability {formatBasisPoints(skill.reliabilityBps)}
                    </span>
                    <span>
                      Semantic {formatBasisPoints(skill.semanticScoreBps)}
                    </span>
                    <span>
                      Adjusted {formatBasisPoints(skill.adjustedScoreBps)}
                    </span>
                    {registryEntry?.lease.runtimeTargetLabel ? (
                      <span>{registryEntry.lease.runtimeTargetLabel}</span>
                    ) : null}
                    {registryEntry?.sourceLabel ? (
                      <span>{registryEntry.sourceLabel}</span>
                    ) : null}
                  </div>
                  <p>
                    <strong>Selected because:</strong> {skill.matchRationale}
                  </p>
                  {registryEntry ? (
                    <>
                      <p>
                        <strong>Capability fabric:</strong>{" "}
                        {registryEntry.whySelectable}
                      </p>
                      <div className="chat-artifact-selection-fabric">
                        <article className="chat-artifact-selection-fabric-card">
                          <span>Authority tier</span>
                          <strong>{registryEntry.authority.tierLabel}</strong>
                          <p>{registryEntry.authority.summary}</p>
                        </article>
                        <article className="chat-artifact-selection-fabric-card">
                          <span>Lease semantics</span>
                          <strong>
                            {registryEntry.lease.modeLabel ??
                              registryEntry.lease.availabilityLabel}
                          </strong>
                          <p>{registryEntry.lease.summary}</p>
                        </article>
                      </div>
                      <div className="chat-artifact-selection-signals">
                        {[
                          ...registryEntry.authority.signals,
                          ...registryEntry.lease.signals,
                        ]
                          .slice(0, 6)
                          .map((signal) => (
                            <span
                              key={`${skill.skillHash}-${signal}`}
                              className="chat-artifact-selection-signal"
                            >
                              {signal}
                            </span>
                          ))}
                      </div>
                    </>
                  ) : null}
                  {guidanceSummary ? (
                    <p>
                      <strong>Published guidance:</strong> {guidanceSummary}
                    </p>
                  ) : null}
                  <p>
                    <strong>Source:</strong>{" "}
                    {sourceLocationForSkill(skill, detail)}
                  </p>
                  {extension ? (
                    <p>
                      <strong>Extension manifest:</strong>{" "}
                      {extension.displayName ?? extension.name} ·{" "}
                      {extension.manifestPath}
                    </p>
                  ) : null}
                  {error ? (
                    <p>
                      <strong>Live detail:</strong> {error}
                    </p>
                  ) : null}
                </article>
              ),
            )}
          </div>
        </section>
      ) : null}

      {validation ? (
        <section className="chat-artifact-inspector-section">
          <span className="chat-artifact-panel-label">Validation</span>
          <div className="chat-artifact-note-list">
            <p>
              <strong>{formatStatusLabel(validation.classification)}</strong> ·{" "}
              {validation.rationale}
            </p>
            <p>
              Faithfulness {validation.requestFaithfulness}/5 · Coverage{" "}
              {validation.conceptCoverage}/5 · Interaction{" "}
              {validation.interactionRelevance}/5
            </p>
            <p>
              Layout {validation.layoutCoherence}/5 · Hierarchy{" "}
              {validation.visualHierarchy}/5 · Completeness{" "}
              {validation.completeness}/5
            </p>
            {validation.issueClasses.length ? (
              <p>
                <strong>Issues:</strong> {validation.issueClasses.join(" · ")}
              </p>
            ) : null}
            {validation.strengths.length ? (
              <p>
                <strong>Strengths:</strong> {validation.strengths.join(" · ")}
              </p>
            ) : null}
            <p>
              <strong>Aesthetic:</strong> {validation.aestheticVerdict}
            </p>
            <p>
              <strong>Interaction:</strong> {validation.interactionVerdict}
            </p>
            {validation.strongestContradiction ? (
              <p>{validation.strongestContradiction}</p>
            ) : null}
            {validation.repairHints.length ? (
              <p>
                <strong>Repair hints:</strong> {validation.repairHints.join(" · ")}
              </p>
            ) : null}
            {validation.truthfulnessWarnings.length ? (
              <p>
                <strong>Truthfulness warnings:</strong>{" "}
                {validation.truthfulnessWarnings.join(" · ")}
              </p>
            ) : null}
            {validation.recommendedNextPass ? (
              <p>
                <strong>Next pass:</strong> {validation.recommendedNextPass}
              </p>
            ) : null}
          </div>
        </section>
      ) : null}

      {hasSwarmExecution ? (
        <>
          {swarmPlan ? (
            <section className="chat-artifact-inspector-section">
              <span className="chat-artifact-panel-label">Execution plan</span>
              <div className="chat-artifact-note-list">
                <p>
                  <strong>Strategy:</strong>{" "}
                  {executionEnvelope?.strategy
                    ? formatStatusLabel(executionEnvelope.strategy)
                    : swarmPlan.strategy}{" "}
                  · {swarmPlan.adapterLabel}
                </p>
                {executionEnvelope?.executionDomain ? (
                  <p>
                    <strong>Domain:</strong> {executionEnvelope.executionDomain}
                    {executionEnvelope.domainKind
                      ? ` · ${formatStatusLabel(executionEnvelope.domainKind)}`
                      : ""}
                  </p>
                ) : null}
                <p>
                  <strong>Parallelism:</strong> {swarmPlan.parallelismMode}
                </p>
                <p>
                  <strong>Work graph:</strong> {swarmPlan.workItems.length} item
                  {swarmPlan.workItems.length === 1 ? "" : "s"}
                </p>
                {swarmPlan.workItems.map((item) => (
                  <div key={item.id} className="chat-artifact-activity">
                    <div>
                      <strong>
                        {formatStatusLabel(item.role)} · {item.title}
                      </strong>
                      <p>{item.summary}</p>
                      {item.spawnedFromId ? (
                        <p>
                          Spawned from <strong>{item.spawnedFromId}</strong>
                        </p>
                      ) : null}
                      {item.acceptanceCriteria.length ? (
                        <p>{item.acceptanceCriteria.join(" · ")}</p>
                      ) : null}
                      {item.leaseRequirements.length ? (
                        <p>
                          Leases:{" "}
                          {item.leaseRequirements
                            .map(
                              (lease) =>
                                `${formatStatusLabel(lease.mode)} ${lease.target}`,
                            )
                            .join(" · ")}
                        </p>
                      ) : null}
                      {item.dependencyIds.length || item.blockedOnIds.length ? (
                        <p>
                          {item.dependencyIds.length
                            ? `Depends on ${item.dependencyIds.join(" · ")}`
                            : ""}
                          {item.dependencyIds.length && item.blockedOnIds.length
                            ? " · "
                            : ""}
                          {item.blockedOnIds.length
                            ? `Blocked on ${item.blockedOnIds.join(" · ")}`
                            : ""}
                        </p>
                      ) : null}
                      {item.verificationPolicy || item.retryBudget !== null ? (
                        <p>
                          {item.verificationPolicy
                            ? `Verification ${formatStatusLabel(item.verificationPolicy)}`
                            : ""}
                          {item.verificationPolicy &&
                          item.retryBudget !== null &&
                          item.retryBudget !== undefined
                            ? " · "
                            : ""}
                          {item.retryBudget !== null &&
                          item.retryBudget !== undefined
                            ? `Retry budget ${item.retryBudget}`
                            : ""}
                        </p>
                      ) : null}
                    </div>
                    <span>{formatStatusLabel(item.status)}</span>
                  </div>
                ))}
              </div>
            </section>
          ) : null}

          {swarmWorkerReceipts.length ? (
            <section className="chat-artifact-inspector-section">
              <span className="chat-artifact-panel-label">Worker receipts</span>
              <div className="chat-artifact-note-list">
                {swarmWorkerReceipts.map((receipt) => (
                  <div
                    key={`${receipt.workItemId}-${receipt.startedAt}`}
                    className="chat-artifact-activity"
                  >
                    <div>
                      <strong>
                        {formatStatusLabel(receipt.role)} · {receipt.workItemId}
                      </strong>
                      <p>{receipt.summary}</p>
                      {receipt.resultKind ? (
                        <p>Result {formatStatusLabel(receipt.resultKind)}</p>
                      ) : null}
                      {receipt.spawnedWorkItemIds.length ? (
                        <p>
                          Spawned {receipt.spawnedWorkItemIds.join(" · ")}
                        </p>
                      ) : null}
                      {receipt.blockedOnIds.length ? (
                        <p>Blocked on {receipt.blockedOnIds.join(" · ")}</p>
                      ) : null}
                      {receipt.notes.length ? (
                        <p>{receipt.notes.join(" · ")}</p>
                      ) : null}
                      {receipt.failure ? <p>{receipt.failure}</p> : null}
                    </div>
                    <span>{formatStatusLabel(receipt.status)}</span>
                  </div>
                ))}
              </div>
            </section>
          ) : null}

          {swarmChangeReceipts.length ||
          swarmMergeReceipts.length ||
          swarmVerificationReceipts.length ||
          dispatchBatches.length ||
          graphMutationReceipts.length ||
          repairReceipts.length ||
          replanReceipts.length ? (
            <section className="chat-artifact-inspector-section">
              <span className="chat-artifact-panel-label">Execution receipts</span>
              <div className="chat-artifact-note-list">
                {dispatchBatches.map((batch) => (
                  <div key={`dispatch-${batch.id}`} className="chat-artifact-activity">
                    <div>
                      <strong>Dispatch · {batch.id}</strong>
                      <p>
                        Wave {batch.sequence} ·{" "}
                        {batch.workItemIds.length
                          ? batch.workItemIds.join(" · ")
                          : "No dispatchable work items"}
                      </p>
                      {batch.deferredWorkItemIds.length ? (
                        <p>Deferred {batch.deferredWorkItemIds.join(" · ")}</p>
                      ) : null}
                      {batch.blockedWorkItemIds.length ? (
                        <p>Blocked {batch.blockedWorkItemIds.join(" · ")}</p>
                      ) : null}
                      {batch.details.length ? (
                        <p>{batch.details.join(" · ")}</p>
                      ) : null}
                    </div>
                    <span>{formatStatusLabel(batch.status)}</span>
                  </div>
                ))}
                {swarmChangeReceipts.map((receipt) => (
                  <div key={`patch-${receipt.workItemId}`} className="chat-artifact-activity">
                    <div>
                      <strong>Patch · {receipt.workItemId}</strong>
                      <p>{receipt.summary}</p>
                      <p>
                        {receipt.operationCount} op{receipt.operationCount === 1 ? "" : "s"} ·{" "}
                        {receipt.touchedPaths.join(" · ") || "No touched paths"}
                      </p>
                    </div>
                    <span>{formatStatusLabel(receipt.status)}</span>
                  </div>
                ))}
                {swarmMergeReceipts.map((receipt) => (
                  <div key={`merge-${receipt.workItemId}`} className="chat-artifact-activity">
                    <div>
                      <strong>Merge · {receipt.workItemId}</strong>
                      <p>{receipt.summary}</p>
                      {receipt.rejectedReason ? (
                        <p>{receipt.rejectedReason}</p>
                      ) : null}
                    </div>
                    <span>{formatStatusLabel(receipt.status)}</span>
                  </div>
                ))}
                {swarmVerificationReceipts.map((receipt) => (
                  <div key={`verify-${receipt.id}`} className="chat-artifact-activity">
                    <div>
                      <strong>{formatStatusLabel(receipt.kind)}</strong>
                      <p>{receipt.summary}</p>
                      {receipt.details.length ? (
                        <p>{receipt.details.join(" · ")}</p>
                      ) : null}
                    </div>
                    <span>{formatStatusLabel(receipt.status)}</span>
                  </div>
                ))}
                {graphMutationReceipts.map((receipt) => (
                  <div key={`graph-${receipt.id}`} className="chat-artifact-activity">
                    <div>
                      <strong>{formatStatusLabel(receipt.mutationKind)}</strong>
                      <p>{receipt.summary}</p>
                      {receipt.affectedWorkItemIds.length ? (
                        <p>{receipt.affectedWorkItemIds.join(" · ")}</p>
                      ) : null}
                      {receipt.details.length ? (
                        <p>{receipt.details.join(" · ")}</p>
                      ) : null}
                    </div>
                    <span>{formatStatusLabel(receipt.status)}</span>
                  </div>
                ))}
                {repairReceipts.map((receipt) => (
                  <div key={`repair-${receipt.id}`} className="chat-artifact-activity">
                    <div>
                      <strong>Repair · {receipt.id}</strong>
                      <p>{receipt.summary}</p>
                      {receipt.details.length ? (
                        <p>{receipt.details.join(" · ")}</p>
                      ) : null}
                    </div>
                    <span>{formatStatusLabel(receipt.status)}</span>
                  </div>
                ))}
                {replanReceipts.map((receipt) => (
                  <div key={`replan-${receipt.id}`} className="chat-artifact-activity">
                    <div>
                      <strong>Replan · {receipt.id}</strong>
                      <p>{receipt.summary}</p>
                      {receipt.spawnedWorkItemIds.length ? (
                        <p>Spawned {receipt.spawnedWorkItemIds.join(" · ")}</p>
                      ) : null}
                      {receipt.blockedWorkItemIds.length ? (
                        <p>Blocked {receipt.blockedWorkItemIds.join(" · ")}</p>
                      ) : null}
                      {receipt.details.length ? (
                        <p>{receipt.details.join(" · ")}</p>
                      ) : null}
                    </div>
                    <span>{formatStatusLabel(receipt.status)}</span>
                  </div>
                ))}
              </div>
            </section>
          ) : null}
        </>
      ) : candidates.length ? (
        <section className="chat-artifact-inspector-section">
          <span className="chat-artifact-panel-label">Candidates</span>
          <div className="chat-artifact-note-list">
            {winningCandidate ? (
              <p>
                <strong>Winner:</strong> {winningCandidate.candidateId}
                {chatSession.materialization.winningCandidateRationale
                  ? ` · ${chatSession.materialization.winningCandidateRationale}`
                  : ""}
              </p>
            ) : null}
            {repairPassCount > 0 ? (
              <p>
                <strong>Repair history:</strong> {repairPassCount} bounded
                repair attempt
                {repairPassCount === 1 ? "" : "s"} recorded across the selected
                candidate line; acceptance is grounded in cleared obligations,
                not attempt count.
              </p>
            ) : null}
            {validationCounts.required > 0 ? (
              <p>
                <strong>Validation:</strong> {validationCounts.cleared}/
                {validationCounts.required} required obligations cleared
                {validationCounts.failed > 0
                  ? ` · ${validationCounts.failed} unresolved`
                  : ""}
                .
              </p>
            ) : null}
            {candidates.map((candidate) => (
              <div
                key={candidate.candidateId}
                className="chat-artifact-activity"
              >
                <div>
                  <strong>
                    {candidate.selected ? "Winner" : "Candidate"}{" "}
                    {candidate.candidateId}
                  </strong>
                  <p>{candidate.summary}</p>
                  {candidate.convergence ? (
                    <p>
                      {candidate.convergence.passKind} pass{" "}
                      {candidate.convergence.passIndex} · score{" "}
                      {candidate.convergence.scoreTotal}
                      {candidate.convergence.scoreDeltaFromParent !== null &&
                      candidate.convergence.scoreDeltaFromParent !== undefined
                        ? ` · delta ${candidate.convergence.scoreDeltaFromParent >= 0 ? "+" : ""}${candidate.convergence.scoreDeltaFromParent}`
                        : ""}
                      {candidate.convergence.terminatedReason
                        ? ` · ${candidate.convergence.terminatedReason}`
                        : ""}
                    </p>
                  ) : null}
                  {candidate.failure ? <p>{candidate.failure}</p> : null}
                </div>
                <span>
                  {formatStatusLabel(candidate.validation.classification)}
                </span>
              </div>
            ))}
          </div>
        </section>
      ) : null}

      {tasteMemory ? (
        <section className="chat-artifact-inspector-section">
          <span className="chat-artifact-panel-label">Taste memory</span>
          <div className="chat-artifact-note-list">
            <p>{tasteMemory.summary}</p>
            {tasteMemory.directives.length ? (
              <p>{tasteMemory.directives.join(" · ")}</p>
            ) : null}
          </div>
        </section>
      ) : null}

      <section className="chat-artifact-inspector-section">
        <span className="chat-artifact-panel-label">Pipeline</span>
        <div className="chat-artifact-step-list">
          {pipelineSteps.length ? (
            pipelineSteps.map((step) => (
              <div key={step.id} className="chat-artifact-step">
                <div>
                  <strong>{step.label}</strong>
                  <p>{step.summary}</p>
                  {step.outputs.length ? (
                    <p className="chat-artifact-inline-meta">
                      {step.outputs.join(" · ")}
                    </p>
                  ) : null}
                  {step.verificationGate ? (
                    <p>
                      <strong>Gate:</strong> {step.verificationGate}
                    </p>
                  ) : null}
                </div>
                <span>{formatStatusLabel(step.status)}</span>
              </div>
            ))
          ) : (
            <p>No pipeline evidence is attached yet.</p>
          )}
        </div>
      </section>

      {receipts.length ? (
        <section className="chat-artifact-inspector-section">
          <span className="chat-artifact-panel-label">Receipts</span>
          <div className="chat-artifact-receipt-list">
            {receipts.map((receipt) => (
              <article
                key={receipt.receiptId}
                className="chat-artifact-receipt"
              >
                <strong>{receipt.title}</strong>
                <span>{formatStatusLabel(receipt.status)}</span>
                <p>{receipt.summary}</p>
              </article>
            ))}
          </div>
        </section>
      ) : null}

      {notes.length ? (
        <section className="chat-artifact-inspector-section">
          <span className="chat-artifact-panel-label">Notes</span>
          <div className="chat-artifact-note-list">
            {notes.map((note) => (
              <p key={note}>{note}</p>
            ))}
          </div>
        </section>
      ) : null}

      <section className="chat-artifact-inspector-section">
        <span className="chat-artifact-panel-label">Materialized files</span>
        <div className="chat-artifact-note-list">
          {evidence.length ? (
            evidence.map((entry) => <p key={entry}>{entry}</p>)
          ) : (
            <p>No files recorded yet.</p>
          )}
        </div>
      </section>

      {revisions.length ? (
        <section className="chat-artifact-inspector-section">
          <span className="chat-artifact-panel-label">Revisions</span>
          <div className="chat-artifact-receipt-list">
            {revisions.map((revision) => (
              <article
                key={revision.revisionId}
                className="chat-artifact-receipt"
              >
                <strong>
                  {revision.branchLabel}
                  {revision.revisionId === activeRevisionId ? " · Active" : ""}
                </strong>
                <span>{new Date(revision.createdAt).toLocaleString()}</span>
                <p>{revision.prompt}</p>
                <div className="chat-artifact-chip-row">
                  {revision.revisionId !== activeRevisionId ? (
                    <button
                      type="button"
                      className="chat-artifact-stage-button"
                      onClick={() => void compareRevision(revision)}
                    >
                      Compare
                    </button>
                  ) : null}
                  {revision.revisionId !== activeRevisionId ? (
                    <button
                      type="button"
                      className="chat-artifact-stage-button"
                      onClick={() => void restoreRevision(revision)}
                      disabled={revisionBusy === revision.revisionId}
                    >
                      Restore
                    </button>
                  ) : null}
                  <button
                    type="button"
                    className="chat-artifact-stage-button"
                    onClick={() => void branchRevision(revision)}
                    disabled={revisionBusy === revision.revisionId}
                  >
                    Branch
                  </button>
                </div>
              </article>
            ))}
          </div>
          {comparison ? (
            <div className="chat-artifact-note-list">
              <p>
                <strong>Compare:</strong> {comparison.summary}
              </p>
              {comparison.changedPaths.length ? (
                comparison.changedPaths.map((path) => <p key={path}>{path}</p>)
              ) : (
                <p>No surfaced file paths changed.</p>
              )}
            </div>
          ) : null}
        </section>
      ) : null}

      {workspaceActivity.length ? (
        <section className="chat-artifact-inspector-section">
          <span className="chat-artifact-panel-label">Recent activity</span>
          <div className="chat-artifact-note-list">
            {workspaceActivity.slice(0, 8).map((entry) => (
              <div key={entry.id} className="chat-artifact-activity">
                <div>
                  <strong>{entry.title}</strong>
                  {entry.detail ? <p>{entry.detail}</p> : null}
                </div>
                <span>{entry.source}</span>
              </div>
            ))}
          </div>
        </section>
      ) : null}
    </aside>
  );
}
