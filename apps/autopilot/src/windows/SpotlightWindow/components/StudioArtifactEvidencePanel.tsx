import { useState } from "react";
import { invoke } from "@tauri-apps/api/core";

import type { StudioArtifactRevision } from "../../../types";
import {
  formatRuntimeProvenance,
  formatStatusLabel,
  type ArtifactEvidencePanelProps,
  type StudioArtifactRevisionComparison,
} from "./studioArtifactSurfaceShared";

export function StudioArtifactEvidencePanel({
  manifest,
  studioSession,
  pipelineSteps,
  notes,
  evidence,
  receipts = [],
  workspaceActivity = [],
}: ArtifactEvidencePanelProps) {
  const revisions = [...(studioSession.revisions ?? [])].reverse();
  const activeRevisionId =
    studioSession.activeRevisionId ?? revisions[0]?.revisionId ?? null;
  const brief = studioSession.materialization.artifactBrief ?? null;
  const blueprint = studioSession.materialization.blueprint ?? null;
  const artifactIr = studioSession.materialization.artifactIr ?? null;
  const selectedSkills = studioSession.materialization.selectedSkills ?? [];
  const judge = studioSession.materialization.judge ?? null;
  const candidates = studioSession.materialization.candidateSummaries ?? [];
  const tasteMemory = studioSession.tasteMemory ?? null;
  const repairPassCount = candidates.filter(
    (candidate) =>
      candidate.convergence && candidate.convergence.passKind !== "initial",
  ).length;
  const winningCandidate =
    candidates.find((candidate) => candidate.selected) ??
    (studioSession.materialization.winningCandidateId
      ? (candidates.find(
          (candidate) =>
            candidate.candidateId ===
            studioSession.materialization.winningCandidateId,
        ) ?? null)
      : null);
  const [comparison, setComparison] =
    useState<StudioArtifactRevisionComparison | null>(null);
  const [revisionBusy, setRevisionBusy] = useState<string | null>(null);
  const selectedSkillNames = selectedSkills
    .map((skill) => skill.name)
    .slice(0, 3);
  const verificationHeadline = manifest.verification.failure
    ? "Verification blocked"
    : "Verification retained";
  const judgeHeadline = judge
    ? formatStatusLabel(judge.classification)
    : "Judge pending";
  const deliveryHeadline = `${evidence.length} file${evidence.length === 1 ? "" : "s"} · ${
    receipts.length
  } receipt${receipts.length === 1 ? "" : "s"}`;
  const contextHeadline = selectedSkills.length
    ? `${selectedSkills.length} skill${selectedSkills.length === 1 ? "" : "s"} selected`
    : brief
      ? brief.subjectDomain
      : "Context pending";

  const compareRevision = async (revision: StudioArtifactRevision) => {
    if (!activeRevisionId || activeRevisionId === revision.revisionId) {
      setComparison(null);
      return;
    }
    const result = await invoke<StudioArtifactRevisionComparison>(
      "studio_compare_artifact_revisions",
      {
        baseRevisionId: activeRevisionId,
        targetRevisionId: revision.revisionId,
      },
    );
    setComparison(result);
  };

  const restoreRevision = async (revision: StudioArtifactRevision) => {
    setRevisionBusy(revision.revisionId);
    try {
      await invoke("studio_restore_artifact_revision", {
        revisionId: revision.revisionId,
      });
    } finally {
      setRevisionBusy(null);
    }
  };

  const branchRevision = async (revision: StudioArtifactRevision) => {
    setRevisionBusy(revision.revisionId);
    try {
      await invoke("studio_branch_artifact_revision", {
        revisionId: revision.revisionId,
      });
    } finally {
      setRevisionBusy(null);
    }
  };

  return (
    <aside
      className="studio-artifact-inspector"
      aria-label="Artifact evidence inspector"
    >
      <section className="studio-artifact-inspector-section studio-artifact-summary-tier">
        <div className="studio-artifact-summary-copy">
          <span className="studio-artifact-panel-label">At a glance</span>
          <p>
            Summary-first trust, judge, and delivery view for the current
            artifact run.
          </p>
        </div>
        <div className="studio-artifact-summary-grid">
          <article className="studio-artifact-summary-card">
            <span>Verification</span>
            <strong>{verificationHeadline}</strong>
            <p>{manifest.verification.summary}</p>
            <p>
              Production:{" "}
              {formatRuntimeProvenance(
                manifest.verification.productionProvenance,
              )}
            </p>
            <p>
              Acceptance:{" "}
              {formatRuntimeProvenance(
                manifest.verification.acceptanceProvenance,
              )}
            </p>
          </article>
          <article className="studio-artifact-summary-card">
            <span>Judge</span>
            <strong>{judgeHeadline}</strong>
            <p>
              {judge ? judge.rationale : "No judge decision is attached yet."}
            </p>
            {judge ? (
              <p>
                Faithfulness {judge.requestFaithfulness}/5 · Layout{" "}
                {judge.layoutCoherence}/5 · Completeness {judge.completeness}/5
              </p>
            ) : null}
            {judge?.recommendedNextPass ? (
              <p>Next pass: {judge.recommendedNextPass}</p>
            ) : null}
          </article>
          <article className="studio-artifact-summary-card">
            <span>Delivery</span>
            <strong>{deliveryHeadline}</strong>
            <p>
              {winningCandidate
                ? `Winner ${winningCandidate.candidateId}${
                    studioSession.materialization.winningCandidateRationale
                      ? ` · ${studioSession.materialization.winningCandidateRationale}`
                      : ""
                  }`
                : "Winning candidate not recorded yet."}
            </p>
            <p>
              {revisions.length} revision{revisions.length === 1 ? "" : "s"} ·{" "}
              {repairPassCount} repair pass{repairPassCount === 1 ? "" : "es"}
            </p>
            {workspaceActivity[0]?.detail ? (
              <p>{workspaceActivity[0].detail}</p>
            ) : null}
          </article>
          <article className="studio-artifact-summary-card">
            <span>Context</span>
            <strong>{contextHeadline}</strong>
            <p>
              {brief?.artifactThesis ||
                tasteMemory?.summary ||
                "Artifact thesis pending."}
            </p>
            {selectedSkillNames.length ? (
              <p>{selectedSkillNames.join(" · ")}</p>
            ) : null}
            {blueprint ? <p>Scaffold: {blueprint.scaffoldFamily}</p> : null}
          </article>
        </div>
      </section>

      <section className="studio-artifact-inspector-section">
        <span className="studio-artifact-panel-label">Verification</span>
        <p>{manifest.verification.summary}</p>
        <div className="studio-artifact-note-list">
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
        <section className="studio-artifact-inspector-section">
          <span className="studio-artifact-panel-label">Artifact brief</span>
          <div className="studio-artifact-note-list">
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
        <section className="studio-artifact-inspector-section">
          <span className="studio-artifact-panel-label">Blueprint</span>
          <div className="studio-artifact-note-list">
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
        <section className="studio-artifact-inspector-section">
          <span className="studio-artifact-panel-label">Artifact IR</span>
          <div className="studio-artifact-note-list">
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
        <section className="studio-artifact-inspector-section">
          <span className="studio-artifact-panel-label">Selected skills</span>
          <div className="studio-artifact-note-list">
            {selectedSkills.map((skill) => (
              <p key={skill.skillHash}>
                <strong>{skill.name}</strong>:{" "}
                {skill.matchedNeedKinds.join(" · ")}
                {skill.guidanceMarkdown
                  ? ` · ${skill.guidanceMarkdown.split("\n")[0]}`
                  : ""}
              </p>
            ))}
          </div>
        </section>
      ) : null}

      {judge ? (
        <section className="studio-artifact-inspector-section">
          <span className="studio-artifact-panel-label">Judge</span>
          <div className="studio-artifact-note-list">
            <p>
              <strong>{formatStatusLabel(judge.classification)}</strong> ·{" "}
              {judge.rationale}
            </p>
            <p>
              Faithfulness {judge.requestFaithfulness}/5 · Coverage{" "}
              {judge.conceptCoverage}/5 · Interaction{" "}
              {judge.interactionRelevance}/5
            </p>
            <p>
              Layout {judge.layoutCoherence}/5 · Hierarchy{" "}
              {judge.visualHierarchy}/5 · Completeness {judge.completeness}/5
            </p>
            {judge.issueClasses.length ? (
              <p>
                <strong>Issues:</strong> {judge.issueClasses.join(" · ")}
              </p>
            ) : null}
            {judge.strengths.length ? (
              <p>
                <strong>Strengths:</strong> {judge.strengths.join(" · ")}
              </p>
            ) : null}
            <p>
              <strong>Aesthetic:</strong> {judge.aestheticVerdict}
            </p>
            <p>
              <strong>Interaction:</strong> {judge.interactionVerdict}
            </p>
            {judge.strongestContradiction ? (
              <p>{judge.strongestContradiction}</p>
            ) : null}
            {judge.repairHints.length ? (
              <p>
                <strong>Repair hints:</strong> {judge.repairHints.join(" · ")}
              </p>
            ) : null}
            {judge.truthfulnessWarnings.length ? (
              <p>
                <strong>Truthfulness warnings:</strong>{" "}
                {judge.truthfulnessWarnings.join(" · ")}
              </p>
            ) : null}
            {judge.recommendedNextPass ? (
              <p>
                <strong>Next pass:</strong> {judge.recommendedNextPass}
              </p>
            ) : null}
          </div>
        </section>
      ) : null}

      {candidates.length ? (
        <section className="studio-artifact-inspector-section">
          <span className="studio-artifact-panel-label">Candidates</span>
          <div className="studio-artifact-note-list">
            {winningCandidate ? (
              <p>
                <strong>Winner:</strong> {winningCandidate.candidateId}
                {studioSession.materialization.winningCandidateRationale
                  ? ` · ${studioSession.materialization.winningCandidateRationale}`
                  : ""}
              </p>
            ) : null}
            {repairPassCount > 0 ? (
              <p>
                <strong>Repair history:</strong> {repairPassCount} bounded
                repair pass
                {repairPassCount === 1 ? "" : "es"} recorded across the selected
                candidate line.
              </p>
            ) : null}
            {candidates.map((candidate) => (
              <div
                key={candidate.candidateId}
                className="studio-artifact-activity"
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
                <span>{formatStatusLabel(candidate.judge.classification)}</span>
              </div>
            ))}
          </div>
        </section>
      ) : null}

      {tasteMemory ? (
        <section className="studio-artifact-inspector-section">
          <span className="studio-artifact-panel-label">Taste memory</span>
          <div className="studio-artifact-note-list">
            <p>{tasteMemory.summary}</p>
            {tasteMemory.directives.length ? (
              <p>{tasteMemory.directives.join(" · ")}</p>
            ) : null}
          </div>
        </section>
      ) : null}

      <section className="studio-artifact-inspector-section">
        <span className="studio-artifact-panel-label">Pipeline</span>
        <div className="studio-artifact-step-list">
          {pipelineSteps.length ? (
            pipelineSteps.map((step) => (
              <div key={step.id} className="studio-artifact-step">
                <div>
                  <strong>{step.label}</strong>
                  <p>{step.summary}</p>
                  {step.outputs.length ? (
                    <div className="studio-artifact-chip-row studio-artifact-chip-row--compact">
                      {step.outputs.map((output) => (
                        <span
                          key={`${step.id}-${output}`}
                          className="studio-artifact-chip"
                        >
                          {output}
                        </span>
                      ))}
                    </div>
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
        <section className="studio-artifact-inspector-section">
          <span className="studio-artifact-panel-label">Receipts</span>
          <div className="studio-artifact-receipt-list">
            {receipts.map((receipt) => (
              <article
                key={receipt.receiptId}
                className="studio-artifact-receipt"
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
        <section className="studio-artifact-inspector-section">
          <span className="studio-artifact-panel-label">Notes</span>
          <div className="studio-artifact-note-list">
            {notes.map((note) => (
              <p key={note}>{note}</p>
            ))}
          </div>
        </section>
      ) : null}

      <section className="studio-artifact-inspector-section">
        <span className="studio-artifact-panel-label">Materialized files</span>
        <div className="studio-artifact-note-list">
          {evidence.length ? (
            evidence.map((entry) => <p key={entry}>{entry}</p>)
          ) : (
            <p>No files recorded yet.</p>
          )}
        </div>
      </section>

      {revisions.length ? (
        <section className="studio-artifact-inspector-section">
          <span className="studio-artifact-panel-label">Revisions</span>
          <div className="studio-artifact-receipt-list">
            {revisions.map((revision) => (
              <article
                key={revision.revisionId}
                className="studio-artifact-receipt"
              >
                <strong>
                  {revision.branchLabel}
                  {revision.revisionId === activeRevisionId ? " · Active" : ""}
                </strong>
                <span>{new Date(revision.createdAt).toLocaleString()}</span>
                <p>{revision.prompt}</p>
                <div className="studio-artifact-chip-row">
                  {revision.revisionId !== activeRevisionId ? (
                    <button
                      type="button"
                      className="studio-artifact-stage-button"
                      onClick={() => void compareRevision(revision)}
                    >
                      Compare
                    </button>
                  ) : null}
                  {revision.revisionId !== activeRevisionId ? (
                    <button
                      type="button"
                      className="studio-artifact-stage-button"
                      onClick={() => void restoreRevision(revision)}
                      disabled={revisionBusy === revision.revisionId}
                    >
                      Restore
                    </button>
                  ) : null}
                  <button
                    type="button"
                    className="studio-artifact-stage-button"
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
            <div className="studio-artifact-note-list">
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
        <section className="studio-artifact-inspector-section">
          <span className="studio-artifact-panel-label">Recent activity</span>
          <div className="studio-artifact-note-list">
            {workspaceActivity.slice(0, 8).map((entry) => (
              <div key={entry.id} className="studio-artifact-activity">
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
