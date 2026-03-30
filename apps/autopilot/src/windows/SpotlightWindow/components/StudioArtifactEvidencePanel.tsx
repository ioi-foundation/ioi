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
  const activeRevisionId = studioSession.activeRevisionId ?? revisions[0]?.revisionId ?? null;
  const brief = studioSession.materialization.artifactBrief ?? null;
  const judge = studioSession.materialization.judge ?? null;
  const candidates = studioSession.materialization.candidateSummaries ?? [];
  const tasteMemory = studioSession.tasteMemory ?? null;
  const [comparison, setComparison] = useState<StudioArtifactRevisionComparison | null>(null);
  const [revisionBusy, setRevisionBusy] = useState<string | null>(null);

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
      await invoke("studio_restore_artifact_revision", { revisionId: revision.revisionId });
    } finally {
      setRevisionBusy(null);
    }
  };

  const branchRevision = async (revision: StudioArtifactRevision) => {
    setRevisionBusy(revision.revisionId);
    try {
      await invoke("studio_branch_artifact_revision", { revisionId: revision.revisionId });
    } finally {
      setRevisionBusy(null);
    }
  };

  return (
    <aside className="studio-artifact-inspector" aria-label="Artifact evidence inspector">
      <section className="studio-artifact-inspector-section">
        <span className="studio-artifact-panel-label">Verification</span>
        <p>{manifest.verification.summary}</p>
        <div className="studio-artifact-note-list">
          <p>
            <strong>Production:</strong>{" "}
            {formatRuntimeProvenance(manifest.verification.productionProvenance)}
          </p>
          <p>
            <strong>Acceptance:</strong>{" "}
            {formatRuntimeProvenance(manifest.verification.acceptanceProvenance)}
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
            {brief.visualTone.length ? <p>{brief.visualTone.join(" · ")}</p> : null}
            {brief.styleDirectives.length ? <p>{brief.styleDirectives.join(" · ")}</p> : null}
          </div>
        </section>
      ) : null}

      {judge ? (
        <section className="studio-artifact-inspector-section">
          <span className="studio-artifact-panel-label">Judge</span>
          <div className="studio-artifact-note-list">
            <p>
              <strong>{formatStatusLabel(judge.classification)}</strong> · {judge.rationale}
            </p>
            <p>
              Faithfulness {judge.requestFaithfulness}/5 · Coverage {judge.conceptCoverage}/5
              · Interaction {judge.interactionRelevance}/5
            </p>
            <p>
              Layout {judge.layoutCoherence}/5 · Hierarchy {judge.visualHierarchy}/5 ·
              Completeness {judge.completeness}/5
            </p>
            {judge.strongestContradiction ? <p>{judge.strongestContradiction}</p> : null}
          </div>
        </section>
      ) : null}

      {candidates.length ? (
        <section className="studio-artifact-inspector-section">
          <span className="studio-artifact-panel-label">Candidates</span>
          <div className="studio-artifact-note-list">
            {candidates.map((candidate) => (
              <div key={candidate.candidateId} className="studio-artifact-activity">
                <div>
                  <strong>
                    {candidate.selected ? "Winner" : "Candidate"} {candidate.candidateId}
                  </strong>
                  <p>{candidate.summary}</p>
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
            {tasteMemory.directives.length ? <p>{tasteMemory.directives.join(" · ")}</p> : null}
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
              <article key={receipt.receiptId} className="studio-artifact-receipt">
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
          {evidence.length ? evidence.map((entry) => <p key={entry}>{entry}</p>) : <p>No files recorded yet.</p>}
        </div>
      </section>

      {revisions.length ? (
        <section className="studio-artifact-inspector-section">
          <span className="studio-artifact-panel-label">Revisions</span>
          <div className="studio-artifact-receipt-list">
            {revisions.map((revision) => (
              <article key={revision.revisionId} className="studio-artifact-receipt">
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
