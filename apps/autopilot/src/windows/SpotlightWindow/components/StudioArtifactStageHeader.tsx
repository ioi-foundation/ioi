import { formatStatusLabel, type SurfaceStageHeaderProps } from "./studioArtifactSurfaceShared";

export function StudioArtifactStageHeader({
  manifest,
  title,
  activePath,
  rendererLabel,
  retrying,
  stageMode,
  evidenceOpen,
  onSelectStageMode,
  onToggleEvidence,
  onRetry,
  onCollapse,
}: SurfaceStageHeaderProps) {
  return (
    <header className="studio-artifact-stage-header studio-artifact-stage-header--compact">
      <div className="studio-artifact-stage-header-main">
        <div className="studio-artifact-stage-copy">
          <span className="studio-artifact-kicker">Artifact stage</span>
          <h3>{title}</h3>
        </div>

        <div className="studio-artifact-chip-row studio-artifact-chip-row--compact">
          {activePath ? <span className="studio-artifact-chip">{activePath}</span> : null}
          <span className="studio-artifact-chip">{rendererLabel}</span>
          <span className="studio-artifact-chip">
            {formatStatusLabel(manifest.verification.status)}
          </span>
          <span className="studio-artifact-chip is-muted">
            {formatStatusLabel(manifest.verification.lifecycleState)}
          </span>
        </div>
      </div>

      <div className="studio-artifact-stage-toolbar">
        <div className="studio-artifact-mode-toggle" role="tablist" aria-label="Artifact stage mode">
          <button
            type="button"
            className={`studio-artifact-mode-toggle-button ${
              stageMode === "render" ? "is-active" : ""
            }`}
            onClick={() => onSelectStageMode("render")}
            role="tab"
            aria-selected={stageMode === "render"}
          >
            Render
          </button>
          <button
            type="button"
            className={`studio-artifact-mode-toggle-button ${
              stageMode === "source" ? "is-active" : ""
            }`}
            onClick={() => onSelectStageMode("source")}
            role="tab"
            aria-selected={stageMode === "source"}
          >
            Source
          </button>
        </div>

        <div className="studio-artifact-stage-actions">
          <button
            type="button"
            className={`studio-artifact-stage-button ${
              evidenceOpen ? "is-emphasized" : ""
            }`}
            onClick={onToggleEvidence}
          >
            Evidence
          </button>
          {onRetry ? (
            <button
              type="button"
              className="studio-artifact-stage-button"
              onClick={onRetry}
              disabled={retrying}
            >
              {retrying ? "Retrying…" : "Re-run renderer"}
            </button>
          ) : null}
          {onCollapse ? (
            <button
              type="button"
              className="studio-artifact-stage-button"
              onClick={onCollapse}
            >
              Collapse artifact
            </button>
          ) : null}
        </div>
      </div>
    </header>
  );
}
