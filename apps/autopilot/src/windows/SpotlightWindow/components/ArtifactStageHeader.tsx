import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { executionStageForCurrentStage } from "../../../types";
import { formatStatusLabel, type SurfaceStageHeaderProps } from "./artifactSurfaceShared";

function PreviewIcon() {
  return (
    <svg viewBox="0 0 20 20" fill="currentColor" aria-hidden="true">
      <path d="M10 4c4.028 0 6.643 3.306 7.66 4.866l.08.133a2.06 2.06 0 0 1 0 2.002l-.08.133C16.643 12.694 14.028 16 10 16c-3.777 0-6.311-2.906-7.451-4.555l-.21-.311a2.07 2.07 0 0 1 0-2.268l.21-.311C3.689 6.905 6.223 4 10 4m0 1C6.747 5 4.476 7.53 3.38 9.11l-.202.302a1.07 1.07 0 0 0 0 1.176l.203.302C4.476 12.47 6.747 15 10 15c3.47 0 5.822-2.878 6.822-4.412l.077-.14a1.06 1.06 0 0 0 0-.896l-.077-.14C15.822 7.878 13.47 5 10 5m0 2a3 3 0 1 1 0 6 3 3 0 0 1 0-6m0 1a2 2 0 1 0 0 4 2 2 0 0 0 0-4" />
    </svg>
  );
}

function CodeIcon() {
  return (
    <svg viewBox="0 0 20 20" fill="currentColor" aria-hidden="true">
      <path d="M11.632 4.018a.5.5 0 0 1 .35.614l-3 11a.5.5 0 0 1-.964-.264l3-11a.5.5 0 0 1 .614-.35m1.492 2.153a.5.5 0 0 1 .705-.047l4 3.5.072.078a.5.5 0 0 1-.072.674l-4 3.5-.082.059a.5.5 0 0 1-.645-.738l.069-.073L16.74 10l-3.57-3.124a.5.5 0 0 1-.047-.705m-6.871-.106a.5.5 0 0 1 .645.738l-.069.073L3.26 10l3.57 3.124a.5.5 0 1 1-.658.752l-4-3.5-.072-.078a.5.5 0 0 1 .072-.674l4-3.5z" />
    </svg>
  );
}

function RefreshIcon() {
  return (
    <svg viewBox="0 0 20 20" fill="currentColor" aria-hidden="true">
      <path d="M10.386 2.51A7.5 7.5 0 1 1 5.499 4H3a.5.5 0 0 1 0-1h3.5a.5.5 0 0 1 .49.402L7 3.5V7a.5.5 0 0 1-1 0V4.879a6.5 6.5 0 1 0 4.335-1.37L10 3.5l-.1-.01a.5.5 0 0 1 .1-.99" />
    </svg>
  );
}

function CloseIcon() {
  return (
    <svg viewBox="0 0 20 20" fill="currentColor" aria-hidden="true">
      <path d="M15.147 4.146a.5.5 0 0 1 .707.707L10.707 10l5.147 5.147a.5.5 0 0 1-.63.771l-.078-.064L10 10.707l-5.146 5.147a.5.5 0 0 1-.708-.707L9.293 10 4.146 4.853a.5.5 0 0 1 .708-.707L10 9.293z" />
    </svg>
  );
}

function ChevronDownIcon() {
  return (
    <svg viewBox="0 0 20 20" fill="currentColor" aria-hidden="true">
      <path d="M14.128 7.165a.502.502 0 0 1 .744.67l-4.5 5-.078.07a.5.5 0 0 1-.666-.07l-4.5-5-.06-.082a.501.501 0 0 1 .729-.656l.075.068L10 11.752z" />
    </svg>
  );
}

export function ArtifactStageHeader({
  manifest,
  title,
  stageKicker = "Artifact stage",
  activePath,
  copyText = null,
  copyPath = null,
  rendererLabel,
  swarmExecution,
  retrying,
  stageMode,
  evidenceOpen: _evidenceOpen,
  showStageModes = true,
  onSelectStageMode,
  onToggleEvidence: _onToggleEvidence,
  onRetry,
  onBrowseArtifacts: _onBrowseArtifacts,
  onCollapse,
}: SurfaceStageHeaderProps) {
  const [copyMenuOpen, setCopyMenuOpen] = useState(false);
  const [copiedOptionId, setCopiedOptionId] = useState<string | null>(null);
  const copyMenuRef = useRef<HTMLDivElement | null>(null);
  const genericExecutionStage = swarmExecution?.enabled
    ? swarmExecution.executionStage ??
      executionStageForCurrentStage(swarmExecution.currentStage)
    : null;
  const isRunningMaterialization =
    Boolean(swarmExecution?.enabled) &&
    manifest.files.length === 0 &&
    (swarmExecution?.totalWorkItems ?? 0) > 0 &&
    (swarmExecution?.completedWorkItems ?? 0) < (swarmExecution?.totalWorkItems ?? 0);
  const primaryStatusLabel = isRunningMaterialization
    ? "Running"
    : formatStatusLabel(manifest.verification.status);
  const lifecycleLabel = isRunningMaterialization
    ? "Materializing"
    : formatStatusLabel(manifest.verification.lifecycleState);
  const stageMeta = [
    activePath,
    rendererLabel,
    primaryStatusLabel,
    lifecycleLabel,
    swarmExecution?.enabled ? formatStatusLabel(genericExecutionStage) : null,
    swarmExecution?.enabled ? formatStatusLabel(swarmExecution.currentStage) : null,
    swarmExecution?.enabled
      ? `${swarmExecution.completedWorkItems}/${swarmExecution.totalWorkItems} work items`
      : null,
    swarmExecution?.enabled
      ? formatStatusLabel(swarmExecution.verificationStatus)
      : null,
  ].filter((value): value is string => Boolean(value));
  const titleLabel = stageMeta.length
    ? `${stageKicker} · ${title} · ${stageMeta.join(" · ")}`
    : `${stageKicker} · ${title} · ${rendererLabel}`;
  const copyOptions = useMemo(
    () =>
      [
        copyText?.trim()
          ? {
              id: "content",
              label: "Copy content",
              value: copyText,
            }
          : null,
        copyPath?.trim()
          ? {
              id: "path",
              label: "Copy path",
              value: copyPath,
            }
          : null,
        title.trim()
          ? {
              id: "title",
              label: "Copy title",
              value: title,
            }
          : null,
      ].filter((option): option is { id: string; label: string; value: string } =>
        Boolean(option),
      ),
    [copyPath, copyText, title],
  );
  const primaryCopyOption = copyOptions[0] ?? null;

  useEffect(() => {
    if (!copyMenuOpen) {
      return;
    }

    const handlePointerDown = (event: PointerEvent) => {
      if (!copyMenuRef.current?.contains(event.target as Node)) {
        setCopyMenuOpen(false);
      }
    };

    window.addEventListener("pointerdown", handlePointerDown);
    return () => window.removeEventListener("pointerdown", handlePointerDown);
  }, [copyMenuOpen]);

  const handleCopyOption = useCallback(
    async (option: { id: string; label: string; value: string }) => {
      try {
        await navigator.clipboard.writeText(option.value);
        setCopiedOptionId(option.id);
        setCopyMenuOpen(false);
        window.setTimeout(() => {
          setCopiedOptionId((current) => (current === option.id ? null : current));
        }, 1600);
      } catch {
        setCopyMenuOpen(false);
      }
    },
    [],
  );

  return (
    <header className="studio-artifact-stage-header studio-artifact-stage-header--compact">
      <div className="studio-artifact-stage-header-main">
        {showStageModes ? (
          <div
            className="studio-artifact-mode-toggle"
            role="tablist"
            aria-label="Artifact stage mode"
          >
            <button
              type="button"
              className={`studio-artifact-mode-toggle-button ${
                stageMode === "render" ? "is-active" : ""
              }`}
              onClick={() => onSelectStageMode("render")}
              role="tab"
              aria-selected={stageMode === "render"}
              aria-label="Preview"
              title="Preview"
            >
              <span className="studio-artifact-mode-toggle-icon">
                <PreviewIcon />
              </span>
            </button>
            <button
              type="button"
              className={`studio-artifact-mode-toggle-button ${
                stageMode === "source" ? "is-active" : ""
              }`}
              onClick={() => onSelectStageMode("source")}
              role="tab"
              aria-selected={stageMode === "source"}
              aria-label="Code"
              title="Code"
            >
              <span className="studio-artifact-mode-toggle-icon">
                <CodeIcon />
              </span>
            </button>
          </div>
        ) : null}

        <div className="studio-artifact-stage-copy" title={titleLabel}>
          <h2>
            {title}
            <span className="studio-artifact-stage-copy-divider" aria-hidden="true">
              {" "}
              ·{" "}
            </span>
            <span className="studio-artifact-stage-copy-meta">{rendererLabel}</span>
          </h2>
          {stageMeta.length ? (
            <p
              className="studio-artifact-inline-meta"
              aria-label="Artifact stage details"
            >
              {stageMeta.join(" · ")}
            </p>
          ) : null}
        </div>
      </div>

      <div className="studio-artifact-stage-toolbar">
        <div className="studio-artifact-stage-actions">
          {primaryCopyOption ? (
            <div className="studio-artifact-copy-control" ref={copyMenuRef}>
              <button
                type="button"
                className="studio-artifact-copy-primary"
                onClick={() => void handleCopyOption(primaryCopyOption)}
                title={primaryCopyOption.label}
              >
                {copiedOptionId === primaryCopyOption.id ? "Copied" : "Copy"}
              </button>
              <button
                type="button"
                className="studio-artifact-copy-toggle"
                onClick={() => {
                  if (copyOptions.length <= 1) {
                    void handleCopyOption(primaryCopyOption);
                    return;
                  }
                  setCopyMenuOpen((current) => !current);
                }}
                aria-haspopup="menu"
                aria-expanded={copyMenuOpen}
                title="Copy options"
              >
                <ChevronDownIcon />
              </button>

              {copyMenuOpen && copyOptions.length > 1 ? (
                <div className="studio-artifact-copy-menu" role="menu">
                  {copyOptions.map((option) => (
                    <button
                      key={option.id}
                      type="button"
                      className="studio-artifact-copy-menu-item"
                      onClick={() => void handleCopyOption(option)}
                      role="menuitem"
                    >
                      {option.label}
                    </button>
                  ))}
                </div>
              ) : null}
            </div>
          ) : null}
          {onRetry ? (
            <button
              type="button"
              className="studio-artifact-stage-button studio-artifact-stage-button--refresh"
              onClick={onRetry}
              disabled={retrying}
              aria-label={retrying ? "Refreshing rendered artifact" : "Refresh rendered artifact"}
              title={retrying ? "Refreshing rendered artifact" : "Refresh rendered artifact"}
            >
              <RefreshIcon />
              <span>{retrying ? "Refreshing…" : "Refresh"}</span>
            </button>
          ) : null}
          {onCollapse ? (
            <button
              type="button"
              className="studio-artifact-stage-button studio-artifact-stage-button--icon"
              onClick={onCollapse}
              aria-label="Collapse artifact"
              title="Collapse artifact"
            >
              <CloseIcon />
            </button>
          ) : null}
        </div>
      </div>
    </header>
  );
}
