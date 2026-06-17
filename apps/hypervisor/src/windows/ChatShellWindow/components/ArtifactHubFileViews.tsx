import type { WorkspaceNode } from "@ioi/workspace-substrate";
import type { Artifact, SessionFileContext } from "../../../types";
import { buildFileContextPathOverview } from "./artifactHubFileContextModel";

function clipText(value: string, maxChars: number): string {
  if (value.length <= maxChars) {
    return value;
  }
  return `${value.slice(0, Math.max(0, maxChars - 1)).trimEnd()}…`;
}

function pathLabel(path: string): string {
  const normalized = path.replace(/\\/g, "/");
  const parts = normalized.split("/").filter(Boolean);
  return parts[parts.length - 1] || normalized;
}

function parentPathForFile(path: string): string {
  const normalized = path.replace(/\\/g, "/").trim();
  const parts = normalized.split("/").filter(Boolean);
  parts.pop();
  return parts.length > 0 ? parts.join("/") : ".";
}

function breadcrumbSegments(path: string) {
  const normalized = path.trim();
  if (!normalized || normalized === ".") {
    return [];
  }

  const parts = normalized
    .replace(/\\/g, "/")
    .split("/")
    .filter(Boolean);
  return parts.map((part, index) => ({
    label: part,
    path: parts.slice(0, index + 1).join("/"),
  }));
}

function FilePathSection({
  fileContext,
  title,
  paths,
  pathKind = "path",
  emptyLabel,
  onOpenDirectory,
  onRemovePath,
  onPinPath,
  onIncludePath,
  onExcludePath,
}: {
  fileContext: SessionFileContext | null;
  title: string;
  paths: string[];
  pathKind?: "file" | "path";
  emptyLabel: string;
  onOpenDirectory?: (path: string) => void;
  onRemovePath?: (path: string) => Promise<unknown>;
  onPinPath?: (path: string) => Promise<unknown>;
  onIncludePath?: (path: string) => Promise<unknown>;
  onExcludePath?: (path: string) => Promise<unknown>;
}) {
  return (
    <section className="artifact-hub-files-section">
      <div className="artifact-hub-files-section__header">
        <strong>{title}</strong>
        <span>{paths.length}</span>
      </div>
      {paths.length === 0 ? (
        <p className="artifact-hub-empty">{emptyLabel}</p>
      ) : (
        <div className="artifact-hub-files-path-list">
          {paths.map((path) => {
            const overview = buildFileContextPathOverview(
              fileContext,
              path,
              pathKind,
            );
            return (
              <article
                className="artifact-hub-files-path-row"
                key={`${title}:${path}`}
              >
                <div className="artifact-hub-files-path-copy">
                  <div className="artifact-hub-files-path-label">
                    {pathLabel(path)}
                  </div>
                  <div className="artifact-hub-files-path-detail">{path}</div>
                  {overview.badges.length > 0 ? (
                    <div className="artifact-hub-files-path-meta">
                      {overview.badges.map((badge) => (
                        <span
                          className="artifact-hub-policy-pill"
                          key={`${path}:${badge.key}`}
                        >
                          {badge.label}
                        </span>
                      ))}
                    </div>
                  ) : null}
                </div>
                <div className="artifact-hub-files-path-actions">
                  {onOpenDirectory ? (
                    <button
                      className="artifact-hub-open-btn secondary"
                      type="button"
                      onClick={() => onOpenDirectory(parentPathForFile(path))}
                    >
                      Browse
                    </button>
                  ) : null}
                  {onPinPath && overview.canPin ? (
                    <button
                      className="artifact-hub-open-btn secondary"
                      type="button"
                      onClick={() => void onPinPath(path)}
                    >
                      Pin
                    </button>
                  ) : null}
                  {onIncludePath && overview.canInclude ? (
                    <button
                      className="artifact-hub-open-btn secondary"
                      type="button"
                      onClick={() => void onIncludePath(path)}
                    >
                      {overview.includeLabel}
                    </button>
                  ) : null}
                  {onExcludePath && overview.canExclude ? (
                    <button
                      className="artifact-hub-open-btn secondary"
                      type="button"
                      onClick={() => void onExcludePath(path)}
                    >
                      {overview.excludeLabel}
                    </button>
                  ) : null}
                  {onRemovePath && overview.canRemove ? (
                    <button
                      className="artifact-hub-open-btn secondary"
                      type="button"
                      onClick={() => void onRemovePath(path)}
                    >
                      {overview.removeLabel}
                    </button>
                  ) : null}
                </div>
              </article>
            );
          })}
        </div>
      )}
    </section>
  );
}

export function FilesView({
  fileContext,
  fileContextStatus,
  fileContextError,
  fileBrowsePath,
  fileBrowseEntries,
  fileBrowseStatus,
  fileBrowseError,
  fileArtifacts,
  onOpenArtifact,
  onOpenFileDirectory,
  onBrowseFileParent,
  onRememberFilePath,
  onPinFilePath,
  onIncludeFilePath,
  onExcludeFilePath,
  onRemoveFilePath,
  onRefreshFileContext,
  onClearFileContext,
  openExternalUrl,
  extractArtifactUrl,
  formatTimestamp,
}: {
  fileContext: SessionFileContext | null;
  fileContextStatus: string;
  fileContextError: string | null;
  fileBrowsePath: string;
  fileBrowseEntries: WorkspaceNode[];
  fileBrowseStatus: string;
  fileBrowseError: string | null;
  fileArtifacts: Artifact[];
  onOpenArtifact?: (artifactId: string) => void;
  onOpenFileDirectory?: (path: string) => void;
  onBrowseFileParent?: () => void;
  onRememberFilePath?: (path: string) => Promise<unknown>;
  onPinFilePath?: (path: string) => Promise<unknown>;
  onIncludeFilePath?: (path: string) => Promise<unknown>;
  onExcludeFilePath?: (path: string) => Promise<unknown>;
  onRemoveFilePath?: (path: string) => Promise<unknown>;
  onRefreshFileContext?: () => Promise<unknown>;
  onClearFileContext?: () => Promise<unknown>;
  openExternalUrl: (url: string) => Promise<void>;
  extractArtifactUrl: (artifact: Artifact) => string | null;
  formatTimestamp: (value: string) => string;
}) {
  if (!fileContext && fileContextStatus === "loading") {
    return <p className="artifact-hub-empty">Loading session file context…</p>;
  }

  if (!fileContext) {
    return (
      <p className="artifact-hub-empty">
        {fileContextError || "No runtime file context is available for this session yet."}
      </p>
    );
  }

  const breadcrumb = breadcrumbSegments(fileBrowsePath);
  const syncLabel = fileContextStatus === "loading" ? "Syncing" : "Ready";
  const updatedAtLabel = new Date(fileContext.updated_at_ms).toLocaleTimeString(
    [],
    {
      hour: "numeric",
      minute: "2-digit",
    },
  );

  return (
    <div className="artifact-hub-files">
      <section className="artifact-hub-files-identity">
        <div className="artifact-hub-files-identity__eyebrow">Files</div>
        <h3 className="artifact-hub-files-identity__title">
          Session file context
        </h3>
        <p className="artifact-hub-files-identity__summary">
          Workspace root: {fileContext.workspace_root}
        </p>
        <div className="artifact-hub-files-identity__rows">
          <div className="artifact-hub-files-identity__row">
            <span>Current browser path</span>
            <strong>{fileBrowsePath === "." ? "root" : fileBrowsePath}</strong>
          </div>
          <div className="artifact-hub-files-identity__row">
            <span>Runtime sync</span>
            <strong>
              {syncLabel} · Updated {updatedAtLabel}
            </strong>
          </div>
          <div className="artifact-hub-files-identity__row">
            <span>File context counts</span>
            <strong>
              Pinned {fileContext.pinned_files.length} · Included{" "}
              {fileContext.explicit_includes.length} · Excluded{" "}
              {fileContext.explicit_excludes.length} · Recent{" "}
              {fileContext.recent_files.length}
            </strong>
          </div>
        </div>
      </section>

      <section className="artifact-hub-files-hero">
        <div>
          <div className="artifact-hub-generic-meta">
            <span>Session files</span>
            <span>{syncLabel}</span>
            <span>{updatedAtLabel}</span>
          </div>
          <div className="artifact-hub-generic-title">
            {fileContext.workspace_root}
          </div>
          <p className="artifact-hub-generic-summary">
            Retained session file context survives follow-up runs and keeps the
            primary shell aligned on which files matter.
          </p>
        </div>
        <div className="artifact-hub-files-hero__actions">
          {onRefreshFileContext ? (
            <button
              className="artifact-hub-open-btn secondary"
              type="button"
              onClick={() => void onRefreshFileContext()}
            >
              Refresh
            </button>
          ) : null}
          {onClearFileContext ? (
            <button
              className="artifact-hub-open-btn secondary"
              type="button"
              onClick={() => void onClearFileContext()}
            >
              Clear context
            </button>
          ) : null}
        </div>
      </section>

      <div className="artifact-hub-files-stats">
        <article className="artifact-hub-files-stat">
          <strong>{fileContext.pinned_files.length}</strong>
          <span>Pinned</span>
        </article>
        <article className="artifact-hub-files-stat">
          <strong>{fileContext.explicit_includes.length}</strong>
          <span>Included</span>
        </article>
        <article className="artifact-hub-files-stat">
          <strong>{fileContext.explicit_excludes.length}</strong>
          <span>Excluded</span>
        </article>
        <article className="artifact-hub-files-stat">
          <strong>{fileContext.recent_files.length}</strong>
          <span>Recent</span>
        </article>
      </div>

      <section className="artifact-hub-files-section">
        <div className="artifact-hub-files-section__header">
          <strong>Workspace browser</strong>
          <span>{fileBrowsePath === "." ? "root" : fileBrowsePath}</span>
        </div>
        <div className="artifact-hub-files-breadcrumbs">
          <button
            className="artifact-hub-open-btn secondary"
            type="button"
            onClick={() => onOpenFileDirectory?.(".")}
          >
            Root
          </button>
          {breadcrumb.map((segment) => (
            <button
              key={segment.path}
              className="artifact-hub-open-btn secondary"
              type="button"
              onClick={() => onOpenFileDirectory?.(segment.path)}
            >
              {segment.label}
            </button>
          ))}
          {fileBrowsePath !== "." && onBrowseFileParent ? (
            <button
              className="artifact-hub-open-btn secondary"
              type="button"
              onClick={onBrowseFileParent}
            >
              Up
            </button>
          ) : null}
        </div>
        {fileBrowseStatus === "loading" ? (
          <p className="artifact-hub-empty">Loading workspace directory…</p>
        ) : fileBrowseError ? (
          <p className="artifact-hub-empty">{fileBrowseError}</p>
        ) : fileBrowseEntries.length === 0 ? (
          <p className="artifact-hub-empty">
            No files were found at this workspace level.
          </p>
        ) : (
          <div className="artifact-hub-files-browser">
            {fileBrowseEntries.map((entry) => {
              const isDirectory = entry.kind === "directory";
              const overview = buildFileContextPathOverview(
                fileContext,
                entry.path,
                entry.kind,
              );
              return (
                <article
                  className="artifact-hub-files-browser-row"
                  key={entry.path}
                >
                  <div className="artifact-hub-files-browser-copy">
                    <div className="artifact-hub-files-path-label">{entry.name}</div>
                    <div className="artifact-hub-files-path-detail">{entry.path}</div>
                    {overview.badges.length > 0 ? (
                      <div className="artifact-hub-files-path-meta">
                        {overview.badges.map((badge) => (
                          <span
                            className="artifact-hub-policy-pill"
                            key={`${entry.path}:${badge.key}`}
                          >
                            {badge.label}
                          </span>
                        ))}
                      </div>
                    ) : null}
                  </div>
                  <div className="artifact-hub-files-path-actions">
                    {isDirectory ? (
                      <button
                        className="artifact-hub-open-btn"
                        type="button"
                        onClick={() => onOpenFileDirectory?.(entry.path)}
                      >
                        Open
                      </button>
                    ) : null}
                    {!isDirectory && onRememberFilePath && overview.canRemember ? (
                      <button
                        className="artifact-hub-open-btn secondary"
                        type="button"
                        onClick={() => void onRememberFilePath?.(entry.path)}
                      >
                        Recent
                      </button>
                    ) : null}
                    {!isDirectory && onPinFilePath && overview.canPin ? (
                      <button
                        className="artifact-hub-open-btn secondary"
                        type="button"
                        onClick={() => void onPinFilePath?.(entry.path)}
                      >
                        Pin
                      </button>
                    ) : null}
                    {onIncludeFilePath && overview.canInclude ? (
                      <button
                        className="artifact-hub-open-btn secondary"
                        type="button"
                        onClick={() => void onIncludeFilePath?.(entry.path)}
                      >
                        {overview.includeLabel}
                      </button>
                    ) : null}
                    {onExcludeFilePath && overview.canExclude ? (
                      <button
                        className="artifact-hub-open-btn secondary"
                        type="button"
                        onClick={() => void onExcludeFilePath?.(entry.path)}
                      >
                        {overview.excludeLabel}
                      </button>
                    ) : null}
                    {onRemoveFilePath && overview.canRemove ? (
                      <button
                        className="artifact-hub-open-btn secondary"
                        type="button"
                        onClick={() => void onRemoveFilePath?.(entry.path)}
                      >
                        {overview.removeLabel}
                      </button>
                    ) : null}
                    {!isDirectory ? (
                      <>
                        {!overview.canRemember &&
                        !overview.canPin &&
                        !overview.canInclude &&
                        !overview.canExclude &&
                        !overview.canRemove ? (
                          <span className="artifact-hub-empty">Already tracked</span>
                        ) : null}
                      </>
                    ) : null}
                  </div>
                </article>
              );
            })}
          </div>
        )}
      </section>

      <FilePathSection
        fileContext={fileContext}
        title="Pinned files"
        paths={fileContext.pinned_files}
        pathKind="file"
        emptyLabel="No pinned files yet. Pin a file from the browser to keep it in session context."
        onOpenDirectory={onOpenFileDirectory}
        onRemovePath={onRemoveFilePath}
        onIncludePath={onIncludeFilePath}
        onExcludePath={onExcludeFilePath}
      />

      <FilePathSection
        fileContext={fileContext}
        title="Explicit includes"
        paths={fileContext.explicit_includes}
        emptyLabel="No explicit include list yet."
        onOpenDirectory={onOpenFileDirectory}
        onPinPath={onPinFilePath}
        onRemovePath={onRemoveFilePath}
        onExcludePath={onExcludeFilePath}
      />

      <FilePathSection
        fileContext={fileContext}
        title="Explicit excludes"
        paths={fileContext.explicit_excludes}
        emptyLabel="No explicit exclude list yet."
        onOpenDirectory={onOpenFileDirectory}
        onPinPath={onPinFilePath}
        onRemovePath={onRemoveFilePath}
        onIncludePath={onIncludeFilePath}
      />

      <FilePathSection
        fileContext={fileContext}
        title="Recent files"
        paths={fileContext.recent_files}
        pathKind="file"
        emptyLabel="Recent files appear here after you touch them from the Files drawer."
        onOpenDirectory={onOpenFileDirectory}
        onPinPath={onPinFilePath}
        onIncludePath={onIncludeFilePath}
        onExcludePath={onExcludeFilePath}
        onRemovePath={onRemoveFilePath}
      />

      {fileArtifacts.length > 0 ? (
        <ArtifactListView
          items={fileArtifacts}
          label="Outputs"
          onOpenArtifact={onOpenArtifact}
          openExternalUrl={openExternalUrl}
          extractArtifactUrl={extractArtifactUrl}
          formatTimestamp={formatTimestamp}
        />
      ) : null}
    </div>
  );
}

export function ArtifactListView({
  items,
  label,
  onOpenArtifact,
  openExternalUrl,
  extractArtifactUrl,
  formatTimestamp,
}: {
  items: Artifact[];
  label: string;
  onOpenArtifact?: (artifactId: string) => void;
  openExternalUrl: (url: string) => Promise<void>;
  extractArtifactUrl: (artifact: Artifact) => string | null;
  formatTimestamp: (value: string) => string;
}) {
  if (items.length === 0) {
    return (
      <p className="artifact-hub-empty">No {label.toLowerCase()} available.</p>
    );
  }

  return (
    <div className="artifact-hub-generic-list">
      {items.map((artifact) => {
        const url = extractArtifactUrl(artifact);
        return (
          <article
            className="artifact-hub-generic-row"
            key={artifact.artifact_id}
          >
            <div className="artifact-hub-generic-meta">
              <span>{artifact.artifact_type}</span>
              <span>{formatTimestamp(artifact.created_at)}</span>
            </div>
            <div className="artifact-hub-generic-title">{artifact.title}</div>
            {artifact.description && (
              <p className="artifact-hub-generic-summary">
                {clipText(artifact.description, 180)}
              </p>
            )}
            <div className="artifact-hub-generic-actions">
              {onOpenArtifact && (
                <button
                  className="artifact-hub-open-btn"
                  onClick={() => onOpenArtifact(artifact.artifact_id)}
                  type="button"
                >
                  Open artifact
                </button>
              )}
              {url && (
                <button
                  className="artifact-hub-open-btn secondary"
                  onClick={() => void openExternalUrl(url)}
                  type="button"
                >
                  Open URL
                </button>
              )}
            </div>
          </article>
        );
      })}
    </div>
  );
}
