import clsx from "clsx";
import { Codicon } from "./Codicon";
import workbenchExplorerHeaderFullStrip from "../assets/workbench-explorer-header-full-strip.png";
import type { WorkspaceExplorerPaneProps, WorkspaceNode } from "../types";

type WorkspaceFileIconKind =
  | "file"
  | "image"
  | "markdown"
  | "json"
  | "yaml"
  | "html"
  | "typescript"
  | "javascript"
  | "rust"
  | "vite";

function fileIconKind(name: string): WorkspaceFileIconKind {
  const lower = name.toLowerCase();

  if (
    lower.endsWith(".png") ||
    lower.endsWith(".jpg") ||
    lower.endsWith(".jpeg") ||
    lower.endsWith(".gif") ||
    lower.endsWith(".webp") ||
    lower.endsWith(".ico") ||
    lower.endsWith(".bmp")
  ) {
    return "image";
  }

  if (lower.endsWith(".md") || lower.endsWith(".mdx")) {
    return "markdown";
  }

  if (lower.startsWith("vite.config.")) {
    return "vite";
  }

  if (lower === "cargo.toml" || lower.endsWith(".rs") || lower.endsWith(".toml")) {
    return "rust";
  }

  if (lower.endsWith(".json")) {
    return "json";
  }

  if (lower.endsWith(".yaml") || lower.endsWith(".yml")) {
    return "yaml";
  }

  if (lower.endsWith(".html") || lower.endsWith(".htm")) {
    return "html";
  }

  if (lower.endsWith(".ts") || lower.endsWith(".tsx")) {
    return "typescript";
  }

  if (lower.endsWith(".js") || lower.endsWith(".jsx")) {
    return "javascript";
  }

  return "file";
}

function FolderIcon({ open }: { open: boolean }) {
  return (
    <svg
      className={clsx("workspace-folder-icon", open && "is-open")}
      width="15"
      height="12"
      viewBox="0 0 29 22"
      fill="none"
      aria-hidden="true"
    >
      <path
        className="workspace-folder-back"
        d="M2 4a1.5 1.5 0 011.5-1.5h5.2c.55 0 1.07.25 1.4.68L11.3 4.7c.2.25.5.3.7.3H21a2 2 0 012 2V18a2 2 0 01-2 2H4a2 2 0 01-2-2V4z"
      />
      <path
        className="workspace-folder-front workspace-folder-front--closed"
        d="M3.5 7.5h19a1.5 1.5 0 011.5 1.5v9a2 2 0 01-2 2H4a2 2 0 01-2-2V9a1.5 1.5 0 011.5-1.5z"
      />
      <path
        className="workspace-folder-front workspace-folder-front--open"
        d="M6.5 7.5h19a1.5 1.5 0 011.5 1.5L24 18a2 2 0 01-2 2H4a2 2 0 01-2-2L5 9a1.5 1.5 0 011.5-1.5z"
      />
    </svg>
  );
}

function ExplorerMenuIcon() {
  return <Codicon name="menu" />;
}

function ExplorerMoreIcon() {
  return <Codicon name="ellipsis" />;
}

function TreeChevron({ expanded }: { expanded: boolean }) {
  return (
    <svg
      className={clsx("workspace-tree-chevron", expanded && "is-expanded")}
      width="10"
      height="10"
      viewBox="0 0 10 10"
      fill="none"
      aria-hidden="true"
    >
      <path d="m3.2 2 3.2 3-3.2 3" stroke="currentColor" strokeWidth="1.2" strokeLinecap="round" strokeLinejoin="round" />
    </svg>
  );
}

function FileIcon({ name }: { name: string }) {
  const kind = fileIconKind(name);

  if (kind === "file") {
    return <span className="workspace-file-sheet" aria-hidden="true" />;
  }

  if (kind === "markdown") {
    return (
      <svg
        className="workspace-file-icon is-markdown"
        width="14"
        height="14"
        viewBox="0 0 16 16"
        fill="none"
        aria-hidden="true"
      >
        <circle cx="8" cy="8" r="6" stroke="currentColor" strokeWidth="1.4" />
        <path d="M8 7v4" stroke="currentColor" strokeWidth="1.4" strokeLinecap="round" />
        <circle cx="8" cy="4.6" r="0.8" fill="currentColor" />
      </svg>
    );
  }

  if (kind === "image") {
    return (
      <svg
        className="workspace-file-icon is-image"
        width="14"
        height="14"
        viewBox="0 0 16 16"
        fill="none"
        aria-hidden="true"
      >
        <rect x="2.2" y="3" width="11.6" height="10" rx="1.5" stroke="currentColor" strokeWidth="1.2" />
        <circle cx="6" cy="6.2" r="1.1" fill="currentColor" />
        <path
          d="M3.8 11.5 6.6 8.8a.7.7 0 0 1 .98 0l1.6 1.54a.7.7 0 0 0 .96.03l1.02-.9a.7.7 0 0 1 .94.03l1.04 1.02"
          stroke="currentColor"
          strokeWidth="1.2"
          strokeLinecap="round"
          strokeLinejoin="round"
        />
      </svg>
    );
  }

  if (kind === "rust") {
    return (
      <svg
        className="workspace-file-icon is-rust"
        width="14"
        height="14"
        viewBox="0 0 16 16"
        fill="none"
        aria-hidden="true"
      >
        <path
          d="M8 3.2 9.1 2.6l1 1.1 1.42-.1.42 1.43 1.28.63-.33 1.39.92 1.08-.92 1.08.33 1.39-1.28.63-.42 1.43-1.42-.1-1 1.1L8 12.8l-1.1.6-1-1.1-1.42.1-.42-1.43-1.28-.63.33-1.39-.92-1.08.92-1.08-.33-1.39 1.28-.63.42-1.43 1.42.1 1-1.1L8 3.2Z"
          stroke="currentColor"
          strokeWidth="1.1"
          strokeLinejoin="round"
        />
        <circle cx="8" cy="8" r="2" fill="currentColor" />
      </svg>
    );
  }

  if (kind === "vite") {
    return (
      <svg
        className="workspace-file-icon is-vite"
        width="14"
        height="14"
        viewBox="0 0 16 16"
        fill="none"
        aria-hidden="true"
      >
        <path
          d="M8.9 1.8 4.9 8.3h2.34L6.6 14.2l4.5-7.06H8.74L8.9 1.8Z"
          fill="currentColor"
        />
      </svg>
    );
  }

  const label =
    kind === "json"
      ? "{}"
      : kind === "yaml"
        ? "!"
        : kind === "html"
          ? "<>"
          : kind === "typescript"
            ? "TS"
            : "JS";

  return (
    <span className={clsx("workspace-file-badge", `is-${kind}`)} aria-hidden="true">
      {label}
    </span>
  );
}

function branchLabel(branch: string | null) {
  return branch?.trim() || "detached";
}

function basenameLabel(path: string): string {
  const segments = path.split("/").filter(Boolean);
  return segments.length > 0 ? segments[segments.length - 1] : path;
}

function hasExpandedChildDirectory(
  nodes: WorkspaceNode[],
  expandedPaths: Record<string, boolean>,
): boolean {
  return nodes.some(
    (node) => node.kind === "directory" && !!expandedPaths[node.path],
  );
}

function renderTree(
  nodes: WorkspaceNode[],
  props: Pick<
    WorkspaceExplorerPaneProps,
    | "activePath"
    | "expandedPaths"
    | "loadingDirectories"
    | "readOnly"
    | "onToggleDirectory"
    | "onOpenFile"
    | "onRenamePath"
    | "onDeletePath"
  >,
): JSX.Element {
  return (
    <>
      {nodes.map((node) => {
        const expanded = node.kind === "directory" && !!props.expandedPaths[node.path];
        const isActive = node.kind === "file" && node.path === props.activePath;
        const isLoading = !!props.loadingDirectories[node.path];
        const childGuideTone = hasExpandedChildDirectory(node.children, props.expandedPaths)
          ? "is-ancestor"
          : "is-youngest";
        return (
          <div key={`${node.kind}:${node.path}`} className="workspace-tree-group">
            <div
              className={clsx(
                "workspace-tree-row",
                expanded && "is-expanded",
                isActive && "is-active",
                node.kind === "directory" && "is-directory",
              )}
            >
              <button
                type="button"
                className="workspace-tree-trigger"
                onClick={() =>
                  node.kind === "directory"
                    ? props.onToggleDirectory(node)
                    : props.onOpenFile(node.path)
                }
              >
                {node.kind === "directory" ? (
                  <TreeChevron expanded={expanded} />
                ) : (
                  <span className="workspace-tree-chevron workspace-tree-chevron--spacer" aria-hidden="true" />
                )}
                {node.kind === "directory" ? (
                  <FolderIcon open={expanded} />
                ) : (
                  <FileIcon name={node.name} />
                )}
                <span className="workspace-tree-name">{node.name}</span>
              </button>

              {node.path !== "." && !props.readOnly ? (
                <div className="workspace-tree-actions">
                  <button
                    type="button"
                    className="workspace-tree-action"
                    onClick={() => props.onRenamePath(node.path)}
                    title={`Rename ${node.name}`}
                    aria-label={`Rename ${node.name}`}
                  >
                    Rename
                  </button>
                  <button
                    type="button"
                    className="workspace-tree-action is-danger"
                    onClick={() => props.onDeletePath(node.path)}
                    title={`Delete ${node.name}`}
                    aria-label={`Delete ${node.name}`}
                  >
                    Delete
                  </button>
                </div>
              ) : null}
            </div>

            {node.kind === "directory" && expanded ? (
              <div className={clsx("workspace-tree-children", childGuideTone)}>
                {isLoading && node.children.length === 0 ? (
                  <div className="workspace-pane-message workspace-pane-message--nested">
                    Loading directory...
                  </div>
                ) : (
                  renderTree(node.children, props)
                )}
              </div>
            ) : null}
          </div>
        );
      })}
    </>
  );
}

export function WorkspaceExplorerPane(props: WorkspaceExplorerPaneProps) {
  const treeGuideTone = hasExpandedChildDirectory(props.tree, props.expandedPaths)
    ? "is-ancestor"
    : "is-youngest";
  const eyebrow = props.eyebrow || "Workspace";
  const title = props.title || "Explorer";
  const showGitSummary = props.showGitSummary ?? true;
  const workspaceFolderName =
    props.workspaceFolderName?.trim() || basenameLabel(props.rootPath) || "workspace";
  const workspaceHeadingLabel =
    props.workspaceLabel?.trim().toUpperCase() ||
    workspaceFolderName.toUpperCase();
  const alreadyWrappedByWorkspaceNode =
    props.tree.length === 1 &&
    props.tree[0]?.kind === "directory" &&
    props.tree[0]?.name.trim().toUpperCase() === workspaceHeadingLabel;
  const syntheticRootNode: WorkspaceNode = {
    name: workspaceFolderName,
    path: ".",
    kind: "directory",
    hasChildren: true,
    children: props.tree,
  };
  const syntheticRootExpanded = !!props.expandedPaths[syntheticRootNode.path];
  const syntheticRootLoading = !!props.loadingDirectories[syntheticRootNode.path];

  return (
    <section className="workspace-pane">
      <header className="workspace-pane-header">
        <img src={workbenchExplorerHeaderFullStrip} alt="" className="workspace-pane-header-strip" aria-hidden="true" />
        <div className="workspace-pane-header-live">
          <div className="workspace-pane-header-leading">
            <button type="button" className="workspace-pane-header-icon" tabIndex={-1} aria-hidden="true">
              <ExplorerMenuIcon />
            </button>
            <div>
            <span className="workspace-pane-eyebrow">{eyebrow}</span>
            <h3>{title}</h3>
            </div>
          </div>
          <div className="workspace-pane-header-actions">
            <button type="button" className="workspace-pane-header-icon" tabIndex={-1} aria-hidden="true">
              <ExplorerMoreIcon />
            </button>
          </div>
        </div>
      </header>

      {showGitSummary ? (
        <div className="workspace-pane-meta">
          <span className="workspace-chip">{branchLabel(props.git.branch)}</span>
          <span className="workspace-chip">
            {props.git.isRepo ? (props.git.dirty ? "Dirty" : "Clean") : "No repo"}
          </span>
        </div>
      ) : null}
      <p className="workspace-root-path" title={props.rootPath}>
        {props.rootPath}
      </p>

      <div className={clsx("workspace-tree", treeGuideTone)}>
        {alreadyWrappedByWorkspaceNode ? (
          renderTree(props.tree, props)
        ) : (
          <div className="workspace-tree-group workspace-tree-group--workspace-root">
            <div className="workspace-tree-workspace-heading">
              <span className="workspace-tree-workspace-chevron" aria-hidden="true">
                <TreeChevron expanded />
              </span>
              <span className="workspace-tree-workspace-label">{workspaceHeadingLabel}</span>
            </div>

            <div
              className={clsx(
                "workspace-tree-row",
                "is-directory",
                "workspace-tree-row--workspace-folder",
                syntheticRootExpanded && "is-expanded",
              )}
            >
              <button
                type="button"
                className="workspace-tree-trigger workspace-tree-trigger--plain-folder"
                onClick={() => props.onToggleDirectory(syntheticRootNode)}
              >
                <FolderIcon open={syntheticRootExpanded} />
                <span className="workspace-tree-name">{workspaceFolderName}</span>
              </button>
              {props.git.isRepo ? (
                <span
                  className="workspace-tree-status-marker"
                  aria-label={
                    props.git.dirty
                      ? "Workspace has uncommitted changes"
                      : "Workspace repository status"
                  }
                >
                  !
                </span>
              ) : null}
            </div>

            {syntheticRootExpanded ? (
              <div className={clsx("workspace-tree-children", treeGuideTone)}>
                {syntheticRootLoading && props.tree.length === 0 ? (
                  <div className="workspace-pane-message workspace-pane-message--nested">
                    Loading directory...
                  </div>
                ) : (
                  renderTree(props.tree, props)
                )}
              </div>
            ) : null}
          </div>
        )}
      </div>
    </section>
  );
}
