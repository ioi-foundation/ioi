import type { WorkspaceNode } from "@ioi/workspace-substrate";
import type { SessionFileContext } from "../../../types";

export type FileContextPathKind = WorkspaceNode["kind"] | "path";

export interface FileContextPathBadge {
  key:
    | "directory"
    | "pinned"
    | "included"
    | "excluded"
    | "recent"
    | "conflicted";
  label: string;
}

export interface FileContextPathOverview {
  path: string;
  kind: FileContextPathKind;
  badges: FileContextPathBadge[];
  canRemember: boolean;
  canPin: boolean;
  canInclude: boolean;
  includeLabel: string;
  canExclude: boolean;
  excludeLabel: string;
  canRemove: boolean;
  removeLabel: string;
}

function normalizePath(path: string): string {
  return path.trim().replace(/\\/g, "/").replace(/^\.\/+/, "");
}

function hasPath(paths: string[], target: string): boolean {
  const normalizedTarget = normalizePath(target);
  return paths.some((path) => normalizePath(path) === normalizedTarget);
}

export function buildFileContextPathOverview(
  context: SessionFileContext | null,
  path: string,
  kind: FileContextPathKind,
): FileContextPathOverview {
  const isDirectory = kind === "directory";
  const isPinned = hasPath(context?.pinned_files ?? [], path);
  const isIncluded = hasPath(context?.explicit_includes ?? [], path);
  const isExcluded = hasPath(context?.explicit_excludes ?? [], path);
  const isRecent = hasPath(context?.recent_files ?? [], path);
  const isConflicted = (isPinned && isExcluded) || (isIncluded && isExcluded);

  const badges: FileContextPathBadge[] = [];
  if (isDirectory) {
    badges.push({ key: "directory", label: "Folder" });
  }
  if (isConflicted) {
    badges.push({ key: "conflicted", label: "Needs review" });
  }
  if (isPinned) {
    badges.push({ key: "pinned", label: "Pinned" });
  }
  if (isIncluded) {
    badges.push({
      key: "included",
      label: isDirectory || kind === "path" ? "Included scope" : "Included",
    });
  }
  if (isExcluded) {
    badges.push({
      key: "excluded",
      label: isDirectory || kind === "path" ? "Excluded scope" : "Excluded",
    });
  }
  if (isRecent) {
    badges.push({ key: "recent", label: "Recent" });
  }

  const includeLabel = isDirectory ? "Include folder" : "Include";
  const excludeLabel = isDirectory ? "Exclude folder" : "Exclude";
  const hasAnyState = isPinned || isIncluded || isExcluded || isRecent;
  const removeLabel =
    isDirectory || kind === "path"
      ? isIncluded || isExcluded
        ? "Clear scope"
        : "Remove"
      : "Remove";

  return {
    path,
    kind,
    badges,
    canRemember: kind === "file" && !isRecent,
    canPin: kind === "file" && (!isPinned || isExcluded),
    canInclude: !isIncluded || isExcluded,
    includeLabel,
    canExclude: !isExcluded || isIncluded || isPinned,
    excludeLabel,
    canRemove: hasAnyState,
    removeLabel,
  };
}
