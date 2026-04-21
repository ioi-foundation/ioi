import type { WorkspaceNode } from "@ioi/workspace-substrate";
import type {
  ChatArtifactManifest,
  ChatArtifactManifestFile,
  ChatRendererSession,
} from "../../../types";

export type ChatArtifactStageMode = "render" | "source";

type MutableTreeNode = {
  name: string;
  path: string;
  kind: "directory" | "file";
  children: Map<string, MutableTreeNode>;
};

export function buildArtifactTree(files: ChatArtifactManifestFile[]): WorkspaceNode[] {
  const root: MutableTreeNode = {
    name: ".",
    path: ".",
    kind: "directory",
    children: new Map(),
  };

  for (const file of files) {
    const parts = file.path.split("/").filter(Boolean);
    let current = root;

    for (let index = 0; index < parts.length; index += 1) {
      const part = parts[index];
      const nextPath = parts.slice(0, index + 1).join("/");
      const isLeaf = index === parts.length - 1;
      const existing = current.children.get(part);

      if (existing) {
        current = existing;
        continue;
      }

      const node: MutableTreeNode = {
        name: part,
        path: nextPath,
        kind: isLeaf ? "file" : "directory",
        children: new Map(),
      };
      current.children.set(part, node);
      current = node;
    }
  }

  const finalize = (node: MutableTreeNode): WorkspaceNode => {
    const children = Array.from(node.children.values())
      .sort((left, right) => {
        if (left.kind !== right.kind) {
          return left.kind === "directory" ? -1 : 1;
        }
        return left.name.localeCompare(right.name);
      })
      .map(finalize);

    return {
      name: node.name,
      path: node.path,
      kind: node.kind,
      hasChildren: children.length > 0,
      children,
    };
  };

  return Array.from(root.children.values())
    .sort((left, right) => {
      if (left.kind !== right.kind) {
        return left.kind === "directory" ? -1 : 1;
      }
      return left.name.localeCompare(right.name);
    })
    .map(finalize);
}

export function expandArtifactAncestors(
  current: Record<string, boolean>,
  path: string,
): Record<string, boolean> {
  const next = { ...current };
  const parts = path.split("/").filter(Boolean);

  for (let index = 0; index < parts.length - 1; index += 1) {
    next[parts.slice(0, index + 1).join("/")] = true;
  }

  return next;
}

export function findArtifactFile(
  files: ChatArtifactManifestFile[],
  path: string | null | undefined,
): ChatArtifactManifestFile | null {
  if (!path) {
    return null;
  }
  return files.find((file) => file.path === path) ?? null;
}

export function resolveSourceFilePath(
  manifest: ChatArtifactManifest,
  preferredPath?: string | null,
): string | null {
  const existingPreferred = preferredPath
    ? findArtifactFile(manifest.files, preferredPath)
    : null;
  if (existingPreferred) {
    return existingPreferred.path;
  }

  const primaryTab = manifest.tabs.find((tab) => tab.id === manifest.primaryTab);
  if (primaryTab?.filePath) {
    return primaryTab.filePath;
  }

  return manifest.files[0]?.path ?? null;
}

export function resolveRenderFile(
  manifest: ChatArtifactManifest,
  preferredPath?: string | null,
): ChatArtifactManifestFile | null {
  const preferredFile = findArtifactFile(manifest.files, preferredPath);
  if (preferredFile?.renderable) {
    return preferredFile;
  }

  const renderTab = manifest.tabs.find((tab) => tab.kind === "render");
  if (renderTab?.filePath) {
    return findArtifactFile(manifest.files, renderTab.filePath) ?? manifest.files[0] ?? null;
  }

  return manifest.files.find((file) => file.renderable) ?? manifest.files[0] ?? null;
}

export function hasVerifiedRender(
  manifest: ChatArtifactManifest,
  rendererSession?: ChatRendererSession | null,
): boolean {
  if (manifest.verification.status !== "ready") {
    return false;
  }

  if (manifest.renderer === "workspace_surface") {
    return Boolean(
      rendererSession?.previewUrl || manifest.files.some((file) => Boolean(file.externalUrl)),
    );
  }

  if (manifest.renderer === "download_card") {
    return manifest.files.some((file) => file.downloadable);
  }

  return manifest.files.some((file) => file.renderable);
}

function hasAddressableArtifactFile(manifest: ChatArtifactManifest): boolean {
  return manifest.files.some(
    (file) =>
      Boolean(file.path) &&
      (Boolean(file.artifactId) ||
        Boolean(file.externalUrl) ||
        file.renderable ||
        file.downloadable),
  );
}

export function hasOpenableArtifactSurface(
  manifest: ChatArtifactManifest,
  rendererSession?: ChatRendererSession | null,
  workspaceRoot?: string | null,
): boolean {
  if (hasVerifiedRender(manifest, rendererSession)) {
    return true;
  }

  if (!hasAddressableArtifactFile(manifest)) {
    return false;
  }

  if (manifest.renderer === "workspace_surface") {
    return (
      Boolean(rendererSession?.workspaceRoot || workspaceRoot) &&
      manifest.verification.lifecycleState !== "draft" &&
      manifest.verification.lifecycleState !== "planned" &&
      manifest.verification.lifecycleState !== "materializing" &&
      manifest.verification.lifecycleState !== "rendering" &&
      manifest.verification.lifecycleState !== "blocked" &&
      manifest.verification.lifecycleState !== "failed"
    );
  }

  return (
    manifest.verification.lifecycleState === "ready" ||
    manifest.verification.lifecycleState === "partial" ||
    manifest.verification.lifecycleState === "draft"
  );
}

export function resolveInitialStageMode(
  manifest: ChatArtifactManifest,
  rendererSession?: ChatRendererSession | null,
): ChatArtifactStageMode {
  const renderableDraftSurface =
    manifest.renderer !== "workspace_surface" &&
    Boolean(resolveRenderFile(manifest)?.renderable) &&
    (manifest.verification.lifecycleState === "ready" ||
      manifest.verification.lifecycleState === "partial" ||
      manifest.verification.lifecycleState === "draft");
  return hasVerifiedRender(manifest, rendererSession) || renderableDraftSurface
    ? "render"
    : "source";
}

export function shouldSwitchToSourceForSelection(
  manifest: ChatArtifactManifest,
  file: ChatArtifactManifestFile | null,
): boolean {
  if (!file || file.renderable) {
    return false;
  }

  return (
    manifest.renderer !== "download_card" &&
    manifest.renderer !== "bundle_manifest" &&
    manifest.renderer !== "workspace_surface"
  );
}
