import assert from "node:assert/strict";
import type { ChatArtifactManifest, ChatRendererSession } from "../../../types";
import {
  buildArtifactTree,
  hasOpenableArtifactSurface,
  hasVerifiedRender,
  resolveInitialStageMode,
  resolveRenderFile,
  resolveSourceFilePath,
  shouldSwitchToSourceForSelection,
} from "./chatArtifactSurfaceModel";

function sampleManifest(
  overrides: Partial<ChatArtifactManifest> = {},
): ChatArtifactManifest {
  return {
    artifactId: "artifact-1",
    title: "Artifact",
    artifactClass: "document",
    renderer: "markdown",
    primaryTab: "render",
    tabs: [
      {
        id: "render",
        label: "Render",
        kind: "render",
        renderer: "markdown",
        filePath: "docs/release-checklist.md",
        lens: "render",
      },
      {
        id: "source",
        label: "Source",
        kind: "source",
        renderer: null,
        filePath: null,
        lens: "source",
      },
      {
        id: "evidence",
        label: "Evidence",
        kind: "evidence",
        renderer: null,
        filePath: null,
        lens: "evidence",
      },
    ],
    files: [
      {
        path: "docs/release-checklist.md",
        mime: "text/markdown",
        role: "primary",
        renderable: true,
        downloadable: true,
        artifactId: "file-1",
        externalUrl: null,
      },
      {
        path: "support/notes.txt",
        mime: "text/plain",
        role: "supporting",
        renderable: false,
        downloadable: true,
        artifactId: "file-2",
        externalUrl: null,
      },
    ],
    verification: {
      status: "ready",
      lifecycleState: "ready",
      summary: "Render contract verified.",
    },
    storage: null,
    ...overrides,
  };
}

function sampleWorkspaceSession(
  overrides: Partial<ChatRendererSession> = {},
): ChatRendererSession {
  return {
    sessionId: "renderer-1",
    chatSessionId: "chat-1",
    renderer: "workspace_surface",
    workspaceRoot: "/tmp/chat-workspace",
    entryDocument: "src/App.tsx",
    previewUrl: "http://127.0.0.1:4173",
    previewProcessId: 42,
    scaffoldRecipeId: "react-vite",
    presentationVariantId: null,
    packageManager: "npm",
    status: "preview-ready",
    verificationStatus: "passed",
    receipts: [],
    currentWorkerExecution: null,
    currentTab: "preview",
    availableTabs: ["preview", "workspace", "evidence"],
    readyTabs: ["preview", "workspace", "evidence"],
    retryCount: 0,
    lastFailureSummary: null,
    ...overrides,
  };
}

function buildArtifactTreeTest(): void {
  const tree = buildArtifactTree(sampleManifest().files);
  assert.equal(tree[0]?.kind, "directory");
  assert.equal(tree[0]?.name, "docs");
  assert.equal(tree[1]?.kind, "directory");
  assert.equal(tree[1]?.name, "support");
}

function sourcePathResolutionTest(): void {
  const manifest = sampleManifest();
  assert.equal(resolveSourceFilePath(manifest), "docs/release-checklist.md");
  assert.equal(resolveSourceFilePath(manifest, "support/notes.txt"), "support/notes.txt");
}

function renderAvailabilityTest(): void {
  const readyManifest = sampleManifest();
  assert.equal(hasVerifiedRender(readyManifest), true);
  assert.equal(hasOpenableArtifactSurface(readyManifest), true);
  assert.equal(resolveInitialStageMode(readyManifest), "render");

  const blockedManifest = sampleManifest({
    verification: {
      status: "blocked",
      lifecycleState: "blocked",
      summary: "Weak artifact output downgraded to blocked.",
    },
  });
  assert.equal(hasVerifiedRender(blockedManifest), false);
  assert.equal(hasOpenableArtifactSurface(blockedManifest), false);
  assert.equal(resolveInitialStageMode(blockedManifest), "source");

  const partialBundleManifest = sampleManifest({
    renderer: "bundle_manifest",
    artifactClass: "compound_bundle",
    verification: {
      status: "partial",
      lifecycleState: "partial",
      summary: "Bundle exists but still needs follow-up verification.",
    },
    files: [
      {
        path: "README.md",
        mime: "text/markdown",
        role: "primary",
        renderable: false,
        downloadable: true,
        artifactId: "file-1",
        externalUrl: null,
      },
    ],
  });
  assert.equal(hasVerifiedRender(partialBundleManifest), false);
  assert.equal(hasOpenableArtifactSurface(partialBundleManifest), true);
  assert.equal(resolveInitialStageMode(partialBundleManifest), "source");

  const partialRenderableManifest = sampleManifest({
    verification: {
      status: "partial",
      lifecycleState: "partial",
      summary: "Draft surfaced while acceptance remains pending.",
    },
  });
  assert.equal(hasVerifiedRender(partialRenderableManifest), false);
  assert.equal(hasOpenableArtifactSurface(partialRenderableManifest), true);
  assert.equal(resolveInitialStageMode(partialRenderableManifest), "render");

  const draftRenderableManifest = sampleManifest({
    verification: {
      status: "partial",
      lifecycleState: "draft",
      summary: "Draft surfaced while acceptance remains pending.",
    },
  });
  assert.equal(hasVerifiedRender(draftRenderableManifest), false);
  assert.equal(hasOpenableArtifactSurface(draftRenderableManifest), true);
  assert.equal(resolveInitialStageMode(draftRenderableManifest), "render");

  const workspaceManifest = sampleManifest({
    renderer: "workspace_surface",
    artifactClass: "workspace_project",
    verification: {
      status: "ready",
      lifecycleState: "ready",
      summary: "Preview verified.",
    },
  });
  assert.equal(hasVerifiedRender(workspaceManifest, sampleWorkspaceSession()), true);
  assert.equal(hasOpenableArtifactSurface(workspaceManifest, sampleWorkspaceSession()), true);
  assert.equal(resolveInitialStageMode(workspaceManifest, sampleWorkspaceSession()), "render");
  assert.equal(
    hasVerifiedRender(
      workspaceManifest,
      sampleWorkspaceSession({ previewUrl: null }),
    ),
    false,
  );
  assert.equal(
    hasOpenableArtifactSurface(
      workspaceManifest,
      sampleWorkspaceSession({ previewUrl: null }),
    ),
    true,
  );
}

function renderFileResolutionTest(): void {
  const manifest = sampleManifest();
  assert.equal(resolveRenderFile(manifest)?.path, "docs/release-checklist.md");
  assert.equal(
    resolveRenderFile(manifest, "support/notes.txt")?.path,
    "docs/release-checklist.md",
  );
}

function sourceSwitchTest(): void {
  const manifest = sampleManifest();
  const supportFile = manifest.files[1] ?? null;
  assert.equal(shouldSwitchToSourceForSelection(manifest, supportFile), true);
  assert.equal(
    shouldSwitchToSourceForSelection(
      sampleManifest({ renderer: "download_card", artifactClass: "downloadable_file" }),
      supportFile,
    ),
    false,
  );
}

buildArtifactTreeTest();
sourcePathResolutionTest();
renderAvailabilityTest();
renderFileResolutionTest();
sourceSwitchTest();
