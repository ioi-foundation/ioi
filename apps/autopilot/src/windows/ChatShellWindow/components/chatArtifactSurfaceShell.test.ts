import assert from "node:assert/strict";
import fs from "node:fs";

const surfaceSource = fs.readFileSync(
  new URL("./ChatArtifactSurface.tsx", import.meta.url),
  "utf8",
);
const logicalSurfaceSource = fs.readFileSync(
  new URL("./ArtifactLogicalSurface.tsx", import.meta.url),
  "utf8",
);
const workspaceSurfaceSource = fs.readFileSync(
  new URL("./ArtifactWorkspaceSurface.tsx", import.meta.url),
  "utf8",
);
const evidencePanelSource = fs.readFileSync(
  new URL("./ArtifactEvidencePanel.tsx", import.meta.url),
  "utf8",
);
const workbenchSource = fs.readFileSync(
  new URL("./ArtifactSourceWorkbench.tsx", import.meta.url),
  "utf8",
);
const rendererHostSource = fs.readFileSync(
  new URL("./ArtifactRendererHost.tsx", import.meta.url),
  "utf8",
);
const thoughtsDrawerSource = fs.readFileSync(
  new URL("./ThoughtsDrawerSurface.tsx", import.meta.url),
  "utf8",
);
const stageHeaderSource = fs.readFileSync(
  new URL("./ArtifactStageHeader.tsx", import.meta.url),
  "utf8",
);
const chatShellWindowSource = fs.readFileSync(
  new URL("../index.tsx", import.meta.url),
  "utf8",
);
const surfaceFamilySource = [
  surfaceSource,
  logicalSurfaceSource,
  workspaceSurfaceSource,
  evidencePanelSource,
  stageHeaderSource,
].join("\n");
const logicalExplorerSidebarSource =
  logicalSurfaceSource.match(
    /<aside className="chat-artifact-sidebar chat-artifact-sidebar--explorer">[\s\S]*?<\/aside>/,
  )?.[0] ?? "";

assert.match(
  surfaceFamilySource,
  /chat-artifact-mode-toggle[\s\S]*Render[\s\S]*Source/,
  "stage header should expose the compact Render | Source toggle",
);

assert.match(
  surfaceFamilySource,
  /<aside className="chat-artifact-sidebar chat-artifact-sidebar--explorer">[\s\S]*title="Explorer"/,
  "artifact sidebar should remain explorer-only",
);

assert.match(
  surfaceFamilySource,
  /stageMode === "source" \? \([\s\S]*showExplorer=\{false\}/,
  "logical source mode should reuse the main stage without duplicating the explorer",
);

assert.match(
  surfaceFamilySource,
  /chat-artifact-source-shell chat-artifact-source-shell--editor-only/,
  "workspace source mode should stay editor-only in the main stage",
);

assert.match(
  surfaceFamilySource,
  /evidenceOpen \? \([\s\S]*<ArtifactEvidencePanel/,
  "evidence should be rendered as a secondary inspector, not the default artifact view",
);

assert.match(
  surfaceFamilySource,
  /chat-artifact-panel-label">Revisions<\/span>/,
  "evidence inspector should expose revision history controls",
);

assert.match(
  surfaceFamilySource,
  /chat_attach_artifact_selection/,
  "artifact-local selections should persist into the Chat session before seeding follow-up intent",
);

assert.doesNotMatch(
  logicalExplorerSidebarSource,
  /Pipeline/,
  "pipeline details should not render inside the left explorer rail",
);

assert.doesNotMatch(
  workbenchSource,
  /WorkspaceExplorerPane/,
  "source workbench should stay editor-only; explorer belongs to the artifact rail",
);

assert.match(
  rendererHostSource,
  /Attach render selection/,
  "render host should expose an explicit attach-selection affordance for in-render targeting",
);

assert.match(
  chatShellWindowSource,
  /const \[chatArtifactVisible, setChatArtifactVisible\] = useState\(false\);/,
  "chat should start in the full-screen conversation layout with the artifact drawer closed",
);

assert.match(
  chatShellWindowSource,
  /studioArtifactAvailable,[\s\S]*studioArtifactExpected,[\s\S]*\} = useChatSurfaceState\(/,
  "chat should delegate artifact availability to the shared surface state model",
);

assert.match(
  chatShellWindowSource,
  /chatArtifactDrawerAvailable && chatArtifactVisible[\s\S]*spot-chat-artifact-drawer/,
  "chat should only render the artifact drawer after an artifact surface becomes available",
);

assert.match(
  surfaceSource,
  /if \(\s*!chatSession && activeConversationRun\s*\)[\s\S]*<ThoughtsDrawerSurface/,
  "direct conversation runs should render the Thoughts drawer before considering historical artifact menus",
);

assert.match(
  surfaceSource,
  /availableArtifacts\.length > 0[\s\S]*<ArtifactMenuSurface/,
  "historical artifact browsing should remain available for artifact contexts",
);

assert.doesNotMatch(
  surfaceSource,
  /Runtime workbench|Chat runtime/,
  "non-artifact drawer copy should not use the old runtime workbench dashboard framing",
);

assert.match(
  thoughtsDrawerSource,
  /<h2>Thoughts<\/h2>/,
  "the non-artifact drawer should present as a Thoughts drawer",
);

assert.match(
  thoughtsDrawerSource,
  /chat-thoughts-groups/,
  "the Thoughts drawer should group process evidence instead of rendering a raw activity feed",
);

for (const heading of [
  "Thinking about your request",
  "Research and tools",
  "What I learned",
  "Verification",
]) {
  assert.match(
    thoughtsDrawerSource,
    new RegExp(heading),
    `the Thoughts drawer should include the ${heading} group`,
  );
}

assert.doesNotMatch(
  thoughtsDrawerSource,
  /chat-thoughts-source-pill|Sources<\/span>|Used this turn/,
  "the Thoughts drawer should not render source pills as its default process summary",
);

console.log("studioArtifactSurfaceShell.test.ts: ok");
