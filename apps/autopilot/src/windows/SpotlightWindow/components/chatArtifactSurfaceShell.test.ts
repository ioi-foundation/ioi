import assert from "node:assert/strict";
import fs from "node:fs";

const surfaceSource = fs.readFileSync(
  new URL("./ChatArtifactSurface.tsx", import.meta.url),
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
const spotlightWindowSource = fs.readFileSync(
  new URL("../index.tsx", import.meta.url),
  "utf8",
);

assert.match(
  surfaceSource,
  /chat-artifact-mode-toggle[\s\S]*Render[\s\S]*Source/,
  "stage header should expose the compact Render | Source toggle",
);

assert.match(
  surfaceSource,
  /<aside className="chat-artifact-sidebar chat-artifact-sidebar--explorer">[\s\S]*title="Explorer"/,
  "artifact sidebar should remain explorer-only",
);

assert.match(
  surfaceSource,
  /stageMode === "source" \? \([\s\S]*showExplorer=\{false\}/,
  "logical source mode should reuse the main stage without duplicating the explorer",
);

assert.match(
  surfaceSource,
  /chat-artifact-source-shell chat-artifact-source-shell--editor-only/,
  "workspace source mode should stay editor-only in the main stage",
);

assert.match(
  surfaceSource,
  /evidenceOpen \? \([\s\S]*<ArtifactEvidencePanel/,
  "evidence should be rendered as a secondary inspector, not the default artifact view",
);

assert.match(
  surfaceSource,
  /chat-artifact-panel-label">Revisions<\/span>/,
  "evidence inspector should expose revision history controls",
);

assert.match(
  surfaceSource,
  /chat_attach_artifact_selection/,
  "artifact-local selections should persist into the Chat session before seeding follow-up intent",
);

assert.doesNotMatch(
  surfaceSource,
  /chat-artifact-sidebar[\s\S]*Pipeline/,
  "pipeline details should not render inside the left explorer rail",
);

assert.match(
  workbenchSource,
  /showExplorer \? \([\s\S]*<WorkspaceExplorerPane[\s\S]*\) : null/,
  "source workbench should gate the explorer behind showExplorer",
);

assert.match(
  rendererHostSource,
  /Attach render selection/,
  "render host should expose an explicit attach-selection affordance for in-render targeting",
);

assert.match(
  spotlightWindowSource,
  /const \[chatArtifactVisible, setChatArtifactVisible\] = useState\(false\);/,
  "chat should start in the full-screen conversation layout with the artifact drawer closed",
);

assert.match(
  spotlightWindowSource,
  /const studioArtifactAvailable = useMemo\(\(\) => \{[\s\S]*hasOpenableArtifactSurface\(/,
  "chat should only treat the drawer as available once a real openable artifact surface exists",
);

assert.match(
  spotlightWindowSource,
  /\{studioArtifactAvailable \? \([\s\S]*spot-chat-artifact-drawer/,
  "chat should only render the artifact drawer after an artifact surface becomes available",
);

console.log("studioArtifactSurfaceShell.test.ts: ok");
