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
  /studio-artifact-mode-toggle[\s\S]*Render[\s\S]*Source/,
  "stage header should expose the compact Render | Source toggle",
);

assert.match(
  surfaceSource,
  /<aside className="studio-artifact-sidebar studio-artifact-sidebar--explorer">[\s\S]*title="Explorer"/,
  "artifact sidebar should remain explorer-only",
);

assert.match(
  surfaceSource,
  /stageMode === "source" \? \([\s\S]*showExplorer=\{false\}/,
  "logical source mode should reuse the main stage without duplicating the explorer",
);

assert.match(
  surfaceSource,
  /studio-artifact-source-shell studio-artifact-source-shell--editor-only/,
  "workspace source mode should stay editor-only in the main stage",
);

assert.match(
  surfaceSource,
  /evidenceOpen \? \([\s\S]*<ArtifactEvidencePanel/,
  "evidence should be rendered as a secondary inspector, not the default artifact view",
);

assert.match(
  surfaceSource,
  /studio-artifact-panel-label">Revisions<\/span>/,
  "evidence inspector should expose revision history controls",
);

assert.match(
  surfaceSource,
  /studio_attach_artifact_selection/,
  "artifact-local selections should persist into the Studio session before seeding follow-up intent",
);

assert.doesNotMatch(
  surfaceSource,
  /studio-artifact-sidebar[\s\S]*Pipeline/,
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
  /const \[chatArtifactVisible, setStudioArtifactVisible\] = useState\(false\);/,
  "studio should start in the full-screen conversation layout with the artifact drawer closed",
);

assert.match(
  spotlightWindowSource,
  /const studioArtifactAvailable = useMemo\(\(\) => \{[\s\S]*hasOpenableArtifactSurface\(/,
  "studio should only treat the drawer as available once a real openable artifact surface exists",
);

assert.match(
  spotlightWindowSource,
  /\{studioArtifactAvailable \? \([\s\S]*spot-studio-artifact-drawer/,
  "studio should only render the artifact drawer after an artifact surface becomes available",
);

console.log("studioArtifactSurfaceShell.test.ts: ok");
