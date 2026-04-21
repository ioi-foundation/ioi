import assert from "node:assert/strict";
import fs from "node:fs";

const spotlightWindowSource = fs.readFileSync(
  new URL("../index.tsx", import.meta.url),
  "utf8",
);
const studioSurfaceSource = fs.readFileSync(
  new URL("../styles/StudioSurface.css", import.meta.url),
  "utf8",
);

assert.match(
  spotlightWindowSource,
  /artifactDrawerVisible=\{\s*studioArtifactDrawerAvailable && chatArtifactVisible\s*\}/,
  "studio should only mount the artifact drawer while it is explicitly open",
);

assert.match(
  studioSurfaceSource,
  /\.spot-studio-conversation-shell-item\s*\{\s*grid-column:\s*1;\s*grid-row:\s*1;/,
  "conversation shell item should stay pinned to the first grid cell",
);

assert.match(
  studioSurfaceSource,
  /\.spot-studio-artifact-drawer\s*\{\s*grid-row:\s*1;\s*grid-column:\s*2;/,
  "artifact drawer should stay pinned to the second grid column instead of creating implicit rows",
);

console.log("studioArtifactDrawerLayout.test.ts: ok");
