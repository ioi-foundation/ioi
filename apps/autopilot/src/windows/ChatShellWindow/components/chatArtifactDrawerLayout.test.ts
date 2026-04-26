import assert from "node:assert/strict";
import fs from "node:fs";

const chatShellWindowSource = fs.readFileSync(
  new URL("../index.tsx", import.meta.url),
  "utf8",
);
const studioSurfaceSource = fs.readFileSync(
  new URL("../styles/ChatSurface.css", import.meta.url),
  "utf8",
);

assert.match(
  chatShellWindowSource,
  /artifactDrawerVisible=\{\s*chatArtifactDrawerAvailable && chatArtifactVisible\s*\}/,
  "chat should only mount the artifact drawer while it is explicitly open",
);

assert.match(
  studioSurfaceSource,
  /\.spot-chat-conversation-shell-item\s*\{\s*grid-column:\s*2;\s*grid-row:\s*1;/,
  "conversation shell item should stay pinned to the second grid cell after the chat session rail",
);

assert.match(
  studioSurfaceSource,
  /\.spot-chat-artifact-drawer\s*\{\s*grid-row:\s*1;\s*grid-column:\s*3;/,
  "artifact drawer should stay pinned to the third grid column instead of creating implicit rows",
);

console.log("studioArtifactDrawerLayout.test.ts: ok");
