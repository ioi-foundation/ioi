import assert from "node:assert/strict";
import fs from "node:fs";

const timelineSource = fs.readFileSync(
  new URL("./ConversationTimeline.tsx", import.meta.url),
  "utf8",
);
const surfaceSource = fs.readFileSync(
  new URL("./StudioArtifactSurface.tsx", import.meta.url),
  "utf8",
);
const menuSurfaceSource = fs.readFileSync(
  new URL("./StudioArtifactMenuSurface.tsx", import.meta.url),
  "utf8",
);
const spotlightWindowSource = fs.readFileSync(
  new URL("../index.tsx", import.meta.url),
  "utf8",
);

assert.match(
  timelineSource,
  /turnContext\.artifacts\.length > 0[\s\S]*onOpenStudioArtifact/,
  "conversation turns should expose inline artifact mini-project cards",
);

assert.match(
  timelineSource,
  /onClick=\{\(\) => onOpenStudioArtifact\(artifact\.sessionId\)\}/,
  "conversation artifact cards should reopen the selected Studio artifact session",
);

assert.match(
  surfaceSource,
  /selectedStudioSessionId[\s\S]*historicalStudioSessions/,
  "Studio artifact surface should resolve historical artifact sessions from the trace",
);

assert.match(
  surfaceSource,
  /selectedStudioSessionId === null[\s\S]*<StudioArtifactMenuSurface/,
  "Studio artifact surface should show a higher-level artifact menu before a specific artifact view",
);

assert.match(
  menuSurfaceSource,
  /onOpenStudioSession\(artifact\.sessionId\)/,
  "artifact menu entries should open the selected artifact session",
);

assert.match(
  spotlightWindowSource,
  /onOpenStudioArtifact=\{\s*isStudioVariant \? handleOpenStudioArtifact : undefined\s*\}/,
  "conversation timeline should receive the Studio artifact selection callback",
);

assert.match(
  spotlightWindowSource,
  /selectedStudioArtifactSessionId !== null[\s\S]*setSelectedStudioArtifactSessionId\(null\)/,
  "Studio artifact toggle should return to the higher-level artifact menu before collapsing",
);

assert.match(
  spotlightWindowSource,
  /<StudioConversationSidebar[\s\S]*showArtifactNav=\{showStudioArtifactNav\}[\s\S]*onToggleArtifacts=\{handleToggleStudioArtifacts\}/,
  "studio artifact navigation should be routed through the Studio sidebar",
);

assert.match(
  spotlightWindowSource,
  /artifactMenuVisible=\{studioArtifactMenuVisible\}[\s\S]*is-menu/,
  "Studio conversation shell should narrow the drawer when only the artifact menu is open",
);

assert.match(
  timelineSource,
  /showArtifactReplyBubble[\s\S]*<MarkdownMessage text=\{inlineArtifactReply\} \/>/,
  "conversation turns with artifact-only outcomes should emit a companion assistant message",
);

assert.match(
  fs.readFileSync(new URL("./StudioArtifactStageHeader.tsx", import.meta.url), "utf8"),
  /studio-artifact-copy-control[\s\S]*Refresh/,
  "artifact stage header should expose a split copy control and refresh action",
);

console.log("studioConversationArtifactFlow.test.mjs: ok");
