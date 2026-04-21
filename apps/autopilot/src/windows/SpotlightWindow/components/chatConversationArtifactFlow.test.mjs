import assert from "node:assert/strict";
import fs from "node:fs";

const timelineSource = fs.readFileSync(
  new URL("./ConversationTimeline.tsx", import.meta.url),
  "utf8",
);
const surfaceSource = fs.readFileSync(
  new URL("./ChatArtifactSurface.tsx", import.meta.url),
  "utf8",
);
const menuSurfaceSource = fs.readFileSync(
  new URL("./ArtifactMenuSurface.tsx", import.meta.url),
  "utf8",
);
const spotlightWindowSource = fs.readFileSync(
  new URL("../index.tsx", import.meta.url),
  "utf8",
);

assert.match(
  timelineSource,
  /turnContext\.artifacts\.length > 0[\s\S]*onOpenChatArtifact/,
  "conversation turns should expose inline artifact mini-project cards",
);

assert.match(
  timelineSource,
  /onClick=\{\(\) => onOpenChatArtifact\(artifact\.sessionId\)\}/,
  "conversation artifact cards should reopen the selected Chat artifact session",
);

assert.match(
  surfaceSource,
  /selectedChatSessionId[\s\S]*historicalChatSessions/,
  "Chat artifact surface should resolve historical artifact sessions from the trace",
);

assert.match(
  surfaceSource,
  /selectedChatSessionId === null[\s\S]*<ArtifactMenuSurface/,
  "Chat artifact surface should show a higher-level artifact menu before a specific artifact view",
);

assert.match(
  menuSurfaceSource,
  /onOpenStudioSession\(artifact\.sessionId\)/,
  "artifact menu entries should open the selected artifact session",
);

assert.match(
  spotlightWindowSource,
  /onOpenChatArtifact=\{\s*isStudioVariant \? handleOpenChatArtifact : undefined\s*\}/,
  "conversation timeline should receive the Chat artifact selection callback",
);

assert.match(
  spotlightWindowSource,
  /selectedChatArtifactSessionId !== null[\s\S]*setSelectedChatArtifactSessionId\(null\)/,
  "Chat artifact toggle should return to the higher-level artifact menu before collapsing",
);

assert.match(
  spotlightWindowSource,
  /<ChatConversationSidebar[\s\S]*showArtifactNav=\{showChatArtifactNav\}[\s\S]*onToggleArtifacts=\{handleToggleChatArtifacts\}/,
  "chat artifact navigation should be routed through the Chat sidebar",
);

assert.match(
  spotlightWindowSource,
  /artifactMenuVisible=\{studioArtifactMenuVisible\}[\s\S]*is-menu/,
  "Chat conversation shell should narrow the drawer when only the artifact menu is open",
);

assert.match(
  timelineSource,
  /showArtifactReplyBubble[\s\S]*<MarkdownMessage text=\{inlineArtifactReply\} \/>/,
  "conversation turns with artifact-only outcomes should emit a companion assistant message",
);

assert.match(
  fs.readFileSync(new URL("./ArtifactStageHeader.tsx", import.meta.url), "utf8"),
  /chat-artifact-copy-control[\s\S]*Refresh/,
  "artifact stage header should expose a split copy control and refresh action",
);

console.log("studioConversationArtifactFlow.test.mjs: ok");
