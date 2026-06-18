import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";

const chatInput = readFileSync(
  "apps/hypervisor/src/windows/ChatShellWindow/components/ChatInputSection.tsx",
  "utf8",
);
const sharedCommandCss = readFileSync(
  "apps/hypervisor/src/components/ui/CommandMenus.css",
  "utf8",
);
const shellCommandCss = readFileSync(
  "apps/hypervisor/src/windows/ChatShellWindow/styles/Components.css",
  "utf8",
);

test("slash menu defaults to curated user-facing actions", () => {
  assert.match(chatInput, /const slashQuickMode = !searchablePaletteMode && commandQuery\.length === 0;/);
  assert.match(chatInput, /id: "add-context"/);
  assert.match(chatInput, /title: "New chat"/);
  assert.match(chatInput, /title: "Model"/);
  assert.match(chatInput, /title: "Skills"/);
  assert.match(chatInput, /title: "Capabilities"/);
  assert.match(chatInput, /title: "Workflows"/);
  assert.match(chatInput, /if \(!slashQuickMode\) {\s*commandItems\.push\(\s*\.\.\.buildSharedSessionCommandItems/s);
});

test("search-backed slash sections stay out of the empty quick menu", () => {
  assert.match(chatInput, /const shouldShowSearchBackedItems = searchablePaletteMode \|\| commandQuery\.length > 0;/);
  assert.match(chatInput, /const recentSessionItems = shouldShowSearchBackedItems\s*\?/);
  assert.match(chatInput, /const liveToolItems: CommandMenuItem\[\] =\s*!shouldShowSearchBackedItems\s*\?\s*\[\]/);
  assert.match(chatInput, /const modelItems = shouldShowSearchBackedItems\s*\?/);
  assert.match(chatInput, /const workspaceItems = shouldShowSearchBackedItems\s*\?/);
  assert.doesNotMatch(chatInput, /runtimeCatalog|Runtime Catalog|open-catalog/);
});

test("slash menu is compact while palette mode remains roomy", () => {
  assert.match(sharedCommandCss, /\.spot-slash-menu \{\s*right: auto;\s*width: min\(360px, 100%\);/s);
  assert.match(sharedCommandCss, /\.spot-slash-menu--palette \{\s*width: min\(720px, 100%\);/s);
  assert.match(sharedCommandCss, /\.spot-slash-menu:not\(\.spot-slash-menu--palette\) \.spot-slash-item-description \{\s*display: none;/s);
  assert.doesNotMatch(shellCommandCss, /\.spot-slash-menu\s*\{/);
});
