import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";

const commandPalette = readFileSync(
  "apps/hypervisor/src/components/CommandPalette.tsx",
  "utf8",
);
const commandPaletteCss = readFileSync(
  "apps/hypervisor/src/components/CommandPalette.css",
  "utf8",
);

test("global command palette uses its own quick-pick surface", () => {
  assert.doesNotMatch(commandPalette, /<CommandMenu/);
  assert.doesNotMatch(commandPalette, /spot-slash-menu--palette/);
  assert.match(commandPalette, /className="command-palette-search-input"/);
  assert.match(
    commandPalette,
    /Search files by name \(append : to go to line or @ to go to symbol\)/,
  );
  assert.match(commandPalette, /data-command-palette-item-id=\{item\.id\}/);
});

test("global command palette defaults to compact command-first quick picks", () => {
  assert.match(commandPalette, /title: "Go to File"[\s\S]*shortcut: \["Ctrl", "P"\]/);
  assert.match(
    commandPalette,
    /title: "Show and Run Commands"[\s\S]*suffix: ">"[\s\S]*shortcut: \["Ctrl", "Shift", "P"\]/,
  );
  assert.match(commandPalette, /title: "Search for Text"[\s\S]*suffix: "%"/);
  assert.match(commandPalette, /title: "Open Quick Chat"/);
  assert.match(commandPalette, /title: "Run Task"/);
  assert.match(commandPalette, /title: "More"[\s\S]*suffix: "\?"/);
});

test("global command palette styling follows quick-pick density", () => {
  assert.match(commandPaletteCss, /\.command-palette-shell\s*\{[\s\S]*width: min\(596px, 100%\);/);
  assert.match(commandPaletteCss, /\.command-palette-search-input\s*\{[\s\S]*border: 1px solid #007fd4;/);
  assert.match(commandPaletteCss, /\.command-palette-row\s*\{[\s\S]*min-height: 23px;/);
  assert.match(commandPaletteCss, /\.command-palette-row:hover,\s*\.command-palette-row\.is-selected\s*\{\s*background: #094771;/);
  assert.match(commandPaletteCss, /\.command-palette-shortcut-key\s*\{/);
});
