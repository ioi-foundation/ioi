import assert from "node:assert/strict";
import { createRequire } from "node:module";
import test from "node:test";

const require = createRequire(import.meta.url);
const { createStudioToolPalette } = require("./tool-palette.js");

function createPalette() {
  return createStudioToolPalette({
    firstArray: (value) => Array.isArray(value) ? value : [],
    quickPickSeparatorKind: "separator",
    stringValue: (value, fallback = "") => typeof value === "string" ? value.trim() || fallback : fallback,
    themeIcon: (icon) => ({ id: icon }),
  });
}

test("tool palette row normalization accepts aliases and filters empty rows", () => {
  const palette = createPalette();
  const rows = palette.normalizeStudioToolPaletteRows([
    null,
    { toolId: "tool-1", label: "  Tool One  ", description: " Do work ", provider: "live", selected: true },
    { name: "tool-two", summary: "Second", status: "disabled", enabled: false },
    { title: "   " },
  ], "fallback");

  assert.deepEqual(rows, [
    {
      id: "tool-1",
      title: "Tool One",
      detail: "Do work",
      meta: "live",
      enabled: true,
      selected: true,
    },
    {
      id: "tool-two",
      title: "tool-two",
      detail: "Second",
      meta: "disabled",
      enabled: false,
      selected: false,
    },
  ]);
});

test("tool palette sections use live/runtime rows or stable fallbacks", () => {
  const palette = createPalette();
  const sections = palette.studioToolPaletteSections({
    commandCenter: {
      liveTools: [{ id: "live.search", title: "Live Search", meta: "ready" }],
      runtimeCatalog: [{ toolId: "runtime.read", label: "Runtime Read", kind: "daemon" }],
    },
  });

  assert.equal(sections[0].id, "built-in");
  assert.equal(sections[0].rows.some((row) => row.id === "execute"), true);
  assert.equal(sections[1].rows[0].id, "live.search");
  assert.equal(sections[2].rows[0].id, "runtime.read");

  const fallbackSections = palette.studioToolPaletteSections({});
  assert.equal(fallbackSections[1].rows[0].id, "loading-live-tools");
  assert.equal(fallbackSections[1].rows[0].enabled, false);
  assert.equal(fallbackSections[2].rows.some((row) => row.id === "kernel-backend-gallery"), true);
});

test("tool quick pick items preserve section separators and theme icons", () => {
  const palette = createPalette();
  const items = palette.studioToolQuickPickItems({
    commandCenter: {
      liveTools: [{ id: "live.search", title: "Live Search", detail: "Query", selected: true }],
    },
  });

  assert.equal(items.some((item) => item.label === "Live Tools" && item.kind === "separator"), true);
  assert.equal(items.some((item) => item.label === "Runtime Catalog" && item.kind === "separator"), true);

  const execute = items.find((item) => item.label === "execute");
  assert.equal(execute.alwaysShow, true);
  assert.equal(execute.picked, true);
  assert.deepEqual(execute.iconPath, { id: "terminal" });

  const liveSearch = items.find((item) => item.label === "Live Search");
  assert.equal(liveSearch.sectionId, "live-tools");
  assert.equal(liveSearch.picked, true);
});

test("context quick pick items keep bridge requests and command affordances", () => {
  const palette = createPalette();
  const items = palette.studioContextQuickPickItems();

  assert.deepEqual(
    items.map((item) => item.row.requestType),
    [
      "chat.attachFilesAndFolders",
      "chat.generateAgentInstructions",
      "chat.attachProblems",
      "chat.attachSymbols",
      "chat.contextTools.open",
    ],
  );
  assert.equal(items.every((item) => item.alwaysShow), true);
  assert.deepEqual(items.find((item) => item.row.id === "tools").iconPath, { id: "tools" });
  assert.equal(items.find((item) => item.row.id === "tools").row.command, "ioi.quickInput.tools.configure");
});
