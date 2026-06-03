import assert from "node:assert/strict";
import { createRequire } from "node:module";
import test from "node:test";

const require = createRequire(import.meta.url);
const { createStudioSourceChipRenderer } = require("./source-chip-renderer.js");

function createRenderer() {
  return createStudioSourceChipRenderer({
    compactStudioWhitespace: (value = "") => String(value || "").replace(/\s+/g, " ").trim(),
    escapeHtml: (value = "") => String(value ?? "")
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;")
      .replace(/'/g, "&#39;"),
    firstArray: (value) => Array.isArray(value) ? value : [],
    stringValue: (value, fallback = "") => typeof value === "string" ? value.trim() || fallback : fallback,
    studioRecordValue: (value) => value && typeof value === "object" && !Array.isArray(value) ? value : {},
  });
}

test("source URL sanitizer only allows http URLs and data image icons", () => {
  const renderer = createRenderer();

  assert.equal(renderer.sanitizeStudioSourceUrl("https://example.com/a"), "https://example.com/a");
  assert.equal(renderer.sanitizeStudioSourceUrl("data:image/png;base64,abc"), "data:image/png;base64,abc");
  assert.equal(renderer.sanitizeStudioSourceUrl("javascript:alert(1)"), "");
  assert.equal(renderer.sanitizeStudioSourceUrl("https://example.com/\ntrace"), "");
});

test("favicon URL uses explicit safe icons or falls back to the source domain", () => {
  const renderer = createRenderer();

  assert.equal(
    renderer.studioSourceChipFaviconUrl({ icon_url: "data:image/svg+xml;utf8,%3Csvg%3E" }),
    "data:image/svg+xml;utf8,%3Csvg%3E",
  );
  assert.equal(
    renderer.studioSourceChipFaviconUrl({ url: "https://www.example.com/docs", title: "Docs" }),
    "https://www.google.com/s2/favicons?sz=32&domain_url=https%3A%2F%2Fwww.example.com%2Fdocs",
  );
  assert.equal(renderer.studioSourceChipFaviconUrl({ icon_url: "file:///tmp/icon.png" }), "");
});

test("source chip rows render safe anchors, escaped labels, state, and fallback spans", () => {
  const renderer = createRenderer();
  const html = renderer.studioSourceChipRows([
    {
      url: "https://example.com/path",
      title: "<Docs>",
      domain: "www.example.com",
      excerpt: "Result <one>",
      state: "used",
    },
    {
      title: "Local trace",
      url: "javascript:alert(1)",
      state: "ignored",
    },
  ]);

  assert.match(html, /<a class="studio-source-chip" href="https:\/\/example\.com\/path"/);
  assert.match(html, /&lt;Docs&gt;/);
  assert.match(html, /<small>example\.com<\/small>/);
  assert.match(html, /<em>used<\/em>/);
  assert.match(html, /<span class="studio-source-chip" title="Local trace">/);
  assert.doesNotMatch(html, /href="javascript:alert/);
});

test("turn source rows merge direct and artifact sources while removing duplicates", () => {
  const renderer = createRenderer();
  const html = renderer.studioTurnSourceRows({
    source_refs: [
      { url: "https://example.com/a", title: "Example A" },
      { url: "file:///tmp/raw", title: "Raw trace" },
    ],
    artifacts: [
      {
        sourceRefs: [
          { url: "https://example.com/a", title: "Example A" },
          { url: "https://example.com/b", title: "Example B" },
        ],
      },
    ],
  });

  assert.match(html, /data-testid="studio-answer-sources"/);
  assert.equal((html.match(/class="studio-source-chip"/g) || []).length, 2);
  assert.match(html, /Example A/);
  assert.match(html, /Example B/);
  assert.doesNotMatch(html, /Raw trace/);
});

test("source chip icon data URI is stable and escaped", () => {
  const renderer = createRenderer();
  const uri = renderer.studioSourceChipIconDataUri({ domain: "www.example.com", title: "<Example>" });

  assert.match(uri, /^data:image\/svg\+xml;utf8,/);
  assert.match(decodeURIComponent(uri), /<svg/);
  assert.match(decodeURIComponent(uri), />E<\/text>/);
});
