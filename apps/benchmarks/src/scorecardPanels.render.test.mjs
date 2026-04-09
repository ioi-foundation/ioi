import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import test, { after, before } from "node:test";
import { fileURLToPath } from "node:url";

import reactPlugin from "@vitejs/plugin-react";
import React from "react";
import { renderToStaticMarkup } from "react-dom/server";
import { createServer } from "vite";

import { normalizeAgentModelMatrixView } from "../../../scripts/lib/agent-model-matrix.mjs";

const repoRoot = path.resolve(fileURLToPath(new URL("../../..", import.meta.url)));
const appRoot = path.resolve(fileURLToPath(new URL("..", import.meta.url)));
const fixturePath = new URL(
  "../../../scripts/lib/fixtures/agent-model-matrix-interrupted.json",
  import.meta.url,
);

let viteServer;
let scorecardPanelsModule;
let scorecardViewModelModule;
let scorecardPreviewModule;

function loadFixtureMatrix() {
  const fixture = JSON.parse(fs.readFileSync(fixturePath, "utf8"));
  return normalizeAgentModelMatrixView(fixture, repoRoot);
}

function renderComponent(Component, props) {
  return renderToStaticMarkup(React.createElement(Component, props));
}

before(async () => {
  viteServer = await createServer({
    configFile: false,
    root: appRoot,
    plugins: [reactPlugin()],
    logLevel: "silent",
    optimizeDeps: { noDiscovery: true },
    server: { middlewareMode: true, hmr: false },
    appType: "custom",
  });
  scorecardPanelsModule = await viteServer.ssrLoadModule("/src/components/ScorecardPanels.tsx");
  scorecardViewModelModule = await viteServer.ssrLoadModule("/src/scorecardViewModel.ts");
  scorecardPreviewModule = await viteServer.ssrLoadModule("/src/scorecardPreview.ts");
});

after(async () => {
  await viteServer?.close();
});

test("scorecard panels render interrupted scorecard content", () => {
  const matrix = loadFixtureMatrix();
  const scorecard = scorecardViewModelModule.buildScorecardViewModel(
    matrix,
    "2026-04-05T22:50:16.168Z",
  );

  const heroHtml = renderComponent(scorecardPanelsModule.ScorecardHero, { scorecard });
  assert.match(heroHtml, /Benchmark matrix/);
  assert.match(heroHtml, /Run interrupted by SIGINT\. 1 preset incomplete\./);
  assert.match(heroHtml, /Summarized \/ completed/);
  assert.match(heroHtml, /2 \/ 1/);

  const boardHtml = renderComponent(scorecardPanelsModule.PresetScorecardBoard, {
    scorecard,
  });
  assert.match(boardHtml, /Preset scorecard/);
  assert.match(boardHtml, /Planner-grade local OSS \(Qwen3 8B\)/);
  assert.match(boardHtml, /Coding executor local OSS/);
  assert.match(boardHtml, /Decision/);
  assert.match(boardHtml, /Evidence/);
});

test("scorecard panels render deployment and candidate review surfaces", () => {
  const previewData = scorecardPreviewModule.withScorecardPreview({
    agentModelMatrix: loadFixtureMatrix(),
  });
  const matrix = previewData.agentModelMatrix;
  const scorecard = scorecardViewModelModule.buildScorecardViewModel(
    matrix,
    "2026-04-05T22:50:16.168Z",
    { previewMode: true },
  );
  const deployments = scorecardViewModelModule.buildDeploymentsViewModel(matrix, scorecard, {
    previewMode: true,
  });
  const candidates = scorecardViewModelModule.buildCandidatesViewModel(matrix, scorecard, {
    previewMode: true,
  });

  const deploymentsHtml = renderComponent(scorecardPanelsModule.DeploymentsView, {
    deployments,
  });
  assert.match(deploymentsHtml, /Tiered defaults/);
  assert.match(deploymentsHtml, /Blind cloud candidate/);
  assert.match(deploymentsHtml, /Workstation local candidate/);
  assert.match(
    deploymentsHtml,
    /Blind-cloud leaders remain shadow-scoped and cannot silently replace local defaults\./,
  );
  assert.match(deploymentsHtml, /preview fixture/);
  assert.match(deploymentsHtml, /8GB-class local/);
  assert.match(deploymentsHtml, /Blind cloud premium/);

  const candidatesHtml = renderComponent(scorecardPanelsModule.CandidatesView, {
    candidates,
  });
  assert.match(candidatesHtml, /Candidate lineage/);
  assert.match(candidatesHtml, /shadow winner/);
  assert.match(
    candidatesHtml,
    /Planner-grade local OSS \(Qwen3 8B\) → Blind cloud candidate/,
  );
  assert.match(candidatesHtml, /role-model assignment/);
  assert.match(candidatesHtml, /full stack change/);
});
