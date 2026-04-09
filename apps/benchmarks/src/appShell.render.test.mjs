import assert from "node:assert/strict";
import test, { after, before } from "node:test";
import { renderToStaticMarkup } from "react-dom/server";
import React from "react";
import { createServer } from "vite";
import reactPlugin from "@vitejs/plugin-react";
import path from "node:path";
import { fileURLToPath } from "node:url";

const appRoot = path.resolve(fileURLToPath(new URL("..", import.meta.url)));

let viteServer;
let appModule;

function renderAppWithSearch(search) {
  const previousWindow = globalThis.window;
  globalThis.window = {
    location: { search },
    setInterval: () => 0,
    clearInterval: () => {},
    addEventListener: () => {},
    removeEventListener: () => {},
  };

  try {
    return renderToStaticMarkup(React.createElement(appModule.default));
  } finally {
    if (previousWindow === undefined) {
      delete globalThis.window;
    } else {
      globalThis.window = previousWindow;
    }
  }
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
  appModule = await viteServer.ssrLoadModule("/src/App.tsx");
});

after(async () => {
  await viteServer?.close();
});

test("App shell renders benchmark tabs", () => {
  const html = renderAppWithSearch("");

  assert.match(html, /Benchmarks/);
  assert.match(html, />Scorecard</);
  assert.match(html, />Deployments</);
  assert.match(html, />Candidates</);
  assert.match(html, />Triage</);
  assert.match(html, /Benchmark matrix/);
});

test("App shell activates preview mode from query state", () => {
  const html = renderAppWithSearch("?scorecardPreview=1");

  assert.match(html, /preview fixture/);
  assert.match(html, /Living scorecard/);
});
