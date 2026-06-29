#!/usr/bin/env node
// Behavioral contract test — the session workbench bound to a LIVE environment (parity gate).
//
// Asserts the source-owned WorkspaceHost, mounted in the Session surface, drives the daemon's OWN
// env-ops contracts to render a real workspace: the file EXPLORER from the env-ops file plane, the
// EDITOR from a real ReadFile, and a real openpty TERMINAL (create + stream). Deterministic via
// route mocking of the daemon endpoints; the assertion checks the adapter speaks the native daemon
// routes (no upstream-namespace wire bridge). Requires the vite dev server on :1420 (with the
// /supervisor proxy). Run: node apps/hypervisor/tests/workspace.contract.mjs
import { chromium } from "playwright";

const BASE = process.env.APP_URL || "http://127.0.0.1:1420";
const fails = [];
const ok = (n) => console.log(`  ✓ ${n}`);
const bad = (n, d) => { fails.push(n); console.error(`  ✗ ${n}${d ? " — " + d : ""}`); };

const TID = "thread_workbench_1";
const ENV = "env_contract_demo";

// The thread record binds the session to a real environment via its workspace field.
const THREAD = {
  thread_id: TID,
  title: "Workbench parity",
  status: "active",
  updated_at: new Date(Date.now() - 600e3).toISOString(),
  workspace: ENV,
  workspace_root: ENV,
};

// Real workspace contents the env-ops file plane projects.
const ROOT_ENTRIES = [
  { path: "src", isDirectory: true, size: "4096" },
  { path: "README.md", isDirectory: false, size: "42" },
  { path: "main.rs", isDirectory: false, size: "31" },
];
const README = "# Live workspace\n\nServed by the daemon.\n";

const b64 = (s) => Buffer.from(s, "utf8").toString("base64");

// Build a base64 SSE terminal frame the way the daemon emits it.
function terminalFrame(output, offset) {
  return (
    `event: output\ndata: ${JSON.stringify({ terminal_id: "term_x", from: 0, offset, output, running: true })}\n\n` +
    `event: done\ndata: ${JSON.stringify({ offset })}\n\n`
  );
}

const browser = await chromium.launch();
const ctx = await browser.newContext({ viewport: { width: 1480, height: 920 }, colorScheme: "dark" });
const page = await ctx.newPage();
const seen = [];

// ── Mock the daemon env-ops plane (every native daemon route the adapter speaks) ──────────────────
await page.route("**/v1/**", (route) => {
  const p = route.request().url().replace(/^https?:\/\/[^/]+/, "");
  seen.push(p);
  const fulfill = (obj, status = 200) =>
    route.fulfill({ status, contentType: "application/json", body: JSON.stringify(obj) });

  // Thread record + (empty) timeline.
  if (p.includes(`/v1/threads/${TID}/events`)) return route.fulfill({ status: 200, contentType: "text/event-stream", body: "" });
  if (p.includes(`/v1/threads/${TID}`)) return fulfill(THREAD);
  if (p.includes("/v1/threads")) return fulfill({ threads: [THREAD] });

  // env-ops capability lease (file plane bearer).
  if (p.includes(`/environments/${ENV}/ops-lease`)) return fulfill({ accessToken: "lease_demo", environment_id: ENV });

  // Terminal control + stream (real openpty PTY routes).
  if (/\/v1\/hypervisor\/terminals\/[^/]+\/stream/.test(p)) {
    return route.fulfill({ status: 200, contentType: "text/event-stream", body: terminalFrame("hello-from-pty\r\n", 16) });
  }
  if (/\/v1\/hypervisor\/terminals\/[^/]+\/(input|resize|close)/.test(p)) return fulfill({ ok: true });
  if (p.endsWith("/v1/hypervisor/terminals")) return fulfill({ ok: true, terminal_id: "term_x", shell: "bash" });

  return fulfill({});
});

// The env-ops file/git plane: /supervisor/:env/supervisor.v1.EnvironmentOpsService/:Method
await page.route("**/supervisor/**", (route) => {
  const p = route.request().url().replace(/^https?:\/\/[^/]+/, "");
  seen.push(p);
  const method = p.split("/").pop() || "";
  const fulfill = (obj) => route.fulfill({ status: 200, contentType: "application/json", body: JSON.stringify(obj) });
  if (method === "ReadFile") {
    const body = JSON.parse(route.request().postData() || "{}");
    const path = (body.path || "").replace(/^\/+/, "");
    if (path === "" || path === ".") return fulfill({ directory: { entries: ROOT_ENTRIES } });
    if (path === "src") return fulfill({ directory: { entries: [{ path: "src/lib.rs", isDirectory: false, size: "10" }] } });
    if (path === "README.md") {
      seen.push("__readfile_README__"); // marker: the clicked file's REAL content was fetched
      return fulfill({ content: { data: b64(README), totalSize: String(README.length), contentHash: "" } });
    }
    return fulfill({ content: { data: b64(`// ${path}\n`), totalSize: "8", contentHash: "" } });
  }
  if (method === "GetGitStatus") {
    return fulfill({ status: { branch: "main", changedFiles: [{ path: "README.md", changeType: "CHANGE_TYPE_MODIFIED" }], totalChangedFiles: 1 } });
  }
  if (method === "GetFileDiffContent") return fulfill({ originalContent: b64("a\n"), newContent: b64("b\n"), isBinary: false });
  if (method === "Find") return fulfill({ files: [], truncated: false });
  if (method === "WriteFile") return fulfill({ bytesWritten: "1" });
  return fulfill({});
});

// Any upstream-namespace wire would be a regression — fail it closed if the surface ever calls one.
await page.route("**/api/**", (route) => {
  seen.push(route.request().url().replace(/^https?:\/\/[^/]+/, ""));
  route.fulfill({ status: 404, body: "" });
});

// The live terminal polls continuously, so the network never goes idle — wait for DOM + a beat.
await page.goto(`${BASE}/sessions/${TID}`, { waitUntil: "domcontentloaded" });
await page.waitForTimeout(1800);

// ── Assertions ────────────────────────────────────────────────────────────────────────────────────
const base = await page.evaluate(() => ({
  workspaceMount: !!document.querySelector("[data-testid=session-workspace]"),
  envBadge: document.querySelector("[data-testid=session-workspace-env]")?.textContent || null,
  noEnv: !!document.querySelector("[data-testid=session-no-env]"),
}));
base.workspaceMount ? ok("workspace pane mounted") : bad("workspace pane");
base.envBadge === ENV ? ok("session bound to the real environment id") : bad("env binding", base.envBadge);
!base.noEnv ? ok("no 'no environment bound' fallback for a bound session") : bad("unexpected no-env fallback");

// The workspace root is expanded on open, so the env's real files appear in the explorer.
await page.waitForTimeout(600);
const tree = await page.evaluate(() => {
  const ws = document.querySelector("[data-testid=session-workspace]");
  const text = ws ? ws.innerText : "";
  return { showsReadme: text.includes("README.md"), showsMainRs: text.includes("main.rs"), showsSrc: /\bsrc\b/.test(text) };
});
tree.showsReadme && tree.showsMainRs && tree.showsSrc
  ? ok("file explorer renders the env's real files (ReadFile tree)")
  : bad("explorer files", JSON.stringify(tree));

// Open a file → the adapter fetches its REAL content via ReadFile and the code editor opens it.
// (The editor is a virtualized code surface; liveness is the native ReadFile for the clicked file
// plus the editor mounting that document — not a fragile scrape of the rendered glyphs.)
await page
  .locator("[data-testid=session-workspace]")
  .getByText("README.md", { exact: false })
  .first()
  .click()
  .catch(() => undefined);
await page.waitForTimeout(1500);
const readReadme = seen.includes("__readfile_README__");
const editorOpened = await page.evaluate(() => {
  const ws = document.querySelector("[data-testid=session-workspace]");
  const text = ws?.innerText || "";
  const mounted = !!ws?.querySelector("[data-editor-runtime]") || !!ws?.querySelector(".monaco-editor");
  return mounted && !text.includes("No editor open");
});
editorOpened ? ok("opening a file mounts the editor with the file open") : bad("editor open-file mount");
readReadme ? ok("opening a file fetches its REAL content via native ReadFile") : bad("editor open-file ReadFile");

// The terminal: a real PTY was created, mounted (xterm canvas), and its byte stream consumed. xterm
// renders to a canvas, so liveness is proven by the native routes + the stream offset advancing.
await page.waitForTimeout(900);
const createdTerminal = seen.some((s) => s.endsWith("/v1/hypervisor/terminals"));
const readTerminal = seen.some((s) => /\/v1\/hypervisor\/terminals\/[^/]+\/stream/.test(s));
const consumedOffset = seen.some((s) => /\/stream\?since=([1-9]\d*)/.test(s)); // since advanced past 0
const termMounted = await page.evaluate(() => !!document.querySelector(".workspace-terminal-canvas"));
createdTerminal ? ok("terminal created via native daemon route") : bad("terminal create route");
readTerminal ? ok("terminal output streamed via native daemon route") : bad("terminal stream route");
termMounted ? ok("real PTY terminal mounted (xterm canvas)") : bad("terminal mount");
consumedOffset ? ok("terminal byte stream consumed (offset advanced from daemon)") : bad("terminal offset advance", seen.filter((s) => s.includes("/stream")).join(","));

// Native env-ops routes were used; NO upstream-namespace bridge.
const usedReadFile = seen.some((s) => /\/supervisor\/[^/]+\/supervisor\.v1\.EnvironmentOpsService\/ReadFile/.test(s));
const bridged = seen.some((s) => /\/api\/[a-z][a-z0-9.]*\.v\d+\//i.test(s));
usedReadFile ? ok("file tree from native env-ops ReadFile plane") : bad("native env-ops file plane", seen.join(","));
!bridged ? ok("no upstream-wire bridge (/api/*.vN/)") : bad("no upstream-wire bridge", seen.filter((s) => /\/api\//.test(s)).join(","));

await page.screenshot({ path: "/tmp/claude-1000/-home-heathledger-Documents-ioi-repos-ioi/beeedf53-0407-44be-b0fe-84d138a82853/scratchpad/workspace-contract.png", fullPage: false });
await browser.close();

if (fails.length) { console.error(`\nworkspace contract FAILED: ${fails.length}`); process.exit(1); }
console.log("\nworkspace contract PASSED.");
