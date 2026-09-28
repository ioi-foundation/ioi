#!/usr/bin/env node
// THE SESSIONS SHELL WORKS OVER DAEMON TRUTH, OR SAYS WHY IT CANNOT (R-240 Arm A on Sessions, R-241 seed depth).
//
// The Sessions pages are the vendored product shell answered by ioi-api-adapter.mjs. Driving them against the
// reference's 44 harvested states found a destructive defect and several dead or crashing views; this proves each
// fix in a real browser against an ISOLATED daemon + serve (never the owner's):
//   - the Archived view lists only archived environments, and its "Delete all" deletes only those;
//   - opening a changed file shows a named gap instead of crashing the session page (a missing shell chunk);
//   - the session details card renders (the projection names the runner it waits on);
//   - the editor openers resolve an editor URL (the projection names the organization; ResolveEditorURL is bound);
//   - "New Terminal" opens a real terminal bound to the environment (the env-ops bridge carries the person's session);
//   - Create PR files a governed draft owned by the environment's tenant (it could never succeed for anyone);
//   - Services, Tasks, Add port and Resource usage each say, in a sentence, what is absent and why;
//   - the personal settings routes show a named gap instead of a blank page;
//   - a disposable serve never writes the owner's preference store.
//
// Exit: 0 pass · 1 fail · 2 blocked (no daemon binary).
//   IOI_HYPERVISOR_DAEMON_BINARY  default target/debug/hypervisor-daemon
//   node apps/hypervisor/scripts/verify-hypervisor-sessions-shell.mjs

import { spawn, spawnSync } from "node:child_process";
import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import net from "node:net";
import { fileURLToPath } from "node:url";
import { emitVerifierCensus } from "./lib/verifier-census.mjs";

const HERE = path.dirname(fileURLToPath(import.meta.url));
const APP = path.resolve(HERE, "..");
const ROOT = path.resolve(APP, "..", "..");
const BIN = process.env.IOI_HYPERVISOR_DAEMON_BINARY || path.join(ROOT, "target", "debug", "hypervisor-daemon");
const OWNER_PREFS = path.join(ROOT, ".ioi", "hypervisor-app-local", "app-preferences.json");

const results = [];
const ok = (name, cond, detail) => results.push({ name, pass: !!cond, detail: detail || "" });
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const freePort = () => new Promise((r) => { const s = net.createServer(); s.listen(0, "127.0.0.1", () => { const p = s.address().port; s.close(() => r(p)); }); });
const waitFor = async (url, ms = 60000) => { const end = Date.now() + ms; while (Date.now() < end) { try { const r = await fetch(url); if (r.status < 500) return true; } catch { /* not yet */ } await sleep(300); } return false; };
const hashOf = (file) => { try { return crypto.createHash("sha256").update(fs.readFileSync(file)).digest("hex"); } catch { return "absent"; } };

let daemon = null;
let serve = null;
const dataDir = fs.mkdtempSync(path.join(os.tmpdir(), "ioi-sessions-shell-"));

async function run() {
  if (!fs.existsSync(BIN)) { console.log(`BLOCKED: no daemon binary at ${BIN}`); process.exit(2); }
  const ownerPrefsBefore = hashOf(OWNER_PREFS);
  const daemonPort = await freePort();
  const DAEMON = `http://127.0.0.1:${daemonPort}`;
  let log = "";
  daemon = spawn(BIN, [], { cwd: ROOT, env: { ...process.env, IOI_HYPERVISOR_DAEMON_ADDR: `127.0.0.1:${daemonPort}`, IOI_HYPERVISOR_DATA_DIR: dataDir, IOI_HYPERVISOR_MODEL_UPSTREAM: "http://127.0.0.1:1/v1" }, stdio: ["ignore", "pipe", "pipe"] });
  daemon.stdout.on("data", (c) => (log += c)); daemon.stderr.on("data", (c) => (log += c));
  await waitFor(`${DAEMON}/healthz`);
  const token = log.match(/ioi_bootstrap_[a-f0-9]{64}/gu)?.at(-1);
  const boot = await (await fetch(`${DAEMON}/v1/hypervisor/auth/bootstrap`, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ token, password: "sessions-shell-bootstrap-v1", email: "sessions@ioi.local" }) })).json();
  const COOKIE = `ioi_session=${boot.session_token}`;
  const servePort = await freePort();
  const SERVE = `http://127.0.0.1:${servePort}`;
  serve = spawn(process.execPath, [path.join(HERE, "serve-product-ui.mjs")], {
    cwd: APP,
    env: { ...process.env, PORT: String(servePort), PRODUCT_UI_PORT: String(await freePort()), IOI_PRODUCT_UI_PUBLIC: path.join(APP, "product-ui", "owned", "public"), IOI_HYPERVISOR_DAEMON_URL: DAEMON, IOI_PRODUCT_SIGNIN_REQUIRED: "0" },
    stdio: ["ignore", "pipe", "pipe"],
  });
  await waitFor(`${SERVE}/__ioi/login`);
  const api = (m, b) => fetch(`${SERVE}/api/ioi.v1.${m}`, { method: "POST", headers: { cookie: COOKIE, "content-type": "application/json" }, body: JSON.stringify(b || {}) }).then(async (r) => ({ status: r.status, j: await r.json().catch(() => ({})) }));
  const daemonReq = (route) => fetch(`${DAEMON}${route}`, { headers: { cookie: COOKIE } }).then((r) => r.json()).catch(() => ({}));
  const phases = async () => Object.fromEntries(((await daemonReq("/v1/hypervisor/environments")).environments || []).map((e) => [e.id, e.status?.phase]));

  // ---- seed: a project; one running environment, one stopped, one archived ----------------------------------
  const project = (await api("ProjectService/CreateProject", { name: "sessions-shell", initializer: { specs: [{ git: { remoteUri: "https://example.invalid/acme/sessions-shell.git" } }] } })).j.project?.id;
  const mk = async () => (await api("EnvironmentService/CreateEnvironment", { spec: { projectId: project } })).j.environment?.id;
  const RUNNING = await mk(), STOPPED = await mk(), ARCHIVED = await mk();
  await api("EnvironmentService/StartEnvironment", { environmentId: RUNNING });
  await api("EnvironmentService/ArchiveEnvironment", { environmentId: ARCHIVED });
  for (let i = 0; i < 40 && (await phases())[RUNNING] !== "running"; i++) await sleep(500);
  const seeded = await phases();
  ok("PRECONDITION: one running, one stopped and one archived environment exist on the isolated daemon",
    seeded[RUNNING] === "running" && seeded[STOPPED] === "stopped" && seeded[ARCHIVED] === "archived", JSON.stringify(seeded));

  const { chromium } = await import(path.join(ROOT, "node_modules", "playwright", "index.mjs"));
  const browser = await chromium.launch();
  try {
    const ctx = await browser.newContext({ viewport: { width: 1600, height: 1000 } });
    await ctx.addCookies([{ name: "ioi_session", value: boot.session_token, url: SERVE }]);
    const pg = await ctx.newPage();
    const rpc = [];
    const consoleErrors = [];
    // the shell's own RPC paths (whatever package prefix it sends): …/<Service>/<Method>
    pg.on("response", (r) => { const u = new URL(r.url()); if (/Service\/[A-Za-z]+$/u.test(u.pathname)) rpc.push(`${r.status()} ${u.pathname.split("/").pop()}`); });
    pg.on("console", (m) => { if (m.type() === "error") consoleErrors.push(m.text()); });
    const text = async () => (await pg.evaluate(() => document.body.innerText)).replace(/\s+/gu, " ");

    // ---- the Archived view: only archived environments; its Delete all deletes only those ------------------
    const archivedList = await api("EnvironmentService/ListEnvironments", { filter: { archivalStatus: "ARCHIVAL_STATUS_ARCHIVED" } });
    const activeList = await api("EnvironmentService/ListEnvironments", { filter: { archivalStatus: "ARCHIVAL_STATUS_ACTIVE" } });
    await pg.goto(`${SERVE}/ai`, { waitUntil: "domcontentloaded", timeout: 60000 });
    await pg.waitForTimeout(8000);
    await pg.getByRole("button", { name: /Filter sessions/u }).first().click({ timeout: 4000 }).catch(() => { /* named below */ });
    await pg.waitForTimeout(800);
    await pg.getByText(/^Archived/u).first().click({ timeout: 4000 }).catch(() => { /* named below */ });
    await pg.waitForTimeout(3000);
    await pg.getByRole("button", { name: "Delete all" }).first().click({ timeout: 4000 }).catch(() => { /* named below */ });
    await pg.waitForTimeout(1500);
    const dialog = (await pg.evaluate(() => [...document.querySelectorAll('[role="dialog"],[role="alertdialog"]')].map((d) => d.innerText).join(" | "))).replace(/\s+/gu, " ");
    await pg.getByRole("button", { name: /Yes, delete/u }).first().click({ timeout: 4000 }).catch(() => { /* named below */ });
    await pg.waitForTimeout(6000);
    const after = await phases();
    ok("the Archived view lists only archived environments, and its Delete all deletes only those — the running and stopped environments survive",
      (archivedList.j.environments || []).map((e) => e.id).join(",") === ARCHIVED && !(activeList.j.environments || []).some((e) => e.id === ARCHIVED)
        && /Delete archived environment\?/u.test(dialog) && after[ARCHIVED] === "deleted" && after[RUNNING] === "running" && after[STOPPED] === "stopped",
      `archived list ${(archivedList.j.environments || []).length} · dialog "${dialog.slice(0, 80)}" · after ${JSON.stringify(after)}`);

    // ---- the running session: editor openers, a changed file, the details card, a terminal -----------------
    await pg.goto(`${SERVE}/details/${RUNNING}`, { waitUntil: "domcontentloaded", timeout: 60000 });
    rpc.length = 0;
    await pg.waitForTimeout(9000);
    await pg.getByRole("button", { name: /Open VS Code/u }).first().click({ timeout: 4000 }).catch(() => { /* named below */ });
    await pg.waitForTimeout(3000);
    const envRec = (await api("EnvironmentService/GetEnvironment", { environmentId: RUNNING })).j.environment;
    const resolved = await api("EditorService/ResolveEditorURL", { environmentId: RUNNING, organizationId: envRec?.metadata?.organizationId, editorId: "vscode-browser" });
    ok("the editor openers resolve an editor URL for the session: the environment names its organization and runner, and ResolveEditorURL answers the offered editor's open route",
      !!envRec?.metadata?.organizationId && envRec?.metadata?.runnerId === "local-microvm" && rpc.some((x) => /^200 ResolveEditorURL$/u.test(x))
        && !consoleErrors.some((e) => /No environment or organization ID provided/u.test(e))
        && resolved.j.url === `/__ioi/editor/open?environmentId=${encodeURIComponent(RUNNING)}`,
      `metadata ${JSON.stringify(envRec?.metadata)} · page rpc ${rpc.filter((x) => /Editor/u.test(x)).join(",")} · url ${resolved.j.url}`);

    const changed = pg.getByText("devcontainer.json", { exact: true }).first();
    await changed.click({ timeout: 5000 }).catch(() => { /* named below */ });
    await pg.waitForTimeout(3000);
    const diff = await text();
    ok("opening a changed file shows a named gap (the file diff view is not part of the shell yet) instead of crashing the session page",
      /The file diff view is not part of the Hypervisor shell yet\./u.test(diff) && !/Something went wrong|Uh oh/u.test(diff), diff.includes("file diff view") ? "named gap" : diff.slice(0, 200));

    await pg.goto(`${SERVE}/details/${RUNNING}`, { waitUntil: "domcontentloaded", timeout: 60000 });
    await pg.waitForTimeout(8000);
    await pg.locator("button,[role=tab]").filter({ hasText: /^Terminal$/u }).last().click({ timeout: 4000 }).catch(() => { /* named below */ });
    await pg.waitForTimeout(1500);
    await pg.getByRole("button", { name: "New Terminal", exact: true }).first().click({ timeout: 4000 }).catch(() => { /* named below */ });
    let term = "";
    for (let i = 0; i < 15; i++) { await pg.waitForTimeout(1000); term = await text(); if (/connected/u.test(term) || /Failed to create terminal/u.test(term)) break; }
    const terminals = ((await daemonReq("/v1/hypervisor/terminals")).terminals || []).filter((t) => t.environment_ref === `environment:${RUNNING}`);
    ok("New Terminal opens a real terminal bound to the session's environment (the env-ops bridge carries the person's session to the daemon)",
      terminals.length >= 1 && /connected/u.test(term) && !/Failed to create terminal/u.test(term),
      `daemon terminals for the env ${terminals.length} · pane connected ${/connected/u.test(term)} · toast ${/Failed to create terminal/u.test(term)}`);

    await pg.goto(`${SERVE}/details/${RUNNING}?view=environment`, { waitUntil: "domcontentloaded", timeout: 60000 });
    let card = "", skeletons = 99;
    for (let i = 0; i < 25; i++) {
      await pg.waitForTimeout(1000);
      card = await text();
      skeletons = await pg.evaluate(() => document.querySelectorAll('[class*="skeleton" i],[data-slot="skeleton"]').length);
      if (/Created/u.test(card) && /Last started/u.test(card) && skeletons < 3) break;
    }
    ok("the session details card renders (its runner is named), rather than a skeleton forever",
      /Created/u.test(card) && /Last started/u.test(card) && skeletons < 3, `skeletons ${skeletons} · created ${/Created/u.test(card)} · last started ${/Last started/u.test(card)}`);

    // ---- named gaps that read: Services, Tasks, Add port, Resource usage ------------------------------------------
    await pg.goto(`${SERVE}/details/${RUNNING}`, { waitUntil: "domcontentloaded", timeout: 60000 });
    await pg.waitForTimeout(8000);
    const paneOf = (t) => pg.evaluate((t) => { const tab = [...document.querySelectorAll("[role=tab]")].find((x) => x.innerText.trim() === t); const id = tab?.getAttribute("aria-controls"); const p = id ? document.getElementById(id) : null; return (p?.innerText || "").replace(/\s+/gu, " "); }, t);
    const overlays = () => pg.evaluate(() => [...document.querySelectorAll("[role=dialog],[role=alertdialog],[data-sonner-toast],[role=status],[role=alert]")].map((e) => e.innerText).join(" | ").replace(/\s+/gu, " "));
    await pg.getByRole("tab", { name: "Ports & Services", exact: true }).first().click({ timeout: 4000 }).catch(() => { /* named below */ });
    let portsPane = "";
    for (let i = 0; i < 12; i++) { await pg.waitForTimeout(800); portsPane = await paneOf("Ports & Services"); if (/environment_services_plane_absent/u.test(portsPane)) break; }
    ok("the Services section names the absent services plane in a sentence (the shell labels Unimplemented \"Internal\" and showed a red \"Internal: …\" line)",
      /Services aren't tracked for Hypervisor environments yet/u.test(portsPane) && /environment_services_plane_absent/u.test(portsPane) && !/Internal:/u.test(portsPane), portsPane.slice(0, 220));
    rpc.length = 0;
    await pg.getByRole("tab", { name: "Tasks", exact: true }).first().click({ timeout: 4000 }).catch(() => { /* named below */ });
    let tasksPane = "";
    for (let i = 0; i < 12; i++) { await pg.waitForTimeout(800); tasksPane = await paneOf("Tasks"); if (/environment_tasks_plane_absent/u.test(tasksPane)) break; }
    await pg.waitForTimeout(3000);
    const taskAsks = rpc.filter((x) => /ListTasks$/u.test(x)).length;
    ok("the Tasks tab names the absent tasks plane instead of \"No tasks defined in this environment\" (it read only its data), and asks once rather than in a loop",
      /Tasks aren't tracked for Hypervisor environments yet/u.test(tasksPane) && /environment_tasks_plane_absent/u.test(tasksPane) && !/No tasks defined/u.test(tasksPane) && taskAsks <= 2,
      `${tasksPane.slice(0, 160)} · ListTasks asked ${taskAsks}×`);
    await pg.getByRole("tab", { name: "Ports & Services", exact: true }).first().click({ timeout: 4000 }).catch(() => { /* named below */ });
    await pg.waitForTimeout(800);
    await pg.getByRole("button", { name: "Add port" }).first().click({ timeout: 4000 }).catch(() => { /* named below */ });
    await pg.waitForTimeout(1200);
    await pg.locator('[role=dialog] input[name="name"]').fill("web", { timeout: 3000 }).catch(() => { /* named below */ });
    await pg.locator('[role=dialog] input[name="port"]').fill("3000", { timeout: 3000 }).catch(() => { /* named below */ });
    await pg.locator("[role=dialog]").getByRole("button", { name: "Open port" }).first().click({ timeout: 3000 }).catch(() => { /* named below */ });
    let portToast = "";
    for (let i = 0; i < 10; i++) { await pg.waitForTimeout(600); portToast = await overlays(); if (/can't be opened|Failed to open port/u.test(portToast)) break; }
    const envPorts = (await daemonReq(`/v1/hypervisor/environments/${RUNNING}`)).environment?.status?.ports || [];
    ok("Add port's new port is refused naming the real rule — only the ports the recipe declares, only behind the opener's lease, never public — and nothing is exposed (it named the update rule it happened to reach)",
      /Port 3000 can't be opened/u.test(portToast) && /only the ports their recipe declares/u.test(portToast) && !envPorts.some((x) => Number(x.port) === 3000),
      `${(portToast.match(/Failed to open port[^|]*/u) || [portToast.slice(0, 160)])[0]} · daemon ports ${envPorts.map((x) => x.port).join(",") || "none"}`);
    await pg.keyboard.press("Escape").catch(() => { /* closed */ });
    await pg.goto(`${SERVE}/details/${RUNNING}`, { waitUntil: "domcontentloaded", timeout: 60000 });
    await pg.waitForTimeout(8000);
    await pg.getByRole("button", { name: "Environment actions" }).first().click({ timeout: 4000 }).catch(() => { /* named below */ });
    await pg.waitForTimeout(800);
    await pg.getByRole("menuitem", { name: "Resource usage", exact: true }).first().click({ timeout: 4000 }).catch(() => { /* named below */ });
    let usage = "";
    for (let i = 0; i < 12; i++) { await pg.waitForTimeout(800); usage = await overlays(); if (/environment_live_usage_plane_absent/u.test(usage)) break; }
    ok("Resource usage says why there are no readings (the daemon reports no live usage for an environment) instead of \"N/A\" with no reason",
      /environment_live_usage_plane_absent/u.test(usage) && /don't report live CPU, memory, disk or load/u.test(usage), usage.slice(0, 220));
    await pg.keyboard.press("Escape").catch(() => { /* closed */ });

    // ---- Create PR: the shell's own prompt files a governed draft owned by the environment's tenant ------------
    // (the draft named the person's user:// ref as its owner, which is never a tenant, so every draft with changes
    // was refused for every caller — and the timeline dropped the daemon's reason for a bare status)
    const wsRoot = (await daemonReq(`/v1/hypervisor/environments/${RUNNING}`)).environment?.status?.workspace_root;
    if (wsRoot) {
      const git = (...a) => spawnSync("git", ["-C", wsRoot, "-c", "user.email=sessions@ioi.local", "-c", "user.name=sessions-shell", ...a], { encoding: "utf8" });
      if (!fs.existsSync(path.join(wsRoot, ".git"))) git("init", "-q");
      git("add", "-A");
      git("commit", "-q", "--allow-empty", "-m", "base");
      fs.writeFileSync(path.join(wsRoot, "BUILD.md"), "# Build\n\nnpm ci && npm run build\n");
    }
    const prRun = (await api("AgentService/CreateAgentExecution", { codeContext: { environmentId: RUNNING } })).j.agentExecutionId;
    if (prRun) await api("AgentService/SendToAgentExecution", { agentExecutionId: prRun, userInput: { inputs: [{ text: { content: "Create a pull request for the current changes." } }] } });
    let prRec = {};
    for (let i = 0; i < 30 && prRun; i++) { prRec = (await daemonReq(`/v1/hypervisor/agent-run-transcripts/${prRun}`)).run || {}; if (prRec.status && !/running|waiting/u.test(prRec.status)) break; await sleep(500); }
    ok("Create PR files a governed draft proposal owned by the environment's tenant (it named the person as the owner, so every draft with changes was refused for every caller)",
      !!wsRoot && prRec.status === "done" && /^proposal:\/\/local\/hypervisor\/prd_/u.test(prRec.publication_proposal_ref || "") && !prRec.error,
      `workspace ${wsRoot ? "seeded" : "absent"} · run ${prRec.status} · proposal ${prRec.publication_proposal_ref} · ${String(prRec.error || "").slice(0, 140)}`);

    // ---- the composer: the shell's own submit, with the project it chose ------------------------------------
    const before = new Set(Object.keys(await phases()));
    await pg.goto(`${SERVE}/ai#new-session`, { waitUntil: "domcontentloaded", timeout: 60000 });
    await pg.waitForTimeout(8000);
    await pg.getByRole("button", { name: "Add context" }).first().click({ timeout: 4000 }).catch(() => { /* named below */ });
    await pg.waitForTimeout(1000);
    await pg.getByText(/Start from project/u).first().click({ timeout: 4000 }).catch(() => { /* named below */ });
    await pg.waitForTimeout(1500);
    // the picker's option (the sidebar also names the project now that sessions are grouped under it)
    await pg.locator('[role="listbox"], [cmdk-list], [role="dialog"]').getByText("sessions-shell", { exact: true }).first().click({ timeout: 4000 }).catch(() => { /* named below */ });
    await pg.waitForTimeout(1500);
    await pg.locator('[data-testid="prompt-input-textarea"]').fill("Document the build steps", { timeout: 4000 }).catch(() => { /* named below */ });
    await pg.waitForTimeout(800);
    // the composer then asks for a session class (the picker opens by itself; else open it)
    const firstClass = pg.getByText("local microVM node (Phase 1 lifecycle)", { exact: true }).first();
    if (!(await firstClass.isVisible().catch(() => false))) { await pg.getByRole("button", { name: /Session class/u }).first().click({ timeout: 3000 }).catch(() => { /* no picker */ }); await pg.waitForTimeout(800); }
    await firstClass.click({ timeout: 3000 }).catch(() => { /* named below */ });
    await pg.waitForTimeout(1500);
    const composerSubmit = pg.locator('[data-testid="prompt-input-submit-button"]');
    const submitEnabled = !(await composerSubmit.isDisabled().catch(() => true));
    await composerSubmit.click({ timeout: 4000 }).catch(() => { /* named below */ });
    await pg.waitForTimeout(12000);
    const created = Object.keys(await phases()).filter((id) => !before.has(id));
    const createdEnv = ((await daemonReq("/v1/hypervisor/environments")).environments || []).find((e) => created.includes(e.id));
    const createdView = created[0] ? (await api("EnvironmentService/GetEnvironment", { environmentId: created[0] })).j.environment : null;
    ok("the new session carries its project to the shell (the sidebar groups it there; \"Go to project\" needs it) and the daemon's auto-stop (never), not the shell's 30-minute default",
      createdView?.metadata?.projectId === project && createdView?.spec?.timeout?.disconnected === "0s",
      `metadata.projectId ${createdView?.metadata?.projectId} · timeout ${JSON.stringify(createdView?.spec?.timeout)}`);
    ok("the composer's own submit files the new session under the project it chose (it had sent the prompt alone, so every session was filed under no project), and lands on the session",
      submitEnabled && created.length === 1 && createdEnv?.spec?.project_id === project && /\/details\//u.test(pg.url()),
      `submit enabled ${submitEnabled} · created ${created.length} · project ${createdEnv?.spec?.project_id} (want ${project}) · at ${pg.url().replace(SERVE, "")}`);

    // ---- a failed run reads Failed (its phase is one the shell knows), not "Starting…" forever -------------------
    let rowText = "";
    if (created[0]) {
      await pg.goto(`${SERVE}/ai`, { waitUntil: "domcontentloaded", timeout: 60000 });
      await pg.waitForTimeout(6000);
      // the session is grouped under its project now; open the group only if its row is not shown (a click toggles it)
      const rowShown = () => pg.evaluate((id) => [...document.querySelectorAll("a[href]")].some((x) => (x.getAttribute("href") || "").includes(id)), created[0]);
      if (!(await rowShown())) await pg.locator("button").filter({ hasText: /^sessions-shell$/u }).first().click({ timeout: 3000 }).catch(() => { /* no group */ });
      for (let i = 0; i < 20; i++) {
        await pg.waitForTimeout(1500);
        // the session's row (some links to it are icon-only, with no text)
        rowText = await pg.evaluate((id) => [...document.querySelectorAll("a[href]")].filter((x) => (x.getAttribute("href") || "").includes(id)).map((x) => x.innerText.replace(/\s+/g, " ").trim()).find(Boolean) || "", created[0]);
        if (rowText && !/Starting…|Working…/u.test(rowText)) break;
      }
    }
    const runs = created[0] ? ((await api("AgentService/ListAgentExecutions", {})).j.agentExecutions || []).filter((x) => x.spec?.codeContext?.environmentId === created[0]) : [];
    // the row's dot follows the ENVIRONMENT (still running, as the reference's does); the run's own state is the record the
    // shell derives "Failed" from — STOPPED with a failureMessage
    ok("a session whose agent run failed no longer reads \"Starting…\" forever: its run projects a phase the shell knows (STOPPED, with the run's reason), which the shell reads as Failed",
      !!rowText && !/Starting…|Working…/u.test(rowText) && runs.some((x) => x.status?.phase === "PHASE_STOPPED" && x.status?.failureMessage),
      `row "${rowText.slice(0, 120)}" · run ${JSON.stringify(runs.map((x) => [x.status?.phase, (x.status?.failureMessage || "").slice(0, 60)]))}`);

    // ---- the agent's Stop on a finished run: nothing is running, so it is done (it answered 503 for every run) ------
    const runId = runs[0]?.id;
    const stopped = runId ? await api("AgentService/StopAgentExecution", { agentExecutionId: runId }) : { status: 0, j: {} };
    const delRun = runId ? await api("AgentService/DeleteAgentExecution", { agentExecutionId: runId }) : { status: 0, j: {} };
    ok("the agent's Stop on a finished run is done (it answered 503 for every run: a registry run is not a daemon thread), and deleting a run's conversation is refused by name (its receipted history is kept)",
      stopped.status === 200 && delRun.status === 412 && /agent_run_history_kept/u.test(JSON.stringify(delRun.j)),
      `stop ${stopped.status} · delete ${delRun.status} ${JSON.stringify(delRun.j).slice(0, 100)}`);

    // ---- the list follows the daemon: a deleted session leaves the open list without a reload (WatchEvents) ---
    await pg.goto(`${SERVE}/ai`, { waitUntil: "domcontentloaded", timeout: 60000 });
    await pg.waitForTimeout(8000);
    const listed = async () => (await pg.evaluate(() => [...document.querySelectorAll("a[href]")].map((a) => a.getAttribute("href")))).some((h) => h && h.includes(STOPPED));
    const wasListed = await listed();
    const deleted = await api("EnvironmentService/DeleteEnvironment", { environmentId: STOPPED });
    let left = false;
    for (let i = 0; i < 25 && !left; i++) { await pg.waitForTimeout(1000); left = !(await listed()); }
    ok("the open session list follows the daemon: a deleted session leaves it within seconds, without a reload (the change stream had ended at once with no event)",
      wasListed && deleted.status === 200 && left, `listed before ${wasListed} · delete ${deleted.status} · gone ${left}`);

    // ---- personal settings: a named gap, not a blank page ---------------------------------------------------
    await pg.goto(`${SERVE}/settings/preferences`, { waitUntil: "domcontentloaded", timeout: 60000 });
    await pg.waitForTimeout(6000);
    const prefsPage = await text();
    ok("a personal settings route shows a named gap rather than a blank page",
      /Personal settings is not part of the Hypervisor shell yet\./u.test(prefsPage), prefsPage.slice(0, 160));
  } finally {
    await browser.close();
  }

  // ---- Plan mode: refused by name before anything is created ---------------------------------------------------
  const envCountBefore = ((await daemonReq("/v1/hypervisor/environments")).environments || []).length;
  const planned = await api("AgentService/CreateAgentSession", { createEnvironmentFromProject: { projectId: project, spec: {} }, agent: { turnOptions: { modes: ["AGENT_MODE_SPEC"] } }, initialInput: { inputs: [{ text: { content: "plan the migration" } }] } });
  const envCountAfter = ((await daemonReq("/v1/hypervisor/environments")).environments || []).length;
  ok("a Plan session is refused by name (no read-only turn exists; it would run with the environment's full authority) and creates nothing",
    planned.status === 501 && /plan_mode_not_supported/u.test(JSON.stringify(planned.j)) && envCountAfter === envCountBefore,
    `status ${planned.status} · ${JSON.stringify(planned.j).slice(0, 120)} · environments ${envCountBefore} → ${envCountAfter}`);

  // ---- preferences: a disposable serve keeps its own store ----------------------------------------------------
  await api("UserService/SetPreference", { preference: { key: "sessions-shell-probe", value: "isolated" } });
  ok("a disposable serve's preference writes land in its own store, never the owner's",
    hashOf(OWNER_PREFS) === ownerPrefsBefore, `owner store ${ownerPrefsBefore === "absent" ? "absent" : "unchanged?"} → ${hashOf(OWNER_PREFS) === ownerPrefsBefore ? "unchanged" : "CHANGED"}`);
}

function cleanup() {
  try { serve?.kill("SIGTERM"); } catch { /* gone */ }
  try { daemon?.kill("SIGTERM"); } catch { /* gone */ }
  try { fs.rmSync(dataDir, { recursive: true, force: true }); } catch { /* keep */ }
}

run().then(() => {
  const fails = results.filter((r) => !r.pass);
  for (const r of results) console.log(`${r.pass ? "PASS" : "FAIL"}  ${r.name}${r.detail ? ` — ${r.detail}` : ""}`);
  console.log(`\n${results.length - fails.length}/${results.length} passed`);
  emitVerifierCensus({ verifierId: "sessions-shell", sourceUrl: import.meta.url, results });
  cleanup();
  process.exit(fails.length ? 1 : 0);
}).catch((e) => { console.error(e); cleanup(); process.exit(1); });
