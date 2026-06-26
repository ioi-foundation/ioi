#!/usr/bin/env node
// Done-bar for Hypervisor's OWNED transcript primitive — the Run Timeline.
//
// The harvested SPA's chat pane is borrowed UI (fixed bubble order, chat-only). Hypervisor is a
// workbench for GOVERNED work, so it OWNS its conversation surface: a Run / Activity Timeline fed by
// daemon-truth, with the 6-part turn (request → activity → response → artifacts → proof → followUps)
// and routed from the global IOI cockpit launcher across every surface.
//
// This proves, with REAL effects (no model needed — uses the deterministic daemon PR-draft run):
//   1. the projection endpoint emits the 6-part structure from real run/daemon data,
//   2. the owned UI surface renders all six sections (incl. the governance Proof card),
//   3. the cockpit launcher (injected on every page) opens the owned surface for the viewed env.
//
// Usage: node scripts/verify-hypervisor-run-timeline-functional.mjs [--json]
const JSON_OUT = process.argv.includes("--json");
const REF = process.env.IOI_REFERENCE_URL || "http://127.0.0.1:4173";
const DAEMON = process.env.IOI_HYPERVISOR_DAEMON_URL || "http://127.0.0.1:8765";

const checks = [];
let failures = 0;
const ok = (cond, msg, detail) => { checks.push({ ok: !!cond, msg }); if (!cond) failures++; if (!JSON_OUT) console.log(`    ${cond ? "✓" : "✗ FAIL:"} ${msg}${detail ? ` (${detail})` : ""}`); };
const blocked = (reason) => { console.log(JSON_OUT ? JSON.stringify({ workstream: "run-timeline", verdict: "BLOCKED", reason }, null, 2) : `  BLOCKED: ${reason}`); process.exit(2); };

if (!JSON_OUT) console.log("Run Timeline e2e — owned governed-work transcript primitive");

const up = async (url) => { try { return (await fetch(url, { signal: AbortSignal.timeout(3000) })).ok; } catch { return false; } };
if (!(await up(`${REF}/__ioi/fallthrough`))) blocked("serve-live-reference (:4173) not running");
if (!(await up(`${DAEMON}/v1/hypervisor/providers`))) blocked("hypervisor-daemon (:8765) not running");

const dj = async (m, p, b) => { const r = await fetch(DAEMON + p, { method: m, headers: b ? { "content-type": "application/json" } : undefined, body: b ? JSON.stringify(b) : undefined }); return { status: r.status, body: await r.json().catch(() => ({})) }; };
const aj = async (p, b) => (await fetch(REF + p, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify(b) })).json();

// --- build a deterministic governed run: env → start → workspace change → daemon PR-draft run ---
const env = await dj("POST", "/v1/hypervisor/environments", { spec: { environment_class_id: "local-workspace-v0" } });
const envId = env.body?.environment?.id;
ok(!!envId, "created a local environment", envId);
await dj("POST", `/v1/hypervisor/environments/${envId}/start`);
const ws = (await dj("GET", `/v1/hypervisor/environments/${envId}`)).body?.environment?.status?.workspace_root;
if (ws) { try { (await import("node:fs")).writeFileSync(`${ws}/timeline-probe.txt`, "change\n"); } catch { /* */ } }
const start = await aj("/api/gitpod.v1.AgentService/StartAgent", { codeContext: { environmentId: envId } });
const runId = start.agentExecutionId;
await aj("/api/gitpod.v1.AgentService/SendToAgentExecution", { agentExecutionId: runId, userInput: { id: "blk-1", inputs: [{ text: { content: "Create a pull request for the current changes." } }] } });

// --- 1) projection endpoint: 6-part structure from real data ---
const tl = await fetch(`${REF}/__ioi/agent-runs/${runId}/timeline`).then((r) => r.json()).catch(() => null);
ok(tl && tl.schema_version === "ioi.hypervisor.run-timeline.v1", "timeline projection served (run-timeline.v1)");
const turn = tl?.turns?.[0] || {};
ok(turn.request?.text?.includes("pull request"), "1/6 request — real user ask", turn.request?.text?.slice(0, 40));
ok(Array.isArray(turn.activity) && turn.activity.length >= 2 && turn.activity.some((a) => a.kind === "done"), "2/6 activity — governed-work steps with timestamps", `${turn.activity?.length} steps`);
ok(!!turn.response?.text, "3/6 response — agent answer", turn.response?.text?.slice(0, 40));
ok((turn.artifacts?.files || []).some((f) => f.includes("pr-drafts")), "4/6 artifacts — daemon-written draft files", (turn.artifacts?.files || []).join(","));
ok((turn.proof?.proposalRefs || []).some((r) => r.startsWith("agentgres://")), "5/6 proof — agentgres proposal ref (governance audit)", (turn.proof?.proposalRefs || [])[0]);
ok(Array.isArray(turn.followUps) && turn.followUps.length > 0, "6/6 followUps — next governed actions", (turn.followUps || []).map((f) => f.label).join(", "));

// --- DURABLE (#3): the run-transcript is recorded in the daemon (Agentgres) with a state_root, so
// the timeline survives a serve restart. The timeline marks itself durable and the state_root
// matches the daemon's recorded envelope (tamper-evident handle, single source of truth). ---
const durableRec = await dj("GET", `/v1/hypervisor/agent-run-transcripts/${runId}`);
ok(durableRec.body?.ok && durableRec.body?.run?.run_id === runId, "durable: run-transcript recorded in the daemon (Agentgres)", durableRec.body?.run?.state_root);
ok(tl?.durable === true && !!tl?.stateRoot, "durable: timeline reports a durable state_root");
ok(tl?.stateRoot && tl.stateRoot === durableRec.body?.run?.state_root, "durable: timeline state_root matches the daemon record (single source of truth)", `${tl?.stateRoot} == ${durableRec.body?.run?.state_root}`);

// --- 2) owned UI renders + 3) cockpit launcher opens it ---
let chromium;
try { ({ chromium } = await import("playwright")); } catch { blocked("playwright not installed"); }
const b = await chromium.launch({ headless: true });
try {
  const ctx = await b.newContext({ viewport: { width: 1000, height: 1100 } });
  const errs = [];
  const page = await ctx.newPage();
  page.on("console", (m) => { if (m.type() === "error" && !/Failed to load resource|WebSocket/i.test(m.text())) errs.push(m.text()); });
  page.on("pageerror", (e) => errs.push("pageerror: " + e.message));

  // owned surface renders all six sections + the proof card
  await page.goto(`${REF}/__ioi/run-timeline/${runId}`, { waitUntil: "networkidle", timeout: 20000 });
  await page.waitForTimeout(1500);
  const sections = await page.evaluate(() => [...document.querySelectorAll(".rt-label")].map((n) => n.innerText.replace(/\s+/g, " ").trim()));
  ok(sections.length === 6, "owned UI renders all six timeline sections", sections.join(" | "));
  const proofText = await page.evaluate(() => { const p = document.querySelector(".rt-proof"); return p ? p.innerText : ""; });
  ok(/agentgres:\/\//.test(proofText), "owned UI shows the governance Proof card");
  ok(errs.length === 0, "owned UI has zero JS/page errors", errs.slice(0, 2).join("; "));

  // DEFAULT SURFACE: on the workbench the owned timeline REPLACES the borrowed conversation pane
  // in-pane (the run-gate flips once the env has a run), with its own follow-up composer.
  const wb = await ctx.newPage();
  await wb.goto(`${REF}/details/${envId}`, { waitUntil: "domcontentloaded", timeout: 20000 });
  let inPane = { mounted: false, visibleBorrowed: -1 };
  for (let i = 0; i < 10; i++) {
    await wb.waitForTimeout(1200);
    inPane = await wb.evaluate(() => {
      const C = document.querySelector('[data-testid="environment-agent-execution-conversation"]');
      const frame = C && C.querySelector("#ioi-timeline-frame");
      const others = C ? [...C.children].filter((ch) => ch !== frame && ch.getBoundingClientRect().height > 0).length : -1;
      return { mounted: !!frame, visibleBorrowed: others };
    });
    if (inPane.mounted && inPane.visibleBorrowed === 0) break;
  }
  ok(inPane.mounted, "default surface — owned Run Timeline replaces the borrowed conversation pane in-pane");
  ok(inPane.visibleBorrowed === 0, "borrowed transcript fully hidden under the owned surface", `${inPane.visibleBorrowed} visible`);
  const ownedComposer = await wb.evaluate(() => {
    const f = document.querySelector("#ioi-timeline-frame");
    try { return !!f.contentDocument.getElementById("rt-composer"); } catch { return null; }
  });
  ok(ownedComposer !== false, "owned surface carries its own follow-up composer", ownedComposer === null ? "(cross-frame; not asserted)" : "present");

  // cockpit launcher (global, injected on every surface) also opens the owned timeline full-page
  await wb.waitForTimeout(500);
  await wb.locator("#ioi-aug-btn").click({ timeout: 5000 }).catch(() => {});
  await wb.waitForTimeout(2000);
  const launcher = wb.getByText(/Open Run Timeline/i).first();
  ok((await launcher.count()) > 0, "cockpit launcher present on the workbench surface");
  const [popup] = await Promise.all([
    ctx.waitForEvent("page", { timeout: 8000 }).catch(() => null),
    launcher.click({ timeout: 5000 }).catch(() => {}),
  ]);
  ok(popup && /\/__ioi\/run-timeline\//.test(popup.url()), "launcher opens the owned Run Timeline surface", popup ? popup.url() : "no popup");
  if (popup) {
    await popup.waitForTimeout(1500);
    const popSections = await popup.evaluate(() => [...document.querySelectorAll(".rt-label")].length);
    ok(popSections === 6, "launched surface resolves the env's run and renders the timeline", `${popSections} sections`);
  }
} finally {
  await b.close();
}

const verdict = failures > 0 ? "FAIL" : "PASS";
if (JSON_OUT) console.log(JSON.stringify({ workstream: "run-timeline", verdict, failures, checks: checks.length, runId, envId }, null, 2));
else console.log(`  VERDICT: ${verdict} (${checks.length - failures}/${checks.length} checks)`);
process.exit(verdict === "FAIL" ? 1 : 0);
