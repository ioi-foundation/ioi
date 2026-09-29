#!/usr/bin/env node
// Memory graph + projection explainability done-bar.
//
// Proves the vault is an inspectable graph (derived-only, no new store) and every projection
// is explainable from vault truth to harness prompt: mixed-sensitivity fixture vault → one
// session's projections for two harnesses → same MemorySpace, DIVERGENT per-harness decisions →
// explanations reveal reason codes + refs + receipts but never private/secret bodies →
// graph carries the expected node/edge kinds → Work Ledger links to explain.
//
// RE-TYPED 2026-09-29 (R-240, GoalRun residue). The per-harness projections came from a REAL IOI
// Agent Compare launch that minted a GoalRun, read back by `goal_run_ref`, and the goal-run Run
// Timeline linked them to explain. R-192 (S5-1) took goal pursuit out of the Hypervisor — a goal run
// is an ioi.ai composition over the thread orchestration primitives (standing owner ruling
// 2026-09-24) — so that lane and its timeline are gone. The projections are now created for a
// SESSION (the Hypervisor's own work subject) through the projection lane an invocation references,
// read back by `session_ref`; the retired timeline's link clause is dropped (the Work Ledger and the
// Memory tab's explain panel below carry the same backlink).
//
// FIXTURES THROUGH THE PROPOSAL LANE (R-240, verifier hazard sweep 2, 2026-09-29). Memory entries are
// proposal-only since XXXII (M13.7): the direct POST/PATCH answer 409 memory_entry_direct_mutation_refused, so
// the mixed vault was never written and the Memory tab's node search waited on a node that did not exist
// (a crash). Each entry is now proposed and approved by the operator (lib/memory-proposal-lane.mjs); the
// archived one is an archive proposal, the revoked one a supersede naming its status.
//
// Usage: node apps/hypervisor/scripts/verify-hypervisor-memory-graph-explainability.mjs (≈1 min)
// Its own isolated daemon + serve, the operator signed in (lib/verifier-stack.mjs); an explicit
// URL naming the owner's stack (:8765, :36173, :4173) is refused.

import { chromium } from "playwright";
import { liveConnectorFixture, memoryProposalLane } from "./lib/memory-proposal-lane.mjs";
import { verifierStack } from "./lib/verifier-stack.mjs";

const STACK = await verifierStack({ serve: true });
const DAEMON = STACK.daemonUrl;
const SHELL = STACK.serveUrl;

const results = [];
const ok = (name, cond, detail) => { results.push({ name, pass: !!cond, detail: detail || "" }); };
// Every request carries the stack operator's session (verifier-stack).
async function jd(method, url, body) {
  const r = await fetch(url.startsWith("http") ? url : `${DAEMON}${url}`, {
    method,
    headers: { "content-type": "application/json" },
    body: body ? JSON.stringify(body) : undefined,
  }).catch(() => null);
  const text = r ? await r.text().catch(() => "") : "";
  let j = {}; try { j = JSON.parse(text); } catch { j = {}; }
  return { status: r?.status ?? 0, j };
}

async function run() {
  const tag = Date.now().toString(16);
  const privBody = `graphpriv-${tag}`;
  const secretBody = `graphsecret-${tag}`;

  // ── Mixed vault fixture ──
  const lane = memoryProposalLane(jd, { reason: `memory graph fixture ${tag}` });
  const mk = async (body) => (await lane.create(body)).record || {};
  // A lease-ready connector the connector_derived entry names — on a fresh stack an open one registered through the
  // product's own route (lib/memory-proposal-lane.mjs), so the connector-derived clauses run instead of skipping.
  const liveConn = await liveConnectorFixture(jd, `graph-${tag}`);
  const pub = await mk({ title: `g-pub-${tag}`, entry_kind: "concept", body: "public concept", tags: [`gtag-${tag}`], source_refs: [`hpo_gsrc_${tag}`] });
  const priv = await mk({ title: `g-priv-${tag}`, entry_kind: "fact", body: privBody, sensitivity: "private" });
  const secret = await mk({ title: `g-secret-${tag}`, entry_kind: "note", body: secretBody, sensitivity: "secret" });
  const dsOnly = await mk({ title: `g-ds-${tag}`, entry_kind: "tool_affordance", body: "ds only", compatible_harness_refs: ["harness-profile:hp_deepseek_tui"] });
  const routeOnly = await mk({ title: `g-route-${tag}`, entry_kind: "note", body: "other route only", compatible_model_route_refs: ["model-route:mrt_other"] });
  const expired = await mk({ title: `g-exp-${tag}`, entry_kind: "note", body: "old", expires_at: "2020-01-01T00:00:00Z" });
  const archived = await mk({ title: `g-arch-${tag}`, entry_kind: "note", body: "arch" });
  await lane.archive(archived);
  const revoked = await mk({ title: `g-rev-${tag}`, entry_kind: "note", body: "rev" });
  await lane.supersede(revoked, { status: "revoked" });
  const connEntry = liveConn ? await mk({ title: `g-conn-${tag}`, entry_kind: "connector_derived", body: "derived", connector_refs: [`connector://${liveConn.connector_id}`] }) : null;
  const skill = (await jd("POST", "/v1/hypervisor/skill-entries", { title: `g-skill-${tag}`, description: "graph skill" })).j?.record;
  const affinity = (await jd("POST", "/v1/hypervisor/automation-affinities", { title: `g-aff-${tag}`, goal_pattern: `graphtoken-${tag}`, preferred_policy_ref: "ioi-agent-policy://pol_fast_local" })).j?.record;

  // ── One session's projections for two harnesses (R-240, 2026-09-29: a REAL IOI Agent Compare
  // launch — a GoalRun over both harnesses — stood here) ──
  const sessionRef = `session://graph-run-${tag}`;
  for (const harness of ["harness-profile:hp_opencode", "harness-profile:hp_deepseek_tui"]) {
    await jd("POST", "/v1/hypervisor/memory-projections", { goal: `graph-run-${tag} explained`, harness_profile_ref: harness, model_route_ref: "model-route:mrt_local_default", session_ref: sessionRef });
  }
  const projections = await jd("GET", `/v1/hypervisor/memory-projections?session_ref=${encodeURIComponent(sessionRef)}`);
  const byHarness = Object.fromEntries((projections.j?.projections || []).map((p) => [p.harness_profile_ref, p]));
  const oc = byHarness["harness-profile:hp_opencode"] || {};
  const ds = byHarness["harness-profile:hp_deepseek_tui"] || {};
  ok("one session's projections for two harnesses share one MemorySpace",
    !!oc.projection_ref && !!ds.projection_ref && oc.memory_space_ref === ds.memory_space_ref && oc.projection_ref !== ds.projection_ref);
  ok("projections DIVERGE on harness-scoped decisions",
    (ds.included_entry_refs || []).includes(dsOnly.entry_ref) && !(oc.included_entry_refs || []).includes(dsOnly.entry_ref));

  // ── Explainability ──
  const explain = async (p) => (await jd("GET", `/v1/hypervisor/intelligence/projections/${p.projection_id}/explain`)).j || {};
  const ocx = await explain(oc);
  const dsx = await explain(ds);
  const decOf = (x, ref) => [...(x.decisions?.included || []), ...(x.decisions?.redacted || []), ...(x.decisions?.excluded || [])].find((d) => d.ref === ref);
  ok("explain covers every candidate with a decision + reason/checks",
    decOf(ocx, pub.entry_ref)?.decision === "included"
    && decOf(ocx, priv.entry_ref)?.reason_code === "sensitivity_private_policy_disallows"
    && decOf(ocx, secret.entry_ref)?.reason_code === "sensitivity_secret_always_redacted"
    && decOf(ocx, dsOnly.entry_ref)?.reason_code === "incompatible_harness"
    && decOf(ocx, routeOnly.entry_ref)?.reason_code === "incompatible_model_route"
    && decOf(ocx, expired.entry_ref)?.reason_code === "expired"
    && decOf(ocx, archived.entry_ref)?.reason_code === "archived"
    && decOf(ocx, revoked.entry_ref)?.reason_code === "revoked");
  ok("explanations for the two harnesses differ where compatibility differs",
    decOf(dsx, dsOnly.entry_ref)?.decision === "included" && decOf(ocx, dsOnly.entry_ref)?.decision === "excluded");
  ok("explain carries context refs + receipts (deterministic, receipt-linked)",
    ocx.context?.session_ref === sessionRef && ocx.deterministic === true
    && String((ocx.receipt_refs || [])[0] || "").startsWith("receipt://hypervisor/memory-projection/"));
  const blob = JSON.stringify(ocx) + JSON.stringify(dsx);
  ok("explanations never expose private/secret bodies", !blob.includes(privBody) && !blob.includes(secretBody));
  ok("included decisions carry source/compatibility metadata (refs only)",
    (decOf(ocx, pub.entry_ref)?.meta?.source_refs || []).includes(`hpo_gsrc_${tag}`)
    && (decOf(ocx, pub.entry_ref)?.checks || []).some((c) => c.check === "harness_compatible" && c.pass));

  // ── Graph (derived-only) ──
  const graph = (await jd("GET", `/v1/hypervisor/intelligence/graph?q=${tag}`)).j || {};
  const nodeIds = new Set((graph.nodes || []).map((n) => n.id));
  const edge = (from, to, kind) => (graph.edges || []).some((e) => e.from === from && e.to === to && e.edge_kind === kind);
  ok("graph is a derived-only projection", graph.derived_only === true && graph.counts?.nodes >= 5);
  ok("graph carries the expected node kinds",
    nodeIds.has(pub.entry_ref) && nodeIds.has(skill.skill_ref) && nodeIds.has(affinity.affinity_ref)
    && nodeIds.has(`hpo_gsrc_${tag}`) && nodeIds.has(`tag://gtag-${tag}`)
    && (!connEntry || nodeIds.has(`connector://${liveConn.connector_id}`)));
  ok("graph carries the expected edge kinds",
    edge(pub.entry_ref, `hpo_gsrc_${tag}`, "cites")
    && edge(pub.entry_ref, `tag://gtag-${tag}`, "tagged")
    && edge(dsOnly.entry_ref, "harness-profile:hp_deepseek_tui", "compatible_with")
    && edge(affinity.affinity_ref, "ioi-agent-policy://pol_fast_local", "affinity_to")
    && (!connEntry || edge(connEntry.entry_ref, `connector://${liveConn.connector_id}`, "derives_from")));
  const fullGraph = (await jd("GET", "/v1/hypervisor/intelligence/graph")).j || {};
  ok("projections + proposals + receipts appear as graph citizens",
    (fullGraph.nodes || []).some((n) => n.node_kind === "memory_projection")
    && (fullGraph.nodes || []).some((n) => n.node_kind === "mutation_proposal")
    && (fullGraph.edges || []).some((e) => e.edge_kind === "projects_to")
    && (fullGraph.edges || []).some((e) => e.edge_kind === "approved_by"));
  ok("graph text never contains private/secret bodies",
    !JSON.stringify(fullGraph).includes(privBody) && !JSON.stringify(fullGraph).includes(secretBody));

  // ── Proof-surface links ──
  // R-240 (2026-09-29): "Run Timeline links projections to their explain view" read the retired
  // goal-run timeline page; the ledger row and the Memory tab's explain panel carry the backlink.
  const wl = await fetch(`${SHELL}/__ioi/work-ledger`).then((r) => r.text());
  ok("Work Ledger memory_projection rows can reach explain (backlink lane present)", /Projection explain/.test(wl) || wl.includes("intelligence/projections"));
  const explainPage = await fetch(`${SHELL}/__ioi/intelligence/projections/${oc.projection_id}/explain`).then((r) => r.text());
  ok("explain page renders decisions without private bodies",
    /Projection explain/.test(explainPage) && /Redacted/.test(explainPage) && !explainPage.includes(privBody) && !explainPage.includes(secretBody));

  // ── Agent Studio UI ──
  // The Studio's tabbed editor renders for a SELECTED agent; a fresh stack holds none (the owner's daemon always did),
  // so one is recorded through the runtime's own agent route before the page is read (R-240, hazard sweep 2).
  const agentsNow = (await jd("GET", "/v1/agents")).j;
  if (!(Array.isArray(agentsNow) && agentsNow.length)) await jd("POST", "/v1/agents", { options: {} });
  const browser = await chromium.launch();
  const page = await browser.newPage({ viewport: { width: 1600, height: 1000 } });
  await STACK.signIn(page);
  const consoleErrors = [];
  page.on("pageerror", (e) => consoleErrors.push(String(e)));
  await page.goto(`${SHELL}/__ioi/agent-studio#memory`, { waitUntil: "networkidle" });
  await page.waitForSelector("#memory-graph", { timeout: 15000 });
  await page.waitForFunction(() => /nodes ·/.test(document.getElementById("graph-nodes")?.textContent || ""), null, { timeout: 15000 });
  await page.fill("#graph-search", `g-pub-${tag}`);
  // Wait for the FILTERED render (small node count), not just the needle (which can pre-exist
  // in the unfiltered list) — then select the fixture node itself.
  await page.waitForFunction(() => {
    const box = document.getElementById("graph-nodes");
    return box && box.querySelectorAll(".memnode").length > 0 && box.querySelectorAll(".memnode").length < 20;
  }, null, { timeout: 15000 });
  await page.locator(".memnode", { hasText: `g-pub-${tag}` }).first().click();
  await page.waitForFunction(() => /Edges out/i.test(document.getElementById("graph-detail")?.textContent || ""), null, { timeout: 10000 });
  const detail = await page.locator("#graph-detail").innerText();
  ok("Memory tab graph is useful (search → node → edge list detail)", /Edges out/i.test(detail) && /cites|tagged/i.test(detail));
  ok("Memory tab renders the Projection explain panel", (await page.locator("#projection-explain").count()) === 1 && (await page.locator('a[href*="/explain"]').count()) >= 1);
  const tabs = await page.locator("#astabs .tab").allTextContents();
  ok("tab set unchanged (no Automations/Workflows child tabs)", tabs.length === 8 && !tabs.some((t) => /automations|workflows/i.test(t)));
  ok("no console errors", consoleErrors.length === 0, consoleErrors.slice(0, 2).join(" | "));
  await browser.close();

  // ── Hygiene + restore ──
  const ft = await fetch(`${SHELL}/__ioi/fallthrough`).then((r) => r.json()).catch(() => ({}));
  ok("fallthrough stays empty", Array.isArray(ft.proxied) && ft.proxied.length === 0);
  for (const e of [pub, priv, secret, dsOnly, routeOnly, expired, connEntry].filter(Boolean)) {
    await lane.archive(e);
  }
  await jd("PATCH", `/v1/hypervisor/skill-entries/${skill.skill_id}`, { status: "archived" });
  await jd("PATCH", `/v1/hypervisor/automation-affinities/${affinity.affinity_id}`, { status: "archived" });
  // R-240 (2026-09-29): the drivers were enabled only to run the retired launch; nothing to restore.
  const skillAfter = (await jd("GET", `/v1/hypervisor/skill-entries/${skill?.skill_id}`)).j?.record || {};
  const affAfter = (await jd("GET", `/v1/hypervisor/automation-affinities/${affinity?.affinity_id}`)).j?.record || {};
  ok("fixtures archived", skillAfter.status === "archived" && affAfter.status === "archived", `${skillAfter.status}/${affAfter.status}`);
}

run().then(() => {
  let fail = 0;
  for (const r of results) { console.log(`  ${r.pass ? "PASS" : "FAIL"}  ${r.name}${r.detail ? `  (${r.detail})` : ""}`); if (!r.pass) fail++; }
  console.log(`\n${results.length - fail}/${results.length} passed`);
  console.log(`memory graph + explainability readiness: ${fail ? "FAIL" : "OK"}`);
  process.exit(fail ? 1 : 0);
}).catch((e) => {
  console.error("verifier crashed:", e);
  process.exit(1);
});
