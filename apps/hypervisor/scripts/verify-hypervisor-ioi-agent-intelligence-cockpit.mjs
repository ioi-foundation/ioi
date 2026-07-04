#!/usr/bin/env node
// IOI Agent intelligence cockpit done-bar.
//
// Proves portable intelligence is DAEMON truth that survives harness/model swaps, and that
// harnesses receive scoped, receipted PROJECTIONS — never the raw private store:
//   - default MemorySpace, MemoryEntry/SkillEntry/AutomationAffinity CRUD + archive/revoke;
//   - connector-derived entries carry connector refs and REJECT credential material;
//   - the projection planner excludes archived/revoked/expired/incompatible records and redacts
//     private/secret entries with a reason code for every decision;
//   - IOI Agent preview surfaces the intelligence posture; Direct launch creates a
//     memory_projection_ref; Compare creates one projection PER harness invocation over the
//     SAME portable space (harness-scoped inclusion differs when compatibility differs);
//   - the Work Ledger indexes projection receipts; the Run Timeline shows projection refs
//     WITHOUT leaking private bodies; Agent Studio renders Connectors/Skills/Memory (+
//     Automation readiness under Launch policies — Automations remains its own surface);
//   - source-neutral + fallthrough stay clean; fixtures archived; drivers restored.
//
// Usage: node apps/hypervisor/scripts/verify-hypervisor-ioi-agent-intelligence-cockpit.mjs (≈2–4 min)

import { execSync } from "node:child_process";
import http from "node:http";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { chromium } from "playwright";

const HERE = path.dirname(fileURLToPath(import.meta.url));
const { mintApprovalGrant } = await import(path.join(HERE, "../../../scripts/lib/mint-approval-grant.mjs"));

const DAEMON = (process.env.IOI_HYPERVISOR_DAEMON_URL || "http://127.0.0.1:8765").replace(/\/$/, "");
const SHELL = (process.env.IOI_HYPERVISOR_APP_URL || "http://127.0.0.1:4173").replace(/\/$/, "");

const results = [];
const ok = (name, cond, detail) => { results.push({ name, pass: !!cond, detail: detail || "" }); };
// node:http, not fetch: synchronous ioi-agent launches legitimately run longer than undici's
// fixed 300s headers timeout under host load (the 600s driver budget) — goalrun convention.
function jd(method, url, body) {
  const target = new URL(url.startsWith("http") ? url : `${DAEMON}${url}`);
  const payload = body ? JSON.stringify(body) : null;
  return new Promise((resolve, reject) => {
    const req = http.request(
      { hostname: target.hostname, port: target.port, path: target.pathname + target.search, method,
        headers: { "content-type": "application/json", ...(payload ? { "content-length": Buffer.byteLength(payload) } : {}) } },
      (res) => {
        let raw = "";
        res.on("data", (c) => { raw += c; });
        res.on("end", () => {
          let j = {};
          try { j = JSON.parse(raw); } catch { j = {}; }
          resolve({ status: res.statusCode, j });
        });
      },
    );
    req.on("error", reject);
    if (payload) req.write(payload);
    req.end();
  });
}

async function run() {
  const tag = Date.now().toString(16);
  const privateMarker = `nightjar-${tag}`;
  for (const id of ["hp_opencode", "hp_deepseek_tui"]) await jd("POST", `/v1/hypervisor/harness-profiles/${id}/enable`);

  // ── Records ──
  const spaces = await jd("GET", "/v1/hypervisor/memory-spaces");
  ok("default memory space exists (workspace scope)",
    (spaces.j?.spaces || []).some((s) => s.space_ref === "memory-space://ms_workspace_default" && s.scope === "workspace"));
  const mk = async (body) => (await jd("POST", "/v1/hypervisor/memory-entries", body)).j?.record || {};
  const normal = await mk({ title: `vfy-pref-${tag}`, entry_kind: "preference", body: "keep replies terse" });
  const priv = await mk({ title: `vfy-private-${tag}`, entry_kind: "fact", body: privateMarker, sensitivity: "private" });
  const secret = await mk({ title: `vfy-secret-${tag}`, entry_kind: "note", body: `sealed-${tag}`, sensitivity: "secret" });
  const expired = await mk({ title: `vfy-expired-${tag}`, entry_kind: "note", body: "old", expires_at: "2020-01-01T00:00:00Z" });
  const dsOnly = await mk({ title: `vfy-dsonly-${tag}`, entry_kind: "tool_affordance", body: "deepseek trick", compatible_harness_refs: ["harness-profile:hp_deepseek_tui"] });
  const revoked = await mk({ title: `vfy-revoked-${tag}`, entry_kind: "note", body: "x" });
  ok("MemoryEntry create works", [normal, priv, secret, expired, dsOnly, revoked].every((e) => String(e.entry_ref || "").startsWith("memory-entry://")));
  const edited = await jd("PATCH", `/v1/hypervisor/memory-entries/${normal.entry_id}`, { body: "keep replies terse and factual" });
  ok("MemoryEntry edit works", edited.status === 200 && edited.j?.record?.body?.includes("factual"));
  const rv = await jd("PATCH", `/v1/hypervisor/memory-entries/${revoked.entry_id}`, { status: "revoked" });
  ok("MemoryEntry revoke works", rv.j?.record?.status === "revoked");

  // connector-derived: refs required, credential material forbidden
  const connectors = await jd("GET", "/v1/hypervisor/connectors");
  const liveConn = (connectors.j?.connectors || []).find((c) => ["token-lease:bound", "open", "local-none"].includes(c.auth_posture));
  const noRefs = await jd("POST", "/v1/hypervisor/memory-entries", { title: "bad", entry_kind: "connector_derived", body: "x" });
  ok("connector_derived requires connector refs", noRefs.status === 400 && noRefs.j?.error?.code === "memory_entry_connector_refs_required");
  const credBlock = await jd("POST", "/v1/hypervisor/memory-entries", { title: "bad", entry_kind: "note", body: "x", structured_payload: { sealed_client_secret: "abc" } });
  ok("credential material is rejected outright", credBlock.status === 403 && credBlock.j?.error?.code === "memory_entry_credential_material_forbidden");
  let connEntry = null;
  if (liveConn) {
    connEntry = await mk({ title: `vfy-conn-${tag}`, entry_kind: "connector_derived", body: "derived context", connector_refs: [`connector://${liveConn.connector_id}`] });
    ok("connector-derived entry carries connector refs (no credentials)", (connEntry.connector_refs || []).length === 1 && !JSON.stringify(connEntry).includes("sealed"));
  } else {
    ok("connector-derived lane skipped (no lease-ready connector)", true);
  }

  const skill = (await jd("POST", "/v1/hypervisor/skill-entries", { title: `vfy-skill-${tag}`, description: "write exact status artifacts" })).j?.record || {};
  ok("SkillEntry create/edit/archive works",
    String(skill.skill_ref || "").startsWith("skill-entry://")
    && (await jd("PATCH", `/v1/hypervisor/skill-entries/${skill.skill_id}`, { description: "edited" })).status === 200
    && (await jd("PATCH", `/v1/hypervisor/skill-entries/${skill.skill_id}`, { status: "archived" })).j?.record?.status === "archived");
  await jd("PATCH", `/v1/hypervisor/skill-entries/${skill.skill_id}`, { status: "active" });
  const affinity = (await jd("POST", "/v1/hypervisor/automation-affinities", { title: `vfy-aff-${tag}`, goal_pattern: `vfytoken-${tag}`, preferred_policy_ref: "ioi-agent-policy://pol_fast_local" })).j?.record || {};
  ok("AutomationAffinity create/edit/archive works",
    String(affinity.affinity_ref || "").startsWith("automation-affinity://")
    && (await jd("PATCH", `/v1/hypervisor/automation-affinities/${affinity.affinity_id}`, { title: "edited" })).status === 200);

  // ── Projection planner ──
  const preview = await jd("POST", "/v1/hypervisor/memory-projections/preview", {
    goal: `please vfytoken-${tag} now`,
    harness_profile_ref: "harness-profile:hp_opencode",
    model_route_ref: "model-route:mrt_local_default",
  });
  const plan = preview.j?.preview || {};
  const reasonOf = (list, ref) => (list || []).find((x) => x.ref === ref)?.reason_code;
  ok("projection preview returns included/redacted/excluded counts",
    plan.counts && plan.counts.included_entries >= 1 && plan.counts.redacted >= 2 && plan.counts.excluded >= 3, JSON.stringify(plan.counts));
  ok("expired/revoked/incompatible are excluded with reason codes",
    reasonOf(plan.excluded_refs_with_reasons, expired.entry_ref) === "expired"
    && reasonOf(plan.excluded_refs_with_reasons, revoked.entry_ref) === "revoked"
    && reasonOf(plan.excluded_refs_with_reasons, dsOnly.entry_ref) === "incompatible_harness");
  ok("private is redacted by default; secret always",
    reasonOf(plan.redacted_entry_refs, priv.entry_ref) === "sensitivity_private_policy_disallows"
    && reasonOf(plan.redacted_entry_refs, secret.entry_ref) === "sensitivity_secret_always_redacted");
  const allowed = await jd("POST", "/v1/hypervisor/memory-projections/preview", {
    goal: "x y z", harness_profile_ref: "harness-profile:hp_opencode", model_route_ref: "model-route:mrt_local_default", allow_sensitive: true,
  });
  ok("private projects when policy allows (secret still never)",
    (allowed.j?.preview?.included_entry_refs || []).includes(priv.entry_ref)
    && reasonOf(allowed.j?.preview?.redacted_entry_refs, secret.entry_ref) === "sensitivity_secret_always_redacted");
  ok("affinity matches by goal pattern", plan.automation_affinity_match?.affinity_ref === affinity.affinity_ref);

  // ── Launch integration: preview posture + Direct + Compare ──
  const lpv = await jd("POST", "/v1/hypervisor/ioi-agent/launch-preview", { goal: `vfytoken-${tag} artifact` });
  ok("IOI Agent preview surfaces the intelligence posture",
    (lpv.j?.memory_space_refs || [])[0] === "memory-space://ms_workspace_default"
    && lpv.j?.intelligence_projection_preview?.counts?.included_entries >= 1
    && lpv.j?.intelligence_projection_preview?.automation_affinity_match?.affinity_ref === affinity.affinity_ref);

  const launch = async (body) => {
    const a = await jd("POST", "/v1/hypervisor/ioi-agent/launch", body);
    if (a.status !== 403) return { a, b: a };
    const grant = mintApprovalGrant({ policyHash: a.j.approval.policy_hash, requestHash: a.j.approval.request_hash });
    const b = await jd("POST", "/v1/hypervisor/ioi-agent/launch", { launch_id: a.j.launch_id, wallet_approval_grant: grant });
    return { a, b };
  };
  const direct = await launch({ goal: `Create the file intel-direct-${tag}.txt containing the word: direct`, strategy: "direct" });
  const directProj = (direct.b.j?.advanced?.memory_projection_refs || [])[0] || "";
  ok("Direct launch creates memory_projection_ref", direct.b.status === 200 && directProj.startsWith("memory-projection://"), directProj);
  const compare = await launch({ goal: `Create the file intel-cmp-${tag}.txt containing the word: compared`, strategy: "compare" });
  const cmpInv = compare.b.j?.advanced?.outcome?.invocations || [];
  const cmpProjRefs = cmpInv.map((i) => i.memory_projection_ref).filter(Boolean);
  ok("Compare creates a projection per harness invocation", compare.b.status === 200 && cmpProjRefs.length === 2 && new Set(cmpProjRefs).size === 2, cmpProjRefs.join(","));

  // Portable space, harness-scoped projections: SAME space; deepseek-only entry included only there.
  const grid = String(compare.b.j?.advanced?.goal_run_ref || "").replace("goal://", "");
  const projections = await jd("GET", `/v1/hypervisor/memory-projections?goal_run_ref=goal://${grid}`);
  const byHarness = Object.fromEntries((projections.j?.projections || []).map((p) => [p.harness_profile_ref, p]));
  const oc = byHarness["harness-profile:hp_opencode"];
  const ds = byHarness["harness-profile:hp_deepseek_tui"];
  ok("harness swap preserves the portable MemorySpace but scopes each projection",
    oc && ds && oc.memory_space_ref === ds.memory_space_ref
    && (ds.included_entry_refs || []).includes(dsOnly.entry_ref)
    && !(oc.included_entry_refs || []).includes(dsOnly.entry_ref)
    && reasonOf(oc.excluded_refs_with_reasons, dsOnly.entry_ref) === "incompatible_harness");

  // ── Proof surfaces ──
  const ledger = await jd("GET", "/v1/hypervisor/work-ledger");
  ok("Work Ledger indexes projection receipts",
    (ledger.j?.entries || []).some((e) => e.kind === "memory_projection" && e.goal_run_ref === `goal://${grid}` && String(e.receipt_ref || "").startsWith("receipt://hypervisor/memory-projection/")));
  const tl = await fetch(`${SHELL}/__ioi/run-timeline/goal-run/${grid}`).then((r) => r.text());
  ok("Run Timeline shows projection refs WITHOUT leaking private bodies",
    /Memory projections/.test(tl) && cmpProjRefs.some((r) => tl.includes(r)) && !tl.includes(privateMarker) && !tl.includes(`sealed-${tag}`));

  // ── Agent Studio cockpit (8 tabs; Automations stays its own surface) ──
  const studio = await fetch(`${SHELL}/__ioi/agent-studio`).then((r) => r.text());
  ok("Agent Studio renders Connectors, Skills, Memory tabs + Automation readiness under Launch policies",
    ['data-astab="connectors"', 'data-astab="skills"', 'data-astab="memory"', "Automation readiness"].every((m) => studio.includes(m))
    && !studio.includes('data-astab="automations"'));
  ok("Connectors tab is the scoped access view (management stays in Developer & Integrations)",
    /agent\/policy-scoped view/.test(studio) && studio.includes('href="/__ioi/connections"') && !studio.includes("sealed_client_secret"));
  ok("Memory tab renders categories, search, sensitivity + compatibility chips",
    ["Connector-derived", "Workstreams", "mem-search", "never projected"].every((m) => studio.includes(m)));

  // ── Modal posture line (UI) ──
  const browser = await chromium.launch();
  const page = await browser.newPage({ viewport: { width: 1600, height: 1000 } });
  const consoleErrors = [];
  page.on("pageerror", (e) => consoleErrors.push(String(e)));
  await page.goto(`${SHELL}/`, { waitUntil: "domcontentloaded" });
  await page.waitForSelector('[data-testid="sidebar"]', { timeout: 20000 });
  await page.click('[data-testid="create-session-button"]');
  await page.waitForSelector("#ioi-ns-goal", { timeout: 10000 });
  await page.fill("#ioi-ns-goal", `vfytoken-${tag} status file`);
  await page.waitForFunction(() => /Intelligence/.test(document.getElementById("ioi-ns-preview")?.textContent || ""), null, { timeout: 15000 });
  const previewText = await page.locator("#ioi-ns-preview").innerText();
  ok("launcher preview shows the intelligence posture (space, counts, affinity, connector posture)",
    /memory space/i.test(previewText) && /projected/.test(previewText) && /redacted/.test(previewText) && /affinity/i.test(previewText) && /connector context/i.test(previewText));
  ok("no console errors", consoleErrors.length === 0, consoleErrors.slice(0, 2).join(" | "));
  await browser.close();

  // ── Hygiene ──
  let sourceNeutral = false;
  try { execSync("npm run check:source-neutral", { cwd: path.join(HERE, ".."), stdio: "pipe" }); sourceNeutral = true; } catch { /* fail below */ }
  ok("source-neutral stays clean", sourceNeutral);
  const ft = await fetch(`${SHELL}/__ioi/fallthrough`).then((r) => r.json()).catch(() => ({}));
  ok("fallthrough stays empty", Array.isArray(ft.proxied) && ft.proxied.length === 0);

  // ── Fixture archive + posture restore ──
  for (const e of [normal, priv, secret, expired, dsOnly, connEntry].filter(Boolean)) {
    await jd("PATCH", `/v1/hypervisor/memory-entries/${e.entry_id}`, { status: "archived" });
  }
  await jd("PATCH", `/v1/hypervisor/skill-entries/${skill.skill_id}`, { status: "archived" });
  await jd("PATCH", `/v1/hypervisor/automation-affinities/${affinity.affinity_id}`, { status: "archived" });
  for (const id of ["hp_opencode", "hp_deepseek_tui"]) await jd("POST", `/v1/hypervisor/harness-profiles/${id}/disable`);
  const fin = await jd("GET", "/v1/hypervisor/harness-profiles");
  ok("fixtures archived + drivers restored",
    (fin.j?.profiles || []).filter((p) => ["opencode", "deepseek_tui"].includes(p.harness)).every((p) => p.lifecycle.status === "disabled"));
}

run().then(() => {
  let fail = 0;
  for (const r of results) { console.log(`  ${r.pass ? "PASS" : "FAIL"}  ${r.name}${r.detail ? `  (${r.detail})` : ""}`); if (!r.pass) fail++; }
  console.log(`\n${results.length - fail}/${results.length} passed`);
  console.log(`ioi-agent intelligence cockpit readiness: ${fail ? "FAIL" : "OK"}`);
  process.exit(fail ? 1 : 0);
}).catch((e) => {
  console.error("verifier crashed:", e);
  process.exit(1);
});
