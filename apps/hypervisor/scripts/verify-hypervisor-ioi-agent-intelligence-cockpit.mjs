#!/usr/bin/env node
// IOI Agent intelligence cockpit done-bar.
//
// Proves portable intelligence is DAEMON truth that survives harness/model swaps, and that
// harnesses receive scoped, receipted PROJECTIONS — never the raw private store:
//   - default MemorySpace, MemoryEntry/SkillEntry/AutomationAffinity CRUD + archive/revoke;
//   - connector-derived entries carry connector refs and REJECT credential material;
//   - the projection planner excludes archived/revoked/expired/incompatible records and redacts
//     private/secret entries with a reason code for every decision;
//   - a session's projections are receipted records, one PER harness over the SAME portable
//     space (harness-scoped inclusion differs when compatibility differs);
//   - the Work Ledger indexes projection receipts; the projection records carry refs WITHOUT
//     leaking private bodies; Agent Studio renders Connectors/Skills/Memory (+ Automation
//     readiness under Launch policies — Automations remains its own surface);
//   - source-neutral + fallthrough stay clean; fixtures archived.
//
// RE-TYPED 2026-09-29 (R-240, GoalRun residue). The projections used to come from a REAL IOI Agent
// Direct launch and a Compare launch that minted a GoalRun with one invocation per harness, read
// back by `goal_run_ref` and on the goal-run timeline; the IOI Agent preview and the launcher's
// posture line surfaced the intelligence posture. R-192 (S5-1) took goal pursuit out of the
// Hypervisor — a goal run is an ioi.ai composition over the thread orchestration primitives
// (standing owner ruling 2026-09-24) — so that lane, its preview and its timeline are gone and the
// verifier crashed. The projections are now created for a SESSION (the Hypervisor's own work
// subject) through the projection lane an invocation references, read back by `session_ref`; the
// preview/launcher posture clauses are dropped (the projection preview above is the daemon truth
// they relayed), and the timeline's no-leak claim is asserted on the projection records themselves.
//
// Usage: node apps/hypervisor/scripts/verify-hypervisor-ioi-agent-intelligence-cockpit.mjs (≈1 min)
// Its own isolated daemon + serve, the operator signed in (lib/verifier-stack.mjs); an explicit
// URL naming the owner's stack (:8765, :36173, :4173) is refused.

import { execSync } from "node:child_process";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { verifierStack } from "./lib/verifier-stack.mjs";

const HERE = path.dirname(fileURLToPath(import.meta.url));
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
  const privateMarker = `nightjar-${tag}`;
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

  // ── A session's projections: receipted, one per harness, over one portable space ──
  // R-240 (2026-09-29): an IOI Agent preview-posture clause and a Direct + Compare launch stood
  // here; the lane is retired. The projection lane they called is the daemon's own, so it is driven
  // directly for a session — the Hypervisor's work subject — rather than for a goal run.
  const sessionRef = `session://vfy-intel-${tag}`;
  const project = async (harness) => (await jd("POST", "/v1/hypervisor/memory-projections", {
    goal: `vfytoken-${tag} status artifact`, harness_profile_ref: harness, model_route_ref: "model-route:mrt_local_default", session_ref: sessionRef,
  })).j?.projection || {};
  const ocMade = await project("harness-profile:hp_opencode");
  ok("a session projection is a receipted record (the ref an invocation carries)",
    String(ocMade.projection_ref || "").startsWith("memory-projection://")
    && String((ocMade.receipt_refs || [])[0] || "").startsWith("receipt://hypervisor/memory-projection/"), ocMade.projection_ref);
  const dsMade = await project("harness-profile:hp_deepseek_tui");
  ok("a second harness gets its own projection for the same session", !!dsMade.projection_ref && dsMade.projection_ref !== ocMade.projection_ref, dsMade.projection_ref);

  // Portable space, harness-scoped projections: SAME space; deepseek-only entry included only there.
  const projections = await jd("GET", `/v1/hypervisor/memory-projections?session_ref=${encodeURIComponent(sessionRef)}`);
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
    (ledger.j?.entries || []).some((e) => e.kind === "memory_projection" && e.session_ref === sessionRef && String(e.receipt_ref || "").startsWith("receipt://hypervisor/memory-projection/")));
  // R-240 (2026-09-29): read on the goal-run Run Timeline until that page retired; the records are the proof.
  const records = [];
  for (const p of [ocMade, dsMade]) records.push(JSON.stringify((await jd("GET", `/v1/hypervisor/memory-projections/${p.projection_id}`)).j || {}));
  ok("projection records carry refs WITHOUT leaking private bodies",
    records.length === 2 && records.every((r) => r.includes("memory-projection://") && !r.includes(privateMarker) && !r.includes(`sealed-${tag}`)));

  // ── Agent Studio cockpit (8 tabs; Automations stays its own surface) ──
  const studio = await fetch(`${SHELL}/__ioi/agent-studio`).then((r) => r.text());
  ok("Agent Studio renders Connectors, Skills, Memory tabs + Automation readiness under Launch policies",
    ['data-astab="connectors"', 'data-astab="skills"', 'data-astab="memory"', "Automation readiness"].every((m) => studio.includes(m))
    && !studio.includes('data-astab="automations"'));
  ok("Connectors tab is the scoped access view (management stays in Developer & Integrations)",
    /agent\/policy-scoped view/.test(studio) && studio.includes('href="/__ioi/connections"') && !studio.includes("sealed_client_secret"));
  ok("Memory tab renders categories, search, sensitivity + compatibility chips",
    ["Connector-derived", "Workstreams", "mem-search", "never projected"].every((m) => studio.includes(m)));

  // R-240 (2026-09-29): the launcher's intelligence posture line (and the console-error check of
  // that browser flow) belonged to the IOI Agent preview; the New Session launcher previews
  // placement, and the posture it showed is the projection preview asserted above.

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
  // R-240 (2026-09-29): the drivers were enabled only to run the retired launches; nothing to restore.
  const skillAfter = (await jd("GET", `/v1/hypervisor/skill-entries/${skill.skill_id}`)).j?.record || {};
  const affAfter = (await jd("GET", `/v1/hypervisor/automation-affinities/${affinity.affinity_id}`)).j?.record || {};
  ok("fixtures archived", skillAfter.status === "archived" && affAfter.status === "archived", `${skillAfter.status}/${affAfter.status}`);
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
