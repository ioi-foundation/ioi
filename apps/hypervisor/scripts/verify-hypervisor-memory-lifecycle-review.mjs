#!/usr/bin/env node
// Memory lifecycle + review done-bar.
//
// Proves memory quality is a governed lifecycle, not a fuzzy feature: quality states
// (candidate/accepted/stale/disputed/superseded) orthogonal to archive/revoke, every
// transition reason-coded + receipted, projections obey lifecycle + policy posture
// (private mode stricter by default, no harness bypass), explanations reveal lifecycle
// decisions, the review queue surfaces deterministic signals only, the Work Ledger links
// lifecycle receipts — and no model/harness silently promotes memory into truth.
//
// Usage: node apps/hypervisor/scripts/verify-hypervisor-memory-lifecycle-review.mjs (≈1–2 min)

import path from "node:path";
import { fileURLToPath } from "node:url";
import { chromium } from "playwright";

const HERE = path.dirname(fileURLToPath(import.meta.url));

const DAEMON = (process.env.IOI_HYPERVISOR_DAEMON_URL || "http://127.0.0.1:8765").replace(/\/$/, "");
const SHELL = (process.env.IOI_HYPERVISOR_APP_URL || "http://127.0.0.1:4173").replace(/\/$/, "");

const results = [];
const ok = (name, cond, detail) => { results.push({ name, pass: !!cond, detail: detail || "" }); };
async function jd(method, url, body) {
  const r = await fetch(url.startsWith("http") ? url : `${DAEMON}${url}`, {
    method, headers: { "content-type": "application/json" }, body: body ? JSON.stringify(body) : undefined,
  });
  return { status: r.status, j: await r.json().catch(() => ({})) };
}

async function run() {
  const tag = Date.now().toString(16);
  const privBody = `lcpriv-${tag}`;
  const mk = async (body) => (await jd("POST", "/v1/hypervisor/memory-entries", body)).j?.record || {};

  // ── Fixture spread across the full lifecycle/sensitivity matrix ──
  const accepted = await mk({ title: `lc-accepted-${tag}`, entry_kind: "fact", body: "operator truth" });
  const candidate = await mk({ title: `lc-candidate-${tag}`, entry_kind: "note", body: "run claim", quality_state: "candidate" });
  const stale = await mk({ title: `lc-stale-${tag}`, entry_kind: "note", body: "aging" });
  const disputed = await mk({ title: `lc-disputed-${tag}`, entry_kind: "note", body: "contested" });
  const oldEntry = await mk({ title: `lc-old-${tag}`, entry_kind: "note", body: "old way" });
  const newEntry = await mk({ title: `lc-new-${tag}`, entry_kind: "note", body: "new way", quality_state: "candidate" });
  const privCand = await mk({ title: `lc-privcand-${tag}`, entry_kind: "fact", body: privBody, sensitivity: "private", quality_state: "candidate" });
  const lowConf = await mk({ title: `lc-lowconf-${tag}`, entry_kind: "note", body: "unsure", confidence: 0.2 });
  const dupA = await mk({ title: `lc-dup-${tag}`, entry_kind: "note", body: "a" });
  const dupB = await mk({ title: `lc-dup-${tag}`, entry_kind: "note", body: "b" });
  ok("operator-authored entries default to accepted; explicit candidate honored",
    (accepted.quality_state === "accepted") && (candidate.quality_state === "candidate"));

  // ── Transitions: receipted, reason-coded, guarded ──
  const trans = (id, body) => jd("POST", `/v1/hypervisor/memory-entries/${id}/lifecycle`, body);
  const noReason = await trans(stale.entry_id, { transition: "mark_stale" });
  ok("transitions require a reason", noReason.status === 422 && noReason.j?.error?.code === "memory_lifecycle_reason_required");
  const staled = await trans(stale.entry_id, { transition: "mark_stale", reason: "aged out" });
  const disputedT = await trans(disputed.entry_id, { transition: "dispute", reason: "contradicted by run evidence" });
  const superT = await trans(oldEntry.entry_id, { transition: "supersede", reason: "replaced", superseded_by_ref: newEntry.entry_ref });
  ok("mark_stale / dispute / supersede transitions write receipts",
    [staled, disputedT, superT].every((t) => t.status === 200 && String(t.j?.receipt_ref || "").startsWith("receipt://hypervisor/memory-lifecycle/")));
  ok("supersession links old and new refs bidirectionally",
    superT.j?.record?.superseded_by_ref === newEntry.entry_ref
    && (await jd("GET", `/v1/hypervisor/memory-entries/${newEntry.entry_id}`)).j?.record?.supersedes_ref === oldEntry.entry_ref);
  const promoted = await trans(newEntry.entry_id, { transition: "promote", reason: "validated" });
  ok("promote candidate→accepted works and appends receipted history",
    promoted.j?.record?.quality_state === "accepted" && (promoted.j?.record?.lifecycle_history || []).length >= 1);
  const badPromote = await trans(accepted.entry_id, { transition: "promote", reason: "x" });
  ok("promote guards its precondition", badPromote.status === 409 && badPromote.j?.error?.code === "memory_lifecycle_promote_invalid");

  // ── No silent promotion: proposal approval yields CANDIDATE ──
  const prop = (await jd("POST", "/v1/hypervisor/memory-mutation-proposals", {
    operation: "add", mutation_type: "fact",
    suggested: { title: `lc-proposed-${tag}`, entry_kind: "fact", body: "model claim" },
    reason: "run learned", source_authority: "worker",
  })).j?.proposal || {};
  const approvedProp = (await jd("POST", `/v1/hypervisor/memory-mutation-proposals/${prop.mutation_id}/approve`)).j?.proposal || {};
  const appliedId = String(approvedProp.applied_ref || "").replace("memory-entry://", "");
  const applied = (await jd("GET", `/v1/hypervisor/memory-entries/${appliedId}`)).j?.record || {};
  ok("approved model claim lands as CANDIDATE, never silently accepted", applied.quality_state === "candidate", applied.quality_state);

  // ── Projections obey lifecycle + policy ──
  const preview = (body) => jd("POST", "/v1/hypervisor/memory-projections/preview", {
    goal: "x y z", harness_profile_ref: "harness-profile:hp_opencode", model_route_ref: "model-route:mrt_local_default", ...body,
  });
  const std = (await preview({})).j?.preview || {};
  const reasonOf = (list, ref) => (list || []).find((x) => x.ref === ref)?.reason_code;
  ok("standard mode: candidate included, superseded/stale/disputed excluded with lifecycle reasons",
    (std.included_entry_refs || []).includes(candidate.entry_ref)
    && reasonOf(std.excluded_refs_with_reasons, oldEntry.entry_ref) === "superseded"
    && reasonOf(std.excluded_refs_with_reasons, stale.entry_ref) === "stale"
    && reasonOf(std.excluded_refs_with_reasons, disputed.entry_ref) === "disputed_excluded_by_policy");
  const priv = (await preview({ privacy_posture: "private_local" })).j?.preview || {};
  ok("private mode is stricter by default: candidates excluded",
    reasonOf(priv.excluded_refs_with_reasons, candidate.entry_ref) === "candidate_excluded_by_policy");
  const widened = (await preview({ memory_posture: { allow_candidate_memory_projection: true, include_disputed_memory: true, max_stale_age: 14 } })).j?.preview || {};
  ok("policy posture widens deterministically (candidate + disputed + recent-stale admitted)",
    (widened.included_entry_refs || []).includes(candidate.entry_ref)
    && (widened.included_entry_refs || []).includes(disputed.entry_ref)
    && (widened.included_entry_refs || []).includes(stale.entry_ref));
  const privAccepted = (await preview({ allow_sensitive: true, memory_posture: { require_accepted_memory_for_private: true } })).j?.preview || {};
  ok("require_accepted_memory_for_private redacts candidate private memory",
    reasonOf(privAccepted.redacted_entry_refs, privCand.entry_ref) === "private_requires_accepted_memory");
  ok("accepted memory leads the rendered summary; candidates are labeled",
    (std.projection_summary || "").indexOf(`lc-accepted-${tag}`) < (std.projection_summary || "").indexOf(`lc-candidate-${tag}`)
    && (std.projection_summary || "").includes("[candidate note]"));

  // ── Explainability reveals lifecycle decisions ──
  const projection = (await jd("POST", "/v1/hypervisor/memory-projections", {
    goal: "x y z", harness_profile_ref: "harness-profile:hp_opencode", model_route_ref: "model-route:mrt_local_default",
  })).j?.projection || {};
  const explain = (await jd("GET", `/v1/hypervisor/intelligence/projections/${projection.projection_id}/explain`)).j || {};
  const dec = (ref) => [...(explain.decisions?.included || []), ...(explain.decisions?.redacted || []), ...(explain.decisions?.excluded || [])].find((d) => d.ref === ref);
  ok("explain shows lifecycle-based decisions with quality metadata",
    dec(oldEntry.entry_ref)?.reason_code === "superseded" && dec(oldEntry.entry_ref)?.meta?.quality_state === "superseded"
    && dec(candidate.entry_ref)?.decision === "included" && dec(candidate.entry_ref)?.meta?.quality_state === "candidate");
  ok("explanations still leak no private bodies", !JSON.stringify(explain).includes(privBody));

  // ── Review queue: deterministic signals ──
  const queue = (await jd("GET", "/v1/hypervisor/intelligence/review-queue")).j || {};
  const itemOf = (ref) => (queue.items || []).find((i) => i.ref === ref);
  const proposalOpen = (await jd("POST", "/v1/hypervisor/memory-mutation-proposals", {
    operation: "add", mutation_type: "fact", suggested: { title: `lc-openprop-${tag}`, entry_kind: "note", body: "pending" }, reason: "pending", source_authority: "worker",
  })).j?.proposal || {};
  const queue2 = (await jd("GET", "/v1/hypervisor/intelligence/review-queue")).j || {};
  ok("review queue is deterministic-signals-only and surfaces the expected signals",
    queue.deterministic_signals_only === true
    && (itemOf(lowConf.entry_ref)?.signals || []).includes("low_confidence")
    && (itemOf(dupA.entry_ref)?.signals || []).includes("conflict_with_existing")
    && (itemOf(dupB.entry_ref)?.signals || []).includes("conflict_with_existing")
    && (queue2.items || []).some((i) => i.ref === proposalOpen.proposal_ref && i.signals.includes("proposed_by_run")));

  // ── Work Ledger links lifecycle receipts ──
  const ledger = await jd("GET", "/v1/hypervisor/work-ledger");
  ok("Work Ledger indexes lifecycle transition receipts",
    (ledger.j?.entries || []).some((e) => e.kind === "memory_lifecycle" && e.record_ref === oldEntry.entry_ref && e.status === "supersede" && String(e.receipt_ref || "").startsWith("receipt://hypervisor/memory-lifecycle/")));

  // ── UI ──
  const browser = await chromium.launch();
  const page = await browser.newPage({ viewport: { width: 1600, height: 1000 } });
  const consoleErrors = [];
  page.on("pageerror", (e) => consoleErrors.push(String(e)));
  await page.goto(`${SHELL}/__ioi/agent-studio#memory`, { waitUntil: "networkidle" });
  await page.waitForSelector("#review-queue", { timeout: 15000 });
  const studio = await page.content();
  ok("Memory tab renders the Review queue with signal chips",
    studio.includes("deterministic signals only") && studio.includes("low_confidence"));
  ok("entry cards show lifecycle pills, transitions, and supersession links",
    studio.includes("superseded by") && studio.includes("Mark stale") && studio.includes("transition"));
  const explainPage = await fetch(`${SHELL}/__ioi/intelligence/projections/${projection.projection_id}/explain`).then((r) => r.text());
  ok("explain page shows the Quality column with lifecycle decisions",
    /<th>Quality<\/th>/.test(explainPage) && explainPage.includes("superseded"));
  ok("no console errors", consoleErrors.length === 0, consoleErrors.slice(0, 2).join(" | "));
  await browser.close();

  // ── Hygiene + cleanup ──
  const ft = await fetch(`${SHELL}/__ioi/fallthrough`).then((r) => r.json()).catch(() => ({}));
  ok("fallthrough stays empty", Array.isArray(ft.proxied) && ft.proxied.length === 0);
  await jd("POST", `/v1/hypervisor/memory-mutation-proposals/${proposalOpen.mutation_id}/reject`, { reason: "fixture cleanup" });
  for (const e of [accepted, candidate, stale, disputed, oldEntry, newEntry, privCand, lowConf, dupA, dupB, applied].filter((x) => x.entry_id)) {
    await jd("PATCH", `/v1/hypervisor/memory-entries/${e.entry_id}`, { status: "archived" });
  }
  const after = (await jd("GET", "/v1/hypervisor/intelligence/review-queue")).j || {};
  ok("fixtures archived (queue clear of this run's entry signals)",
    !(after.items || []).some((i) => String(i.ref).includes(lowConf.entry_id)));
}

run().then(() => {
  let fail = 0;
  for (const r of results) { console.log(`  ${r.pass ? "PASS" : "FAIL"}  ${r.name}${r.detail ? `  (${r.detail})` : ""}`); if (!r.pass) fail++; }
  console.log(`\n${results.length - fail}/${results.length} passed`);
  console.log(`memory lifecycle + review readiness: ${fail ? "FAIL" : "OK"}`);
  process.exit(fail ? 1 : 0);
}).catch((e) => {
  console.error("verifier crashed:", e);
  process.exit(1);
});
