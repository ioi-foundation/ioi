// Evaluations, rebound onto the governed evaluation plane (R-240 journey WP-D; ADR 0056 Amendment 1,
// answer 5: "Rebinding Evaluations onto the governed evaluation-* plane ... is sequenced beside planes
// 1–5, not deferred").
//
// ADOPTED, NOT RECREATED. /__ioi/evaluations is the owner surface for the eval-suite LIBRARY (the
// declaration-only `eval-suite://` suites, their consent rungs and subjects), and that seed stays as it
// is. This module renders the governed plane's objects BELOW the library, in the same page grammar, as
// canon's Product Surface Shape lists them (components/hypervisor/evaluations.md): Evaluators (what
// judges — a frozen root with its validity lifecycle), Suites / Revisions (a library suite FROZEN into a
// revision whose every task carries its exact source commitment, and RELEASED before an epoch or run may
// bind it) and Runs / Scorecards (admitted runs and their results, with the verdict the daemon derived).
// Every row is the daemon's record, read as the signed-in caller; every write is one of that plane's own
// routes, identity-first and owner-scoped, and its answer is read back — never assumed.
//
// What the page does NOT offer, by name: admitting a run or its scorecard. A run binds an ACTIVE
// evaluation epoch (opened under an improvement campaign, which binds an admitted learning-boundary
// profile) and a current policy-bound data-view revision, and no product surface opens either yet — so
// a run form here could only be refused. Runs a Judgment admits through the daemon are listed.
import { createHash, randomUUID } from "node:crypto";
import { callerOwnerRef, escHtml as esc, refusalCodeOf, refusalMessageOf } from "../surfaces/kit.mjs";

export const EVALUATIONS_ROUTE = "/__ioi/evaluations";
export const GOVERNED_LANE = "/__ioi/evaluations/governed";
export const GOVERNED_ACTIONS = Object.freeze({
  register: `${GOVERNED_LANE}/evaluators`,
  transition: (family, verb) => `${GOVERNED_LANE}/evaluators/${encodeURIComponent(family)}/${verb}`,
  freeze: `${GOVERNED_LANE}/suite-revisions`,
  release: (family, revision) => `${GOVERNED_LANE}/suite-revisions/${encodeURIComponent(family)}/${revision}/release`,
});
// The one thing this page names as absent, marked so the journey can read that it is still true.
export const EVALUATION_RUN_GAP = "running an evaluation from this page (an active evaluation epoch and a current policy-bound data-view revision)";

// Canon's vocabularies (evaluations.md § Registered Shapes) — the daemon refuses anything else by name.
export const EVALUATOR_KINDS = Object.freeze(["scorer", "judge", "rubric_scorer", "simulator", "formal_verifier", "human_panel", "reproduction_harness"]);
export const LANES = Object.freeze(["visible", "sealed", "transfer_ood", "adversarial", "cross_play_ablation", "external_reality", "production_acceptance", "independent_reproduction"]);
export const NONDETERMINISM = Object.freeze(["deterministic", "seeded", "declared_nondeterministic"]);
export const COST_CLASSES = Object.freeze(["negligible", "sublinear", "comparable", "superlinear", "unverifiable_at_price"]);
// The validity lifecycle's forward verbs, each offered on the row whose status it leaves from. Challenge,
// degrade, invalidate and reverify name the evidence that moved them; they are not offered here.
export const NEXT_VERB = Object.freeze({ draft: "validate", validated: "release", released: "activate" });
const VERB_LABEL = Object.freeze({ validate: "Validate", release: "Release", activate: "Activate" });

const tailOf = (reference, scheme) => (String(reference || "").startsWith(scheme) ? String(reference).slice(scheme.length) : "");
const sha = (text) => createHash("sha256").update(text).digest("hex");

async function readJson(daemonFetch, route, init) {
  try {
    const res = await daemonFetch(route, init);
    const body = await res.json().catch(() => ({}));
    return { status: res.status, body };
  } catch (error) {
    return { status: 0, body: { error: { code: "daemon_unreachable", message: String(error?.message || error) } } };
  }
}
const recordsOf = (answer) => (answer.status === 200 && Array.isArray(answer.body?.records) ? answer.body.records : null);

// ---- read -----------------------------------------------------------------------------------------
// The four inventories, as the caller. A read that did not come back is carried as its refusal, so a
// section can say WHY it is empty rather than drawing absence as "none yet".
export async function readGovernedEvaluations(daemonFetch) {
  const [evaluators, suites, runs, results] = await Promise.all([
    readJson(daemonFetch, "/v1/hypervisor/evaluators"),
    readJson(daemonFetch, "/v1/hypervisor/evaluation-suites"),
    readJson(daemonFetch, "/v1/hypervisor/evaluation-runs"),
    readJson(daemonFetch, "/v1/hypervisor/evaluation-results"),
  ]);
  const refused = (answer) => (recordsOf(answer) ? null : { code: refusalCodeOf(answer.body, answer.status), message: refusalMessageOf(answer.body) });
  return {
    evaluators: recordsOf(evaluators) || [],
    suites: recordsOf(suites) || [],
    runs: recordsOf(runs) || [],
    results: recordsOf(results) || [],
    unread: Object.fromEntries([["evaluators", evaluators], ["suite revisions", suites], ["runs", runs], ["results", results]]
      .map(([name, answer]) => [name, refused(answer)]).filter(([, why]) => why)),
  };
}

// ---- render ---------------------------------------------------------------------------------------
const sub = (txt) => `<span class="sub" style="text-transform:none;letter-spacing:0;font-weight:400">${txt}</span>`;
const code = (text) => `<code style="font-size:10px">${esc(text)}</code>`;
const shortHash = (hash) => (String(hash || "").startsWith("sha256:") ? `${String(hash).slice(0, 19)}…` : String(hash || "—"));
const statusPill = (status, good) => `<span class="pill ${status === good ? "ok" : status === "draft" ? "muted" : "warn"}" style="margin:0">${esc(status || "—")}</span>`;
const hidden = (name, value) => `<input type="hidden" name="${esc(name)}" value="${esc(value)}">`;
const input = (name, placeholder, value = "") => `<input name="${esc(name)}" value="${esc(value)}" placeholder="${esc(placeholder)}" style="width:100%;padding:8px 10px;border-radius:8px;border:1px solid #2a2c33;background:#0e0f13;color:#e6e7ea;font:inherit">`;
const select = (name, options, selected) => `<select name="${esc(name)}" style="width:100%;padding:8px 10px;border-radius:8px;border:1px solid #2a2c33;background:#0e0f13;color:#e6e7ea;font:inherit">${options.map(([value, label]) => `<option value="${esc(value)}"${value === selected ? " selected" : ""}>${esc(label)}</option>`).join("")}</select>`;
const unreadNote = (unread, name) => (unread[name] ? `<div class="empty" data-governed-unread="${esc(name)}">The ${esc(name)} could not be read — <code>${esc(unread[name].code)}</code>${unread[name].message ? ` ${esc(unread[name].message)}` : ""}. An empty list here is not an empty plane.</div>` : "");

function renderEvaluators(state) {
  const rows = state.evaluators.map((row) => {
    const current = row.current || {};
    const family = tailOf(row.ref, "evaluator://");
    const verb = NEXT_VERB[current.validity_status];
    const action = verb
      ? `<form class="inline" method="post" action="${esc(GOVERNED_ACTIONS.transition(family, verb))}" data-evaluator-transition="${esc(`${family}/${verb}`)}">${hidden("expected_head", row.head || "")}${hidden("form_nonce", randomUUID())}<button class="act ghost" type="submit">${VERB_LABEL[verb]}</button></form>`
      : `<span class="sub" style="margin:0">${current.validity_status === "active" ? "judges runs" : "no forward step here"}</span>`;
    return `<tr data-evaluator="${esc(current.revision_ref || "")}" data-evaluator-status="${esc(current.validity_status || "")}">
      <td><b>${esc(family)}</b><div class="sub" style="margin:1px 0 0">${code(current.revision_ref || row.ref)}</div></td>
      <td>${esc(current.evaluator_kind || "—")}<div class="sub" style="margin:1px 0 0">${code(current.implementation_ref || "")}</div></td>
      <td>${statusPill(current.validity_status, "active")}${current.validity_decision_ref ? `<div class="sub" style="margin:1px 0 0">${code(current.validity_decision_ref)}</div>` : ""}</td>
      <td title="${esc(current.evaluator_root || "")}">${code(shortHash(current.evaluator_root))}</td>
      <td>${action}</td></tr>`;
  }).join("");
  const table = rows
    ? `<table data-governed-evaluators="1"><thead><tr><th>Evaluator</th><th>Kind · implementation</th><th>Validity</th><th>Frozen root</th><th></th></tr></thead><tbody>${rows}</tbody></table>`
    : `<div class="empty" data-governed-evaluators-empty="1">No evaluator is registered on the governed plane yet — register one below. An evaluator starts as a draft and judges a run only once it is validated, released and active.</div>`;
  const form = `<form method="post" action="${esc(GOVERNED_ACTIONS.register)}" id="new-evaluator"><div class="card" style="display:block;margin-top:8px">
    ${hidden("form_nonce", randomUUID())}
    <div class="two"><div class="field"><label>Family (the lineage token: lowercase letters, digits, . _ -)</label>${input("family", "e.g. acme.exact-match")}</div>
    <div class="field"><label>Kind</label>${select("evaluator_kind", EVALUATOR_KINDS.map((k) => [k, k]), "scorer")}</div></div>
    <div class="field"><label>Implementation (a content-addressed artifact://… or a registered model-route:…)</label>${input("implementation_ref", "artifact://…")}</div>
    <div class="row" style="margin-top:6px"><button class="act" type="submit">Register evaluator</button> <span class="sub" style="margin:0">admitted as a draft revision 1 under your organization; its frozen root is the daemon's</span></div></div></form>`;
  return `<h2 id="governed-evaluators">Evaluators ${sub(`— what judges: a frozen root and its validity lifecycle, on the governed evaluation plane (${state.evaluators.length})`)}</h2>`
    + unreadNote(state.unread, "evaluators") + table
    + `<details style="margin:8px 0 16px"><summary style="cursor:pointer;color:#9ea1ab;font-size:13px">Register an evaluator</summary>${form}</details>`;
}

function renderSuiteRevisions(state, library) {
  const revisionRows = state.suites.flatMap((row) => (row.revisions?.length ? row.revisions : [row.current || {}]).map((revision) => ({ row, revision })));
  const rows = revisionRows.map(({ row, revision }) => {
    const family = tailOf(row.ref, "evaluation-suite://");
    const release = revision.registry_status === "draft"
      ? `<form class="inline" method="post" action="${esc(GOVERNED_ACTIONS.release(family, revision.revision))}" data-suite-release="${esc(revision.revision_ref || "")}">${hidden("expected_head", row.head || "")}${hidden("form_nonce", randomUUID())}<button class="act ghost" type="submit">Release</button></form>`
      : "";
    const libraryName = (library.find((s) => s.ref === revision.library_suite_ref) || {}).name;
    return `<tr data-suite-revision="${esc(revision.revision_ref || "")}" data-suite-revision-status="${esc(revision.registry_status || "")}" data-suite-revision-hash="${esc(revision.content_hash || "")}">
      <td><b>${esc(family)}</b> · revision ${esc(revision.revision ?? "?")}<div class="sub" style="margin:1px 0 0">${code(revision.revision_ref || "")}</div></td>
      <td>${esc(libraryName || "—")}<div class="sub" style="margin:1px 0 0">${code(revision.library_suite_ref || "")}</div></td>
      <td>${(revision.tasks || []).length}</td>
      <td>${(revision.scorer_revision_refs || []).map(code).join(" ") || "—"}</td>
      <td>${(revision.required_lanes || []).map((l) => `<span class="pill muted" style="margin:0 3px 3px 0">${esc(l)}</span>`).join("")}</td>
      <td>${statusPill(revision.registry_status, "released")}${revision.release_decision_ref ? `<div class="sub" style="margin:1px 0 0">${code(revision.release_decision_ref)}</div>` : ""}</td>
      <td title="${esc(revision.content_hash || "")}">${code(shortHash(revision.content_hash))}</td>
      <td>${release}</td></tr>`;
  }).join("");
  const table = rows
    ? `<table data-governed-suite-revisions="1"><thead><tr><th>Revision</th><th>Freezes library suite</th><th>Tasks</th><th>Scorers</th><th>Required lanes</th><th>Status</th><th>Content hash</th><th></th></tr></thead><tbody>${rows}</tbody></table>`
    : `<div class="empty" data-governed-suite-revisions-empty="1">No suite revision is frozen yet. Freezing a library suite binds each task to its exact source commitment; only a released revision can be bound by an epoch or a run.</div>`;
  const scorers = state.evaluators.flatMap((row) => (row.revisions?.length ? row.revisions : [row.current || {}]))
    .filter((r) => r.revision_ref).map((r) => [r.revision_ref, `${r.revision_ref} (${r.validity_status || "?"})`]);
  const librarySuites = library.filter((s) => s && s.ref).map((s) => [s.ref, `${s.name || s.id} · ${s.ref}`]);
  const form = librarySuites.length
    ? `<form method="post" action="${esc(GOVERNED_ACTIONS.freeze)}" id="freeze-suite"><div class="card" style="display:block;margin-top:8px">
    ${hidden("form_nonce", randomUUID())}
    <div class="two"><div class="field"><label>Library suite to freeze</label>${select("library_suite_ref", librarySuites, librarySuites[0][0])}</div>
    <div class="field"><label>Revision family (the lineage token; an existing family gains its next revision)</label>${input("family", "e.g. acme.intake-visible")}</div></div>
    <div class="field"><label>Tasks — one per line: a dataset://… or artifact://… ref and its exact source commitment (sha256:…); a task without one is the mutable latest canon refuses</label><textarea name="tasks" rows="3" style="width:100%;padding:8px 10px;border-radius:8px;border:1px solid #2a2c33;background:#0e0f13;color:#e6e7ea;font:inherit" placeholder="artifact://acme/cases/1 sha256:…"></textarea></div>
    <div class="two"><div class="field"><label>Scorer (an evaluator revision)</label>${scorers.length ? select("scorer_revision_ref", scorers, scorers[0][0]) : `<div class="sub" style="margin:0">No evaluator is registered — register one above first.</div>`}</div>
    <div class="field"><label>Nondeterminism</label>${select("nondeterminism_class", NONDETERMINISM.map((n) => [n, n]), "deterministic")}</div></div>
    <div class="field"><label>Required lanes (the lanes a passing claim needs)</label><div>${LANES.map((l) => `<label style="display:inline-flex;align-items:center;gap:4px;margin:0 10px 4px 0;font-size:12px;color:#c7c9d1"><input type="checkbox" name="required_lanes" value="${esc(l)}"${l === "visible" ? " checked" : ""}> ${esc(l)}</label>`).join("")}</div></div>
    <div class="two"><div class="field"><label>Verification cost class</label>${select("verification_cost_class", COST_CLASSES.map((c) => [c, c]), "negligible")}</div>
    <div class="field"><label>Seed policy (a seeded suite only: policy://…)</label>${input("declared_seed_policy_ref", "policy://…")}</div></div>
    <div class="two"><div class="field"><label>Rubric refs (optional, space-separated rubric://…)</label>${input("rubric_refs", "rubric://…")}</div>
    <div class="field"><label>World refs (optional, space-separated artifact:// or environment-class://)</label>${input("world_refs", "environment-class://…")}</div></div>
    <div class="row" style="margin-top:6px"><button class="act" type="submit">Freeze into a revision</button> <span class="sub" style="margin:0">admitted as a draft; Release it from its row</span></div></div></form>`
    : `<div class="empty">Declare a library suite above first — a revision freezes one.</div>`;
  return `<h2 id="governed-suite-revisions">Suite revisions ${sub(`— library suites frozen into exact, released judgment contracts (${revisionRows.length})`)}</h2>`
    + unreadNote(state.unread, "suite revisions") + table
    + `<details style="margin:8px 0 16px"><summary style="cursor:pointer;color:#9ea1ab;font-size:13px">Freeze a library suite into a revision</summary>${form}</details>`;
}

function renderRuns(state) {
  const resultsByRun = new Map();
  for (const row of state.results) {
    const current = row.current || {};
    const list = resultsByRun.get(current.evaluation_run_ref) || [];
    list.push(current);
    resultsByRun.set(current.evaluation_run_ref, list);
  }
  const verdictPill = (r) => `<span class="pill ${r.verdict === "pass" ? "ok" : r.verdict === "fail" ? "warn" : "muted"}" style="margin:0" data-evaluation-verdict="${esc(r.verdict || "")}">${esc(r.verdict || "—")}</span> <span class="sub" style="margin:0">${esc(r.verdict_basis || "")}</span>`;
  const rows = state.runs.map((row) => {
    const run = row.current || {};
    const results = resultsByRun.get(run.evaluation_run_id) || [];
    return `<tr data-evaluation-run="${esc(run.evaluation_run_id || row.ref)}" data-evaluation-run-system="${esc(run.system_ref || "")}">
      <td>${code(run.evaluation_run_id || row.ref)}<div class="sub" style="margin:1px 0 0">${esc(run.lane || "")} · ${esc(run.submitter_role || "")}</div></td>
      <td>${code(run.suite_revision_ref || "")}<div class="sub" style="margin:1px 0 0">${code(run.evaluator_revision_ref || "")}</div></td>
      <td>${code(run.evaluation_epoch_ref || "")}</td>
      <td>${run.system_ref ? code(run.system_ref) : `<span class="sub" style="margin:0">no System</span>`}</td>
      <td>${(run.execution_evidence_refs || []).length}</td>
      <td>${results.length ? results.map((r) => `<div data-evaluation-result="${esc(r.evaluation_result_id || "")}">${verdictPill(r)}</div>`).join("") : `<span class="sub" style="margin:0">no scorecard yet</span>`}</td></tr>`;
  }).join("");
  const table = rows
    ? `<table data-governed-runs="1"><thead><tr><th>Run</th><th>Suite revision · evaluator</th><th>Epoch</th><th>System measured</th><th>Evidence</th><th>Scorecard</th></tr></thead><tbody>${rows}</tbody></table>`
    : `<div class="empty" data-governed-runs-empty="1">No evaluation run is admitted yet.</div>`;
  const gap = `<div class="empty" data-evaluation-named-gap="${esc(EVALUATION_RUN_GAP)}">Admitting a run or its scorecard from this page — a run binds an ACTIVE evaluation epoch (opened under an improvement campaign, which binds an admitted learning-boundary profile) and a current policy-bound data-view revision, and no surface opens either yet, so this page offers no run form — a named gap: <b>${esc(EVALUATION_RUN_GAP)}</b> is not built, so nothing here stands in for it. Runs and scorecards a Judgment admits through the daemon are listed above, each with the verdict the daemon derived and the System it measured.</div>`;
  return `<h2 id="governed-runs">Runs and scorecards ${sub(`— admitted runs and their immutable results (${state.runs.length} run${state.runs.length === 1 ? "" : "s"}, ${state.results.length} result${state.results.length === 1 ? "" : "s"})`)}</h2>`
    + unreadNote(state.unread, "runs") + unreadNote(state.unread, "results") + table + gap;
}

// The governed sections, below the library. `query` carries a governed action's answer (acted= and
// record=, or refused= and reason=) so the page says what happened, by the daemon's own words.
export function renderGovernedEvaluations(state, library, query) {
  const acted = query?.get?.("acted") || "";
  const record = query?.get?.("record") || "";
  const actedNote = acted
    ? `<div class="card" style="display:block;border-color:#23523a" data-evaluations-acted="${esc(acted)}"><b style="color:#4fb37a">Done:</b> <span class="sub" style="margin:0;text-transform:none;letter-spacing:0">${esc(acted.replace(/-/gu, " "))}${record ? ` — ${code(record)}` : ""}</span></div>`
    : "";
  return `<div id="governed-evaluations" data-governed-evaluations="1">${actedNote}`
    + renderEvaluators(state) + renderSuiteRevisions(state, Array.isArray(library) ? library : []) + renderRuns(state) + `</div>`;
}

// ---- write ----------------------------------------------------------------------------------------
const back = (res, params, anchor) => {
  const q = new URLSearchParams(Object.entries(params).filter(([, v]) => v !== undefined && v !== null && v !== ""));
  res.writeHead(302, { Location: `${EVALUATIONS_ROUTE}?${q}${anchor ? `#${anchor}` : ""}`, "Cache-Control": "no-cache" });
  res.end();
  return true;
};
const refusal = (answer, fallback) => ({
  refused: answer.status === 0 ? "daemon_unreachable" : refusalCodeOf(answer.body, answer.status) || fallback,
  reason: refusalMessageOf(answer.body).slice(0, 300) || fallback,
});
const splitRefs = (value) => String(value || "").split(/[\s,]+/u).map((x) => x.trim()).filter(Boolean);
const keyFor = (verb, ...parts) => `evaluations-${verb}-${sha(parts.join("\u0000")).slice(0, 32)}`;
const decisionRef = (family, verb, nonce) => `decision://hypervisor/evaluations/${family}/${verb}/${nonce}`;
async function owner(daemonFetch) {
  return callerOwnerRef((await readJson(daemonFetch, "/v1/hypervisor/auth/whoami")).body);
}
const post = (daemonFetch, route, body) => readJson(daemonFetch, route, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify(body) });

/** POST under /__ioi/evaluations/governed/… — true when handled (it always answers a redirect). */
export async function handleGovernedEvaluationAction(req, res, pathname, rawBody, { daemonFetch }) {
  if (req.method !== "POST" || !pathname.startsWith(`${GOVERNED_LANE}/`)) return false;
  const form = new URLSearchParams(Buffer.isBuffer(rawBody) ? rawBody.toString("utf8") : String(rawBody || ""));
  const nonce = (form.get("form_nonce") || "").trim();
  const rest = pathname.slice(GOVERNED_LANE.length + 1).split("/").map((s) => { try { return decodeURIComponent(s); } catch { return ""; } });
  if (!nonce) return back(res, { refused: "evaluation_form_nonce_required", reason: "submit the form the Evaluations page rendered" }, "governed-evaluations");

  // Register an evaluator: a draft revision 1 under the caller's organization.
  if (rest.length === 1 && rest[0] === "evaluators") {
    const family = (form.get("family") || "").trim();
    const ownerRef = await owner(daemonFetch);
    const admitted = await post(daemonFetch, "/v1/hypervisor/evaluators", {
      owner_ref: ownerRef, idempotency_key: keyFor("register", ownerRef, family, nonce), family,
      evaluator_kind: (form.get("evaluator_kind") || "").trim(), implementation_ref: (form.get("implementation_ref") || "").trim(),
      affiliation_ref: ownerRef || null, custodian_ref: null,
    });
    const revision = admitted.body?.evaluator_revision;
    if (![200, 201].includes(admitted.status) || !revision) return back(res, refusal(admitted, "evaluator_register_refused"), "governed-evaluators");
    return back(res, { acted: "register-evaluator", record: revision.revision_ref }, "governed-evaluators");
  }
  // A validity transition: the family's owner acts, on the head the page read.
  if (rest.length === 3 && rest[0] === "evaluators" && Object.values(NEXT_VERB).includes(rest[2])) {
    const [, family, verb] = rest;
    const read = await readJson(daemonFetch, `/v1/hypervisor/evaluators/${encodeURIComponent(family)}`);
    const current = read.body?.current;
    if (read.status !== 200 || !current) return back(res, refusal(read, "evaluator_unreadable"), "governed-evaluators");
    const moved = await post(daemonFetch, `/v1/hypervisor/evaluators/${encodeURIComponent(family)}/transitions/${verb}`, {
      owner_ref: current.owner_ref, idempotency_key: keyFor(verb, family, nonce),
      expected_head: (form.get("expected_head") || "").trim() || read.body.head, validity_decision_ref: decisionRef(family, verb, nonce),
    });
    const revision = moved.body?.evaluator_revision;
    if (![200, 201].includes(moved.status) || !revision) return back(res, refusal(moved, `evaluator_${verb}_refused`), "governed-evaluators");
    return back(res, { acted: `${verb}-evaluator`, record: revision.revision_ref }, "governed-evaluators");
  }
  // Freeze a library suite into a revision: revision 1 of a new family, or the next of an existing one.
  if (rest.length === 1 && rest[0] === "suite-revisions") {
    const family = (form.get("family") || "").trim();
    const tasks = String(form.get("tasks") || "").split(/\r?\n/u).map((line) => line.trim()).filter(Boolean).map((line) => {
      const [taskRef, commitment] = line.split(/\s+/u);
      return commitment ? { task_ref: taskRef, source_commitment: commitment } : { task_ref: taskRef };
    });
    const scorer = (form.get("scorer_revision_ref") || "").trim();
    const seedPolicy = (form.get("declared_seed_policy_ref") || "").trim();
    const request = {
      family, library_suite_ref: (form.get("library_suite_ref") || "").trim(), tasks,
      scorer_revision_refs: scorer ? [scorer] : [], rubric_refs: splitRefs(form.get("rubric_refs")), world_refs: splitRefs(form.get("world_refs")),
      required_lanes: form.getAll("required_lanes").map((l) => l.trim()).filter(Boolean),
      nondeterminism_class: (form.get("nondeterminism_class") || "").trim(), declared_seed_policy_ref: seedPolicy || null,
      verification_cost_class: (form.get("verification_cost_class") || "").trim(),
    };
    const existing = family ? await readJson(daemonFetch, `/v1/hypervisor/evaluation-suites/${encodeURIComponent(family)}`) : { status: 404, body: {} };
    const ownerRef = existing.status === 200 && existing.body?.current?.owner_ref ? existing.body.current.owner_ref : await owner(daemonFetch);
    const admitted = existing.status === 200 && existing.body?.head
      ? await post(daemonFetch, `/v1/hypervisor/evaluation-suites/${encodeURIComponent(family)}/revisions`, { ...request, owner_ref: ownerRef, idempotency_key: keyFor("revise", family, nonce), expected_head: existing.body.head })
      : await post(daemonFetch, "/v1/hypervisor/evaluation-suites", { ...request, owner_ref: ownerRef, idempotency_key: keyFor("freeze", ownerRef, family, nonce) });
    const revision = admitted.body?.evaluation_suite_revision;
    if (![200, 201].includes(admitted.status) || !revision) return back(res, refusal(admitted, "suite_freeze_refused"), "governed-suite-revisions");
    return back(res, { acted: "freeze-suite", record: revision.revision_ref }, "governed-suite-revisions");
  }
  // Release one draft revision: a successor admission carrying the identical content hash.
  if (rest.length === 4 && rest[0] === "suite-revisions" && rest[3] === "release" && /^[1-9][0-9]{0,8}$/u.test(rest[2])) {
    const [, family, revision] = rest;
    const read = await readJson(daemonFetch, `/v1/hypervisor/evaluation-suites/${encodeURIComponent(family)}`);
    const current = read.body?.current;
    if (read.status !== 200 || !current) return back(res, refusal(read, "suite_unreadable"), "governed-suite-revisions");
    const released = await post(daemonFetch, `/v1/hypervisor/evaluation-suites/${encodeURIComponent(family)}/revisions/${revision}/release`, {
      owner_ref: current.owner_ref, idempotency_key: keyFor("release", family, revision, nonce),
      expected_head: (form.get("expected_head") || "").trim() || read.body.head, release_decision_ref: decisionRef(family, `release-${revision}`, nonce),
    });
    const record = released.body?.evaluation_suite_revision;
    if (![200, 201].includes(released.status) || !record) return back(res, refusal(released, "suite_release_refused"), "governed-suite-revisions");
    return back(res, { acted: "release-suite", record: record.revision_ref }, "governed-suite-revisions");
  }
  return back(res, { refused: "evaluation_action_unknown", reason: "no governed evaluation action answers at that address" }, "governed-evaluations");
}
