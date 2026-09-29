// R-240 journey WP-D: Evaluations rebound onto the governed evaluation plane — the evaluators, suite
// revisions, runs and scorecards the page renders, and the writes its forms send — against a stand-in
// daemon that answers the reads and records every write, so what the surface SENDS is checked, never
// assumed. The System's Evidence mode lists the evaluations narrowed to it.
//
//   node --test apps/hypervisor/scripts/evaluations-governed.test.mjs
import test from "node:test";
import assert from "node:assert/strict";
import http from "node:http";
import {
  EVALUATION_RUN_GAP, GOVERNED_ACTIONS, handleGovernedEvaluationAction, readGovernedEvaluations, renderGovernedEvaluations,
} from "./evaluations-governed.mjs";
import { handleSystemGenesisSurfaces, handleSystemWorkspace, systemEvaluations } from "./system-genesis-surfaces.mjs";

const SYSTEM = "system://acme/lending";
const H = (c) => `sha256:${c.repeat(64)}`;
const LIBRARY = [{ id: "es_1", ref: "eval-suite://es_1", name: "Intake triage" }];
const evaluator = (family, status, head) => ({
  ref: `evaluator://${family}`, head,
  current: { revision_ref: `evaluator://${family}/revision/1`, revision: 1, owner_ref: "org://acme", evaluator_kind: "scorer", implementation_ref: "artifact://acme/x", evaluator_root: H("e"), validity_status: status, validity_decision_ref: status === "draft" ? null : `decision://x/${status}` },
  revisions: [{ revision_ref: `evaluator://${family}/revision/1`, revision: 1, validity_status: status }],
});
const suite = (family, status, head) => {
  const revision = { revision_ref: `evaluation-suite://${family}/revision/1`, revision: 1, owner_ref: "org://acme", library_suite_ref: "eval-suite://es_1", tasks: [{ task_ref: "artifact://acme/case-1", source_commitment: H("1") }], scorer_revision_refs: ["evaluator://acme.exact/revision/1"], required_lanes: ["visible"], registry_status: status, content_hash: H("5"), release_decision_ref: status === "released" ? "decision://x/release" : null };
  return { ref: `evaluation-suite://${family}`, head, current: revision, revisions: [revision] };
};
const run = (id, system) => ({ ref: `evaluation-run://${id}`, head: H("a"), current: { evaluation_run_id: `evaluation-run://${id}`, system_ref: system, suite_revision_ref: "evaluation-suite://acme.visible/revision/1", evaluator_revision_ref: "evaluator://acme.exact/revision/1", evaluation_epoch_ref: "evaluation-epoch://acme.c.epoch-1", lane: "visible", submitter_role: "evaluator", execution_evidence_refs: ["session://s1"] }, revisions: [] });
const result = (id, runId, system, verdict) => ({ ref: `evaluation-result://${id}`, head: H("b"), current: { evaluation_result_id: `evaluation-result://${id}`, evaluation_run_ref: `evaluation-run://${runId}`, system_ref: system, verdict, verdict_basis: "observed" }, revisions: [] });

async function standIn(state) {
  const calls = [];
  const server = http.createServer((req, res) => {
    let raw = "";
    req.on("data", (c) => { raw += c; });
    req.on("end", () => {
      const url = new URL(req.url, "http://x");
      const body = raw ? JSON.parse(raw) : null;
      calls.push({ method: req.method, path: url.pathname, search: url.search, body });
      const send = (status, json) => { res.writeHead(status, { "content-type": "application/json" }); res.end(JSON.stringify(json)); };
      const sys = url.searchParams.get("system_ref");
      const narrow = (rows) => (sys ? rows.filter((r) => r.current.system_ref === sys) : rows);
      if (url.pathname === "/v1/hypervisor/auth/whoami") return send(200, { authenticated: true, principal: { tenant_refs: ["org://acme"] } });
      if (url.pathname === "/v1/hypervisor/evaluators" && req.method === "GET") return send(200, { ok: true, evaluators: state.evaluators.map((r) => r.ref), records: state.evaluators });
      if (url.pathname === "/v1/hypervisor/evaluation-suites" && req.method === "GET") return send(200, { ok: true, evaluation_suites: state.suites.map((r) => r.ref), records: state.suites });
      if (url.pathname === "/v1/hypervisor/evaluation-runs") return send(200, { ok: true, evaluation_runs: narrow(state.runs).map((r) => r.ref), records: narrow(state.runs) });
      if (url.pathname === "/v1/hypervisor/evaluation-results") return send(200, { ok: true, evaluation_results: narrow(state.results).map((r) => r.ref), records: narrow(state.results) });
      if (url.pathname === "/v1/hypervisor/evaluators" && req.method === "POST") {
        return state.refuse ? send(422, { ok: false, error: { code: "evaluator_revision_kind_outside_vocabulary", message: "evaluator_kind is one of …" } })
          : send(201, { ok: true, evaluator_revision: { revision_ref: `evaluator://${body.family}/revision/1`, validity_status: "draft" } });
      }
      const family = /^\/v1\/hypervisor\/evaluators\/([^/]+)$/u.exec(url.pathname);
      if (family) { const row = state.evaluators.find((r) => r.ref === `evaluator://${family[1]}`); return row ? send(200, { ok: true, head: row.head, current: row.current }) : send(404, { ok: false, error: { code: "evaluator_revision_absent" } }); }
      const transition = /^\/v1\/hypervisor\/evaluators\/([^/]+)\/transitions\/([a-z]+)$/u.exec(url.pathname);
      if (transition) return send(201, { ok: true, evaluator_revision: { revision_ref: `evaluator://${transition[1]}/revision/1`, validity_status: transition[2] } });
      const suiteFamily = /^\/v1\/hypervisor\/evaluation-suites\/([^/]+)$/u.exec(url.pathname);
      if (suiteFamily && req.method === "GET") { const row = state.suites.find((r) => r.ref === `evaluation-suite://${suiteFamily[1]}`); return row ? send(200, { ok: true, head: row.head, current: row.current }) : send(404, { ok: false, error: { code: "evaluation_suite_revision_absent" } }); }
      if (url.pathname === "/v1/hypervisor/evaluation-suites" && req.method === "POST") return send(201, { ok: true, evaluation_suite_revision: { revision_ref: `evaluation-suite://${body.family}/revision/1`, registry_status: "draft" } });
      const revise = /^\/v1\/hypervisor\/evaluation-suites\/([^/]+)\/revisions$/u.exec(url.pathname);
      if (revise) return send(201, { ok: true, evaluation_suite_revision: { revision_ref: `evaluation-suite://${revise[1]}/revision/2`, registry_status: "draft" } });
      const release = /^\/v1\/hypervisor\/evaluation-suites\/([^/]+)\/revisions\/(\d+)\/release$/u.exec(url.pathname);
      if (release) return send(201, { ok: true, evaluation_suite_revision: { revision_ref: `evaluation-suite://${release[1]}/revision/${release[2]}`, registry_status: "released" } });
      return send(404, { ok: false, error: { code: "stand_in_route_absent", message: url.pathname } });
    });
  });
  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  const url = `http://127.0.0.1:${server.address().port}`;
  const daemonFetch = (route, init = {}) => fetch(`${url}${route}`, init);
  return { url, calls, daemonFetch, close: () => new Promise((resolve) => server.close(resolve)) };
}

function response() {
  const out = { status: 0, headers: {}, body: "" };
  return { out, res: { writeHead(status, headers = {}) { out.status = status; out.headers = headers; }, end(body = "") { out.body = String(body); } } };
}
async function act(daemon, action, fields) {
  const { out, res } = response();
  const handled = await handleGovernedEvaluationAction({ method: "POST" }, res, action, Buffer.from(new URLSearchParams(fields).toString()), { daemonFetch: daemon.daemonFetch });
  const location = String(out.headers.Location || "");
  return { handled, ...out, location, q: new URLSearchParams(location.split("?")[1]?.split("#")[0] || "") };
}
const posts = (daemon) => daemon.calls.filter((c) => c.method === "POST");

test("the page renders the governed plane as the daemon holds it: each evaluator offers only its next step, a draft revision offers Release, runs carry their scorecards and System, and the run form's absence is named", async () => {
  const daemon = await standIn({
    evaluators: [evaluator("acme.draft", "draft", H("1")), evaluator("acme.validated", "validated", H("2")), evaluator("acme.released", "released", H("3")), evaluator("acme.active", "active", H("4"))],
    suites: [suite("acme.visible", "released", H("6")), suite("acme.next", "draft", H("7"))],
    runs: [run("acme.r1", SYSTEM), run("acme.r2", null)],
    results: [result("acme.res1", "acme.r1", SYSTEM, "fail")],
  });
  try {
    const html = renderGovernedEvaluations(await readGovernedEvaluations(daemon.daemonFetch), LIBRARY, new URLSearchParams("acted=release-suite&record=evaluation-suite://acme.next/revision/1"));
    assert.ok(html.includes('data-evaluator="evaluator://acme.draft/revision/1" data-evaluator-status="draft"'));
    for (const [family, verb] of [["acme.draft", "validate"], ["acme.validated", "release"], ["acme.released", "activate"]]) {
      assert.ok(html.includes(`action="${GOVERNED_ACTIONS.transition(family, verb)}" data-evaluator-transition="${family}/${verb}"`), `${family} offers ${verb}`);
    }
    assert.ok(!html.includes('data-evaluator-transition="acme.active/'), "an active evaluator offers no forward step");
    assert.ok(!html.includes('data-evaluator-transition="acme.draft/activate"'), "a draft is never offered activate");
    assert.match(html, new RegExp(`data-evaluator-transition="acme.draft/validate"><input type="hidden" name="expected_head" value="${H("1")}">`, "u"), "the transition names the head the page read");
    assert.ok(html.includes(`data-suite-release="evaluation-suite://acme.next/revision/1"`), "a draft revision offers Release");
    assert.ok(!html.includes(`data-suite-release="evaluation-suite://acme.visible/revision/1"`), "a released one does not");
    assert.ok(html.includes('data-suite-revision="evaluation-suite://acme.visible/revision/1" data-suite-revision-status="released"'));
    assert.ok(html.includes(`<option value="eval-suite://es_1" selected>`), "the Freeze form offers the library's suites");
    assert.ok(html.includes(`<option value="evaluator://acme.active/revision/1">`), "…and the evaluators as scorers");
    assert.ok(html.includes(`data-evaluation-run="evaluation-run://acme.r1" data-evaluation-run-system="${SYSTEM}"`));
    assert.ok(html.includes('data-evaluation-result="evaluation-result://acme.res1"') && html.includes('data-evaluation-verdict="fail"'));
    assert.ok(html.includes(`data-evaluation-named-gap="${EVALUATION_RUN_GAP}"`), "the run form's absence is named on the page");
    assert.ok(!html.includes(`action="${"/__ioi/evaluations/governed/runs"}`), "no run form is offered");
    assert.ok(html.includes('data-evaluations-acted="release-suite"'), "a governed action's answer is said");
    assert.match(html, /name="form_nonce" value="[0-9a-f-]{36}"/u);
  } finally { await daemon.close(); }
});

test("a plane that did not answer is not an empty plane: each unread inventory says why", async () => {
  const daemonFetch = async (route) => ({ status: 401, json: async () => ({ ok: false, code: "request_principal_required", message: "sign in" }) });
  const html = renderGovernedEvaluations(await readGovernedEvaluations(daemonFetch), [], new URLSearchParams());
  for (const name of ["evaluators", "suite revisions", "runs", "results"]) assert.ok(html.includes(`data-governed-unread="${name}"`), name);
  assert.ok(html.includes("request_principal_required"));
});

test("Register admits a draft evaluator under the caller's organization, one key per rendered form, and a refusal comes back by name", async () => {
  const daemon = await standIn({ evaluators: [], suites: [], runs: [], results: [] });
  try {
    const out = await act(daemon, GOVERNED_ACTIONS.register, { form_nonce: "n-1", family: "acme.exact", evaluator_kind: "scorer", implementation_ref: "artifact://acme/exact/v1" });
    assert.equal(out.status, 302);
    assert.equal(out.q.get("acted"), "register-evaluator");
    assert.equal(out.q.get("record"), "evaluator://acme.exact/revision/1");
    const sent = posts(daemon).at(-1);
    assert.equal(sent.path, "/v1/hypervisor/evaluators");
    assert.equal(sent.body.owner_ref, "org://acme");
    assert.equal(sent.body.family, "acme.exact");
    assert.equal(sent.body.evaluator_kind, "scorer");
    assert.equal(sent.body.implementation_ref, "artifact://acme/exact/v1");
    assert.match(sent.body.idempotency_key, /^evaluations-register-[0-9a-f]{32}$/u);
    const again = await act(daemon, GOVERNED_ACTIONS.register, { form_nonce: "n-1", family: "acme.exact", evaluator_kind: "scorer", implementation_ref: "artifact://acme/exact/v1" });
    assert.equal(posts(daemon).at(-1).body.idempotency_key, sent.body.idempotency_key, "a resubmitted form replays its key");
    assert.equal(again.q.get("acted"), "register-evaluator");
  } finally { await daemon.close(); }
  const refusing = await standIn({ evaluators: [], suites: [], runs: [], results: [], refuse: true });
  try {
    const out = await act(refusing, GOVERNED_ACTIONS.register, { form_nonce: "n-2", family: "acme.x", evaluator_kind: "oracle", implementation_ref: "artifact://x" });
    assert.equal(out.q.get("refused"), "evaluator_revision_kind_outside_vocabulary");
    assert.match(out.q.get("reason"), /evaluator_kind/u);
    const noNonce = await act(refusing, GOVERNED_ACTIONS.register, { family: "acme.x" });
    assert.equal(noNonce.q.get("refused"), "evaluation_form_nonce_required");
  } finally { await refusing.close(); }
});

test("a validity step acts as the evaluator's owner on the head the page read, naming the decision:// the click made", async () => {
  const daemon = await standIn({ evaluators: [evaluator("acme.exact", "draft", H("1"))], suites: [], runs: [], results: [] });
  try {
    const out = await act(daemon, GOVERNED_ACTIONS.transition("acme.exact", "validate"), { form_nonce: "n-3", expected_head: H("1") });
    assert.equal(out.q.get("acted"), "validate-evaluator");
    const sent = posts(daemon).at(-1);
    assert.equal(sent.path, "/v1/hypervisor/evaluators/acme.exact/transitions/validate");
    assert.equal(sent.body.owner_ref, "org://acme");
    assert.equal(sent.body.expected_head, H("1"));
    assert.equal(sent.body.validity_decision_ref, "decision://hypervisor/evaluations/acme.exact/validate/n-3");
    const unknown = await act(daemon, "/__ioi/evaluations/governed/evaluators/acme.exact/bless", { form_nonce: "n-4" });
    assert.equal(unknown.q.get("refused"), "evaluation_action_unknown");
  } finally { await daemon.close(); }
});

test("Freeze admits revision 1 of a new family with every task and its commitment, the next revision of an existing one on its head, and Release names its decision", async () => {
  const daemon = await standIn({ evaluators: [], suites: [suite("acme.visible", "released", H("6"))], runs: [], results: [] });
  try {
    const fields = { form_nonce: "n-5", library_suite_ref: "eval-suite://es_1", family: "acme.fresh", tasks: `artifact://acme/case-1 ${H("1")}\n\nartifact://acme/case-2`, scorer_revision_ref: "evaluator://acme.exact/revision/1", nondeterminism_class: "deterministic", verification_cost_class: "negligible", required_lanes: "visible" };
    const fresh = await act(daemon, GOVERNED_ACTIONS.freeze, fields);
    assert.equal(fresh.q.get("acted"), "freeze-suite");
    assert.equal(fresh.q.get("record"), "evaluation-suite://acme.fresh/revision/1");
    const created = posts(daemon).at(-1);
    assert.equal(created.path, "/v1/hypervisor/evaluation-suites");
    assert.deepEqual(created.body.tasks, [{ task_ref: "artifact://acme/case-1", source_commitment: H("1") }, { task_ref: "artifact://acme/case-2" }], "a task without its commitment is sent as typed, for the daemon to refuse by name");
    assert.deepEqual(created.body.scorer_revision_refs, ["evaluator://acme.exact/revision/1"]);
    assert.deepEqual(created.body.required_lanes, ["visible"]);
    assert.equal(created.body.library_suite_ref, "eval-suite://es_1");
    assert.equal(created.body.declared_seed_policy_ref, null);
    assert.equal(created.body.owner_ref, "org://acme");
    const next = await act(daemon, GOVERNED_ACTIONS.freeze, { ...fields, form_nonce: "n-6", family: "acme.visible" });
    assert.equal(next.q.get("record"), "evaluation-suite://acme.visible/revision/2");
    const revised = posts(daemon).at(-1);
    assert.equal(revised.path, "/v1/hypervisor/evaluation-suites/acme.visible/revisions");
    assert.equal(revised.body.expected_head, H("6"));
    const released = await act(daemon, GOVERNED_ACTIONS.release("acme.visible", 2), { form_nonce: "n-7", expected_head: H("6") });
    assert.equal(released.q.get("acted"), "release-suite");
    const sent = posts(daemon).at(-1);
    assert.equal(sent.path, "/v1/hypervisor/evaluation-suites/acme.visible/revisions/2/release");
    assert.equal(sent.body.release_decision_ref, "decision://hypervisor/evaluations/acme.visible/release-2/n-7");
    assert.equal(sent.body.expected_head, H("6"));
  } finally { await daemon.close(); }
});

// The System's Improve mode (WP-C2's surface) with the evaluations of the System offered as a change's
// basis: a stand-in answering the Systems projection, the System's blueprints, its change sets and its
// evaluation results, and recording the change-set writes.
async function improveStandIn({ results, refuseResults = false }) {
  const BP = { id: "bp_0123456789abcdef", ref: "blueprint://bp_0123456789abcdef", name: "Lending desk", owner_ref: "org://acme", system_ref: SYSTEM };
  const calls = [];
  const cs = (status) => ({ schema_version: "ioi.change-set.v2", change_set_ref: "change://cs_1111111111111111", owner_ref: "org://acme", title: "t", basis_refs: [], status, subject: { kind: "blueprint", family_ref: BP.ref }, drafts: [], validation: status === "open" ? { outcome: "valid", findings: [] } : null, merge: null });
  const server = http.createServer((req, res) => {
    let raw = "";
    req.on("data", (c) => { raw += c; });
    req.on("end", () => {
      const url = new URL(req.url, "http://x");
      calls.push({ method: req.method, path: url.pathname, search: url.search, body: raw ? JSON.parse(raw) : null });
      const send = (status, json) => { res.writeHead(status, { "content-type": "application/json" }); res.end(JSON.stringify(json)); };
      if (url.pathname === "/v1/hypervisor/autonomous-systems/projection") return send(200, { ok: true, state: "ready", systems: [{ system_id: SYSTEM, status: "active" }] });
      if (url.pathname === "/v1/hypervisor/studio/blueprints") return send(200, { ok: true, blueprints: [BP] });
      if (url.pathname === "/v1/hypervisor/change-sets" && req.method === "GET") return send(200, { ok: true, change_sets: [{ ...cs("proposed"), basis_refs: ["evaluation-result://acme.res1"] }] });
      if (url.pathname === "/v1/hypervisor/evaluation-results") return refuseResults ? send(401, { ok: false, code: "request_principal_required" }) : send(200, { ok: true, records: results });
      if (url.pathname === "/v1/hypervisor/change-sets" && req.method === "POST") return send(201, { ok: true, change_set: cs("open") });
      if (url.pathname.endsWith("/validate")) return send(200, { ok: true, change_set: cs("open") });
      if (url.pathname.endsWith("/propose")) return send(200, { ok: true, change_set: cs("proposed") });
      return send(404, { ok: false, error: { code: "stand_in_route_absent", message: url.pathname } });
    });
  });
  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  return { url: `http://127.0.0.1:${server.address().port}`, calls, BP, close: () => new Promise((resolve) => server.close(resolve)) };
}

test("the Improve mode offers the evaluations of THIS System as a change's basis, sends the checked ones as basis_refs, and lists a change set's basis", async () => {
  const daemon = await improveStandIn({ results: [result("acme.res1", "acme.r1", SYSTEM, "fail"), result("acme.res2", "acme.r2", "system://acme/other", "pass")] });
  try {
    const { out, res } = response();
    const pathname = "/__ioi/system-workspace/acme/lending/improve";
    await handleSystemWorkspace({ method: "GET", url: pathname, headers: {} }, res, pathname, { daemonUrl: daemon.url, shell: (t, b) => b });
    assert.ok(daemon.calls.some((c) => c.path === "/v1/hypervisor/evaluation-results" && c.search === `?system_ref=${encodeURIComponent(SYSTEM)}`), "the System's results are read narrowed to it");
    assert.ok(out.body.includes(`data-system-change-set-basis="${SYSTEM}"`));
    assert.ok(out.body.includes('name="basis_ref" value="evaluation-result://acme.res1"'), "this System's result is offered");
    assert.ok(!out.body.includes("acme.res2"), "another System's is not");
    assert.ok(out.body.includes('data-change-set-basis="evaluation-result://acme.res1"'), "a change set's basis is listed on its row");
    const post = async (fields) => {
      const r = response();
      await handleSystemGenesisSurfaces({ method: "POST", url: "/__ioi/systems/change-sets/propose", headers: {} }, r.res, "/__ioi/systems/change-sets/propose", Buffer.from(new URLSearchParams(fields).toString()), { daemonUrl: daemon.url, shell: (t, b) => b });
      return r.out;
    };
    const fields = new URLSearchParams({ system_id: SYSTEM, form_nonce: "n-9", blueprint: daemon.BP.id, title: "Route incomplete applications to review", draft_description: "with review" });
    fields.append("basis_ref", "evaluation-result://acme.res1");
    await post(Object.fromEntries(fields));
    const opened = daemon.calls.find((c) => c.method === "POST" && c.path === "/v1/hypervisor/change-sets");
    assert.deepEqual(opened.body.basis_refs, ["evaluation-result://acme.res1"], "the checked evaluation travels as the change's basis");
    await post({ system_id: SYSTEM, form_nonce: "n-10", blueprint: daemon.BP.id, title: "t2", draft_description: "x" });
    const plain = daemon.calls.filter((c) => c.method === "POST" && c.path === "/v1/hypervisor/change-sets").at(-1);
    assert.ok(!("basis_refs" in plain.body), "no basis checked, none sent");
  } finally { await daemon.close(); }
  for (const [label, options] of [["none admitted", { results: [] }], ["unread", { results: [], refuseResults: true }]]) {
    const quiet = await improveStandIn(options);
    try {
      const { out, res } = response();
      const pathname = "/__ioi/system-workspace/acme/lending/improve";
      await handleSystemWorkspace({ method: "GET", url: pathname, headers: {} }, res, pathname, { daemonUrl: quiet.url, shell: (t, b) => b });
      assert.ok(!out.body.includes('name="basis_ref"'), `${label}: nothing is offered`);
      assert.ok(out.body.includes(options.refuseResults ? 'data-system-basis-unread="1"' : 'data-system-change-set-basis-none="1"'), `${label}: and it says why`);
      assert.ok(out.body.includes('data-system-propose-change-set="1"'), `${label}: the Propose form still renders`);
    } finally { await quiet.close(); }
  }
});

test("the System's Evidence mode lists the evaluations that measured it, read narrowed by system_ref, and says so honestly when none do", async () => {
  const daemon = await standIn({ evaluators: [], suites: [], runs: [run("acme.r1", SYSTEM), run("acme.r2", "system://acme/other")], results: [result("acme.res1", "acme.r1", SYSTEM, "fail")] });
  try {
    const html = await systemEvaluations({ url: daemon.url, headers: {} }, SYSTEM);
    assert.ok(daemon.calls.some((c) => c.path === "/v1/hypervisor/evaluation-runs" && c.search === `?system_ref=${encodeURIComponent(SYSTEM)}`), "runs are read narrowed to the System");
    assert.ok(daemon.calls.some((c) => c.path === "/v1/hypervisor/evaluation-results" && c.search === `?system_ref=${encodeURIComponent(SYSTEM)}`));
    assert.ok(html.includes(`data-system-evaluations="${SYSTEM}"`));
    assert.ok(html.includes('data-system-evaluation-run="evaluation-run://acme.r1"') && !html.includes("acme.r2"));
    assert.ok(html.includes('data-system-evaluation-result="evaluation-result://acme.res1" data-evaluation-verdict="fail"'));
    const none = await systemEvaluations({ url: daemon.url, headers: {} }, "system://acme/quiet");
    assert.ok(none.includes('data-system-evaluations-empty="1"'));
  } finally { await daemon.close(); }
});
