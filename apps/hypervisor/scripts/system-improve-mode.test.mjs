// R-240 journey WP-C2: a System's Improve mode — the change sets on its blueprints, proposed and
// merged through the mode's own forms — against a stand-in daemon that answers the reads and
// records every write, so what the surface SENDS is checked, never assumed.
//
//   node --test apps/hypervisor/scripts/system-improve-mode.test.mjs
import test from "node:test";
import assert from "node:assert/strict";
import http from "node:http";
import { handleSystemGenesisSurfaces, handleSystemWorkspace, IMPROVEMENT_CAMPAIGN_GAP } from "./system-genesis-surfaces.mjs";

const SYSTEM = "system://acme/lending";
const BP = { id: "bp_0123456789abcdef", ref: "blueprint://bp_0123456789abcdef", name: "Lending desk", owner_ref: "org://acme", system_ref: SYSTEM, content_hash: `sha256:${"a".repeat(64)}` };
const OTHER = { id: "bp_fedcba9876543210", ref: "blueprint://bp_fedcba9876543210", name: "Another System's", owner_ref: "org://acme", system_ref: "system://acme/other" };
const changeSet = (id, status, extra = {}) => ({
  schema_version: "ioi.change-set.v2", change_set_ref: `change://cs_${id}`, owner_ref: "org://acme", title: `title ${id}`, description: "", basis_refs: [], status,
  subject: { kind: "blueprint", family_ref: BP.ref, base_revision_ref: BP.content_hash, base_head_ref: `sha256:${"b".repeat(64)}` },
  drafts: [{ ordinal: 1, body: { description: "d" } }], validation: null, merge: null, ...extra,
});

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
      const cs = /^\/v1\/hypervisor\/change-sets\/(cs_[0-9a-f]{16})(?:\/([a-z]+))?$/u.exec(url.pathname);
      if (url.pathname === "/v1/hypervisor/autonomous-systems/projection") return send(200, { ok: true, state: "ready", systems: [{ system_id: SYSTEM, status: "active" }] });
      if (url.pathname === "/v1/hypervisor/studio/blueprints") return send(200, { ok: true, blueprints: state.blueprints });
      if (url.pathname === "/v1/hypervisor/change-sets" && req.method === "GET") return send(200, { ok: true, change_sets: state.changeSets });
      if (url.pathname === "/v1/hypervisor/change-sets" && req.method === "POST") return send(201, { ok: true, change_set: changeSet("1111111111111111", "open") });
      if (cs && req.method === "GET") return send(200, { ok: true, change_set: state.changeSets.find((c) => c.change_set_ref === `change://${cs[1]}`) });
      if (cs && cs[2] === "validate") return send(200, { ok: true, change_set: changeSet(cs[1], "open", { validation: { outcome: state.outcome, findings: state.findings || [] } }) });
      if (cs && cs[2] === "propose") return send(200, { ok: true, change_set: changeSet(cs[1], "proposed") });
      if (cs && cs[2] === "merge") return send(200, { ok: true, change_set: changeSet(cs[1], "merged", { merge: { resulting_head_ref: `sha256:${"c".repeat(64)}` } }) });
      if (cs && cs[2] === "abandon") return send(200, { ok: true, change_set: changeSet(cs[1], "abandoned") });
      return send(404, { ok: false, error: { code: "stand_in_route_absent", message: url.pathname } });
    });
  });
  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  return { url: `http://127.0.0.1:${server.address().port}`, calls, close: () => new Promise((resolve) => server.close(resolve)) };
}

function response() {
  const out = { status: 0, headers: {}, body: "" };
  return { out, res: { writeHead(status, headers = {}) { out.status = status; out.headers = headers; }, end(body = "") { out.body = String(body); } } };
}
const shell = (title, body) => `<title>${title}</title>${body}`;

async function improvePage(daemon) {
  const { out, res } = response();
  const pathname = "/__ioi/system-workspace/acme/lending/improve";
  await handleSystemWorkspace({ method: "GET", url: pathname, headers: {} }, res, pathname, { daemonUrl: daemon.url, shell });
  return out;
}
async function post(daemon, action, fields) {
  const { out, res } = response();
  await handleSystemGenesisSurfaces({ method: "POST", url: action, headers: {} }, res, action, Buffer.from(new URLSearchParams(fields).toString()), { daemonUrl: daemon.url, shell });
  return { ...out, q: new URLSearchParams(String(out.headers.Location || "").split("?")[1] || "") };
}

test("the Improve mode lists the change sets on THIS System's blueprints, offers Merge on a proposed one, and names the campaign gap", async () => {
  const daemon = await standIn({
    blueprints: [BP, OTHER],
    changeSets: [
      changeSet("aaaaaaaaaaaaaaaa", "proposed", { validation: { draft_ordinal: 1, outcome: "valid", findings: [] } }),
      changeSet("bbbbbbbbbbbbbbbb", "merged", { merge: { resulting_head_ref: `sha256:${"c".repeat(64)}`, resulting_revision_ref: `sha256:${"d".repeat(64)}`, branch_merge_plan_ref: `branch-merge://${"e".repeat(64)}` } }),
      { ...changeSet("cccccccccccccccc", "open"), subject: { kind: "blueprint", family_ref: OTHER.ref } },
    ],
  });
  try {
    const page = await improvePage(daemon);
    assert.equal(page.status, 200);
    assert.ok(daemon.calls.some((c) => c.path === "/v1/hypervisor/change-sets" && c.search === "?kind=blueprint"), "the change-set plane is read narrowed to blueprint subjects");
    assert.ok(page.body.includes(`data-system-change-sets="${SYSTEM}"`));
    assert.ok(page.body.includes('data-system-change-set="change://cs_aaaaaaaaaaaaaaaa" data-change-set-status="proposed"'));
    assert.ok(page.body.includes('data-change-set-merge="change://cs_aaaaaaaaaaaaaaaa"'), "a proposed change set offers Merge");
    assert.ok(page.body.includes(`data-change-set-resulting-head="sha256:${"c".repeat(64)}"`), "a merged one names the blueprint's resulting head");
    assert.ok(!page.body.includes("cs_cccccccccccccccc"), "another System's blueprint's change set is not listed");
    assert.ok(page.body.includes(`<option value="${BP.id}">`) && !page.body.includes(`<option value="${OTHER.id}">`), "the Propose form offers only this System's blueprints");
    assert.match(page.body, /name="form_nonce" value="[0-9a-f-]{36}"/u);
    assert.ok(page.body.includes(`data-system-named-gap="${IMPROVEMENT_CAMPAIGN_GAP}"`), "the campaign scope is its own named gap");
  } finally { await daemon.close(); }
});

test("Propose opens a blueprint change set owned by the blueprint's owner, validates and proposes it, each write with its own key", async () => {
  const daemon = await standIn({ blueprints: [BP], changeSets: [], outcome: "valid" });
  try {
    const graph = { nodes: [{ id: "desk" }, { id: "review" }], edges: [] };
    const out = await post(daemon, "/__ioi/systems/change-sets/propose", { system_id: SYSTEM, form_nonce: "n-1", blueprint: BP.id, title: "Add the review step", description: "why", draft_description: "with review", draft_graph_json: JSON.stringify(graph) });
    assert.equal(out.status, 303);
    assert.ok(String(out.headers.Location).startsWith("/systems/acme/lending/improve?"));
    assert.equal(out.q.get("acted"), "propose-change-set");
    assert.equal(out.q.get("record"), "change://cs_1111111111111111");
    const writes = daemon.calls.filter((c) => c.method === "POST");
    assert.deepEqual(writes.map((c) => c.path), ["/v1/hypervisor/change-sets", "/v1/hypervisor/change-sets/cs_1111111111111111/validate", "/v1/hypervisor/change-sets/cs_1111111111111111/propose"]);
    assert.deepEqual(writes[0].body.subject, { kind: "blueprint", family: BP.id });
    assert.equal(writes[0].body.owner_ref, "org://acme", "the change set is owned by its blueprint's owner");
    assert.deepEqual(writes[0].body.draft, { description: "with review", graph }, "a blank draft field keeps what the blueprint says");
    assert.equal(new Set(writes.map((c) => c.body.idempotency_key)).size, 3);
    assert.ok(writes.every((c) => c.body.owner_ref === "org://acme"));
  } finally { await daemon.close(); }
});

test("Propose refuses by name before any write: no draft, a graph that is not an object, a blueprint not bound to the System; an invalid draft stays open, named", async () => {
  const daemon = await standIn({ blueprints: [BP, OTHER], changeSets: [], outcome: "invalid", findings: [{ code: "studio_blueprint_name_invalid", message: "`name` must be a non-blank string" }] });
  try {
    const base = { system_id: SYSTEM, form_nonce: "n-2", blueprint: BP.id, title: "t" };
    assert.equal((await post(daemon, "/__ioi/systems/change-sets/propose", base)).q.get("refused"), "change_set_draft_empty");
    assert.equal((await post(daemon, "/__ioi/systems/change-sets/propose", { ...base, draft_graph_json: "[1]" })).q.get("refused"), "change_set_draft_graph_invalid");
    assert.equal((await post(daemon, "/__ioi/systems/change-sets/propose", { ...base, blueprint: OTHER.id, draft_description: "x" })).q.get("refused"), "change_set_subject_not_bound");
    assert.equal(daemon.calls.filter((c) => c.method === "POST").length, 0, "nothing was written");
    const invalid = await post(daemon, "/__ioi/systems/change-sets/propose", { ...base, draft_name: " " , draft_description: "x" });
    assert.equal(invalid.q.get("refused"), "change_set_draft_invalid");
    assert.match(invalid.q.get("reason"), /^studio_blueprint_name_invalid: /u);
    assert.equal(invalid.q.get("record"), "change://cs_1111111111111111");
    assert.ok(!daemon.calls.some((c) => c.path.endsWith("/propose")), "an invalid draft is never proposed");
  } finally { await daemon.close(); }
});

test("Merge merges a proposed change set on this System's blueprint and answers the resulting head; another System's is refused", async () => {
  const daemon = await standIn({
    blueprints: [BP, OTHER],
    changeSets: [changeSet("aaaaaaaaaaaaaaaa", "proposed"), { ...changeSet("cccccccccccccccc", "proposed"), subject: { kind: "blueprint", family_ref: OTHER.ref } }],
  });
  try {
    const merged = await post(daemon, "/__ioi/systems/change-sets/merge", { system_id: SYSTEM, change_set_ref: "change://cs_aaaaaaaaaaaaaaaa" });
    assert.equal(merged.q.get("acted"), "merge-change-set");
    assert.equal(merged.q.get("head"), `sha256:${"c".repeat(64)}`);
    const write = daemon.calls.find((c) => c.method === "POST");
    assert.equal(write.path, "/v1/hypervisor/change-sets/cs_aaaaaaaaaaaaaaaa/merge");
    assert.equal(write.body.owner_ref, "org://acme");
    const foreign = await post(daemon, "/__ioi/systems/change-sets/merge", { system_id: SYSTEM, change_set_ref: "change://cs_cccccccccccccccc" });
    assert.equal(foreign.q.get("refused"), "change_set_subject_not_bound");
    assert.equal(daemon.calls.filter((c) => c.method === "POST").length, 1, "the foreign change set was never merged");
  } finally { await daemon.close(); }
});
