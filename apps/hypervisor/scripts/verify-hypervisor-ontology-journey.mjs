#!/usr/bin/env node
// SURF-ontology primary journey verifier (next-legs Leg 3a).
//
// Proves, against an ISOLATED real daemon + serve lane (never the shared dev
// processes), the brief §5 acceptance that #219/#222 left open: create /
// version-discipline / read / search-filter / denial / CAS-conflict-and-
// recovery / receipt / reload / restart-survival journeys, plus the typed
// presence assertions for the proposal and saved-object-set families, which next-legs XIII landed
// — the two assertions that used to claim their ABSENCE probed URLs that were never routes and so
// could never have gone red; see the block at their site.
//
// Exit: 0 pass · 1 fail · 2 blocked (daemon binary or product bundle missing).
//
//   IOI_HYPERVISOR_DAEMON_BINARY  default target/debug/hypervisor-daemon
//   node apps/hypervisor/scripts/verify-hypervisor-ontology-journey.mjs

import { spawn } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import net from "node:net";
import { fileURLToPath } from "node:url";
import { emitVerifierCensus } from "./lib/verifier-census.mjs";

const HERE = path.dirname(fileURLToPath(import.meta.url));
const APP = path.resolve(HERE, "..");
const ROOT = path.resolve(APP, "..", "..");

const results = [];
const ok = (name, cond, detail) => results.push({ name, pass: !!cond, detail: detail || "" });

const freePort = () => new Promise((resolve, reject) => {
  const srv = net.createServer();
  srv.listen(0, "127.0.0.1", () => {
    const { port } = srv.address();
    srv.close(() => resolve(port));
  });
  srv.on("error", reject);
});

const waitFor = async (url, ms) => {
  const until = Date.now() + ms;
  while (Date.now() < until) {
    try {
      const r = await fetch(url);
      if (r.status < 500) return;
    } catch { /* not up yet */ }
    await new Promise((r) => setTimeout(r, 400));
  }
  throw new Error(`timeout waiting for ${url}`);
};

const daemonBinary = path.resolve(ROOT, process.env.IOI_HYPERVISOR_DAEMON_BINARY ?? "target/debug/hypervisor-daemon");
try {
  fs.accessSync(daemonBinary, fs.constants.X_OK);
} catch {
  console.error(`BLOCKED: daemon binary not executable at ${daemonBinary}`);
  process.exit(2);
}

const dataDir = fs.mkdtempSync(path.join(os.tmpdir(), "ioi-ontology-journey-"));
let daemon = null;
let serve = null;
let daemonPort = 0;
let DAEMON = "";
let SERVE = "";

async function startDaemon() {
  daemon = spawn(daemonBinary, [], {
    cwd: ROOT,
    env: {
      ...process.env,
      IOI_HYPERVISOR_DAEMON_ADDR: `127.0.0.1:${daemonPort}`,
      IOI_HYPERVISOR_DATA_DIR: dataDir,
      IOI_HYPERVISOR_MODEL_UPSTREAM: "http://127.0.0.1:1/v1",
    },
    stdio: ["ignore", "pipe", "pipe"],
  });
  let log = "";
  daemon.stdout.on("data", (c) => { log = `${log}${c}`.slice(-64000); });
  daemon.stderr.on("data", (c) => { log = `${log}${c}`.slice(-64000); });
  await waitFor(`${DAEMON}/healthz`, 30000);
  return () => log;
}

// Ontology writes are identity-first (rule E — the W1.1/G-2 finding is CLOSED): every
// authoring crossing carries the bootstrap operator's session; the daemon refuses an
// anonymous write typed-401 BEFORE any record load. Reads stay ungated.
let SESSION = "";
const sessionCookie = () => (SESSION ? { cookie: `ioi_session=${SESSION}` } : {});

const jd = (p, init) => fetch(`${DAEMON}${p}`, init ? { headers: { "content-type": "application/json", ...sessionCookie() }, ...init } : undefined)
  .then(async (r) => ({ status: r.status, body: await r.json().catch(() => ({})) }))
  .catch(() => ({ status: 0, body: {} }));

const pageText = (p) => fetch(`${SERVE}${p}`).then(async (r) => ({ status: r.status, text: await r.text() })).catch(() => ({ status: 0, text: "" }));

/**
 * A page fetched AS THE OPERATOR. `pageText` sends no cookie, which is right for the anonymous
 * probes above and wrong for these: object-instance search and the saved-object-set catalog are
 * identity-scoped, so an anonymous render answers 401 and the surface honestly reports "the plane
 * did not answer". Comparing that render against a SESSIONED direct probe would be comparing two
 * different callers and calling the difference a defect.
 */
const pageAs = (p) => fetch(`${SERVE}${p}`, { headers: { ...sessionCookie() } })
  .then(async (r) => ({ status: r.status, text: await r.text() })).catch(() => ({ status: 0, text: "" }));

const MANAGER_ACTIONS = `${"/__ioi/ontology/manager"}/actions`;
async function act(id, data, { anonymous = false } = {}) {
  const r = await fetch(`${SERVE}${MANAGER_ACTIONS}/${id}`, {
    method: "POST",
    headers: { "content-type": "application/x-www-form-urlencoded", ...(anonymous ? {} : sessionCookie()) },
    body: new URLSearchParams(data).toString(),
    redirect: "manual",
  }).catch(() => null);
  const location = r?.headers?.get("location") || "";
  const q = new URLSearchParams(location.split("?")[1]?.split("#")[0] ?? "");
  return { status: r?.status ?? 0, location, q };
}

/**
 * SCRAPE THE RENDERED FORM'S OWN FIELDS — scar 7, and the reason this journey cannot be satisfied by
 * a control that does not exist.
 *
 * A hand-built payload proves the DAEMON works, which was never in doubt: XIII landed all three of
 * these contracts. What was missing was a SURFACE, and a surface is only proven by submitting what
 * it actually rendered. So the journey parses the form out of the served HTML, takes its action URL
 * and every one of its fields with the values the surface put there, and posts THOSE. Delete the
 * form and there is nothing to scrape; render it with a wrong hidden value and the daemon refuses
 * the value the surface chose, not the value this test wished for.
 */
function scrapeForm(html, cls) {
  const open = new RegExp(`<form[^>]*class="[^"]*\\b${cls}\\b[^"]*"[^>]*>`, "u").exec(html);
  if (!open) return null;
  const action = /action="([^"]+)"/u.exec(open[0])?.[1] || "";
  const end = html.indexOf("</form>", open.index);
  const body = html.slice(open.index, end === -1 ? html.length : end);
  const fields = {};
  for (const m of body.matchAll(/<input\b([^>]*)>/gu)) {
    const attrs = m[1];
    const name = /\bname="([^"]*)"/u.exec(attrs)?.[1];
    if (!name) continue;
    fields[name] = /\bvalue="([^"]*)"/u.exec(attrs)?.[1] ?? "";
  }
  const disabled = /<button[^>]*\bdisabled\b/u.test(body);
  return { action, fields, disabled };
}

/** Submit exactly the scraped fields, with only the values a USER would type filled in. */
async function submitScraped(form, typed) {
  const r = await fetch(`${SERVE}${form.action}`, {
    method: "POST",
    headers: { "content-type": "application/x-www-form-urlencoded", ...sessionCookie() },
    body: new URLSearchParams({ ...form.fields, ...typed }).toString(),
    redirect: "manual",
  }).catch(() => null);
  const location = r?.headers?.get("location") || "";
  return { status: r?.status ?? 0, location, q: new URLSearchParams(location.split("?")[1]?.split("#")[0] ?? "") };
}

async function run() {
  daemonPort = await freePort();
  DAEMON = `http://127.0.0.1:${daemonPort}`;
  const daemonLogFn = await startDaemon();

  // Operator bootstrap mirrors scripts/smoke-product-surfaces.mjs; the yielded session is
  // now the AUTHORING identity every write below carries (identity-first ontology writes).
  const token = daemonLogFn().match(/ioi_bootstrap_[a-f0-9]{64}/gu)?.at(-1) ?? null;
  if (token) {
    const boot = await jd("/v1/hypervisor/auth/bootstrap", {
      method: "POST",
      body: JSON.stringify({ token, password: "ontology-journey-bootstrap-v1", email: "ontology-journey@ioi.local" }),
    });
    SESSION = boot.body?.session_token ?? "";
  }
  ok("operator bootstrap yields an authenticated session", SESSION.startsWith("ioi_sess_"), SESSION.slice(0, 12));

  const servePort = await freePort();
  const productUiPort = await freePort();
  SERVE = `http://127.0.0.1:${servePort}`;
  serve = spawn(process.execPath, [path.join(HERE, "serve-product-ui.mjs")], {
    cwd: APP,
    env: {
      ...process.env,
      PORT: String(servePort),
      PRODUCT_UI_PORT: String(productUiPort),
      IOI_PRODUCT_UI_PUBLIC: path.join(APP, "product-ui", "owned", "public"),
      IOI_HYPERVISOR_DAEMON_URL: DAEMON,
    },
    stdio: ["ignore", "pipe", "pipe"],
  });
  await waitFor(`${SERVE}/ontology/schema`, 30000);

  // -- canonical mounts render the preserved grammar -------------------------
  const schemaPage = await pageText("/ontology/schema");
  ok("canonical /ontology/schema renders the Manager", schemaPage.status === 200 && schemaPage.text.includes("og-inspector"), `status ${schemaPage.status}`);
  const explorePage = await pageText("/ontology/explore");
  ok("canonical /ontology/explore renders the Explorer", explorePage.status === 200 && explorePage.text.includes("oe-inspector"), `status ${explorePage.status}`);

  // -- create ---------------------------------------------------------------
  const domain = `journey-${Date.now().toString(36)}`;
  const created = await act("create-ontology", { domain, version: "1.0.0", description: "journey ontology" });
  const ontId = created.q.get("record") || "";
  ok("create-ontology crosses with a receipt", created.status === 303 && created.q.get("acted") === "create-ontology" && (created.q.get("receipt") || "").length > 0, created.location.slice(0, 140));
  const afterCreate = await jd(`/v1/hypervisor/odk/domain-ontologies/${ontId}`);
  ok("created ontology reads back at revision 1", afterCreate.status === 200 && afterCreate.body?.ontology?.revision === 1 && afterCreate.body?.ontology?.domain === domain, `rev ${afterCreate.body?.ontology?.revision}`);

  // -- version discipline: five upserts + metadata, each a receipted revision -
  const steps = [
    ["upsert-object-type", { ontology: ontId, def_id: "obj_journey", name: "JourneyObject", description: "typed object" }],
    ["upsert-property", { ontology: ontId, object_type_id: "obj_journey", def_id: "prop_name", name: "name", value_type: "string", required: "on" }],
    ["upsert-object-type", { ontology: ontId, def_id: "obj_journey", name: "JourneyObject", description: "typed object", title_property: "prop_name" }],
    ["upsert-value-type", { ontology: ontId, def_id: "vt_stage", name: "Stage", base: "enum", enum_values: "draft,active" }],
    ["upsert-link-type", { ontology: ontId, def_id: "lnk_owner", name: "owns", from: "obj_journey", to: "obj_journey", cardinality: "one_to_many" }],
    ["upsert-action-type", { ontology: ontId, def_id: "act_review", name: "review", kind: "modify_object", applies_to: "obj_journey" }],
    ["update-metadata", { ontology: ontId, domain, version: "1.1.0", description: "journey ontology amended" }],
  ];
  let expectedRev = 1;
  for (const [actionId, fields] of steps) {
    const res = await act(actionId, fields);
    expectedRev += 1;
    ok(`${actionId} crosses with a receipt`, res.status === 303 && res.q.get("acted") === actionId && (res.q.get("receipt") || "").length > 0, res.location.slice(0, 140));
  }
  const afterSteps = await jd(`/v1/hypervisor/odk/domain-ontologies/${ontId}`);
  const com = afterSteps.body?.ontology?.canonical_object_model ?? {};
  ok("revision advanced once per mutation", afterSteps.body?.ontology?.revision === expectedRev, `rev ${afterSteps.body?.ontology?.revision}, expected ${expectedRev}`);
  ok("canonical object model holds the authored definitions",
    JSON.stringify(com).includes("obj_journey") && JSON.stringify(com).includes("vt_stage") && JSON.stringify(com).includes("lnk_owner"),
    Object.keys(com).join(","));

  // -- receipts are durable objects -----------------------------------------
  let receiptCount = 0;
  try {
    receiptCount = fs.readdirSync(path.join(dataDir, "odk-ontology-receipts")).length;
  } catch { receiptCount = -1; }
  ok("every mutation left a durable receipt", receiptCount >= expectedRev, `${receiptCount} receipts on disk`);

  // -- CAS conflict and recovery --------------------------------------------
  const stale = await jd(`/v1/hypervisor/odk/domain-ontologies/${ontId}`, {
    method: "PATCH",
    body: JSON.stringify({ expected_revision: 1, description: "stale write" }),
  });
  ok("stale expected_revision refuses with the typed conflict", stale.status === 409 && JSON.stringify(stale.body).includes("odk_revision_conflict"), `status ${stale.status}`);
  const recovered = await act("upsert-object-type", { ontology: ontId, def_id: "obj_recovered", name: "Recovered", description: "post-conflict" });
  expectedRev += 1;
  ok("a fresh read-and-write recovers after the conflict", recovered.status === 303 && (recovered.q.get("receipt") || "").length > 0, recovered.location.slice(0, 120));

  // -- typed refusal surfaces its REAL code through the UI lane ---------------
  const masked = await act("upsert-object-type", { ontology: ontId, def_id: "obj_journey", name: "JourneyObject", title_property: "prop_missing" });
  ok("a plane refusal keeps its typed code through the UI (never receipt_missing)",
    masked.status === 303 && masked.q.get("refused") === "ontology_ref_unresolved",
    masked.location.slice(0, 130));

  // -- denial ----------------------------------------------------------------
  const denied = await act("upsert-object-type", { ontology: "ont-does-not-exist", def_id: "x", name: "X" });
  ok("missing ontology denies with the typed refusal", denied.status === 303 && denied.q.get("refused") === "odk_ontology_not_found", denied.location.slice(0, 120));

  // -- read / search-filter / health / history -------------------------------
  const filtered = await pageText(`/ontology/schema?ontology=${encodeURIComponent(ontId)}&section=object-types`);
  ok("Manager reads back the authored type through the canonical mount", filtered.status === 200 && filtered.text.includes("JourneyObject"), "");
  const scoped = await pageText(`/ontology/explore?ontology=${encodeURIComponent(ontId)}`);
  ok("Explorer scope selector resolves the ontology", scoped.status === 200 && scoped.text.includes(domain), "");
  const history = await jd(`/v1/hypervisor/odk/domain-ontologies/${ontId}/history`);
  ok("history records the mutation trail", history.status === 200 && JSON.stringify(history.body).length > 2, `status ${history.status}`);
  const historyReceipts = Array.isArray(history.body?.receipts) ? history.body.receipts : [];
  ok("receipts bind the resolved acting principal (INV-37)",
    historyReceipts.length > 0 && historyReceipts.every((r) => typeof r.acting_principal_ref === "string" && r.acting_principal_ref.startsWith("user://")),
    historyReceipts[0]?.acting_principal_ref ?? "no receipts");
  const health = await jd(`/v1/hypervisor/odk/domain-ontologies/${ontId}/health`);
  ok("health answers for the authored ontology", health.status === 200, `status ${health.status}`);

  // -- the two families next-legs XIII LANDED, asserted at the routes that actually exist ---------
  //
  // THESE TWO ASSERTIONS USED TO CLAIM THESE FAMILIES WERE ABSENT, AND THEY COULD NEVER HAVE FAILED.
  // They probed `/domain-ontologies/:id/proposals` and `POST /materialized-object-sets` — one was
  // never a route in any build, the other is registered GET-only — so both answered 404/405 for
  // reasons that had nothing to do with the subject, and the gate stayed green while the estate's
  // truth moved underneath it. A merge-blocking audit found them AFTER next-legs XIII landed both
  // families: CI-wired, floor-pinned, and cited in the ledger as corroborating evidence, with two
  // false assertion NAMES hashed into the floors digest as certified estate truth. An assertion
  // whose probe was never real is the purest form of a decorative assertion — it cannot go red on
  // its own finding in any world.
  //
  // They now probe the REAL routes and assert PRESENCE, so this gate fails if either family is
  // withdrawn — which is what an absence claim was supposed to buy and never did.
  const proposals = await jd("/v1/hypervisor/odk/ontology-proposals");
  ok("the ontology PROPOSAL family is REGISTERED at its route and refuses this anonymous probe — this journey sends no session, so what is proven is registration plus an identity-first refusal, not that the family answers; it replaces an assertion that claimed the family was ABSENT while probing a URL that was never a route in any build",
    proposals.status === 401, `status ${proposals.status}`);
  const savedSet = await jd("/v1/hypervisor/odk/saved-object-sets");
  ok("the SAVED-OBJECT-SET family is REGISTERED at its route and refuses this anonymous probe — registration plus an identity-first refusal, not that the family answers; it replaces an assertion that claimed saved-set authoring was ABSENT while probing a GET-only route with a POST",
    savedSet.status === 401, `status ${savedSet.status}`);

  // ================= ACC-A: the three SURFACE CONTROLS next-legs XIV Leg 1 bound ==================
  //
  // XIII landed these contracts and XIV found the atlas still saying "what is missing is a SURFACE
  // control bound to it". Each journey below drives the control the way a user does: fetch the page,
  // SCRAPE THE FORM THE SURFACE RENDERED, submit those exact fields, and then confirm the effect in
  // the daemon's own truth. A hand-built payload would prove the contract, which was never in doubt.

  // ---- (1) OBJECT-INSTANCE SEARCH — a read control, and its two empties are different facts.
  const searchPage = await pageAs(`/__ioi/ontology/explorer?ontology=${encodeURIComponent(ontId)}&oq=zzz-no-such-instance`);
  const searchDirect = await jd("/v1/hypervisor/odk/object-instance-search", {
    method: "POST", body: JSON.stringify({ ontology_ref: ontId, q: "zzz-no-such-instance", limit: 25 }),
  });
  ok("the explorer's object-search control is a BOUND form, not a disabled input — it renders with a name the surface submits and a live submit control",
    /<input[^>]*class="oe-objq"[^>]*name="oq"/u.test(searchPage.text) && !/class="oe-objsearch"[^>]*>[^<]*<input[^>]*disabled/u.test(searchPage.text),
    `page ${searchPage.status}`);
  // THE HALF THAT CARRIES THE FINDING: not that a results box appeared, but that the box says what
  // the daemon said. The daemon types corpus-absent apart from query-unmatched precisely so a
  // surface cannot tell a user their query missed when nothing exists to miss.
  const absenceCode = searchDirect.body?.absence?.code ?? "";
  ok("the rendered search result reports the DAEMON's typed absence state, distinguishing an absent corpus from a query that matched nothing — rendering both as 'no results' would tell a user their query missed when there was nothing to miss",
    absenceCode === "object_instance_corpus_absent"
      ? /Nothing is materialized in this scope/u.test(searchPage.text)
      : absenceCode === "object_instance_query_unmatched"
        ? /No instance matched/u.test(searchPage.text)
        : /match(es)?<\/b>/u.test(searchPage.text),
    `daemon absence=${absenceCode || "none"}`);

  // ---- (2) SAVED OBJECT SET — an ordinary governed mutation, driven from the rendered form.
  const explorerPage = await pageAs(`/__ioi/ontology/explorer?ontology=${encodeURIComponent(ontId)}&oq=journey-selection`);
  const saveForm = scrapeForm(explorerPage.text, "oe-saveform");
  ok("the explorer renders a SAVE form carrying the selection it is displaying — the fields are the surface's own, so a control that saves something other than what it shows cannot pass this journey",
    !!saveForm && String(saveForm.fields.ontology_ref || "").includes(ontId) && saveForm.fields.q === "journey-selection" && "name" in saveForm.fields,
    saveForm ? `action=${saveForm.action} fields=${Object.keys(saveForm.fields).join(",")}` : "no form rendered");
  const saved = saveForm ? await submitScraped(saveForm, { name: "Journey exploration" }) : { status: 0, q: new URLSearchParams() };
  ok("submitting the form the surface rendered creates a saved object set through the family's OWNING plane — an ordinary governed mutation, no wallet crossing and no second admission path",
    saved.status === 303 && !saved.q.get("refused"), `${saved.status} ${saved.location?.slice(0, 110) ?? ""}`);
  const savedList = await jd("/v1/hypervisor/odk/saved-object-sets", { method: "GET" });
  const savedRec = (savedList.body?.saved_object_sets ?? []).find((x) => x && x.name === "Journey exploration");
  ok("the saved set is daemon truth with the SELECTION the form displayed, attributed to the acting principal — the surface's control and the daemon's record agree on what was saved",
    !!savedRec && savedRec.selection?.q === "journey-selection" && String(savedRec.saved_by || "").length > 0 && savedRec.schema_version === "ioi.hypervisor.odk.saved-object-set.v1",
    savedRec ? `${savedRec.ref} sel=${JSON.stringify(savedRec.selection)}` : `${(savedList.body?.saved_object_sets ?? []).length} sets`);
  // THE REFUSAL PATH IS PART OF THE CONTROL. A saved set with no selection saves nothing, and the
  // surface must say so rather than post an empty selection and relay a 400 without context.
  const emptySave = saveForm ? await submitScraped({ ...saveForm, fields: { ...saveForm.fields, q: "", object_type_id: "" } }, { name: "Empty" }) : { q: new URLSearchParams() };
  ok("a save with no selection is REFUSED typed and nothing is recorded — the control refuses in its own words rather than relaying a bare 400",
    emptySave.q.get("refused") === "saved_object_set_selection_required", emptySave.q.get("refused") || "not refused");

  // ---- (3) ONTOLOGY PROPOSAL — the review interval, proposed against the revision on screen.
  const proposalsPage = await pageAs(`/__ioi/ontology/manager?ontology=${encodeURIComponent(ontId)}&section=proposals`);
  const propForm = scrapeForm(proposalsPage.text, "og-propform");
  ok("the manager's Proposals rail item opens a BOUND pane with a propose form — the rail item was a disabled named gap while the plane existed, which is the defect this leg closes",
    !!propForm && "title" in propForm.fields && "change_description" in propForm.fields,
    propForm ? `action=${propForm.action}` : "no form rendered");
  const proposed = propForm ? await submitScraped(propForm, { title: "Journey proposal", change_description: "proposed by the ACC-A journey" }) : { status: 0, q: new URLSearchParams() };
  ok("submitting the rendered propose form records a proposal WITH a receipt — an ordinary governed mutation against the plane that owns the family",
    proposed.status === 303 && !proposed.q.get("refused") && !!proposed.q.get("receipt"),
    proposed.q.get("receipt") || proposed.q.get("refused") || `status ${proposed.status}`);
  const propList = await jd("/v1/hypervisor/odk/ontology-proposals", { method: "GET" });
  const propRec = (propList.body?.ontology_proposals ?? []).find((x) => x && x.title === "Journey proposal");
  ok("the proposal is daemon truth, PINNED TO THE REVISION IT WAS WRITTEN AGAINST and attributed to the proposer — the review interval is only meaningful if the proposal cannot silently rebase",
    !!propRec && propRec.status === "open" && typeof propRec.based_on_revision === "number" && String(propRec.proposed_by || "").length > 0,
    propRec ? `${propRec.ref} r${propRec.based_on_revision} by ${propRec.proposed_by}` : `${(propList.body?.ontology_proposals ?? []).length} proposals`);
  const emptyProp = propForm ? await submitScraped(propForm, { title: "Names nothing" }) : { q: new URLSearchParams() };
  ok("a proposal naming NO change is refused typed — an empty proposal proposes nothing, and the control says so before the daemon has to",
    emptyProp.q.get("refused") === "ontology_proposal_change_required", emptyProp.q.get("refused") || "not refused");

  // -- identity gate (W1.1/G-2 finding CLOSED): anonymous authoring refuses typed ----
  // Rule E — the refusal is owed BEFORE any record load: the serve action lane without a
  // session and a direct daemon write without identity both answer the typed
  // request_principal_required, never a silent success and never a 404 existence oracle.
  const anonAct = await act("upsert-object-type", { ontology: ontId, def_id: "obj_anon", name: "Anon" }, { anonymous: true });
  ok("anonymous serve action refuses typed (request_principal_required, no receipt)",
    anonAct.status === 303 && anonAct.q.get("refused") === "request_principal_required" && !anonAct.q.get("acted") && !anonAct.q.get("receipt"),
    anonAct.location.slice(0, 130));
  const anonCreate = await fetch(`${DAEMON}/v1/hypervisor/odk/domain-ontologies`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ domain: "anon-domain" }),
  }).then(async (r) => ({ status: r.status, body: await r.json().catch(() => ({})) })).catch(() => ({ status: 0, body: {} }));
  ok("anonymous direct daemon create answers typed 401 request_principal_required",
    anonCreate.status === 401 && anonCreate.body?.ok === false && anonCreate.body?.code === "request_principal_required",
    `status ${anonCreate.status} code ${anonCreate.body?.code}`);
  const anonPatch = await fetch(`${DAEMON}/v1/hypervisor/odk/domain-ontologies/${ontId}`, {
    method: "PATCH",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ description: "anon write" }),
  }).then(async (r) => ({ status: r.status, body: await r.json().catch(() => ({})) })).catch(() => ({ status: 0, body: {} }));
  ok("anonymous direct daemon patch answers typed 401 before the record load (rule E)",
    anonPatch.status === 401 && anonPatch.body?.code === "request_principal_required",
    `status ${anonPatch.status} code ${anonPatch.body?.code}`);
  const unchanged = await jd(`/v1/hypervisor/odk/domain-ontologies/${ontId}`);
  ok("anonymous attempts changed nothing", unchanged.status === 200 && unchanged.body?.ontology?.revision === expectedRev, `rev ${unchanged.body?.ontology?.revision}`);

  // -- restart survival -------------------------------------------------------
  daemon.kill("SIGTERM");
  await new Promise((r) => setTimeout(r, 1200));
  await startDaemon();
  const afterRestart = await jd(`/v1/hypervisor/odk/domain-ontologies/${ontId}`);
  ok("ontology survives a daemon restart at the same revision",
    afterRestart.status === 200 && afterRestart.body?.ontology?.revision === expectedRev,
    `rev ${afterRestart.body?.ontology?.revision}, expected ${expectedRev}`);
  let receiptsAfter = 0;
  try { receiptsAfter = fs.readdirSync(path.join(dataDir, "odk-ontology-receipts")).length; } catch { receiptsAfter = -1; }
  ok("receipts survive the restart", receiptsAfter >= receiptCount && receiptCount > 0, `${receiptsAfter} receipts`);
  const reload = await pageText(`/ontology/schema?ontology=${encodeURIComponent(ontId)}`);
  ok("canonical mount re-renders the authored ontology after restart", reload.status === 200 && reload.text.includes(domain), "");

  // ---- the thirteen governed controls: REAL, or a DISABLED NAMED GAP. Never silently absent. ----
  //
  // The frozen census puts 13 of the estate's 24 governed_receipted_action controls on this
  // surface. Six were real (create-ontology + the five inspector EDIT forms). The other seven —
  // the five New-menu create entries, the section New-object-type button, and the 5-step wizard —
  // had daemon authority that SHIPPED and module actions that were DECLARED, yet no rendered
  // gc_entry: with nothing selected the Manager rendered no authoring form at all, and the gaps note
  // never named them. Silently absent is the one state the read-truth / local-UI-state /
  // receipted-authority / disabled-named-gap ladder forbids, and no assertion here could see it,
  // because every authoring assertion drove the action lane directly rather than asking the page
  // whether a control existed.
  const gc_CREATE_ENTRIES = [
    { kind: "object-type", action: "upsert-object-type" },
    { kind: "link-type", action: "upsert-link-type" },
    { kind: "action-type", action: "upsert-action-type" },
    { kind: "value-type", action: "upsert-value-type" },
    { kind: "function", action: "upsert-action-type" },
  ];
  // SUBMIT WHAT THE FORM RENDERS. An assertion that hand-picks field values proves the ACTION works,
  // never that the FORM does — and a form is what a user has. The first cut asserted exactly that
  // and stayed green while `New -> Action type` shipped a hidden kind="action" the daemon's enum
  // refuses on every submit: a control that renders, claims to be real, and can never succeed.
  // This scrapes each rendered form's own fields (hidden values, first non-empty <option>) and
  // POSTs that, supplying only the free-text id.
  const gc_formFields = (html, action) => {
    const at = html.indexOf(`action="/__ioi/ontology/manager/actions/${action}"`);
    if (at < 0) return null;
    const form = html.slice(at, html.indexOf("</form>", at));
    const data = {};
    for (const m of form.matchAll(/<input[^>]*name="([^"]+)"[^>]*>/gu)) {
      if (/type="checkbox"/u.test(m[0])) continue;
      const v = m[0].match(/value="([^"]*)"/u);
      data[m[1]] = v ? v[1] : "";
    }
    for (const m of form.matchAll(/<select[^>]*name="([^"]+)"[^>]*>([\s\S]*?)<\/select>/gu)) {
      const opts = [...m[2].matchAll(/<option value="([^"]*)"/gu)].map((o) => o[1]).filter(Boolean);
      data[m[1]] = opts[0] ?? "";
    }
    return data;
  };
  const gc_missingEntries = [];
  const gc_deadEntries = [];
  for (const gc_entry of gc_CREATE_ENTRIES) {
    const gc_pane = await pageText(`/ontology/schema?ontology=${encodeURIComponent(ontId)}&section=create&newKind=${gc_entry.kind}`);
    const gc_fields = gc_formFields(gc_pane.text, gc_entry.action);
    if (!gc_fields || !("create_new" in gc_fields)) { gc_missingEntries.push(gc_entry.kind); continue; }
    const gc_sent = { ...gc_fields, ontology: ontId, def_id: `${gc_entry.kind.replace(/-/gu, "_")}_probe`, name: `Probe ${gc_entry.kind}` };
    const gc_res = await act(gc_entry.action, gc_sent);
    if (gc_res.q.get("refused") || !gc_res.q.get("receipt")) gc_deadEntries.push(`${gc_entry.kind}:${gc_res.q.get("refused") || "no-receipt"}`);
  }
  ok("every New-menu create entry renders a REAL create form, not an absence",
    gc_missingEntries.length === 0, gc_missingEntries.length ? `missing: ${gc_missingEntries.join(", ")}` : `${gc_CREATE_ENTRIES.length}/5 reachable`);
  ok("every create entry SUBMITS as rendered — no control that renders but can never succeed",
    gc_deadEntries.length === 0, gc_deadEntries.length ? `refused as rendered: ${gc_deadEntries.join(", ")}` : `${gc_CREATE_ENTRIES.length}/5 submit`);

  const gc_discover = await pageText(`/ontology/schema?ontology=${encodeURIComponent(ontId)}`);
  ok("the section-level New object type control is rendered on the surface",
    /<a[^>]+class="og-newobj"[^>]+href="[^"]*newKind=object-type/.test(gc_discover.text), "anchor + href pinned");

  // The create lane AUTHORS — proven on durable truth, not on the redirect.
  const gc_beforeCreate = await jd(`/v1/hypervisor/odk/domain-ontologies/${ontId}`);
  const gc_lnkBefore = ((gc_beforeCreate.body?.ontology?.canonical_object_model || {}).link_types || []).length;
  const madeLink = await act("upsert-link-type", { ontology: ontId, create_new: "1", def_id: "lnk_journey", name: "Journey link", from: "obj_journey", to: "obj_journey", cardinality: "one_to_many" });
  const gc_afterCreate = await jd(`/v1/hypervisor/odk/domain-ontologies/${ontId}`);
  const gc_lnkAfter = ((gc_afterCreate.body?.ontology?.canonical_object_model || {}).link_types || []);
  ok("a create entry authors a NEW definition with a receipt, readable in durable truth",
    madeLink.q.get("acted") === "upsert-link-type" && !!madeLink.q.get("receipt")
      && gc_lnkAfter.length === gc_lnkBefore + 1 && gc_lnkAfter.some((l) => l.id === "lnk_journey"),
    `${gc_lnkBefore} -> ${gc_lnkAfter.length} receipt ${madeLink.q.get("receipt") ? "yes" : "no"}`);

  // CREATE MEANS CREATE. `upsert-*` merges on an existing id, so without this the create gc_entry
  // would silently rewrite a definition and still return a receipt.
  const gc_revBeforeDup = gc_afterCreate.body?.ontology?.revision;
  const gc_dup = await act("upsert-link-type", { ontology: ontId, create_new: "1", def_id: "lnk_journey", name: "CLOBBERED", from: "obj_journey", to: "obj_journey", cardinality: "one_to_one" });
  const gc_afterDup = await jd(`/v1/hypervisor/odk/domain-ontologies/${ontId}`);
  const gc_dupLink = ((gc_afterDup.body?.ontology?.canonical_object_model || {}).link_types || []).find((l) => l.id === "lnk_journey");
  ok("a create entry REFUSES a duplicate id typed — it never merges over an existing definition",
    gc_dup.q.get("refused") === "ontology_definition_exists", `refused ${gc_dup.q.get("refused") || "<none>"}`);
  ok("the refused duplicate changed NOTHING — same revision, original name intact",
    gc_afterDup.body?.ontology?.revision === gc_revBeforeDup && gc_dupLink?.name === "Journey link",
    `rev ${gc_revBeforeDup} -> ${gc_afterDup.body?.ontology?.revision}, name ${gc_dupLink?.name}`);

  // The EDIT lane is the other half of the distinction: same id, no create intent, merges.
  const gc_edited = await act("upsert-link-type", { ontology: ontId, def_id: "lnk_journey", name: "Journey link renamed", from: "obj_journey", to: "obj_journey", cardinality: "one_to_many" });
  const gc_afterEdit = await jd(`/v1/hypervisor/odk/domain-ontologies/${ontId}`);
  ok("the EDIT lane still merges onto the same id — create and edit stay distinct governed acts",
    gc_edited.q.get("acted") === "upsert-link-type"
      && ((gc_afterEdit.body?.ontology?.canonical_object_model || {}).link_types || []).find((l) => l.id === "lnk_journey")?.name === "Journey link renamed",
    "renamed in place");

  // THE PROPERTY LANE IS THE ONE LABELLED "Add", AND IT WAS THE ONE THAT STILL CLOBBERED.
  // A merge-blocking review found the create guard was declared for `upsert-property` but dead:
  // no create entry existed for properties, and the only property-authoring control — the object
  // type inspector's "Add a property" form — sent no create intent, so retyping an existing
  // property id silently changed its value type and returned a receipt for it. The guard is now on
  // that form; without this assertion, removing it again is invisible (it was: the mutation that
  // strips it passed 44/44).
  await act("upsert-object-type", { ontology: ontId, create_new: "1", def_id: "obj_propowner", name: "Prop owner" });
  await act("upsert-property", { ontology: ontId, create_new: "1", object_type_id: "obj_propowner", def_id: "prop_amount", name: "Amount", value_type: "string" });
  // DRIVE THE FORM, NOT THE ACTION. Posting `create_new` by hand proves the ACTION refuses a
  // duplicate; it says nothing about whether the CONTROL sends the create intent. The first version
  // of this assertion did exactly that and the mutation stripping `create_new` from the rendered
  // "Add a property" form passed 46/46 — twice. The fields below come from the form itself.
  const gc_addPane = await pageText(`/ontology/schema?ontology=${encodeURIComponent(ontId)}&section=object-types&definitionKind=object-type&definitionId=obj_propowner`);
  const gc_addFields = gc_formFields(gc_addPane.text, "upsert-property") || {};
  const gc_propDup = await act("upsert-property", { ...gc_addFields, ontology: ontId, object_type_id: "obj_propowner", def_id: "prop_amount", name: "Amount", value_type: "integer" });
  const gc_afterProp = await jd(`/v1/hypervisor/odk/domain-ontologies/${ontId}`);
  const gc_prop = (((gc_afterProp.body?.ontology?.canonical_object_model || {}).object_types || [])
    .find((t) => t.id === "obj_propowner")?.properties || []).find((x) => x.id === "prop_amount");
  ok("the rendered ADD A PROPERTY form carries the create intent — a duplicate id is refused, never silently retyped",
    gc_propDup.q.get("refused") === "ontology_definition_exists" && gc_prop?.value_type === "string",
    `refused ${gc_propDup.q.get("refused") || "<none>"} · value_type ${gc_prop?.value_type}`);

  // The property EDIT lane exists, or making Add create-only would have removed the ability to
  // change a property at all.
  const gc_propEdit = await pageText(`/ontology/schema?ontology=${encodeURIComponent(ontId)}&section=object-types&definitionKind=property&definitionId=${encodeURIComponent("obj_propowner.prop_amount")}`);
  ok("a property EDIT lane is rendered, so create-only Add does not strand the definition",
    /action="\/__ioi\/ontology\/manager\/actions\/upsert-property"/.test(gc_propEdit.text) && !/name="create_new"[^>]*>\s*<label[^>]*>Property id/.test(gc_propEdit.text),
    "edit form present");

  // The one control of the thirteen that stays a gap says so where the gaps are named.
  ok("the 5-step create wizard is a NAMED gap on the surface, not a silent absence",
    gc_discover.text.includes("5-step create wizard"), "named in the gaps note");


  // -- G-8 posture matrix (browser) ------------------------------------------
  let pw = null;
  try { pw = await import("playwright"); } catch { pw = null; }
  if (!pw) {
    ok("posture matrix skipped — playwright unavailable", false, "install playwright to run the browser matrix");
  } else {
    const browser = await pw.chromium.launch();
    for (const [name, opts] of [
      ["light-desktop", { viewport: { width: 1440, height: 900 }, colorScheme: "light" }],
      ["dark-desktop", { viewport: { width: 1440, height: 900 }, colorScheme: "dark" }],
      ["narrow-reduced-motion", { viewport: { width: 390, height: 844 }, colorScheme: "light", reducedMotion: "reduce" }],
    ]) {
      const ctx = await browser.newContext(opts);
      const page = await ctx.newPage();
      const errors = [];
      page.on("console", (m) => { if (m.type() === "error") errors.push(m.text()); });
      const resp = await page.goto(`${SERVE}/ontology/schema?ontology=${encodeURIComponent(ontId)}`, { waitUntil: "networkidle", timeout: 45000 }).catch(() => null);
      const body = resp ? await page.evaluate(() => document.body.innerText) : "";
      await page.keyboard.press("Tab");
      const focused = resp ? await page.evaluate(() => document.activeElement?.tagName ?? "") : "";
      ok(`posture ${name}: renders, keyboard-focusable, zero console errors`,
        resp && resp.status() === 200 && body.includes(domain) && errors.length === 0 && focused !== "" && focused !== "BODY",
        errors[0]?.slice(0, 100) ?? `focus ${focused}`);
      await ctx.close();
    }
    await browser.close();
  }
}

run().then(() => {
  const fails = results.filter((r) => !r.pass);
  for (const r of results) console.log(`${r.pass ? "PASS" : "FAIL"}  ${r.name}${r.detail ? ` — ${r.detail}` : ""}`);
  console.log(`\n${results.length - fails.length}/${results.length} passed`);
  emitVerifierCensus({ verifierId: "ontology-journey", sourceUrl: import.meta.url, results });
  cleanup();
  process.exit(fails.length ? 1 : 0);
}).catch((e) => {
  console.error("verifier crashed:", e);
  cleanup();
  process.exit(1);
});

function cleanup() {
  try { serve?.kill("SIGTERM"); } catch { /* gone */ }
  try { daemon?.kill("SIGTERM"); } catch { /* gone */ }
  try { fs.rmSync(dataDir, { recursive: true, force: true }); } catch { /* keep */ }
}
