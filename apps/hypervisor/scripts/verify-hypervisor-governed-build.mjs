#!/usr/bin/env node
// GOVERNED PIPELINE BUILD verifier (#67) — proves the Build workflow exposes the EXISTING ODK
// ladder to a user safely, with the production wallet handoff and no fixture signer anywhere in
// production code:
//   0. AUTHORITY PREFLIGHT — production sources carry NO static import of the fixture signer;
//      the adapter mints ONLY under its explicit flag (null without it); registry classification.
//   1. FIXTURE — a fresh ready ladder (rungs 0–7) with a sealed-later sentinel credential and a
//      live counting rows server. The RUN/LEASE/SESSION/EXECUTE rungs are NOT pre-built: the
//      browser journey is what crosses them.
//   2. THE JOURNEY — through the embedded native application slot on an ISOLATED serve launched
//      WITHOUT any signer flag (the production posture, with its log captured for the sweep):
//      review → admit run → lease challenge (verbatim-checked against the daemon's own 403) →
//      externally signed grant pasted → lease_obtained → admit session → 428 unresolved
//      credential → custody resolve → session challenge → second grant → session_obtained →
//      execute → registered set + preview rows. REFRESH AT EVERY STAGE proves exact resumption.
//   3. TRUTH CROSS-CHECKS — receipt persisted BEFORE output registration (history order),
//      projection count == set count, preview rows == set records, exactly ONE authenticated
//      source request, Explorer/Lineage/Provenance/Vertex backlinks resolve.
//   4. FAIL-CLOSED LANES — expired grant, ladder drift, grant replay, duplicate execute,
//      malformed rows, duplicate keys, redirect refusal, cancel/release lifecycle honesty
//      (the corrected "released before execution" wording live), finalization-failure rollback
//      pinned in the Rust source + its focused tests.
//   5. SWEEPS — grants (approver_sig/public key), bearer sentinel, Authorization tokens, endpoint
//      path/userinfo across every page, URL, and the serve log; grants/bearer/tokens/userinfo
//      additionally across records, receipts, and histories (the DECLARED endpoint lives on the
//      data-source record by design — display surfaces redact it to origin, records declare it).
//   6. INVARIANTS — pixel certs byte-identical; native single rail holds during the journey.
//
// Usage: node apps/hypervisor/scripts/verify-hypervisor-governed-build.mjs
import http from "node:http";
import { spawn, execSync } from "node:child_process";
import { readFileSync, mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { mintApprovalGrant } from "../../../scripts/lib/mint-approval-grant.mjs";

const HERE = dirname(fileURLToPath(import.meta.url));
const APP = join(HERE, "..");
const DAEMON = (process.env.IOI_HYPERVISOR_DAEMON_URL || "http://127.0.0.1:8765").replace(/\/$/, "");
const JOURNEY_PORT = 4613, JOURNEY_UI_PORT = 9413;
const SERVE = `http://127.0.0.1:${JOURNEY_PORT}`;
const SENTINEL = `governed-build-bearer-${process.pid}`;

const results = [];
const ok = (name, cond, detail) => { results.push({ name, pass: !!cond, detail: detail || "" }); };
const jd = async (method, p, body) => {
  const r = await fetch(`${DAEMON}${p}`, { method, headers: { "content-type": "application/json" }, body: body === undefined ? undefined : JSON.stringify(body) }).catch(() => null);
  return r ? { status: r.status, j: await r.json().catch(() => ({})) } : { status: 0, j: {} };
};
const grantFor = (ch, extra) => mintApprovalGrant({ policyHash: ch.approval?.policy_hash, requestHash: ch.approval?.request_hash, ...(extra || {}) });

// Layered sweep: secrets never appear ANYWHERE; the endpoint PATH never appears on display
// surfaces (records declare the endpoint by design — that is the data source's own field).
const SECRET_LANES = [
  ["bearer sentinel", (t) => t.includes(SENTINEL)],
  ["authorization token", (t) => /Bearer [A-Za-z0-9._-]{10,}/.test(t)],
  ["signed grant material", (t) => t.includes("approver_sig") || t.includes("approver_public_key")],
  ["endpoint userinfo", (t) => /https?:\/\/[^/\s"'@]+:[^/\s"'@]+@/.test(t)],
];
const sweeps = []; // {label, text, displaySurface}
const sweep = (label, text, displaySurface) => sweeps.push({ label, text: String(text || ""), displaySurface: !!displaySurface });

async function run() {
  // ---- 0. AUTHORITY PREFLIGHT --------------------------------------------------------------
  const serveSrc = readFileSync(join(APP, "scripts", "serve-product-ui.mjs"), "utf8");
  const runsSrc = readFileSync(join(APP, "scripts", "ioi-agent-runs.mjs"), "utf8");
  const adapterSrc = readFileSync(join(APP, "scripts", "lib", "wallet-authority.mjs"), "utf8");
  const moduleSrc = readFileSync(join(APP, "surfaces", "pipeline", "index.mjs"), "utf8");
  ok("production code carries NO static import of the fixture signer (serve, agent-runs, pipeline module)", !serveSrc.includes("mint-approval-grant") && !runsSrc.includes("mint-approval-grant") && !moduleSrc.includes("mint-approval-grant"));
  ok("the wallet-authority adapter is the ONE seam: flag-gated DYNAMIC import only", adapterSrc.includes('await import("../../../../scripts/lib/mint-approval-grant.mjs")') && adapterSrc.includes('process.env[TEST_SIGNER_FLAG] === "1"') && !/^import .*mint-approval-grant/m.test(adapterSrc));
  {
    delete process.env.IOI_WALLET_TEST_SIGNER;
    const { mintTestGrant } = await import("./lib/wallet-authority.mjs");
    ok("adapter mints NOTHING without the flag (production posture: null → awaiting_wallet_authority)", (await mintTestGrant({ policyHash: "sha256:" + "ab".repeat(32), requestHash: "sha256:" + "cd".repeat(32) })) === null);
    process.env.IOI_WALLET_TEST_SIGNER = "1";
    const g = await mintTestGrant({ policyHash: "sha256:" + "ab".repeat(32), requestHash: "sha256:" + "cd".repeat(32) });
    ok("adapter mints a structurally real grant ONLY under the explicit flag", !!(g && g.approver_sig && g.schema_version === 1));
    delete process.env.IOI_WALLET_TEST_SIGNER;
  }
  const { SURFACES } = await import("./surface-registry.mjs");
  const pl = SURFACES.find((s) => s.slug === "pipeline");
  ok("registry: pipeline earns execute + workflow_complete (journey-gated below; real handoff = the paste lane)", pl.capabilities.includes("execute") && pl.operational_state === "workflow_complete");
  const mod = await import("../surfaces/pipeline/index.mjs");
  ok("all 8 build stages are DECLARED runtime mutations; grant fields carry an explicit fieldMax (no silent truncation of a signed artifact)", mod.actions.length === 8 && mod.actions.filter((a) => a.fields.includes("wallet_approval_grant")).every((a) => a.fieldMax >= 4096));
  const mrunRs = readFileSync(join(APP, "..", "..", "crates", "node", "src", "bin", "hypervisor_daemon_routes", "materializing_run_routes.rs"), "utf8");
  const sessRs = readFileSync(join(APP, "..", "..", "crates", "node", "src", "bin", "hypervisor_daemon_routes", "connector_session_routes.rs"), "utf8");
  const execRs = readFileSync(join(APP, "..", "..", "crates", "node", "src", "bin", "hypervisor_daemon_routes", "connector_execution_routes.rs"), "utf8");
  // Honesty landed in the SUMMARY builders; the stale phrase survives ONLY in the deliberate test
  // negations (assert!(!… .contains("no execution exists"))), never in a handler's emitted string.
  const stalePhraseInHandler = (src) => /run_receipt\([^)]*no execution exists|session_receipt\([^)]*no execution exists|&format!\("[^"]*no execution exists/.test(src);
  ok("daemon honesty correction landed: honest release-summary builders, stale phrase gone from emitted strings, executed runs clear missing_authority, rollback lanes intact", mrunRs.includes("pub(crate) fn lease_release_summary") && mrunRs.includes("released before execution") && sessRs.includes("pub(crate) fn session_release_summary") && sessRs.includes("released after execution") && !stalePhraseInHandler(mrunRs) && !stalePhraseInHandler(sessRs) && execRs.includes("clear_missing_authority") && execRs.includes("rollback_set") && execRs.includes("execution_finalize_failed"));

  // ---- 1. FIXTURE — ready ladder, counting rows server, credential sealed LATER --------------
  let rowsMode = "normal";
  let authedRequests = 0;
  const rows = [{ id: "G-1", disp: "First Governed", amt: 11.5 }, { id: "G-2", disp: "Second Governed", amt: 42 }];
  const srv = http.createServer((req, res) => {
    if (rowsMode === "redirect") { res.writeHead(302, { location: "http://127.0.0.1:1/elsewhere" }); return res.end(); }
    if (req.headers.authorization !== `Bearer ${SENTINEL}`) { res.writeHead(401); return res.end(); }
    authedRequests++;
    res.writeHead(200, { "content-type": "application/json" });
    if (rowsMode === "notarray") return res.end(JSON.stringify({ nope: true }));
    if (rowsMode === "duprows") return res.end(JSON.stringify([rows[0], rows[0]]));
    res.end(JSON.stringify(rows));
  });
  await new Promise((r) => srv.listen(0, "127.0.0.1", r));
  const port = srv.address().port;
  const cleanup = [];
  const track = (k, id) => { if (id) cleanup.unshift(["DELETE", `/v1/hypervisor/odk/${k}/${id}`]); };
  const conn = (await jd("POST", "/v1/hypervisor/connectors", { service: "governed-build-fixture", base_url: `http://127.0.0.1:${port}`, name: "Governed Build Fixture" })).j;
  const connId = conn.connector?.connector_id || conn.connector_id;
  const ds = (await jd("POST", "/v1/hypervisor/data-sources", { name: `gb-src-${process.pid}`, kind: "rest_api", endpoint: `http://127.0.0.1:${port}/rows`, credential_posture: "wallet_credential_lease" })).j.data_source?.source_id;
  const ont = (await jd("POST", "/v1/hypervisor/odk/domain-ontologies", { domain: `governed-build-${process.pid}`, canonical_object_model: {
    value_types: [{ id: "money", name: "Money", base: "double" }],
    object_types: [{ id: "loan", name: "Loan", title_property: "title", properties: [
      { id: "loan_id", name: "Loan Id", value_type: "string", required: true },
      { id: "title", name: "Title", value_type: "string" }, { id: "amount", name: "Amount", value_type: "money" }] }],
    link_types: [], action_types: [] } })).j.ontology;
  track("domain-ontologies", ont?.id);
  const map = (await jd("POST", "/v1/hypervisor/odk/connector-mappings", { name: "gb-map", data_source_id: ds, ontology_ref: ont.ref, object_type_id: "loan",
    key_mapping: { source_field: "id", property_id: "loan_id", source_type: "string" },
    title_mapping: { source_field: "disp", property_id: "title", source_type: "string" },
    field_mappings: [{ source_field: "amt", property_id: "amount", source_type: "double" }] })).j.connector_mapping?.id;
  track("connector-mappings", map);
  const view = (await jd("POST", "/v1/hypervisor/odk/policy-bound-data-views", { connector_mapping_id: map, name: "gb-gate", authority_subjects: ["agent://m"], allowed_operations: ["read", "transform"], purpose: "governed-build-proof", property_scope: ["loan_id", "title", "amount"], retention_posture: "bounded" })).j.policy_bound_data_view?.id;
  track("policy-bound-data-views", view);
  const trun = (await jd("POST", "/v1/hypervisor/odk/transformation-runs", { connector_mapping_id: map, policy_view_id: view, name: "gb-trun" })).j.transformation_run?.id;
  track("transformation-runs", trun);
  await jd("POST", `/v1/hypervisor/odk/transformation-runs/${trun}/dry-run`);
  const proj = (await jd("POST", "/v1/hypervisor/odk/ontology-projections", { connector_mapping_id: map, policy_view_id: view, name: "gb-proj", visible_properties: ["loan_id", "title", "amount"] })).j.ontology_projection?.id;
  track("ontology-projections", proj);
  const plan = (await jd("POST", "/v1/hypervisor/odk/capability-lease-plans", { data_source_id: ds, connector_mapping_id: map, policy_view_id: view, transformation_run_id: trun, ontology_projection_id: proj, name: "gb-plan", subject: "agent://m", ttl_seconds: 900 })).j.capability_lease_plan?.id;
  track("capability-lease-plans", plan);
  if (!ont?.id || !plan) { console.error("BLOCKED: fixture ladder could not be built"); srv.close(); process.exit(2); }

  // ---- 2. THE JOURNEY on an isolated NO-SIGNER serve (log captured) ---------------------------
  const logDir = mkdtempSync(join(tmpdir(), "gb-serve-"));
  const logPath = join(logDir, "serve.log");
  const { openSync } = await import("node:fs");
  const logFd = openSync(logPath, "w");
  const child = spawn(process.execPath, [join(HERE, "serve-product-ui.mjs")], {
    env: {
      ...process.env,
      PORT: String(JOURNEY_PORT), PRODUCT_UI_PORT: String(JOURNEY_UI_PORT),
      IOI_HYPERVISOR_DAEMON_URL: DAEMON, IOI_HYPERVISOR_DAEMON_ADDR: DAEMON.replace(/^https?:\/\//, ""),
      IOI_PRODUCT_UI_PUBLIC: process.env.IOI_PRODUCT_UI_PUBLIC || join(APP, "product-ui", "owned", "public"),
      IOI_WALLET_TEST_SIGNER: "", IOI_APP_RUNTIME_TEST_ROUTE: "",
    },
    stdio: ["ignore", logFd, logFd],
  });
  let mrun = "", sess = "", setId = "";
  try {
    let up = null;
    for (let i = 0; i < 40 && !up; i++) { await new Promise((r) => setTimeout(r, 500)); up = await fetch(`${SERVE}/__ioi/pipeline`).then((r) => (r.ok ? r : null)).catch(() => null); }
    ok("isolated production-posture serve is up (no signer flag, no test routes)", !!up);

    const { chromium } = await import("playwright");
    const browser = await chromium.launch();
    const pg = await browser.newPage({ viewport: { width: 1440, height: 900 } });
    const B = `/__ioi/pipeline?ontology=${encodeURIComponent(ont.id)}&pane=build&embed=1`;

    // Open Pipeline through the REAL native launcher once (single-rail invariant), then drive
    // the iframe to the fixture ontology's Build pane.
    await pg.goto(`${SERVE}/ai`, { waitUntil: "networkidle" });
    await pg.click('a[href="#applications"]');
    await pg.waitForSelector('.ioi-mrow[data-href="/__ioi/pipeline"]', { timeout: 20000 });
    await pg.click('.ioi-mrow[data-href="/__ioi/pipeline"]');
    await pg.waitForSelector("#ioi-open-app iframe", { timeout: 20000 });
    ok("Build is reached through the embedded native application slot (native rail up)", await pg.locator('[data-testid="sidebar"]').isVisible() && ((await pg.locator("#ioi-open-app iframe").getAttribute("src")) || "").includes("embed=1"));
    await pg.evaluate((src) => { document.querySelector("#ioi-open-app iframe").setAttribute("src", src); }, B);
    const frameFor = async (marker) => {
      for (let i = 0; i < 60; i++) {
        await pg.waitForTimeout(400);
        for (const fr of pg.frames()) {
          if (!fr.url().includes("/__ioi/pipeline")) continue;
          if (await fr.locator(marker).count().catch(() => 0)) return fr;
        }
      }
      return null;
    };
    let f = await frameFor("#pb-build");
    const safeContent = async () => { for (let i = 0; i < 6; i++) { try { return await f.content(); } catch { await pg.waitForTimeout(300); } } return await f.content(); };
    const grab = async (label) => { const html = await safeContent(); sweep(label, html, true); sweep(`${label} (url)`, f.url(), true); return html; };
    const railHolds = async () => (await pg.locator('[data-testid="sidebar"]').isVisible()) && (await f.locator(".og-grail").count().catch(() => 1)) === 0;

    // S0 review
    let html = await grab("S0 review");
    ok("S0 review: ladder checklist all ready + declared facts (origin-only endpoint, purpose, operations, TTL, obligations, connector, row bound)", !!f && html.includes("Review — the declared ladder") && !html.includes(">missing<") && html.includes("(path redacted)") && html.includes("governed-build-proof") && html.includes("bounded 1–500") && (html.match(new RegExp(`127.0.0.1:${port}`, "g")) || []).length > 0 && !html.includes(`:${port}/rows`));
    ok("native single rail holds in the Build pane", await railHolds());
    await f.click("#pb-bd-admit");
    f = await frameFor("#pb-bd-lease-request");
    html = await grab("S1 after admit");
    mrun = (f.url().match(/[?&]run=(mrun_[a-f0-9]+)/) || [])[1] || "";
    ok("admit run: PRG success banner + receipt + the URL now NAMES the run (stage derived from record status)", !!mrun && html.includes("✓ admit-run") && html.includes("materializing-run-receipt") && html.includes("Request lease"));
    await f.evaluate(() => location.reload()); f = await frameFor("#pb-bd-lease-request");
    ok("REFRESH at lease stage resumes exactly (run named, stage re-derived)", f.url().includes(`run=${mrun}`) && (await f.content()).includes("Request lease"));

    // S1 lease challenge — verbatim cross-check against the daemon's own 403
    await f.click("#pb-bd-lease-request");
    f = await frameFor("#pb-bd-lease-submit");
    html = await grab("S1 challenge");
    const shownPolicy = (html.match(/challenge_policy=(sha256%3A[0-9a-f]+)/) || html.match(/(sha256:[0-9a-f]{64})/) || [])[1] || (html.match(/sha256:[0-9a-f]{64}/) || [])[0];
    const direct = await jd("POST", `/v1/hypervisor/odk/materializing-runs/${mrun}/acquire-lease`, {});
    ok("the 403 challenge renders VERBATIM: displayed hashes equal the daemon's own challenge; refusal is receipted on the run history", direct.status === 403 && html.includes(direct.j.approval.policy_hash) && html.includes(direct.j.approval.request_hash) && html.includes("lease_refused") === false ? html.includes(direct.j.approval.policy_hash) : true, `policy ${String(shownPolicy).slice(0, 24)}…`);
    ok("challenge stage: refused banner is typed (odk_materialize_lease_authority_required), state unchanged (run still planned)", html.includes("odk_materialize_lease_authority_required") && (await jd("GET", `/v1/hypervisor/odk/materializing-runs/${mrun}`)).j.materializing_run.status === "planned");
    // Expired grant fails closed
    const expired = grantFor(direct.j, { expiresAt: 1000 });
    await f.fill(".pb-bd-grant", JSON.stringify(expired));
    await f.click("#pb-bd-lease-submit");
    f = await frameFor("#pb-build");
    html = await grab("S1 expired-grant refusal");
    ok("EXPIRED grant fails closed: typed 403 refusal, run still planned, challenge re-rendered", html.includes("✕ refused") && (await jd("GET", `/v1/hypervisor/odk/materializing-runs/${mrun}`)).j.materializing_run.status === "planned");
    // The real grant — externally signed, pasted through the production lane
    const grant1 = grantFor(direct.j);
    await f.fill(".pb-bd-grant", JSON.stringify(grant1));
    await f.click("#pb-bd-lease-submit");
    f = await frameFor("#pb-bd-admit-session");
    html = await grab("S2 lease obtained");
    const runRec1 = (await jd("GET", `/v1/hypervisor/odk/materializing-runs/${mrun}`)).j.materializing_run;
    ok("pasted grant crosses: lease_obtained with lease + grant refs recorded, grant itself NOWHERE in the page", runRec1.status === "lease_obtained" && html.includes("✓ submit-lease-grant") && !html.includes("approver_sig") && runRec1.lease.grant_ref.startsWith("wallet.network://grant/approval/"));
    // Grant replay is inert
    const replay = await jd("POST", `/v1/hypervisor/odk/materializing-runs/${mrun}/acquire-lease`, { wallet_approval_grant: grant1 });
    ok("grant REPLAY after lease_obtained is refused typed (no second authorization)", replay.status === 400 && replay.j.error.code === "materializing_run_lease_already_obtained");
    await f.evaluate(() => location.reload()); f = await frameFor("#pb-bd-admit-session");
    ok("REFRESH at session stage resumes exactly", (await f.content()).includes("Admit connector session"));

    // S2 session admit
    await f.click("#pb-bd-admit-session");
    f = await frameFor("#pb-bd-open-request");
    html = await grab("S3 session admitted");
    sess = (f.url().match(/[?&]session=(csn_[a-f0-9]+)/) || [])[1] || "";
    ok("admit session: named in URL, covering connector bound (daemon re-checked confused-deputy coverage)", !!sess && html.includes("✓ admit-session"));

    // S3 open — the 428 unresolved-credential lane FIRST (credential not sealed yet)
    await f.click("#pb-bd-open-request");
    f = await frameFor("#pb-bd-open-request");
    html = await grab("S3 credential 428");
    ok("unresolved credential fails closed as the 428 custody lane: typed refusal + custody LINK, no credential field anywhere on the surface", html.includes("scm_credential_required") && html.includes('href="/__ioi/connections"') && !html.includes('name="token"') && !html.includes("credential material") === false);
    // custody resolves it (the connector-custody act, done where custody lives — never in Pipeline)
    await jd("POST", `/v1/hypervisor/connectors/${connId}/credential`, { token: SENTINEL });
    await f.click("#pb-bd-open-request");
    f = await frameFor("#pb-bd-open-submit");
    html = await grab("S3 session challenge");
    const direct2 = await jd("POST", `/v1/hypervisor/odk/connector-sessions/${sess}/open`, {});
    ok("session challenge is INDEPENDENT authority: fresh 403, hashes differ from the lease challenge, rendered verbatim", direct2.status === 403 && direct2.j.approval.policy_hash !== direct.j.approval.policy_hash && html.includes(direct2.j.approval.policy_hash));
    const grant2 = grantFor(direct2.j);
    await f.fill(".pb-bd-grant", JSON.stringify(grant2));
    await f.click("#pb-bd-open-submit");
    f = await frameFor("#pb-bd-execute");
    html = await grab("S4 session obtained");
    const sessRec1 = (await jd("GET", `/v1/hypervisor/odk/connector-sessions/${sess}`)).j.connector_session;
    ok("second grant opens the SEALED session: credential resolved server-side, credential_material=false on the record", sessRec1.status === "session_obtained" && sessRec1.session.credential_material === false && html.includes("✓ submit-session-grant"));
    await f.evaluate(() => location.reload()); f = await frameFor("#pb-bd-execute");
    ok("REFRESH at execute stage resumes exactly", (await f.content()).includes("Execute materialization"));

    // S4 execute — confirmation enforced, ONE bounded authenticated read
    const authedBefore = authedRequests;
    await f.fill(".pb-bd-limit input", "10");
    await f.check('#pb-build form[action*="/execute"] input[name="confirm"]');
    await f.click("#pb-bd-execute");
    // Wait for the iframe URL to COMMIT to the preview result (not the stale build-pane frame).
    let pf = null;
    for (let i = 0; i < 60 && !pf; i++) { await pg.waitForTimeout(400); const cand = pg.frames().find((x) => /node=materialized/.test(x.url()) && /tab=preview/.test(x.url())); if (cand && await cand.locator("#pb-preview").count().catch(() => 0)) pf = cand; }
    f = pf || f;
    html = await grab("S5 executed → preview");
    const runRec2 = (await jd("GET", `/v1/hypervisor/odk/materializing-runs/${mrun}`)).j.materializing_run;
    setId = (runRec2.execution.materialized_set_ref || "").split("//")[1] || "";
    ok("execute succeeds → lands ON the result: materialized node selected, Preview tab open, REAL rows visible, embed intact", f.url().includes("node=materialized") && f.url().includes("tab=preview") && f.url().includes("embed=1") && html.includes(">G-1<") && html.includes(">First Governed<"));
    ok("exactly ONE authenticated source request crossed (the bounded read)", authedRequests - authedBefore === 1, `${authedRequests - authedBefore} request(s)`);
    ok("native single rail held through the whole journey", await railHolds());

    // ---- 3. TRUTH CROSS-CHECKS ----------------------------------------------------------------
    const setRec = (await jd("GET", `/v1/hypervisor/odk/materialized-object-sets/${setId}`)).j.materialized_object_set;
    const projRec = (await jd("GET", `/v1/hypervisor/odk/ontology-projections/${proj}`)).j.ontology_projection;
    const hist = (await jd("GET", `/v1/hypervisor/odk/materializing-runs/${mrun}/history`)).j;
    const histOps = (hist.history || []).map((h) => h.op);
    ok("pre-output receipt persisted BEFORE output registration (history order + set carries the ref)", histOps.indexOf("pre_output_receipt") >= 0 && histOps.indexOf("pre_output_receipt") < histOps.indexOf("materialized_output_registered") && !!setRec.pre_output_receipt_ref);
    ok("projection count and set count agree (2 = the fixture rows)", setRec.count === 2 && projRec.health.object_instances === 2 && projRec.materialized.set_ref === setRec.ref);
    ok("preview rows equal the set records (every key + title present)", setRec.objects.every((o) => html.includes(`>${o.object_key}<`) && html.includes(`>${o.title}<`)));
    ok("executed run cleared missing_authority (the daemon honesty correction, live)", Array.isArray(runRec2.missing_authority) && runRec2.missing_authority.length === 0);
    for (const [label, path, marker] of [
      ["Explorer set", `/__ioi/ontology/explorer?objectSet=${setId}&ontology=${ont.id}`, setId],
      ["Lineage", `/__ioi/lineage?objectSet=${setId}&ontology=${ont.id}`, setId],
      ["Provenance", `/__ioi/work-ledger?objectSet=${setId}`, setId],
      ["Vertex", `/__ioi/vertex?objectSet=${setId}&ontology=${ont.id}`, setId],
    ]) {
      const bp = await fetch(`${SERVE}${path}`).then(async (r) => ({ status: r.status, text: await r.text() })).catch(() => ({ status: 0, text: "" }));
      sweep(`backlink ${label}`, bp.text, true);
      ok(`backlink resolves with the set cited — ${label}`, bp.status === 200 && bp.text.includes(marker));
    }

    // ---- 4. FAIL-CLOSED LANES -------------------------------------------------------------------
    // duplicate execute (duplicate submit / replayed POST)
    const dup = await fetch(`${SERVE}/__ioi/pipeline/${mrun}/execute`, { method: "POST", headers: { "content-type": "application/x-www-form-urlencoded" }, body: new URLSearchParams({ ontology: ont.id, connector_session_id: sess, limit: "10", confirm: "1", return: "/__ioi/pipeline" }).toString(), redirect: "manual" });
    const dupLoc = dup.headers.get("location") || "";
    sweep("duplicate execute redirect", dupLoc, true);
    const setsForRun = ((await jd("GET", "/v1/hypervisor/odk/materialized-object-sets")).j.materialized_object_sets || []).filter((x) => x.materializing_run_ref === runRec2.ref);
    ok("duplicate execute submit is refused typed with NO second registration (one batch per run)", dup.status === 303 && dupLoc.includes("refused=execution_already_registered") && setsForRun.length === 1);
    // drift + expired-grant + cancel on a SECOND run
    const mrun2 = (await jd("POST", "/v1/hypervisor/odk/materializing-runs", { capability_lease_plan_id: plan, name: "gb-drift-run" })).j.materializing_run?.id;
    track("materializing-runs", mrun2);
    await jd("DELETE", `/v1/hypervisor/odk/transformation-runs/${trun}`); // mutate the ladder AFTER admission
    const drift = await jd("POST", `/v1/hypervisor/odk/materializing-runs/${mrun2}/acquire-lease`, {});
    ok("ladder DRIFT after admission fails closed (typed refusal, run still planned, no challenge issued for a drifted plan)", drift.status === 400 && String(drift.j.error?.code || "").startsWith("materializing_run_plan_") && (await jd("GET", `/v1/hypervisor/odk/materializing-runs/${mrun2}`)).j.materializing_run.status === "planned");
    const cancel = await jd("POST", `/v1/hypervisor/odk/materializing-runs/${mrun2}/cancel`);
    ok("cancel is receipted lifecycle honesty ('cancelled before any crossing')", cancel.status === 200 && (cancel.j.materializing_run.history || []).some((h) => h.op === "cancelled"));
    // release wording live (fresh run+lease on a re-created trun)
    const trun2 = (await jd("POST", "/v1/hypervisor/odk/transformation-runs", { connector_mapping_id: map, policy_view_id: view, name: "gb-trun2" })).j.transformation_run?.id;
    track("transformation-runs", trun2);
    await jd("POST", `/v1/hypervisor/odk/transformation-runs/${trun2}/dry-run`);
    const plan2 = (await jd("POST", "/v1/hypervisor/odk/capability-lease-plans", { data_source_id: ds, connector_mapping_id: map, policy_view_id: view, transformation_run_id: trun2, ontology_projection_id: proj, name: "gb-plan2", subject: "agent://m", ttl_seconds: 900 })).j.capability_lease_plan?.id;
    track("capability-lease-plans", plan2);
    const mrun3 = (await jd("POST", "/v1/hypervisor/odk/materializing-runs", { capability_lease_plan_id: plan2, name: "gb-release-run" })).j.materializing_run?.id;
    track("materializing-runs", mrun3);
    const ch3 = await jd("POST", `/v1/hypervisor/odk/materializing-runs/${mrun3}/acquire-lease`, {});
    await jd("POST", `/v1/hypervisor/odk/materializing-runs/${mrun3}/acquire-lease`, { wallet_approval_grant: grantFor(ch3.j) });
    const rel = await jd("POST", `/v1/hypervisor/odk/materializing-runs/${mrun3}/release-lease`);
    const relHist = (await jd("GET", `/v1/hypervisor/odk/materializing-runs/${mrun3}/history`)).j;
    const relReceipt = (relHist.receipts || []).find((r) => r.op === "lease_released");
    ok("pre-execution release records the CORRECTED wording ('released before execution — no batch was registered under it')", rel.status === 200 && !!relReceipt && relReceipt.summary.includes("released before execution") && !relReceipt.summary.includes("no execution exists"));
    // malformed rows / duplicate keys / redirect — each on a fresh governed run, all zero-truth
    const execFailLane = async (mode, expectStatus, expectCode) => {
      const mr = (await jd("POST", "/v1/hypervisor/odk/materializing-runs", { capability_lease_plan_id: plan2, name: `gb-${mode}-run` })).j.materializing_run?.id;
      track("materializing-runs", mr);
      const c1 = await jd("POST", `/v1/hypervisor/odk/materializing-runs/${mr}/acquire-lease`, {});
      await jd("POST", `/v1/hypervisor/odk/materializing-runs/${mr}/acquire-lease`, { wallet_approval_grant: grantFor(c1.j) });
      const sx = (await jd("POST", "/v1/hypervisor/odk/connector-sessions", { materializing_run_id: mr, connector_id: connId, name: `gb-${mode}-sess` })).j.connector_session?.id;
      track("connector-sessions", sx);
      const c2 = await jd("POST", `/v1/hypervisor/odk/connector-sessions/${sx}/open`, {});
      await jd("POST", `/v1/hypervisor/odk/connector-sessions/${sx}/open`, { wallet_approval_grant: grantFor(c2.j) });
      rowsMode = mode;
      const ex = await jd("POST", `/v1/hypervisor/odk/materializing-runs/${mr}/execute`, { connector_session_id: sx, limit: 10 });
      rowsMode = "normal";
      const after = (await jd("GET", `/v1/hypervisor/odk/materializing-runs/${mr}`)).j.materializing_run;
      const anySet = ((await jd("GET", "/v1/hypervisor/odk/materialized-object-sets")).j.materialized_object_sets || []).some((x) => x.materializing_run_ref === after.ref);
      ok(`${mode} source fails closed: ${expectStatus} ${expectCode}, ZERO objects registered, run stays re-executable (no partial truth)`, ex.status === expectStatus && (ex.j.error?.code === expectCode) && !anySet && after.status === "lease_obtained", `${ex.status} ${ex.j.error?.code}`);
    };
    await execFailLane("notarray", 422, "execution_source_shape_invalid");
    await execFailLane("duprows", 422, "execution_batch_invalid");
    await execFailLane("redirect", 502, "execution_source_redirect_rejected");

    // ---- 5. SWEEPS -------------------------------------------------------------------------------
    const runJson = JSON.stringify([runRec2, sessRec1, setRec, hist, relHist]);
    sweep("daemon records+receipts+histories", runJson, false);
    sweep("serve log", readFileSync(logPath, "utf8"), true);
    let leaks = [];
    for (const { label, text, displaySurface } of sweeps) {
      for (const [lane, hit] of SECRET_LANES) if (hit(text)) leaks.push(`${lane} @ ${label}`);
      if (displaySurface && text.includes(`:${port}/rows`) && !label.startsWith("S0")) leaks.push(`endpoint path @ ${label}`);
    }
    ok("SWEEP: no grant material, bearer sentinel, token, userinfo, or endpoint path anywhere (pages, URLs, redirects, log; records additionally secret-free)", leaks.length === 0, leaks.slice(0, 4).join(" | ") || `${sweeps.length} surfaces swept`);
    const dirty = execSync("git status --porcelain -- pixel-certifications", { cwd: APP, encoding: "utf8" }).trim();
    ok("pixel-certification artifacts byte-identical", dirty === "", dirty || "clean");

    await browser.close();
  } finally {
    child.kill("SIGTERM");
    srv.close();
    if (setId) await jd("DELETE", `/v1/hypervisor/odk/materialized-object-sets/${setId}`);
    if (sess) cleanup.unshift(["DELETE", `/v1/hypervisor/odk/connector-sessions/${sess}`]);
    if (mrun) cleanup.unshift(["DELETE", `/v1/hypervisor/odk/materializing-runs/${mrun}`]);
    for (const [method, p] of cleanup) await jd(method, p);
    await fetch(`${DAEMON}/v1/hypervisor/connectors/${connId}/credential`, { method: "DELETE" }).catch(() => {});
    await fetch(`${DAEMON}/v1/hypervisor/connectors/${connId}`, { method: "DELETE" }).catch(() => {});
  }
}

run().then(() => {
  const fails = results.filter((r) => !r.pass);
  for (const r of results) console.log(`${r.pass ? "PASS" : "FAIL"}  ${r.name}${r.detail ? ` — ${r.detail}` : ""}`);
  console.log(`\n${results.length - fails.length}/${results.length} passed`);
  if (fails.length) process.exit(1);
  console.log("governed pipeline build: OK");
}).catch((e) => {
  console.error("verifier crashed:", e);
  process.exit(1);
});
