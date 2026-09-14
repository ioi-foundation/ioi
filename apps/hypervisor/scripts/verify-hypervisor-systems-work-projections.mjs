#!/usr/bin/env node
// M08.9 — the Systems and Work projections, proven against an ISOLATED daemon + serve lane.
//
// WHAT THIS GATE CLAIMS (the unit's check text, nothing wider):
//   * exact typed Work rows: a real admitted Session becomes ONE HypervisorWorkSubjectProjection row
//     with the owner's identity verbatim, the typed deep link, and facets DERIVED from the owner's
//     own state; a governance approval over that subject becomes ONE review FACET that points;
//   * policy BEFORE search, counts and recents: the counts and recents are computed over the
//     owner-filtered set and do not move when a search narrows the rows; another principal's
//     projection carries none of this principal's rows;
//   * truth-owner NONMUTATION: the owners' record directories are byte-identical before and after
//     every read this gate performs — a projection that wrote back a common status would show here;
//   * malformed / ambiguous refusal by name; a typed absence for the families no owner enumerates;
//   * REBUILD: the same answer after a daemon restart, because nothing was cached or persisted;
//   * the Systems projection answers under policy with its registered row contract named, and an
//     empty inventory is `honest_empty`, never a fabricated System.
//
// WHAT IT DOES NOT CLAIM: no System is admitted here (genesis needs the governed chain the
// system-genesis journeys drive), so Systems rows are not exercised beyond the envelope; the work
// queue/item/run families are asserted ABSENT-BY-NAME, not present.
//
// Exit: 0 pass · 1 fail · 2 blocked (daemon binary missing).

import { spawn } from "node:child_process";
import crypto from "node:crypto";
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
  srv.listen(0, "127.0.0.1", () => { const { port } = srv.address(); srv.close(() => resolve(port)); });
  srv.on("error", reject);
});
const waitFor = async (url, ms) => {
  const until = Date.now() + ms;
  while (Date.now() < until) {
    try { const r = await fetch(url); if (r.status < 500) return; } catch { /* not up yet */ }
    await new Promise((r) => setTimeout(r, 400));
  }
  throw new Error(`timeout waiting for ${url}`);
};

const daemonBinary = path.resolve(ROOT, process.env.IOI_HYPERVISOR_DAEMON_BINARY ?? "target/debug/hypervisor-daemon");
try { fs.accessSync(daemonBinary, fs.constants.X_OK); } catch {
  console.error(`BLOCKED: daemon binary not executable at ${daemonBinary}`);
  process.exit(2);
}

const dataDir = fs.mkdtempSync(path.join(os.tmpdir(), "ioi-systems-work-projections-"));
let daemon = null;
let serve = null;
let daemonPort = 0;
let DAEMON = "";
let SERVE = "";
let SESSION = "";
const PROJECT_REF = "project://systems-work-projections/p1";

async function startDaemon() {
  daemon = spawn(daemonBinary, [], {
    cwd: ROOT,
    env: { ...process.env, IOI_HYPERVISOR_DAEMON_ADDR: `127.0.0.1:${daemonPort}`, IOI_HYPERVISOR_DATA_DIR: dataDir, IOI_HYPERVISOR_MODEL_UPSTREAM: "http://127.0.0.1:1/v1" },
    stdio: ["ignore", "pipe", "pipe"],
  });
  let log = "";
  daemon.stdout.on("data", (c) => { log = `${log}${c}`.slice(-64000); });
  daemon.stderr.on("data", (c) => { log = `${log}${c}`.slice(-64000); });
  await waitFor(`${DAEMON}/healthz`, 30000);
  return () => log;
}

const jd = (p, init, authenticated = true) => fetch(`${DAEMON}${p}`, {
  headers: { "content-type": "application/json", ...(authenticated && SESSION ? { cookie: `ioi_session=${SESSION}` } : {}) },
  ...init,
}).then(async (r) => ({ status: r.status, body: await r.json().catch(() => ({})) })).catch(() => ({ status: 0, body: {} }));
const pageText = (p, { authenticated = true } = {}) => fetch(`${SERVE}${p}`, {
  headers: authenticated && SESSION ? { cookie: `ioi_session=${SESSION}` } : {},
}).then(async (r) => ({ status: r.status, text: await r.text(), headers: r.headers })).catch(() => ({ status: 0, text: "", headers: new Headers() }));
const projection = (query, authenticated = true) => jd(`/v1/hypervisor/work-projection${query ? `?${query}` : ""}`, undefined, authenticated);

// Byte-level fingerprint of the OWNERS' record directories: the nonmutation witness.
function fingerprint(dirs) {
  const hash = crypto.createHash("sha256");
  for (const dir of dirs) {
    const full = path.join(dataDir, dir);
    if (!fs.existsSync(full)) { hash.update(`${dir}:absent\n`); continue; }
    const walk = (d) => {
      for (const entry of fs.readdirSync(d, { withFileTypes: true }).sort((a, b) => a.name.localeCompare(b.name))) {
        const p = path.join(d, entry.name);
        if (entry.isDirectory()) walk(p);
        else { hash.update(`${path.relative(dataDir, p)}\n`); hash.update(fs.readFileSync(p)); }
      }
    };
    walk(full);
  }
  return hash.digest("hex");
}
// The owners core Work reads (Work subject registry, 2026-09-14): Sessions, approvals, automation
// runs. Goal runs and rooms are CONTRIBUTED families with no core reader, so they are not owners of
// this projection and are not in its nonmutation claim.
const OWNER_DIRS = ["sessions", "governance-approval-requests", "canonical-automation-runs"];

function cleanup() {
  try { serve?.kill("SIGTERM"); } catch { /* gone */ }
  try { daemon?.kill("SIGTERM"); } catch { /* gone */ }
  try { fs.rmSync(dataDir, { recursive: true, force: true }); } catch { /* keep */ }
}

async function run() {
  daemonPort = await freePort();
  DAEMON = `http://127.0.0.1:${daemonPort}`;
  const daemonLogFn = await startDaemon();
  const token = daemonLogFn().match(/ioi_bootstrap_[a-f0-9]{64}/gu)?.at(-1) ?? null;
  if (token) {
    const boot = await jd("/v1/hypervisor/auth/bootstrap", { method: "POST", body: JSON.stringify({ token, password: "systems-work-projections-v1", email: "systems-work@ioi.local" }) });
    SESSION = boot.body?.session_token ?? "";
  }
  ok("operator bootstrap yields an authenticated session", SESSION.startsWith("ioi_sess_"), SESSION.slice(0, 12));
  const who = (await jd("/v1/hypervisor/auth/whoami")).body || {};
  const PRINCIPAL = who.principal?.principal_id ? `user://${who.principal.principal_id}` : "";
  ok("the session authenticates a principal (the policy basis every read below is filtered by)", PRINCIPAL.startsWith("user://") && PRINCIPAL !== "user://local-operator", PRINCIPAL);

  // -- the routes exist, mechanically -----------------------------------------------------------
  const index = await jd("/v1");
  const paths = (index.body.families ?? []).flatMap((f) => f.paths ?? []);
  const has = (p, m) => paths.some((row) => row.path === p && (row.methods || []).includes(m));
  ok("the daemon publishes GET /v1/hypervisor/work-projection and GET /v1/hypervisor/autonomous-systems/projection",
    has("/v1/hypervisor/work-projection", "GET") && has("/v1/hypervisor/autonomous-systems/projection", "GET"), "");

  // -- honest empty ---------------------------------------------------------------------------
  const empty = await projection("view=active");
  ok("an authenticated caller with no work reads an EMPTY typed projection: zero rows, zero counts in every view, the three unenumerated families named as typed absences, the migration map and the rebuild rule stated",
    empty.status === 200 && empty.body?.ok === true && empty.body.schema_version === "ioi.hypervisor.work-projection.v1"
      && Array.isArray(empty.body.rows) && empty.body.rows.length === 0
      && ["active", "sessions", "queues", "reviews", "incidents", "history"].every((v) => empty.body.counts?.[v] === 0)
      && (empty.body.families?.not_projected || []).map((f) => f.subject_kind).sort().join(",") === "work_item,work_queue,work_run"
      && empty.body.families?.incident_facets?.state === "absent"
      && Array.isArray(empty.body.migration?.from) && typeof empty.body.rebuild === "string"
      && empty.body.policy?.applied_before?.[0] === "search",
    JSON.stringify(empty.body).slice(0, 200));

  // -- the Work subject registry is said on every answer ---------------------------------------------
  const contributed = (empty.body.families?.contributed || []);
  ok("core Work enumerates ONLY the families the substrate owns (session, automation_run) and names goal_run and outcome_room as CONTRIBUTED families with the two seams they may arrive through — a Session's typed subject attachment or a registered application-contributed view — and mints no /work/goals or /work/rooms route (Work subject registry, ADR 0022's untangling resolved 2026-09-14)",
    JSON.stringify(empty.body.families?.projected) === JSON.stringify(["session", "automation_run"])
      && contributed.map((f) => f.subject_kind).join(",") === "goal_run,outcome_room"
      && contributed.every((f) => /subject attachment/u.test(f.seam) && /application-contributed Work \/ (?:Goals|Rooms) view/u.test(f.seam) && /no reader/u.test(f.seam))
      && (empty.body.policy?.readers || []).map((r) => r.family).sort().join(",") === "automation_run,session"
      && !JSON.stringify(empty.body).includes("/work/goals") && !JSON.stringify(empty.body).includes("/work/rooms")
      && typeof empty.body.families?.registry === "string",
    JSON.stringify({ projected: empty.body.families?.projected, contributed: contributed.map((f) => f.subject_kind), readers: (empty.body.policy?.readers || []).map((r) => r.family) }));

  // -- one real admitted Session becomes ONE typed row ---------------------------------------------
  const create = await jd("/v1/hypervisor/sessions", { method: "POST", body: JSON.stringify({ project_ref: PROJECT_REF, initial_input: "systems-work-projections seed" }) });
  const sessionRef = create.body?.session_ref || "";
  ok("a real session is admitted through the Session owner (202, session: identity)", create.status === 202 && sessionRef.startsWith("session:"), `${create.status} ${sessionRef}`);
  const tail = sessionRef.replace(/^session:/u, "");
  const active = await projection("view=active");
  const row = (active.body?.rows || []).find((r) => r.subject_ref === sessionRef) || null;
  ok("the Work projection carries EXACTLY one typed row for it: subject_kind session, the owner's identity verbatim, the typed deep link, facets derived from the owner's provisioned state (waiting · interactive), project_ref carried, read_model_only",
    active.status === 200 && (active.body.rows || []).length === 1 && !!row
      && row.schema_version === "ioi.hypervisor.work-subject-projection.v1"
      && row.subject_kind === "session" && row.canonical_detail_route === `/work/sessions/${tail}`
      && row.display_facets?.activity === "waiting" && row.display_facets?.execution_mode === "interactive"
      && row.project_ref === PROJECT_REF && row.read_model_only === true
      && Array.isArray(row.review_facet_projection_refs) && row.review_facet_projection_refs.length === 0,
    JSON.stringify(row ?? active.body).slice(0, 240));
  ok("counts are over the policy-filtered set: active 1, sessions 1, history 0, queues 0; recents lead with the session",
    active.body?.counts?.active === 1 && active.body?.counts?.sessions === 1 && active.body?.counts?.history === 0 && active.body?.counts?.queues === 0
      && active.body?.recents?.[0]?.subject_ref === sessionRef,
    JSON.stringify(active.body?.counts));
  const sessionsView = await projection("view=sessions");
  const historyView = await projection("view=history");
  ok("the typed views partition the same set: /work/sessions carries the row, /work/history does not",
    (sessionsView.body?.rows || []).length === 1 && (historyView.body?.rows || []).length === 0, "");

  // -- policy BEFORE search: a narrowing search leaves counts and recents untouched ----------------
  const hit = await projection(`view=active&q=${encodeURIComponent(tail)}`);
  const miss = await projection("view=active&q=nothing-matches-this");
  ok("search narrows the ROWS only: a matching q returns the row, a missing q returns none, and counts and recents are identical in both — policy precedes search, counts and recents",
    (hit.body?.rows || []).length === 1 && (miss.body?.rows || []).length === 0
      && JSON.stringify(hit.body?.counts) === JSON.stringify(active.body?.counts) && JSON.stringify(miss.body?.counts) === JSON.stringify(active.body?.counts)
      && miss.body?.recents?.[0]?.subject_ref === sessionRef,
    `${(hit.body?.rows || []).length}/${(miss.body?.rows || []).length}`);

  // -- a governance approval over the subject becomes ONE review facet that POINTS ---------------
  const approval = await jd("/v1/hypervisor/governance/approval-requests", { method: "POST", body: JSON.stringify({ subject_ref: sessionRef, request_kind: "review" }) });
  const approvalRef = approval.body?.approval_request?.ref || "";
  ok("a governance approval request over the session is admitted by its owner", approval.status === 201 && approvalRef.startsWith("approval-request://"), `${approval.status} ${approvalRef}`);
  const reviews = await projection("view=reviews");
  const facet = (reviews.body?.facets || []).find((f) => f.facet_ref === approvalRef) || null;
  const reviewRow = (reviews.body?.rows || []).find((r) => r.subject_ref === sessionRef) || null;
  ok("/work/reviews carries ONE review facet pointing at the approval (facet_kind review, owner Governance, typed subject) and the session row now lists the facet — a pointer, no Review object minted",
    !!facet && facet.schema_version === "ioi.hypervisor.work-facet-projection.v1" && facet.facet_kind === "review" && facet.facet_type === "approval_request"
      && facet.subject_kind === "session" && facet.subject_ref === sessionRef && facet.owner_ref === "surface://hypervisor/governance"
      && !!reviewRow && (reviewRow.review_facet_projection_refs || []).includes(facet.facet_projection_id)
      && reviews.body?.counts?.reviews === 1,
    JSON.stringify(facet ?? reviews.body).slice(0, 240));

  // -- malformed / ambiguous refusals, by name ----------------------------------------------------
  const badView = await projection("view=everything");
  const badRef = await projection("view=active&subject_ref=mission%3A%2F%2Fold-1");
  const ambiguous = await projection(`view=active&subject_ref=${encodeURIComponent(sessionRef)}&subject_kind=goal_run`);
  ok("an unknown view, a non-canonical subject ref and a subject/kind disagreement each refuse TYPED (400) rather than answering the nearest thing",
    badView.status === 400 && badView.body?.error?.code === "work_projection_view_unknown"
      && badRef.status === 400 && badRef.body?.error?.code === "work_projection_subject_ref_invalid"
      && ambiguous.status === 400 && ambiguous.body?.error?.code === "work_projection_subject_kind_ambiguous",
    `${badView.body?.error?.code}/${badRef.body?.error?.code}/${ambiguous.body?.error?.code}`);

  // -- truth-owner NONMUTATION ---------------------------------------------------------------------
  // The window opens AFTER this gate's own writes (the session and the approval request) so the
  // only actor between the two fingerprints is the projection being read, repeatedly, in every view.
  const before = fingerprint(OWNER_DIRS);
  for (let i = 0; i < 5; i += 1) await projection("view=active");
  for (const view of ["sessions", "queues", "reviews", "incidents", "history"]) await projection(`view=${view}`);
  await projection(`view=active&q=${encodeURIComponent(tail)}`);
  const after = fingerprint(OWNER_DIRS);
  const record = (await jd(`/v1/hypervisor/sessions/${encodeURIComponent(sessionRef)}`)).body?.session || {};
  ok("NONMUTATION: after every read above the owners' record directories are byte-identical and the session still reads provisioned under its own owner — the projection wrote no common status back",
    after === before && record.lifecycle_state === "provisioned" && record.owner_ref === PRINCIPAL, `${before.slice(0, 12)} → ${after.slice(0, 12)} · ${record.lifecycle_state}`);

  // -- another principal sees none of it: policy is the owner's, applied first --------------------
  const anon = await projection("view=active", false);
  ok("an anonymous caller's projection carries none of this principal's rows (either a typed refusal or a projection filtered to the loopback operator, which owns nothing here)",
    (anon.status === 401 && typeof anon.body?.error?.code === "string") || (anon.status === 200 && !(anon.body?.rows || []).some((r) => r.subject_ref === sessionRef) && anon.body?.counts?.sessions === 0),
    `${anon.status} rows ${(anon.body?.rows || []).length}`);

  // -- the Systems projection, under policy, honest when empty ------------------------------------
  const systems = await jd("/v1/hypervisor/autonomous-systems/projection?view=compact");
  ok("the Systems projection answers under the caller's policy with its registered row contract named and an EMPTY inventory as honest_empty — no fabricated System row",
    systems.status === 200 && systems.body?.row_contract_id === "schema://ioi/components/hypervisor/systems-projection/v1"
      && systems.body?.state === "honest_empty" && Array.isArray(systems.body?.systems) && systems.body.systems.length === 0
      && systems.body?.policy?.principal_ref === PRINCIPAL && systems.body?.nonclaims?.persistence === false,
    JSON.stringify(systems.body).slice(0, 200));
  const badSystemsView = await jd("/v1/hypervisor/autonomous-systems/projection?view=everything");
  ok("an unknown Systems view refuses typed", badSystemsView.status >= 400 && String(JSON.stringify(badSystemsView.body)).includes("system_projection_view_invalid"), String(badSystemsView.status));

  // -- REBUILD: a restart changes nothing the projection answers ---------------------------------
  daemon.kill("SIGTERM");
  await new Promise((r) => setTimeout(r, 1200));
  await startDaemon();
  const again = await projection("view=reviews");
  const rowAgain = (again.body?.rows || []).find((r) => r.subject_ref === sessionRef) || null;
  ok("after a daemon restart the same row, the same facet and the same counts come back — nothing was cached or persisted, so rebuild is a property of every read",
    !!rowAgain && (again.body?.facets || []).some((f) => f.facet_ref === approvalRef) && again.body?.counts?.sessions === 1 && again.body?.counts?.reviews === 1,
    JSON.stringify(again.body?.counts));

  // -- the App renders the canonical routes from the projections ----------------------------------
  const servePort = await freePort();
  const productUiPort = await freePort();
  SERVE = `http://127.0.0.1:${servePort}`;
  serve = spawn(process.execPath, [path.join(HERE, "serve-product-ui.mjs")], {
    cwd: APP,
    env: { ...process.env, PORT: String(servePort), PRODUCT_UI_PORT: String(productUiPort), IOI_PRODUCT_UI_PUBLIC: path.join(APP, "product-ui", "owned", "public"), IOI_HYPERVISOR_DAEMON_URL: DAEMON },
    stdio: ["ignore", "pipe", "pipe"],
  });
  await waitFor(`${SERVE}/work`, 30000);
  const workPage = await pageText("/work");
  ok("canonical /work renders the typed projection under its own ownership headers: the session row's deep link is on the page and the typed-absence families are named, not faked",
    workPage.status === 200 && workPage.headers.get("x-ioi-surface-route") === "/work"
      && workPage.text.includes(`/work/sessions/${tail}`) && workPage.text.includes("work_queue"),
    `status ${workPage.status}`);
  const sessionsPage = await pageText("/work/sessions");
  const reviewsPage = await pageText("/work/reviews");
  ok("canonical /work/sessions and /work/reviews render their views: the session row on one, the review facet's approval ref on the other",
    sessionsPage.status === 200 && sessionsPage.text.includes(sessionRef) && reviewsPage.status === 200 && reviewsPage.text.includes(approvalRef), `${sessionsPage.status}/${reviewsPage.status}`);
  const systemsPage = await pageText("/systems");
  ok("canonical /systems renders the Systems projection honestly empty under its ownership headers — no fabricated System row",
    systemsPage.status === 200 && systemsPage.headers.get("x-ioi-surface-route") === "/systems" && /honest_empty|no admitted System/i.test(systemsPage.text), `status ${systemsPage.status}`);
}

run().then(() => {
  const fails = results.filter((r) => !r.pass);
  for (const r of results) console.log(`${r.pass ? "PASS" : "FAIL"}  ${r.name}${r.detail ? ` — ${r.detail}` : ""}`);
  console.log(`\n${results.length - fails.length}/${results.length} passed`);
  emitVerifierCensus({ verifierId: "systems-work-projections", sourceUrl: import.meta.url, results });
  cleanup();
  process.exit(fails.length ? 1 : 0);
}).catch((e) => {
  console.error("verifier crashed:", e);
  cleanup();
  process.exit(1);
});
