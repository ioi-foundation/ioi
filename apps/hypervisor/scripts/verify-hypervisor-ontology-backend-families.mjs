#!/usr/bin/env node
// The three ontology backend families ACC-A names — proposals, saved object sets, object-instance
// search — driven end to end against a live daemon.
//
// WHY THIS EXISTS. Next-legs XII took SURF-ontology to 12 of 13 real governed controls and then said
// plainly what still blocked closure: it was BACKEND. Derived from the router rather than guessed,
// there was no ontology proposal/branch family, no saved object-set/exploration family, and no
// object-instance search family, so three of the six journeys ACC-A names could not close at any
// depth of UI work. This gate is the proof those three now exist as daemon truth.
//
// WHAT IT CHECKS, and why in this shape:
//   - THE ABSENCE CLAIM IS RE-DERIVED FROM THE ROUTER, both directions: the three families are
//     registered, and the daemon carries no SECOND writer for an ontology edit. A proposal apply
//     that re-implemented validation or revision bumping would be a second admission path for one
//     act, and that mistake has been made twice in this program.
//   - EVERY MUTATION IS IDENTITY-FIRST. Rule E owes a 401 before a 404 that would otherwise answer
//     "does this ontology exist" to a caller with no session. Anonymity is built from RAW TRANSPORT.
//   - CAS IS PROVEN BY DRIFT, not by a happy path: a proposal made against revision N refuses after
//     the ontology advances, and refuses having changed NOTHING.
//   - SAVED SETS ARE PER PRINCIPAL, with three real principals all holding `org://local` — the
//     precondition is asserted, because that tenant is held by everyone and isolates nothing.
//   - THE TWO EMPTIES ARE DIFFERENT FACTS. "No materialized object set exists here" and "your query
//     matched nothing" are distinguished, because a surface that cannot tell them apart shows an
//     empty table and lets a user conclude the wrong one.
//   - DURABLE TRUTH IS READ FROM DISK and survives a restart. Asking the API whether something
//     happened is asking the thing under test to grade itself.

import { spawn } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import net from "node:net";
import crypto from "node:crypto";
import http from "node:http";
import { fileURLToPath } from "node:url";
import { emitVerifierCensus } from "./lib/verifier-census.mjs";
import { mintTestGrant } from "./lib/wallet-authority.mjs";

const HERE = path.dirname(fileURLToPath(import.meta.url));
const APP = path.resolve(HERE, "..");
const ROOT = path.resolve(APP, "..", "..");

const results = [];
const ok = (name, cond, detail) => results.push({ name, pass: !!cond, detail: detail || "" });
const code = (j) => j?.code ?? j?.error?.code ?? "";
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

const freePort = () => new Promise((resolve, reject) => {
  const srv = net.createServer();
  srv.listen(0, "127.0.0.1", () => { const { port } = srv.address(); srv.close(() => resolve(port)); });
  srv.on("error", reject);
});

const waitFor = async (url, ms) => {
  const until = Date.now() + ms;
  while (Date.now() < until) {
    try { const r = await fetch(url); if (r.status < 500) return; } catch { /* not up */ }
    await sleep(300);
  }
  throw new Error(`timeout waiting for ${url}`);
};

const daemonBinary = path.resolve(ROOT, process.env.IOI_HYPERVISOR_DAEMON_BINARY ?? "target/debug/hypervisor-daemon");
try { fs.accessSync(daemonBinary, fs.constants.X_OK); } catch {
  console.error(`BLOCKED: daemon binary not executable at ${daemonBinary}`);
  process.exit(2);
}

const scratch = fs.mkdtempSync(path.join(os.tmpdir(), "ioi-onto-families-"));
const dataDir = path.join(scratch, "data");
fs.mkdirSync(dataDir, { recursive: true });

let DAEMON = "";
let daemon = null;
let daemonLog = "";
const P = { A: { session: "", owner: "", ref: "" }, B: { session: "", owner: "", ref: "" }, C: { session: "", owner: "", ref: "" } };

// ------------------------------------------------------------ the ontology family, watched at RUNTIME
//
// THE ENTAILMENT FOR "NO SECOND ONTOLOGY WRITER", and the reason it is not a source census.
// Five review rounds each defeated a source-derived census with a NEW spelling — a suffixed name, a
// bare literal, a shadowing const, a raw `fs::write`, a `File::create`, a bare `use super::x;`, a
// fn-pointer alias, a `use … as` alias, a writer parked on a line carrying a `://` literal so a
// comment stripper ate it, and an allowlisted module's own exported writer. That is the signal: a
// WHOLE-PROGRAM property cannot be entailed by regexes over one file, and every round of patching
// left the label still claiming more than the code checked.
//
// So the load-bearing check is BEHAVIOURAL. `odk-domain-ontologies` is not a promoted family
// (`PROMOTED_DOMAINS` is `["provider-receipts"]`), so its records are plain files. This fingerprints
// that directory after EVERY request and records which requests changed it. No source spelling can
// evade it: a second writer anywhere, reached by any name, moves the fingerprint under the request
// that ran it.
//
// WHAT IT DOES NOT PROVE, and the label says so: it is a closed world over the routes THIS JOURNEY
// DRIVES, not over all code. A route the journey never calls is not covered by it.
// THIS WATCHES THE LEGACY RECORD DIRECTORY, AND THAT IS ONLY SOUND WHILE THE FAMILY IS NOT
// PROMOTED. A mutation proved the hazard: `substrate_store::persist_promoted` admits into the
// multiplexed substrate log at `<data_dir>/substrate/`, so a second writer reached that way would
// change the ontology's durable truth while this directory sat still. Watching the substrate log
// too is not the answer — it is shared storage, and `auth/bootstrap` and every scope pin churn it
// for entirely legitimate reasons, so it reports noise rather than signal.
//
// So the PRECONDITION IS ASSERTED INSTEAD OF ASSUMED, below: `PROMOTED_DOMAINS` is pinned, and the
// ontology family is not in it. Promote this family and that assertion goes red, which is the
// correct outcome — this observation would need rebuilding against the substrate projection, and it
// must not go on quietly watching a directory the writes no longer reach.
const ONTOLOGY_FAMILY_DIR = "odk-domain-ontologies";
// THE RECEIPT FAMILY IS WATCHED TOO. A review minted fabricated ontology-plane receipts on the
// WITHDRAW requests — three receipts attesting patches that never happened — and the gate was 81/81,
// because only the ontology record store was fingerprinted. A second admission path minting
// ontology-plane RECEIPT truth is a second spine as surely as one minting records.
const ONTOLOGY_RECEIPT_DIR = "odk-ontology-receipts";
/** Every ontology record, keyed by id, with its content digest. Walks subdirectories. */
// ONE READ PRODUCES BOTH THE DIGEST AND THE CONTENT. Taking the digest in one pass and the content
// in a second left a window where a write landing between them yields a snapshot newer than the
// digest that selected it.
const familySnapshot = (rel) => {
  const root = path.join(dataDir, rel);
  const out = new Map();
  const walk = (dir, prefix) => {
    let entries = [];
    try { entries = fs.readdirSync(dir, { withFileTypes: true }); } catch { return; }
    for (const entry of entries) {
      const full = path.join(dir, entry.name);
      // RECURSE. A one-level read makes a subdirectory throw EISDIR and register as one constant
      // string, so it is recorded once on creation and never again — a whole subtree that changes
      // invisibly. Records are flat today; a check that only works while that holds is not a check.
      if (entry.isDirectory()) { walk(full, `${prefix}${entry.name}/`); continue; }
      let bytes;
      try { bytes = fs.readFileSync(full); } catch { out.set(`${prefix}${entry.name}`, { digest: "<unreadable>", record: null }); continue; }
      let record = null;
      try { record = JSON.parse(bytes.toString("utf8")); } catch { record = null; }
      out.set(`${prefix}${entry.name}`, { digest: crypto.createHash("sha256").update(bytes).digest("hex"), record });
    }
  };
  walk(root, "");
  return out;
};
const bothFamilies = () => ({ onto: familySnapshot(ONTOLOGY_FAMILY_DIR), receipts: familySnapshot(ONTOLOGY_RECEIPT_DIR) });
let ontologyPrint = bothFamilies();
/** Proposal id -> the `changes` object THE CALLER sent when creating it. Never read from a response. */
const proposalIntent = new Map();
/**
 * Re-baseline the watch after THE CHECKER ITSELF writes a record.
 *
 * The observation attributes any change it sees to the request that just ran, which is exactly what
 * makes it useful — and it means a fixture this file plants out of band would be blamed on the next
 * request. That happened, and the gate caught it. A fixture is not a daemon write, so it is excluded
 * EXPLICITLY and audibly here rather than by loosening the rule that noticed it.
 */
const resyncOntologyBaseline = () => { ontologyPrint = bothFamilies(); };
/**
 * Every request that left the ontology family different than it found it, with the EXACT set of
 * records it changed and the status it answered.
 *
 * KEYED ON THE WRITE, NOT ON THE ROUTE. The first cut of this recorded only `METHOD path` and
 * allowed three route SHAPES — and a review defeated it live at 78/78 by writing a second ontology
 * record inside `handle_proposal_apply`, the one handler this gate exists to police. One extra
 * write under an allowed name is indistinguishable from the allowed write when all you record is
 * the name. Worse, the write it demonstrated rode a 409-REFUSED apply: a request that refused and
 * still minted a record, with every assertion green. So what is recorded now is WHICH records moved
 * and WHAT the request answered, and the assertions below are about the identity of the write.
 */
const ontologyMutations = [];

/** `as: null` is ANONYMOUS, built from raw transport — no client object to copy, no bound method. */
async function jd(method, p, body, { as = "A" } = {}) {
  const session = as ? P[as].session : "";
  const headers = {};
  if (body !== undefined && body !== null) headers["content-type"] = "application/json";
  if (session) headers.cookie = `ioi_session=${session}`;
  return fetch(`${DAEMON}${p}`, {
    method,
    headers: Object.keys(headers).length ? headers : undefined,
    body: body !== undefined && body !== null ? JSON.stringify(body) : undefined,
  }).then(async (r) => {
    const text = await r.text();
    let j = null;
    try { j = JSON.parse(text); } catch { /* non-json */ }
    return { status: r.status, j, text };
  }).catch((e) => ({ status: 0, j: { transport_error: String(e) }, text: String(e) })).then((out) => {
    const before = ontologyPrint;
    const after = bothFamilies();
    const diff = (b, a) => {
      const changed = [];
      for (const [name, v] of a) if (b.get(name)?.digest !== v.digest) changed.push(name);
      for (const name of b.keys()) if (!a.has(name)) changed.push(`${name}:REMOVED`);
      return changed.sort();
    };
    const changed = diff(before.onto, after.onto);
    const receiptsChanged = diff(before.receipts, after.receipts);
    // THE CALLER'S OWN INTENT — the VALUE is the request's `changes`, which the daemon did not
    // produce, and that is what makes the check below non-circular. The KEY is the response's
    // proposal id, which the daemon DID produce; that is stated rather than glossed, and it fails
    // closed — a key that does not match yields an empty intent and reddens every field.
    const route = `${method} ${p.split("?")[0]}`;
    if (/\/odk\/ontology-proposals$/u.test(route) && method === "POST" && out.j?.ontology_proposal?.id) {
      proposalIntent.set(out.j.ontology_proposal.id, body?.changes ?? {});
    }
    if (changed.length || receiptsChanged.length) {
      ontologyPrint = after;
      ontologyMutations.push({
        route, status: out.status, changed, receiptsChanged, body: out.j, request: body ?? null,
        before: Object.fromEntries(changed.map((n) => [n, before.onto.get(n)?.record ?? null])),
        after: Object.fromEntries(changed.map((n) => [n, after.onto.get(n)?.record ?? null])),
        proposalId: /\/ontology-proposals\/([^/]+)\/apply$/u.exec(p)?.[1] ?? null,
      });
    }
    return out;
  });
}

function startDaemon(port) {
  daemon = spawn(daemonBinary, [], {
    cwd: ROOT,
      env: {
      ...process.env,
      IOI_HYPERVISOR_DAEMON_ADDR: `127.0.0.1:${port}`,
      IOI_HYPERVISOR_DATA_DIR: dataDir,
      IOI_HYPERVISOR_MODEL_UPSTREAM: "http://127.0.0.1:1",
      // The dev signer, so the two wallet crossings in the materialization ladder can be satisfied
      // by this process. Without it the corpus below cannot be PRODUCT-PRODUCED, and a hand-written
      // one would be exactly the fixture corpus this estate forbids a checker.
      IOI_WALLET_TEST_SIGNER: "1",
    },
    stdio: ["ignore", "pipe", "pipe"],
  });
  daemon.stdout.on("data", (c) => { daemonLog = `${daemonLog}${c}`.slice(-64000); });
  daemon.stderr.on("data", (c) => { daemonLog = `${daemonLog}${c}`.slice(-64000); });
}
const stopDaemon = () => { try { daemon?.kill("SIGTERM"); } catch { /* gone */ } daemon = null; };
function cleanup() { stopDaemon(); try { fs.rmSync(scratch, { recursive: true, force: true }); } catch { /* best effort */ } }

// ------------------------------------------------------------------- durable-truth readers
const recordsIn = (dir) => { try { return fs.readdirSync(path.join(dataDir, dir)).filter((f) => f.endsWith(".json")).sort(); } catch { return []; } };
const readRecord = (dir, id) => { try { return JSON.parse(fs.readFileSync(path.join(dataDir, dir, `${id}.json`), "utf8")); } catch { return null; } };

// ------------------------------------------------------------------- the derived closed world
const routerSource = () => fs.readFileSync(path.join(ROOT, "crates/node/src/bin/hypervisor-daemon.rs"), "utf8");

/** Every route registered to the ontology-workbench module, with its methods. */
const workbenchRoutes = () => {
  const found = [];
  for (const chunk of routerSource().split(".route(")) {
    const pathMatch = chunk.match(/^\s*"(\/v1\/hypervisor\/[^"]*)"/u);
    if (!pathMatch) continue;
    const body = chunk.slice(0, chunk.indexOf("\n        )"));
    if (!/ontology_workbench_routes::/u.test(body)) continue;
    for (const method of ["get", "post", "patch", "put", "delete"]) {
      if (new RegExp(`(^|[^a-z_])${method}\\(`, "u").test(body)) found.push({ method: method.toUpperCase(), path: pathMatch[1] });
    }
  }
  return found;
};

async function run() {
  const port = await freePort();
  DAEMON = `http://127.0.0.1:${port}`;
  startDaemon(port);
  await waitFor(`${DAEMON}/healthz`, 30000);

  // ------------------------------------------------------------ principals
  const bootToken = daemonLog.match(/ioi_bootstrap_[a-f0-9]{64}/gu)?.at(-1) ?? null;
  const boot = await jd("POST", "/v1/hypervisor/auth/bootstrap", { token: bootToken, password: "onto-families-a-v1" }, { as: null });
  P.A.session = boot.j?.session_token ?? "";
  const whoA = (await jd("GET", "/v1/hypervisor/auth/whoami", null, { as: "A" })).j || {};
  P.A.owner = (whoA.principal?.tenant_refs || []).find((t) => t === "org://local") || "";
  P.A.ref = whoA.principal?.principal_ref ?? "";
  ok("principal A is a REAL authenticated operator session holding the deployment's org tenant",
    whoA.authenticated === true && P.A.owner === "org://local", `authenticated ${whoA.authenticated} owner ${P.A.owner}`);

  for (const letter of ["B", "C"]) {
    const email = `onto-families-${letter.toLowerCase()}@ioi.local`;
    const created = await jd("POST", "/v1/hypervisor/principals", { email, name: `Member ${letter}`, role: "member", password: `onto-families-${letter}-v1` }, { as: "A" });
    const pid = created.j?.principal?.principal_id ?? "";
    await jd("POST", `/v1/hypervisor/principals/${pid}/tenant-memberships`, {
      tenant_ref: "org://local", expected_revision: 0, idempotency_key: `onto-families-grant-${letter}`,
      reason: "verifier fixture: an ordinary member in the deployment's only organization",
    }, { as: "A" });
    const login = await jd("POST", "/v1/hypervisor/auth/login", { email, password: `onto-families-${letter}-v1` }, { as: null });
    P[letter].session = login.j?.session_token ?? "";
    const who = (await jd("GET", "/v1/hypervisor/auth/whoami", null, { as: letter })).j || {};
    P[letter].owner = (who.principal?.tenant_refs || []).find((t) => t === "org://local") || "";
    P[letter].ref = who.principal?.principal_ref ?? "";
  }
  ok("PRECONDITION: all three principals hold the SAME org tenant, so a tenant check would isolate NOTHING",
    P.A.owner === "org://local" && P.B.owner === "org://local" && P.C.owner === "org://local"
      && P.A.ref !== P.B.ref && P.B.ref !== P.C.ref, `${P.A.owner}/${P.B.owner}/${P.C.owner}`);

  // ------------------------------------------------------------ the ontology under test
  const created = await jd("POST", "/v1/hypervisor/odk/domain-ontologies", {
    domain: "families", version: "1.0.0", description: "the ontology the three families operate on",
    canonical_object_model: { object_types: [{ id: "widget", name: "Widget", properties: [] }], link_types: [], action_types: [], value_types: [] },
  }, { as: "A" });
  const ontologyId = created.j?.ontology?.id ?? "";
  const ontologyRef = created.j?.ontology?.ref ?? "";
  ok("PRECONDITION: a real domain ontology is admitted through the product's own route, at revision 1",
    (created.status === 200 || created.status === 201) && ontologyId.length > 0 && (created.j?.ontology?.revision ?? 0) === 1,
    `status ${created.status} id ${ontologyId} rev ${created.j?.ontology?.revision}`);

  // ============================================================ FAMILY 1 — proposals
  const anonPropose = await jd("POST", "/v1/hypervisor/odk/ontology-proposals", { ontology_ref: ontologyRef, title: "x", changes: { description: "y" } }, { as: null });
  ok("PROPOSE refuses an ANONYMOUS caller — rule E owes a 401 before any record read",
    anonPropose.status === 401, `status ${anonPropose.status}`);
  ok("and the refused anonymous propose admitted NO proposal record",
    recordsIn("odk-ontology-proposals").length === 0, `${recordsIn("odk-ontology-proposals").length} records`);

  const emptyProposal = await jd("POST", "/v1/hypervisor/odk/ontology-proposals", { ontology_ref: ontologyRef, title: "empty", changes: {} }, { as: "A" });
  ok("a proposal naming NO change is refused typed — an empty proposal proposes nothing",
    emptyProposal.status === 400 && code(emptyProposal.j) === "ontology_proposal_change_required",
    `status ${emptyProposal.status} code ${code(emptyProposal.j)}`);

  const unknownOntology = await jd("POST", "/v1/hypervisor/odk/ontology-proposals", { ontology_ref: "domain-ontology://does-not-exist", title: "x", changes: { description: "y" } }, { as: "A" });
  ok("a proposal against an ontology that does not resolve is refused typed, not silently accepted",
    unknownOntology.status === 404 && code(unknownOntology.j) === "odk_ontology_not_found",
    `status ${unknownOntology.status} code ${code(unknownOntology.j)}`);

  const staleBase = await jd("POST", "/v1/hypervisor/odk/ontology-proposals", {
    ontology_ref: ontologyRef, title: "stale base", expected_revision: 99, changes: { description: "z" },
  }, { as: "A" });
  ok("a proposal declaring the WRONG base revision is refused by the same CAS an ordinary edit obeys",
    staleBase.status === 409 && code(staleBase.j) === "odk_revision_conflict",
    `status ${staleBase.status} code ${code(staleBase.j)}`);


  // PROPOSE AND PATCH MUST AGREE, AND ONLY A LIVE PROBE CAN SAY SO. The static assertions below pin
  // that one validator exists and both planes call it; they cannot see a SECOND, hand-maintained
  // pre-check disagreeing with it, which is exactly what a review found — `domain: null` refused at
  // propose and was a 200 no-op at patch, and `canonical_object_model: null` did the reverse because
  // the validator disagreed with ITSELF about whether a null is absent.
  for (const [label, changes, expected] of [
    // A null string field names nothing on either plane, so there is no shared refusal code to pin —
    // parity carries that shape alone, and the exception is named where it is applied.
    ["an explicit null string field", { domain: null }, null],
    ["an explicit null object model", { canonical_object_model: null }, "odk_field_type_invalid"],
    ["an empty required field", { domain: "" }, "odk_domain_required"],
    // The emptiness check TRIMS, and that trim is load-bearing — the module says so itself. Nothing
    // covered a whitespace-only value, so relaxing `value.trim().is_empty()` to `value.is_empty()`
    // made `"   "` admissible on BOTH planes and stayed green.
    ["a whitespace-only required field", { domain: "   " }, "odk_domain_required"],
    // And the `domain` bound was exercised by nothing at all — raising it to 100000 was silent,
    // while `version` and `description` were both pinned.
    ["an over-length domain", { domain: "d".repeat(121) }, "odk_field_too_long"],
    ["an over-length version", { version: "v".repeat(61) }, "odk_field_too_long"],
    ["an over-length description", { description: "x".repeat(2001) }, "odk_field_too_long"],
    ["a non-string field", { domain: 5 }, "odk_field_type_invalid"],
    ["a model the ontology plane rejects", { canonical_object_model: { object_types: [{ id: "dup", name: "A", properties: [] }, { id: "dup", name: "B", properties: [] }], link_types: [], action_types: [], value_types: [] } }, "ontology_duplicate_id"],
  ]) {
    const fresh = (await jd("POST", "/v1/hypervisor/odk/domain-ontologies", { domain: `parity-${encodeURIComponent(label).slice(0, 12)}`, canonical_object_model: { object_types: [], link_types: [], action_types: [], value_types: [] } }, { as: "A" })).j?.ontology;
    const patched = await jd("PATCH", `/v1/hypervisor/odk/domain-ontologies/${fresh?.id}`, { expected_revision: fresh?.revision, ...changes }, { as: "A" });
    const proposed = await jd("POST", "/v1/hypervisor/odk/ontology-proposals", { ontology_ref: fresh?.ref, title: "parity", changes }, { as: "A" });
    const patchCode = patched.j?.ok === true ? "ACCEPTED" : code(patched.j);
    const proposeCode = proposed.status === 201 ? "ACCEPTED" : code(proposed.j);
    // A null names nothing, so patch is a no-op while propose refuses "you proposed nothing" — the
    // one difference that is a PROPOSAL rule rather than a validation rule, and it is named here
    // rather than hidden behind a looser comparison.
    const agree = patchCode === proposeCode
      || (patchCode === "ACCEPTED" && proposeCode === "ontology_proposal_change_required");
    ok(`propose and patch agree on ${label} — one validator means one verdict, and a second hand-maintained pre-check is exactly what disagrees`,
      agree, `patch ${patchCode} / propose ${proposeCode}`);
    // AND THE ABSOLUTE REFUSAL, because AGREEMENT ALONE IS BLIND BY CONSTRUCTION. A shared validator
    // preserves parity under ANY weakening — a review deleted one guard key so an empty `domain`
    // became admissible on BOTH planes, and this journey stayed 63/63 printing "ACCEPTED /
    // ACCEPTED". Parity can only see a second, non-shared pre-check. What holds the contract is a
    // per-shape assertion that the estate REFUSES, with the expected code named.
    if (expected) {
      // AND THE REFUSAL IS AN ABSENCE OF THE ACT, not a code in a body. A review noted this pinned
      // the code and never the EFFECT: the writer answers 200 with `ok:false` for a validation
      // refusal, so "REFUSE" meant only "emitted this string". The ontology is read back and its
      // revision must be exactly the one the shape was made against — a refusal that still advanced
      // the revision is not a refusal, whatever it says.
      const after = await jd("GET", `/v1/hypervisor/odk/domain-ontologies/${fresh?.id}`, null, { as: "A" });
      ok(`and BOTH planes REFUSE ${label} with \`${expected}\`, propose typed 400, and the ontology STAYS at the revision it was made against — parity is preserved by any weakening of a shared validator, so agreement is not the contract, and a code in a body is not an absence of the act`,
        patchCode === expected && proposeCode === expected
          && proposed.status === 400
          && (after.j?.ontology?.revision ?? -1) === fresh?.revision,
        `patch ${patchCode} / propose ${proposeCode} (${proposed.status}) rev ${fresh?.revision} -> ${after.j?.ontology?.revision}`);
    }
  }
  ok("and none of those refused proposals was ADMITTED — a refusal that still writes a record is not a refusal",
    recordsIn("odk-ontology-proposals").length === 0,
    `${recordsIn("odk-ontology-proposals").length} proposal records`);
  // AND THE WRITE PATH STORES WHAT IT WAS GIVEN. The extraction once wrote `value.trim()`, silently
  // rewriting caller data: create stored "  9.9.9  " while patch of the same string stored "9.9.9",
  // and a proposal's reviewed text stopped being the text that got written.
  const verbatim = (await jd("POST", "/v1/hypervisor/odk/domain-ontologies", { domain: "verbatim", canonical_object_model: { object_types: [], link_types: [], action_types: [], value_types: [] } }, { as: "A" })).j?.ontology;
  const spaced = await jd("PATCH", `/v1/hypervisor/odk/domain-ontologies/${verbatim?.id}`, { expected_revision: verbatim?.revision, version: "  9.9.9  " }, { as: "A" });
  ok("the PATCH write path stores the value VERBATIM — trimming belongs to the emptiness check, never to what is persisted",
    spaced.j?.ontology?.version === "  9.9.9  ",
    JSON.stringify(spaced.j?.ontology?.version));
  // AND SO DOES CREATE, WHICH IT DID NOT. A review found `create` trimming `domain` before storing
  // while `apply_ontology_change` stored it verbatim — one field's worth of the exact divergence
  // this module claims to have ended, and the assertion above never saw it because it probes only
  // PATCH and only `version`. Both routes, and the field that diverged.
  const paddedCreate = (await jd("POST", "/v1/hypervisor/odk/domain-ontologies", { domain: "  padded-domain  ", canonical_object_model: { object_types: [], link_types: [], action_types: [], value_types: [] } }, { as: "A" })).j?.ontology;
  ok("and the CREATE write path stores `domain` verbatim too — create and patch may not disagree about what persisting a field means",
    paddedCreate?.domain === "  padded-domain  " && readRecord("odk-domain-ontologies", paddedCreate?.id ?? "")?.domain === "  padded-domain  ",
    JSON.stringify(paddedCreate?.domain));
  // A RECORD WRITTEN BEFORE THIS CAPABILITY LANDED STILL READS THE TRUTH. `health.object_data_note`
  // is computed at write time and PERSISTED, so an ontology already on disk kept whatever sentence
  // was true when it was created — a review found three user-facing pages telling readers no
  // object-instance plane was bound, months after one was, with no backfill anywhere. Prose about
  // the plane is projected on READ now, and this plants a stale record and reads it back to prove it.
  const stalePath = path.join(dataDir, "odk-domain-ontologies", `${verbatim?.id}.json`);
  const staleRecord = JSON.parse(fs.readFileSync(stalePath, "utf8"));
  staleRecord.health = { ...(staleRecord.health ?? {}), object_data_note: "schema only — no object-instance/projection plane is bound; explorer rows require a real ontology-bound object plane (not built here)" };
  fs.writeFileSync(stalePath, JSON.stringify(staleRecord, null, 2));
  resyncOntologyBaseline();   // planted by this file, not by the daemon — see the helper's note
  const staleGet = await jd("GET", `/v1/hypervisor/odk/domain-ontologies/${verbatim?.id}`, null, { as: "A" });
  const staleList = await jd("GET", "/v1/hypervisor/odk/domain-ontologies", null, { as: "A" });
  const staleListed = (staleList.j?.ontologies ?? []).find((o) => o.id === verbatim?.id);
  ok("an ontology whose PERSISTED health note predates this capability reads back the CURRENT note on both the get and the list path — a sentence about what the estate can do is projected on read, never served from a record written before it was true",
    !/no object-instance\/projection plane is bound/u.test(JSON.stringify(staleGet.j?.ontology?.health ?? {}))
      && !/no object-instance\/projection plane is bound/u.test(JSON.stringify(staleListed?.health ?? {}))
      && /object-instance SEARCH plane/u.test(String(staleGet.j?.ontology?.health?.object_data_note ?? "")),
    String(staleGet.j?.ontology?.health?.object_data_note ?? "").slice(0, 60));

  // A SUCCESSFUL MODEL PATCH, walked because nothing walked it. The plane recomputes `health` from
  // the caller's model on every patch, and the caller never names it — so this is the one legitimate
  // write that tells the caller-intent census apart from a census that has simply never met it.
  const modelPatch = await jd("PATCH", `/v1/hypervisor/odk/domain-ontologies/${verbatim?.id}`, {
    expected_revision: spaced.j?.ontology?.revision,
    canonical_object_model: { object_types: [{ id: "walked", name: "Walked", properties: [] }], link_types: [], action_types: [], value_types: [] },
  }, { as: "A" });
  ok("a model patch APPLIES and the plane recomputes health from it — a derived field the caller never names, which is why it is bookkeeping and not a create-only default",
    modelPatch.status === 200 && modelPatch.j?.ok === true
      && (modelPatch.j?.ontology?.canonical_object_model?.object_types ?? []).some((t) => t.id === "walked"),
    `status ${modelPatch.status}`);
  // AND THE FOURTH WRITER IS WALKED. `DELETE /odk/domain-ontologies/:id` is registered and receipted;
  // a model of this plane that names three writers is a false statement about it.
  const doomed = (await jd("POST", "/v1/hypervisor/odk/domain-ontologies", { domain: "doomed", canonical_object_model: { object_types: [], link_types: [], action_types: [], value_types: [] } }, { as: "A" })).j?.ontology;
  const deleted = await jd("DELETE", `/v1/hypervisor/odk/domain-ontologies/${doomed?.id}`, null, { as: "A" });
  ok("the ontology DELETE writer removes its own record and nothing else — the fourth registered writer of this family, walked rather than assumed absent",
    deleted.status === 200 && readRecord("odk-domain-ontologies", doomed?.id ?? "") === null,
    `status ${deleted.status}`);

  const proposal = await jd("POST", "/v1/hypervisor/odk/ontology-proposals", {
    ontology_ref: ontologyRef, title: "describe the widget domain", rationale: "the description was a placeholder",
    expected_revision: 1, changes: { description: "widgets, their links, and the actions over them" },
  }, { as: "A" });
  const proposalId = proposal.j?.ontology_proposal?.id ?? "";
  ok("A PROPOSAL EXISTS as daemon truth: admitted open, attributed to its proposer, pinned to the revision it was made against",
    proposal.status === 201
      && proposal.j?.ontology_proposal?.status === "open"
      && proposal.j?.ontology_proposal?.based_on_revision === 1
      && proposal.j?.ontology_proposal?.proposed_by === P.A.ref,
    `status ${proposal.status} id ${proposalId}`);
  ok("and it is DURABLE on disk, not just in the response",
    readRecord("odk-ontology-proposals", proposalId)?.status === "open",
    recordsIn("odk-ontology-proposals").join(","));

  const listed = await jd("GET", `/v1/hypervisor/odk/ontology-proposals?ontology_ref=${encodeURIComponent(ontologyRef)}&status=open`, null, { as: "B" });
  ok("the proposal is READABLE by another principal — a proposal is estate truth about a shared ontology, not private working state",
    listed.status === 200 && (listed.j?.ontology_proposals ?? []).some((p) => p.id === proposalId),
    `${(listed.j?.ontology_proposals ?? []).length} rows`);
  const listedAnon = await jd("GET", "/v1/hypervisor/odk/ontology-proposals", null, { as: null });
  ok("but not by an anonymous one",
    listedAnon.status === 401, `status ${listedAnon.status}`);

  // THE ONTOLOGY MOVES UNDERNEATH THE PROPOSAL.
  const drift = await jd("PATCH", `/v1/hypervisor/odk/domain-ontologies/${ontologyId}`, { expected_revision: 1, version: "1.0.1" }, { as: "B" });
  ok("PRECONDITION: an ordinary edit really does advance the ontology to revision 2",
    drift.status === 200 && drift.j?.ontology?.revision === 2, `status ${drift.status} rev ${drift.j?.ontology?.revision}`);
  const staleApply = await jd("POST", `/v1/hypervisor/odk/ontology-proposals/${proposalId}/apply`, null, { as: "A" });
  ok("APPLYING A STALE PROPOSAL REFUSES, naming both revisions — applying would silently overwrite whatever landed in between",
    staleApply.status === 409 && code(staleApply.j) === "ontology_proposal_stale"
      && staleApply.j?.error?.based_on_revision === 1 && staleApply.j?.error?.current_revision === 2,
    `status ${staleApply.status} code ${code(staleApply.j)}`);
  const afterStale = await jd("GET", `/v1/hypervisor/odk/domain-ontologies/${ontologyId}`, null, { as: "A" });
  ok("and the stale apply CHANGED NOTHING — the ontology is still at the revision the drift left it",
    afterStale.j?.ontology?.revision === 2 && readRecord("odk-ontology-proposals", proposalId)?.status === "open",
    `rev ${afterStale.j?.ontology?.revision} proposal ${readRecord("odk-ontology-proposals", proposalId)?.status}`);

  // A REBASED PROPOSAL APPLIES, THROUGH THE ONTOLOGY PLANE'S OWN WRITER.
  const rebased = await jd("POST", "/v1/hypervisor/odk/ontology-proposals", {
    ontology_ref: ontologyRef, title: "rebased", expected_revision: 2,
    changes: { description: "widgets, their links, and the actions over them" },
  }, { as: "A" });
  const rebasedId = rebased.j?.ontology_proposal?.id ?? "";
  const receiptsBefore = recordsIn("odk-ontology-receipts").length;
  const applied = await jd("POST", `/v1/hypervisor/odk/ontology-proposals/${rebasedId}/apply`, null, { as: "C" });
  ok("A PROPOSAL APPLIES, and the ontology really carries the proposed change at the next revision",
    applied.status === 200
      && applied.j?.ontology?.revision === 3
      && applied.j?.ontology?.description === "widgets, their links, and the actions over them",
    `status ${applied.status} rev ${applied.j?.ontology?.revision}`);
  ok("the apply went through the ONTOLOGY PLANE'S OWN WRITER — it emitted that plane's receipt, not a second receipt family of its own",
    recordsIn("odk-ontology-receipts").length === receiptsBefore + 1
      && String(applied.j?.ontology_receipt?.schema_version) === "ioi.hypervisor.odk.ontology-receipt.v1"
      && applied.j?.ontology_receipt?.op === "patched",
    `${receiptsBefore} -> ${recordsIn("odk-ontology-receipts").length} receipts`);
  ok("and the ontology's own history carries the applied revision with that receipt — the edit is indistinguishable from an ordinary one, which is the point",
    (applied.j?.ontology?.history ?? []).some((h) => h.revision === 3 && h.receipt_ref === applied.j?.ontology_receipt?.receipt_ref),
    `${(applied.j?.ontology?.history ?? []).length} history entries`);
  ok("the applied proposal records WHO applied it and the revision it produced",
    readRecord("odk-ontology-proposals", rebasedId)?.status === "applied"
      && readRecord("odk-ontology-proposals", rebasedId)?.applied?.applied_by === P.C.ref
      && readRecord("odk-ontology-proposals", rebasedId)?.applied?.resulting_revision === 3,
    JSON.stringify(readRecord("odk-ontology-proposals", rebasedId)?.applied ?? {}));
  const reapply = await jd("POST", `/v1/hypervisor/odk/ontology-proposals/${rebasedId}/apply`, null, { as: "C" });
  const afterReapply = await jd("GET", `/v1/hypervisor/odk/domain-ontologies/${ontologyId}`, null, { as: "A" });
  ok("RE-APPLYING replays rather than editing twice — the ontology stays at the revision the first apply produced",
    reapply.status === 200 && reapply.j?.replayed === true && afterReapply.j?.ontology?.revision === 3,
    `status ${reapply.status} replayed ${reapply.j?.replayed} rev ${afterReapply.j?.ontology?.revision}`);

  const withdrawn = await jd("POST", `/v1/hypervisor/odk/ontology-proposals/${proposalId}/withdraw`, { reason: "superseded by the rebased proposal" }, { as: "A" });
  ok("an OPEN proposal withdraws, attributed and reasoned",
    withdrawn.status === 200 && withdrawn.j?.ontology_proposal?.status === "withdrawn"
      && withdrawn.j?.ontology_proposal?.withdrawn?.withdrawn_by === P.A.ref,
    `status ${withdrawn.status}`);
  const applyWithdrawn = await jd("POST", `/v1/hypervisor/odk/ontology-proposals/${proposalId}/apply`, null, { as: "A" });
  ok("and a withdrawn proposal can never be applied",
    applyWithdrawn.status === 409 && code(applyWithdrawn.j) === "ontology_proposal_not_open",
    `status ${applyWithdrawn.status} code ${code(applyWithdrawn.j)}`);
  const withdrawApplied = await jd("POST", `/v1/hypervisor/odk/ontology-proposals/${rebasedId}/withdraw`, { reason: "too late" }, { as: "A" });
  ok("nor can an APPLIED proposal be withdrawn — a terminal proposal is history",
    withdrawApplied.status === 409 && code(withdrawApplied.j) === "ontology_proposal_terminal",
    `status ${withdrawApplied.status} code ${code(withdrawApplied.j)}`);

  // ============================================================ FAMILY 2 — saved object sets
  const anonSave = await jd("POST", "/v1/hypervisor/odk/saved-object-sets", { name: "x", ontology_ref: ontologyRef, selection: { q: "a" } }, { as: null });
  ok("SAVE refuses an anonymous caller",
    anonSave.status === 401 && recordsIn("odk-saved-object-sets").length === 0,
    `status ${anonSave.status}`);
  const emptySelection = await jd("POST", "/v1/hypervisor/odk/saved-object-sets", { name: "empty", ontology_ref: ontologyRef, selection: {} }, { as: "A" });
  ok("a saved set with an EMPTY selection is refused typed — a set that selects nothing saves nothing",
    emptySelection.status === 400 && code(emptySelection.j) === "saved_object_set_selection_required",
    `status ${emptySelection.status} code ${code(emptySelection.j)}`);

  const saved = await jd("POST", "/v1/hypervisor/odk/saved-object-sets", {
    name: "widgets I care about", description: "the working set", ontology_ref: ontologyRef,
    selection: { object_type_id: "widget", q: "alpha" },
  }, { as: "A" });
  const savedId = saved.j?.saved_object_set?.id ?? "";
  ok("A SAVED OBJECT SET EXISTS as daemon truth, at revision 1, attributed to the principal who saved it",
    saved.status === 201 && savedId.startsWith("sos_")
      && saved.j?.saved_object_set?.revision === 1 && saved.j?.saved_object_set?.saved_by === P.A.ref,
    `status ${saved.status} id ${savedId}`);

  const bReads = await jd("GET", `/v1/hypervisor/odk/saved-object-sets/${savedId}`, null, { as: "B" });
  ok("B cannot READ A's saved set — an exploration is one principal's working state, pinned per PRINCIPAL and not by tenant",
    bReads.status === 403, `status ${bReads.status} code ${code(bReads.j)}`);
  const bList = await jd("GET", "/v1/hypervisor/odk/saved-object-sets", null, { as: "B" });
  ok("and B's own list does not contain it — listing derives from the caller's own authorized scope set",
    bList.status === 200 && (bList.j?.saved_object_sets ?? []).every((s) => s.id !== savedId),
    `${(bList.j?.saved_object_sets ?? []).length} rows for B`);
  const aList = await jd("GET", "/v1/hypervisor/odk/saved-object-sets", null, { as: "A" });
  ok("while A's list does",
    aList.status === 200 && (aList.j?.saved_object_sets ?? []).some((s) => s.id === savedId),
    `${(aList.j?.saved_object_sets ?? []).length} rows for A`);

  const bPatch = await jd("PATCH", `/v1/hypervisor/odk/saved-object-sets/${savedId}`, { expected_revision: 1, name: "mine now" }, { as: "B" });
  ok("B cannot EDIT A's saved set either",
    bPatch.status === 403 && readRecord("odk-saved-object-sets", savedId)?.name === "widgets I care about",
    `status ${bPatch.status} name ${readRecord("odk-saved-object-sets", savedId)?.name}`);

  const staleSetPatch = await jd("PATCH", `/v1/hypervisor/odk/saved-object-sets/${savedId}`, { expected_revision: 7, name: "stale" }, { as: "A" });
  ok("a saved-set edit at the WRONG revision refuses on the same CAS, and changes nothing",
    staleSetPatch.status === 409 && code(staleSetPatch.j) === "odk_revision_conflict"
      && readRecord("odk-saved-object-sets", savedId)?.revision === 1,
    `status ${staleSetPatch.status} code ${code(staleSetPatch.j)}`);
  const noChange = await jd("PATCH", `/v1/hypervisor/odk/saved-object-sets/${savedId}`, { expected_revision: 1 }, { as: "A" });
  ok("and a patch naming NO field is refused rather than bumping the revision for nothing",
    noChange.status === 400 && code(noChange.j) === "saved_object_set_change_required",
    `status ${noChange.status} code ${code(noChange.j)}`);

  const patched = await jd("PATCH", `/v1/hypervisor/odk/saved-object-sets/${savedId}`, {
    expected_revision: 1, name: "widgets I really care about", selection: { object_type_id: "widget", q: "beta" },
  }, { as: "A" });
  ok("A's own edit applies and advances the revision exactly once",
    patched.status === 200 && patched.j?.saved_object_set?.revision === 2
      && patched.j?.saved_object_set?.selection?.q === "beta",
    `status ${patched.status} rev ${patched.j?.saved_object_set?.revision}`);

  const retired = await jd("POST", `/v1/hypervisor/odk/saved-object-sets/${savedId}/retire`, { reason: "done exploring" }, { as: "A" });
  ok("RETIRE, NOT DELETE — the record survives as history with its reason and actor, because content deletion belongs to the retention plane",
    retired.status === 200 && retired.j?.saved_object_set?.status === "retired"
      && readRecord("odk-saved-object-sets", savedId) !== null,
    `status ${retired.status}`);
  const editRetired = await jd("PATCH", `/v1/hypervisor/odk/saved-object-sets/${savedId}`, { expected_revision: 2, name: "back" }, { as: "A" });
  ok("and a retired set accepts no further edits",
    editRetired.status === 409 && code(editRetired.j) === "saved_object_set_retired",
    `status ${editRetired.status} code ${code(editRetired.j)}`);
  const retireAgain = await jd("POST", `/v1/hypervisor/odk/saved-object-sets/${savedId}/retire`, {}, { as: "A" });
  ok("retiring twice replays rather than rewriting the retirement",
    retireAgain.status === 200 && retireAgain.j?.replayed === true,
    `status ${retireAgain.status}`);

  // ============================================================ FAMILY 3 — object-instance search
  const anonSearch = await jd("POST", "/v1/hypervisor/odk/object-instance-search", { q: "x" }, { as: null });
  ok("SEARCH refuses an anonymous caller",
    anonSearch.status === 401, `status ${anonSearch.status}`);

  const emptyCorpus = await jd("POST", "/v1/hypervisor/odk/object-instance-search", { ontology_ref: ontologyRef, q: "alpha" }, { as: "A" });
  ok("with NO materialized corpus the answer is a NAMED ABSENCE, not an empty result list — 'nothing has been materialized' and 'your query matched nothing' are different facts",
    emptyCorpus.status === 200 && (emptyCorpus.j?.results ?? []).length === 0
      && emptyCorpus.j?.absence?.code === "object_instance_corpus_absent"
      && emptyCorpus.j?.corpus?.materialized_object_sets_in_scope === 0,
    `absence ${emptyCorpus.j?.absence?.code}`);

  const badOntology = await jd("POST", "/v1/hypervisor/odk/object-instance-search", { ontology_ref: "domain-ontology://nope", q: "a" }, { as: "A" });
  ok("a search scoped to an ontology that does not resolve NAMES ITSELF rather than reading as 'no results'",
    badOntology.status === 404 && code(badOntology.j) === "odk_ontology_not_found",
    `status ${badOntology.status} code ${code(badOntology.j)}`);
  const badLimit = await jd("POST", "/v1/hypervisor/odk/object-instance-search", { limit: 0 }, { as: "A" });
  ok("an out-of-range limit is refused typed, never silently clamped",
    badLimit.status === 400 && code(badLimit.j) === "object_instance_search_limit_invalid",
    `status ${badLimit.status} code ${code(badLimit.j)}`);

  // A REAL CORPUS, PRODUCED BY THE PRODUCT'S OWN MATERIALIZATION LADDER. Not written to disk by this
  // file: this estate forbids a checker its own fixture corpus, and a search gate fed hand-written
  // rows proves the search code runs, never that it searches what the product actually produces.
  // Every rung below is the same route the connector-execution plane uses — data source, connector
  // mapping, policy-bound view, transformation dry-run, projection, lease plan, wallet-gated
  // materializing run, sealed connector session — ending in a real HTTP fetch of real rows.
  const SENTINEL = "onto-families-bearer-SENTINEL";
  const sourceRows = [
    { id: "L-1", disp: "gold tier loan", amt: 1250.5 },
    { id: "L-2", disp: "silver tier loan", amt: 90000 },
    { id: "L-3", disp: "gold tier renewal", amt: 42 },
  ];
  let sourceHits = 0;
  const rowServer = http.createServer((req, res) => {
    if (req.headers.authorization !== `Bearer ${SENTINEL}`) { res.writeHead(401); return res.end("unauthorized"); }
    sourceHits += 1;
    res.writeHead(200, { "content-type": "application/json" });
    res.end(JSON.stringify(sourceRows));
  });
  await new Promise((resolve) => rowServer.listen(0, "127.0.0.1", resolve));
  const rowPort = rowServer.address().port;

  const connector = await jd("POST", "/v1/hypervisor/connectors", { service: "onto-families", base_url: `http://127.0.0.1:${rowPort}`, name: "Ontology families fixture" }, { as: "A" });
  const connectorId = connector.j?.connector?.connector_id ?? connector.j?.connector_id ?? "";
  await jd("POST", `/v1/hypervisor/connectors/${connectorId}/credential`, { token: SENTINEL }, { as: "A" });

  const grantFor = (challenge) => mintTestGrant({ policyHash: challenge?.approval?.policy_hash, requestHash: challenge?.approval?.request_hash });
  const tag = "ontofam";
  const source = (await jd("POST", "/v1/hypervisor/data-sources", { name: `${tag}-src`, kind: "rest_api", endpoint: `http://127.0.0.1:${rowPort}/rows`, credential_posture: "wallet_credential_lease" }, { as: "A" })).j?.data_source?.source_id;
  const corpusOntology = (await jd("POST", "/v1/hypervisor/odk/domain-ontologies", { domain: `${tag}-domain`, canonical_object_model: {
    value_types: [{ id: "money", name: "Money", base: "double" }],
    object_types: [{ id: "loan", name: "Loan", title_property: "title", properties: [
      { id: "loan_id", name: "Loan Id", value_type: "string", required: true },
      { id: "title", name: "Title", value_type: "string" },
      { id: "amount", name: "Amount", value_type: "money" }] }],
    action_types: [], link_types: [],
  } }, { as: "A" })).j?.ontology;
  const mapping = (await jd("POST", "/v1/hypervisor/odk/connector-mappings", { name: `${tag}-map`, data_source_id: source, ontology_ref: corpusOntology?.ref, object_type_id: "loan",
    key_mapping: { source_field: "id", property_id: "loan_id", source_type: "string" },
    title_mapping: { source_field: "disp", property_id: "title", source_type: "string" },
    field_mappings: [{ source_field: "amt", property_id: "amount", source_type: "double" }] }, { as: "A" })).j?.connector_mapping?.id;
  const view = (await jd("POST", "/v1/hypervisor/odk/policy-bound-data-views", { connector_mapping_id: mapping, name: `${tag}-gate`, authority_subjects: ["agent://materializer"],
    allowed_operations: ["read", "transform"], purpose: "analysis", property_scope: ["loan_id", "title", "amount"], retention_posture: "bounded" }, { as: "A" })).j?.policy_bound_data_view?.id;
  const trun = (await jd("POST", "/v1/hypervisor/odk/transformation-runs", { connector_mapping_id: mapping, policy_view_id: view, name: `${tag}-trun` }, { as: "A" })).j?.transformation_run?.id;
  await jd("POST", `/v1/hypervisor/odk/transformation-runs/${trun}/dry-run`, null, { as: "A" });
  const projection = (await jd("POST", "/v1/hypervisor/odk/ontology-projections", { connector_mapping_id: mapping, policy_view_id: view, name: `${tag}-explorer`, visible_properties: ["loan_id", "title", "amount"] }, { as: "A" })).j?.ontology_projection?.id;
  const plan = (await jd("POST", "/v1/hypervisor/odk/capability-lease-plans", { data_source_id: source, connector_mapping_id: mapping, policy_view_id: view,
    transformation_run_id: trun, ontology_projection_id: projection, name: `${tag}-plan`, subject: "agent://materializer", ttl_seconds: 900 }, { as: "A" })).j?.capability_lease_plan?.id;
  const mrun = (await jd("POST", "/v1/hypervisor/odk/materializing-runs", { capability_lease_plan_id: plan, name: `${tag}-mrun` }, { as: "A" })).j?.materializing_run?.id;
  const leaseChallenge = await jd("POST", `/v1/hypervisor/odk/materializing-runs/${mrun}/acquire-lease`, {}, { as: "A" });
  await jd("POST", `/v1/hypervisor/odk/materializing-runs/${mrun}/acquire-lease`, { wallet_approval_grant: await grantFor(leaseChallenge.j) }, { as: "A" });
  const sessionRes = await jd("POST", "/v1/hypervisor/odk/connector-sessions", { materializing_run_id: mrun, connector_id: connectorId, name: `${tag}-session` }, { as: "A" });
  const sessionId = sessionRes.j?.connector_session?.id ?? "";
  const openChallenge = await jd("POST", `/v1/hypervisor/odk/connector-sessions/${sessionId}/open`, {}, { as: "A" });
  await jd("POST", `/v1/hypervisor/odk/connector-sessions/${sessionId}/open`, { wallet_approval_grant: await grantFor(openChallenge.j) }, { as: "A" });
  const executed = await jd("POST", `/v1/hypervisor/odk/materializing-runs/${mrun}/execute`, { connector_session_id: sessionId, limit: 10 }, { as: "A" });
  const corpusOntologyRef = corpusOntology?.ref ?? "";

  // WHERE THE LADDER STOPS IN THIS LANE, AND WHY THAT IS THE HONEST PLACE FOR IT TO STOP.
  //
  // Every rung up to the wallet crossing is REAL and built here through the product's own routes.
  // The crossing itself is not fakeable: `acquire-lease` requires independently resolved, atomically
  // consumed owner authority (`IOI_HYPERVISOR_AUTHORITY_PRINCIPAL_REF` plus a live principal-authority
  // resolution), and the estate's only way to satisfy it is a real one-validator wallet.network
  // fixture that costs MINUTES to stand up. `check:provider-transport` reached the same wall and
  // ruled it the same way — the credential crossing gets its own opt-in lane rather than a mock,
  // because a mocked authority crossing proves nothing about authority.
  //
  // So this gate proves the ladder is real AND genuinely gated, and stops there.
  //
  // AN EARLIER REVISION SHIPPED A `--live-authority` LANE AND CITED IT AS EVIDENCE. It could never
  // pass: it never started the authority fixture and re-minted a grant from the 501, which carries no
  // approval — a review ran it and found 4 of its 5 assertions RED and the fifth vacuous. A lane
  // nobody has demonstrated passing is not evidence, and citing one is the defect this program
  // exists to catch. It is deleted rather than defended.
  //
  // NAMED RESIDUAL, unhedged: search's MATCHING over a product-produced corpus, the provenance on
  // its rows, its truncation arithmetic and its scope FILTER are proven NOWHERE. Proving them needs
  // the real one-validator wallet.network principal-authority fixture wired the way
  // `verify-hypervisor-provider-transport.mjs` wires it — started BEFORE the daemon, since the
  // authority ref is read at boot, and BLOCKING when unavailable. That is a follow-up packet.
  ok("the materialization ladder is REAL up to its wallet crossing — every rung admitted through the product's own routes, ending at a run that holds no lease",
    Boolean(source && corpusOntology?.ref && mapping && view && trun && projection && plan && mrun),
    `source ${Boolean(source)} map ${Boolean(mapping)} plan ${Boolean(plan)} run ${Boolean(mrun)}`);
  ok("and the crossing that would PRODUCE a corpus is genuinely wallet-gated — it refuses typed, names the authority it needs, and the estate contacted NO source without it",
    leaseChallenge.status === 501
      && String(leaseChallenge.j?.reason ?? "").includes("authority_required")
      && executed.status === 400 && code(executed.j) === "execution_lease_not_obtained"
      && sourceHits === 0 && recordsIn("odk-materialized-object-sets").length === 0,
    `lease ${leaseChallenge.status} execute ${code(executed.j)} source hits ${sourceHits}`);
  ok("so an unauthorized ladder leaves the corpus EMPTY, and search says exactly that rather than reporting an unmatched query",
    (await jd("POST", "/v1/hypervisor/odk/object-instance-search", { ontology_ref: corpusOntologyRef, q: "gold" }, { as: "A" })).j?.absence?.code === "object_instance_corpus_absent",
    "corpus absent");

  // WHAT THIS PROVES AND WHAT IT CANNOT. With no corpus in either scope, "the filter is applied" is
  // unobservable — both scopes report zero whether the filter runs or is ignored entirely, and a
  // mutation replacing the whole scope predicate with `true` came back GREEN against an earlier,
  // broader version of this label. So the label says only what a corpus-free lane can see: the
  // requested scope is RESOLVED and echoed back. That the filter actually SELECTS is a NAMED
  // RESIDUAL — unproven anywhere, for the same reason matching is: it needs a materialized corpus.
  const otherOntology = await jd("POST", "/v1/hypervisor/odk/object-instance-search", { ontology_ref: ontologyRef, q: "gold" }, { as: "A" });
  ok("a search names the ontology scope it RESOLVED and echoes it back, so a caller can tell which corpus an answer is about",
    otherOntology.status === 200 && otherOntology.j?.query?.ontology_ref === ontologyRef
      && otherOntology.j?.corpus?.materialized_object_sets_in_scope === 0,
    `echo ${otherOntology.j?.query?.ontology_ref}`);

  rowServer.close();

  // ============================================================ RESTART SURVIVAL
  const pidBefore = daemon?.pid ?? 0;
  stopDaemon();
  await sleep(600);
  startDaemon(port);
  await waitFor(`${DAEMON}/healthz`, 30000);
  ok("PRECONDITION: this is a NEW PROCESS over the SAME data directory",
    pidBefore > 0 && (daemon?.pid ?? 0) > 0 && daemon.pid !== pidBefore, `pid ${pidBefore} -> ${daemon?.pid}`);
  const proposalAfter = await jd("GET", `/v1/hypervisor/odk/ontology-proposals/${rebasedId}`, null, { as: "A" });
  const setAfter = await jd("GET", `/v1/hypervisor/odk/saved-object-sets/${savedId}`, null, { as: "A" });
  const searchAfter = await jd("POST", "/v1/hypervisor/odk/object-instance-search", { ontology_ref: corpusOntologyRef, q: "gold" }, { as: "A" });
  ok("ACROSS A RESTART all three families read back their durable truth — the applied proposal, the retired set, and a corpus verdict derived from the store rather than from memory",
    proposalAfter.j?.ontology_proposal?.status === "applied"
      && setAfter.j?.saved_object_set?.status === "retired"
      && searchAfter.status === 200
      && searchAfter.j?.corpus?.materialized_object_sets_in_scope === recordsIn("odk-materialized-object-sets").length,
    `${proposalAfter.j?.ontology_proposal?.status} / ${setAfter.j?.saved_object_set?.status} / sets ${searchAfter.j?.corpus?.materialized_object_sets_in_scope}`);
  const setAfterCross = await jd("GET", `/v1/hypervisor/odk/saved-object-sets/${savedId}`, null, { as: "B" });
  ok("and the per-principal pin survives it — B still cannot read A's saved set",
    setAfterCross.status === 403, `status ${setAfterCross.status}`);

  // ============================================================ the derived closed world
  const routes = workbenchRoutes();
  const FAMILIES = ["/v1/hypervisor/odk/ontology-proposals", "/v1/hypervisor/odk/saved-object-sets", "/v1/hypervisor/odk/object-instance-search"];
  ok("all THREE families ACC-A names are registered in the router — derived from the router source, not from guessed URLs",
    FAMILIES.every((family) => routes.some((r) => r.path.startsWith(family))) && routes.length >= 11,
    `${routes.length} routes: ${routes.map((r) => `${r.method} ${r.path}`).join(", ")}`);

  // EVERY route, not only the mutating ones. Reads leak too — a proposal list or a saved-set read is
  // estate truth, and an earlier revision of this sweep filtered GETs out entirely, leaving three of
  // the four read routes never probed anonymously.
  const anonymousDoors = [];
  for (const endpoint of routes) {
    const concrete = endpoint.path.replace(":id", proposalId);
    const response = await jd(endpoint.method, concrete, endpoint.method === "GET" ? null : {}, { as: null });
    if (response.status !== 401) anonymousDoors.push(`${endpoint.method} ${endpoint.path} -> ${response.status}`);
  }
  ok("EVERY route in all three families — reads included — refuses an anonymous caller, probed from raw transport",
    anonymousDoors.length === 0 && routes.length >= 11,
    anonymousDoors.join(", ") || `${routes.length} routes`);

  // NO SECOND SPINE — DERIVED POSITIVELY, because the denylist that stood here was blind to one.
  //
  // The first revision scanned the workbench module for the NAMES of the ontology plane's writers.
  // A review showed the two obvious second spines sail past it: a `persist_record(..., KIND_ONT,
  // ...)` with its own revision bump, and a locally-named receipt minter. A denylist cannot see a
  // writer it was not told to look for, and this estate already names denylist scans a decorative
  // class. So the check is inverted: derive every record family this module writes, and assert the
  // set is exactly its OWN two. A second spine has to write the ontology family to be one.
  // ---------------------------------------------------------- the entailment, observed not derived
  // THE ONLY REQUESTS ALLOWED TO HAVE CHANGED THE ONTOLOGY FAMILY. Three, each justified:
  //   POST  …/odk/domain-ontologies            — the create route; it mints the ontology
  //   PATCH …/odk/domain-ontologies/:id        — `apply_ontology_change`, THE one writer
  //   POST  …/odk/ontology-proposals/:id/apply — which CALLS that same writer, the whole claim
  // Anything else that moved those bytes is a second spine, whatever it is spelled.
  // FOUR, NOT THREE. A review drove `DELETE /odk/domain-ontologies/:id` live — a registered,
  // receipted writer that removes the record — and the three-route model reported a correct
  // product-produced delete as an unexpected route AND as an unreadable record. A model of the
  // plane that omits one of its writers is a false statement about the plane, not a strict gate.
  // NAMED, NOT POSITIONAL. Adding the DELETE writer to a positional list silently re-pointed
  // `sawApply` at the new entry — the gate caught it, which is the point, but an index into a list
  // that grows is a coupling waiting to mis-fire.
  const ONTOLOGY_WRITERS = {
    create: /^POST \/v1\/hypervisor\/odk\/domain-ontologies$/u,
    patch: /^PATCH \/v1\/hypervisor\/odk\/domain-ontologies\/[^/]+$/u,
    delete: /^DELETE \/v1\/hypervisor\/odk\/domain-ontologies\/[^/]+$/u,
    apply: /^POST \/v1\/hypervisor\/odk\/ontology-proposals\/[^/]+\/apply$/u,
  };
  const EXPECTED_ONTOLOGY_MUTATORS = Object.values(ONTOLOGY_WRITERS);
  const stripRustComments = (src) => {
    let out = "";
    for (let i = 0; i < src.length;) {
      const c = src[i];
      if (c === "r" && (src[i + 1] === '"' || src[i + 1] === "#")) {
        let j = i + 1, hashes = 0;
        while (src[j] === "#") { hashes += 1; j += 1; }
        if (src[j] === '"') {
          const close = `"${"#".repeat(hashes)}`;
          const end = src.indexOf(close, j + 1);
          const stop = end === -1 ? src.length : end + close.length;
          out += src.slice(i, stop); i = stop; continue;
        }
      }
      if (c === '"') {
        let j = i + 1;
        while (j < src.length) {
          if (src[j] === "\\") { j += 2; continue; }
          if (src[j] === '"') { j += 1; break; }
          j += 1;
        }
        out += src.slice(i, j); i = j; continue;
      }
      // A CHAR LITERAL CONTAINING A DOUBLE QUOTE — `c == '"'`, `.split('"')`, `matches!(c, '"')`, all
      // ordinary Rust — flips string parity for the REST OF THE FILE if it is not tracked, which
      // re-arms the exact `//`-inside-a-literal regression this scanner exists to close. A review
      // demonstrated it. Lifetimes (`&'a str`) share the tick and have no closing quote, so they are
      // told apart by looking for the close: `'x'` and `'\x'` are literals, `'a ` is a lifetime.
      if (c === "'") {
        let j = i + 1;
        if (src[i + 1] === "\\") {
          // AN ESCAPED QUOTE IS THE LITERAL'S CONTENT, NOT ITS CLOSE. Scanning for the next `'`
          // from i+2 lands ON the escaped quote of `'\\''` and terminates before it starts, leaving
          // the real closing tick stray — which inverts double-quote parity for the rest of the
          // file and re-arms the `//`-inside-a-string regression this scanner exists to close. A
          // review demonstrated exactly that with `matches!(c, '\\''|'"')`.
          // EACH BRANCH LANDS j ON THE CLOSING QUOTE. The previous cut added an unconditional `j += 1`
          // after the `\u{..}` branch had already advanced past `}`, overshooting the quote — and a
          // review showed one line of legal Rust (`matches!(c, '\u{7b}'|'"')`) desynchronising the
          // scanner and re-arming the `//`-in-a-literal regression it exists to close.
          if (src[i + 2] === "u" && src[i + 3] === "{") {
            const close = src.indexOf("}", i + 4);
            j = close === -1 ? src.length : close + 1;   // the char after `}` — the closing quote
          } else if (src[i + 2] === "x") { j = i + 5; }  // `\xNN` then the quote
          else { j = i + 3; }                            // `\n` then the quote
        } else {
          // A NON-BMP CHAR LITERAL IS TWO UTF-16 UNITS. `'😀'` closed at i+3, not i+2, so the old
          // test read it as a LIFETIME, desynchronised, and deleted the rest of a later line — a
          // review showed it swallowing a real `persist_record(.., KIND_ONT, ..)` while every static
          // assertion stayed green. It failed OPEN, which is the worst direction for this class.
          // Scan forward for the closing tick instead of assuming a width.
          let k = i + 1;
          while (k < src.length && k <= i + 3 && src[k] !== "'") k += 1;
          if (src[k] !== "'") { out += c; i += 1; continue; }   // a lifetime, not a literal
          j = k;
        }
        if (src[j] === "'") { out += src.slice(i, j + 1); i = j + 1; continue; }
        out += c; i += 1; continue;
      }
      if (c === "/" && src[i + 1] === "/") { while (i < src.length && src[i] !== "\n") i += 1; continue; }
      if (c === "/" && src[i + 1] === "*") {
        let depth = 1; i += 2;
        while (i < src.length && depth > 0) {
          if (src[i] === "/" && src[i + 1] === "*") { depth += 1; i += 2; continue; }
          if (src[i] === "*" && src[i + 1] === "/") { depth -= 1; i += 2; continue; }
          i += 1;
        }
        continue;
      }
      out += c; i += 1;
    }
    return out;
  };

  // THE PRECONDITION THE OBSERVATION RESTS ON, asserted rather than assumed. The fingerprint reads
  // the LEGACY record directory, which is where this family's writes land only while it is not
  // promoted; a promoted family writes into the substrate log instead and this whole observation
  // would go quietly blind. Pinned from the substrate module's own source.
  const substrateSource = fs.readFileSync(path.join(ROOT, "crates/node/src/bin/hypervisor_daemon_routes/substrate_store.rs"), "utf8");
  // COMMENT-STRIPPED FIRST: an interleaved `// promoted in W3.4` between entries left a split
  // element that matched no family name, so the assertion passed while the family WAS promoted.
  const promotedDomains = (stripRustComments(substrateSource).match(/const PROMOTED_DOMAINS: &\[&str\] = &\[([^\]]*)\]/u)?.[1] ?? "")
    .split(",").map((s) => s.trim().replace(/^"|"$/gu, "")).filter(Boolean);
  ok("PRECONDITION for the runtime observation below: the ontology family is NOT a promoted substrate family, so its durable writes land in the record directory that observation watches — promote it and this goes red rather than the watch going quietly blind",
    promotedDomains.length > 0 && !promotedDomains.includes(ONTOLOGY_FAMILY_DIR),
    `PROMOTED_DOMAINS = [${promotedDomains.join(",")}]`);
  // A REFUSED REQUEST MUST NOT HAVE WRITTEN, and this is where the route-shaped version died. The
  // review's mutant wrote a second ontology record on a 409-REFUSED apply and every assertion stayed
  // green, because a refusal is an ABSENCE OF THE ACT and nothing was checking the act. No status,
  // no route, no spelling exempts a write from this: if the answer was not 2xx, the family did not
  // move.
  // THIS ESTATE'S PRIMARY REFUSAL IS A 200 WITH `ok:false` — `apply_ontology_change` answers
  // validation refusals that way, and this very journey pins it thirty lines up. Filtering on status
  // alone exempted the commonest refusal from the assertion whose label reads "a refusal is the
  // absence of the act".
  const refusedWrites = ontologyMutations.filter((m) => m.status < 200 || m.status >= 300 || m.body?.ok === false);
  ok("ON THE JOURNEYS THIS GATE WALKS, no refused request moved an ontology record — a refusal is the absence of the act, so a request answering non-2xx or `ok:false` that still moved a record is admitting truth it declined to admit. Scoped to the traffic below; it does not speak for requests this journey never makes",
    refusedWrites.length === 0,
    refusedWrites.length ? `WROTE ON REFUSAL: ${refusedWrites.map((m) => `${m.route} -> ${m.status} changed ${m.changed.join(",")}`).join(" ; ")}` : `${ontologyMutations.length} writing request(s), none refused`);
  // EVERY WRITE CHANGED EXACTLY ONE RECORD, AND IT IS THE ONE THE RESPONSE NAMES. Route-shape
  // allowlisting cannot tell "composed over the one writer" from "wrote BESIDE it": a second spine
  // running in addition to `apply_ontology_change` moves the print exactly once, under an allowed
  // name. Binding the delta to the ontology id the response reports is what separates them — and it
  // also catches a write deferred past its own response, which the route-keyed version attributed to
  // whichever request happened to come next.
  // BOUND TO THE CALLER'S INTENT, BECAUSE BINDING TO THE RESPONSE WAS CIRCULAR. The previous cut
  // compared the record on disk to the `ontology` object the response reports — and that object is
  // the WRITER'S OWN IN-MEMORY PRODUCT. A review defeated it live at 81/81 with a second writer that
  // injects an object type nobody proposed and then reports the record it wrote: disk and response
  // agree perfectly, because one produced the other. A check whose reference the subject produces
  // can only catch a write that ESCAPES the response, never one composed INTO it.
  //
  // So the reference is the one thing in this journey the daemon did not make: THE REQUEST. For each
  // writing request, every field the CALLER named must hold the value the CALLER SENT, every field
  // the caller did not name must be byte-unchanged from the record before, and the only fields
  // allowed to move on their own are the plane's declared bookkeeping. An extra object type, an
  // extra admission block, a silently rewritten description — none of them survive that, whatever
  // the response says about them.
  // BOTH SETS WERE WRONG ABOUT THE PLANE, and a review drove each one live.
  //  - `health` is recomputed from the caller's model on EVERY patch (`odk_routes.rs` recomputes
  //    `validate_object_model` after applying the change), so it is bookkeeping, not create-only.
  //    Listing it as create-only made this rule go RED on a legitimate model patch; the journey
  //    simply never lands one, so the gate was green for the wrong reason.
  //  - `created_at` is mintable at genesis and immutable after, so it belongs to the create set. In
  //    bookkeeping it let a patch BACK-DATE a record with nothing objecting.
  //  - `owner_ref`, `created_by` and `admitted_head` are minted by nothing in this plane. A dead
  //    entry in a set the label calls closed is a door held open under a name nobody uses.
  const CREATE_DERIVED = new Set(["id", "ref", "schema_version", "domain", "version", "description", "status", "object", "canonical_object_model", "created_at"]);
  const BOOKKEEPING = new Set(["revision", "updated_at", "history", "receipt_refs", "health"]);
  const canonical = (v) => JSON.stringify(v, (_k, val) =>
    (val && typeof val === "object" && !Array.isArray(val))
      ? Object.fromEntries(Object.keys(val).sort().map((k) => [k, val[k]]))
      : val);
  /** What the CALLER asked this request to change — from the request body, or the proposal it created. */
  const intentOf = (m) => {
    if (m.proposalId) return proposalIntent.get(m.proposalId) ?? {};
    const req = m.request ?? {};
    return Object.fromEntries(Object.entries(req).filter(([k]) => k !== "expected_revision" && k !== "idempotency_key"));
  };
  const unexplained = [];
  for (const m of ontologyMutations) {
    if (!m.changed.length) continue;
    if (m.changed.length !== 1) { unexplained.push(`${m.route} changed ${m.changed.length} records [${m.changed.join(",")}]`); continue; }
    const name = m.changed[0];
    // A REMOVAL IS ITS OWN FACT. Folding it in with "unreadable" reported two entirely different
    // things — a record the plane deleted and a record this checker could not parse — under one
    // diagnostic, and flagged a correct delete as a defect.
    if (name.endsWith(":REMOVED")) {
      const removedId = name.slice(0, -":REMOVED".length).replace(/\.json$/u, "");
      const pathId = /\/domain-ontologies\/([^/]+)$/u.exec(m.route.split(" ")[1])?.[1] ?? "";
      if (!m.route.startsWith("DELETE ") || removedId !== pathId) {
        unexplained.push(`${m.route} removed ${removedId} without being that record's delete route`);
      }
      continue;
    }
    const prev = m.before[name];
    const now = m.after[name];
    if (!now) { unexplained.push(`${m.route} ${name} could not be read back after the write`); continue; }
    const intent = intentOf(m);
    for (const key of new Set([...Object.keys(now), ...Object.keys(prev ?? {})])) {
      if (BOOKKEEPING.has(key)) continue;
      // A NULL NAMES NOTHING — the plane's own rule, pinned by the parity journey above: an explicit
      // null is a no-op, not a value. So it does not count as caller-named, and the field falls
      // through to the stricter test: it must be byte-unchanged.
      if (key in intent && intent[key] !== null) {
        if (canonical(now[key]) !== canonical(intent[key])) {
          unexplained.push(`${m.route} ${name}.${key} is not what the caller sent`);
        }
        continue;
      }
      // Not named by the caller and not bookkeeping: it must be exactly what it was.
      // ON A CREATE the plane derives its own defaults, so "unchanged from before" is meaningless.
      // What IS checkable is that the derived key set is CLOSED: a create may mint these and nothing
      // else, so a field a second spine adds at genesis is red.
      if (!prev) { if (!CREATE_DERIVED.has(key)) unexplained.push(`${m.route} ${name}.${key} is neither caller-sent nor a declared create-derived field`); continue; }
      if (canonical(now[key]) !== canonical(prev[key])) unexplained.push(`${m.route} ${name}.${key} changed without the caller asking`);
    }
  }
  ok("ON THE JOURNEYS THIS GATE WALKS, the ontology truth admitted through the watched path equals what the CALLER REQUESTED — named fields hold the value the request sent, unnamed fields are byte-unchanged, only declared bookkeeping moves on its own. The reference is the request because a response is the writer's own product. THIS IS A JOURNEY-SCOPED FACT, NOT the whole-program property \"no second admission path writes ontology truth\" — that property is filed as a residual and is commissioned to be entailed from module SOURCE, which is the layer it lives at",
    ontologyMutations.length > 0 && unexplained.length === 0,
    unexplained.length ? `UNEXPLAINED: ${unexplained.join(" ; ")}` : `${ontologyMutations.length} writing request(s), every field explained by the request that caused it`);
  // AND A RECEIPT IS MINTED ONLY BESIDE THE WRITE IT ATTESTS. A review minted fabricated ontology
  // receipts on the WITHDRAW requests — attesting patches that never happened — and nothing saw it,
  // because only the record store was watched.
  // THE LABEL CLAIMS CO-OCCURRENCE AND COUNT, WHICH IS WHAT IT CHECKS. It does NOT read receipt
  // CONTENT, so a receipt minted beside a real write but attesting a different ontology, or a wrong
  // operation, passes — and a receipt DELETED registers here as one "appearing". A review named
  // both. Attestation binding is part of the whole-program property filed as a residual, not
  // something this journey-scoped observation entails.
  const strayReceipts = ontologyMutations.filter((m) => m.receiptsChanged.length && !m.changed.length);
  const multiReceipts = ontologyMutations.filter((m) => m.receiptsChanged.length > 1);
  const removedReceipts = ontologyMutations.filter((m) => m.receiptsChanged.some((n) => n.endsWith(":REMOVED")));
  ok("and an ontology-plane receipt record APPEARS only in a request that also wrote the ontology, at most one per write, and none is ever removed — co-occurrence and count over the journeys walked; this does not read receipt CONTENT, so what a receipt ATTESTS is not checked here",
    ontologyMutations.length > 0 && strayReceipts.length === 0 && multiReceipts.length === 0 && removedReceipts.length === 0,
    strayReceipts.length || multiReceipts.length || removedReceipts.length
      ? `STRAY: ${[...strayReceipts, ...multiReceipts, ...removedReceipts].map((m) => `${m.route} -> ${m.receiptsChanged.length} receipt(s) [${m.receiptsChanged.join(",")}], ${m.changed.length} record(s)`).join(" ; ")}`
      : `${ontologyMutations.filter((m) => m.receiptsChanged.length).length} receipt-minting request(s), each beside its own write`);
  // AND THE WRITING ROUTES ARE STILL A CLOSED SET. Three, each justified:
  //   POST  …/odk/domain-ontologies            — the create route; it mints the ontology
  //   PATCH …/odk/domain-ontologies/:id        — `apply_ontology_change`, THE one writer
  //   POST  …/odk/ontology-proposals/:id/apply — which CALLS that same writer, the whole claim
  // This is the weakest of the three assertions and is kept because it names the shape; the two
  // above are what entail the claim. A closed world over the traffic THIS JOURNEY DRIVES.
  const unexpectedRoutes = [...new Set(ontologyMutations.map((m) => m.route).filter((r) => !EXPECTED_ONTOLOGY_MUTATORS.some((re) => re.test(r))))];
  const sawApply = ontologyMutations.some((m) => ONTOLOGY_WRITERS.apply.test(m.route));
  const sawPatch = ontologyMutations.some((m) => ONTOLOGY_WRITERS.patch.test(m.route));
  ok("and on those same journeys the only routes that moved an ontology record are its four registered writers — create, patch, delete, and the proposal apply that calls the patch writer — a shape claim over observed traffic, standing beside the identity claims above rather than in place of them",
    unexpectedRoutes.length === 0 && sawApply && sawPatch,
    unexpectedRoutes.length ? `UNEXPECTED: ${unexpectedRoutes.join(" ; ")}` : `observed: ${[...new Set(ontologyMutations.map((m) => m.route))].join(" ; ")}`);

  const workbenchSource = fs.readFileSync(path.join(ROOT, "crates/node/src/bin/hypervisor_daemon_routes/ontology_workbench_routes.rs"), "utf8");
  const odkSource = fs.readFileSync(path.join(ROOT, "crates/node/src/bin/hypervisor_daemon_routes/odk_routes.rs"), "utf8");
  // THE CALL-SITE SET, and it must be able to see a write however it is spelled. The previous
  // revision matched `\b(?:persist_record|remove_record)\(` and a review found three spellings it
  // still could not see: another module's ontology writer, a raw `std::fs::write` into the family
  // directory, and `persist_record_durable(` — the estate's NORMAL durable write, whose name this
  // regex could not match because it is a SUFFIX. Two of those three were named in the comment that
  // claimed to have closed them.
  // STRIPPING COMMENTS WITH A REGEX DELETED EXECUTABLE CODE. The previous revision ran
  // `.replace(/\/\/[^\n]*/gu, "")` over raw Rust, so a `//` INSIDE A STRING LITERAL ate the rest of
  // the line. It truncated four live lines of this very module — every `org://` and
  // `ontology-proposal://` literal — and a review demonstrated a second writer parked after a `://`
  // literal going GREEN here while the code this replaced caught it. The repair was a REGRESSION.
  // So: a real scanner, which tracks string literals, raw strings and nested block comments.
  const commentFree = stripRustComments(workbenchSource);
  // THE `use` DECLARATIONS ARE KEPT, NOT DISCARDED. Stripping them stops an import counting as a
  // use of the writer — but it also erased `use super::persist_record as mint;`, so the ALIAS that
  // defeats a name census became invisible while the harmless plain re-import was caught. They are
  // parsed first, and any alias they bind to a writer joins the set of names counted below.
  // NOT LINE-ANCHORED. `^[^\S\n]*use\s` required the declaration to start its line, so
  // `fn shadow(..) { use std::fs as sysfs; sysfs::write(..) }` was seen by NEITHER the import pin
  // (count still 8) nor the symbol allowlist (it derives no `super::`/`crate::`/`ioi_*` path) — and
  // the fs denylist misses `sysfs::write` because `\bfs::` finds no word boundary inside it. A
  // review demonstrated a raw write into the ontology family through exactly that hole.
  // NOT ANCHORED ON A CHARACTER CLASS EITHER. `[{};\s]` moved the anchor off line-start and a review
  // walked past it one character over: `#[allow(unused_imports)]use std::fs as sysfs;` — an
  // attribute's `]` is in neither set, the pin printed "8 declarations, all pinned" with a ninth in
  // the file, and `sysfs::write` misses the fs denylist because `\bfs::` finds no word boundary
  // inside it. A NEGATIVE LOOKBEHIND for an identifier character is the anchor that has no gap.
  const useDecls = [...commentFree.matchAll(/(?<![A-Za-z0-9_])use\s([^;]*);/gu)].map((m) => m[1].replace(/\s+/gu, " ").trim());
  const executableSource = commentFree.replace(/(?<![A-Za-z0-9_])use\s[^;]*;/gu, " ");
  const WRITER_BASE = ["persist_record", "remove_record", "persist_promoted", "admit_required"];
  // EVERY alias in the declaration. A non-global `.match()` registered only the FIRST, so
  // `use super::{persist_record as mint, persist_record as forge, …}` bound `mint` and left `forge`
  // an unknown name calling the writer in plain sight. A review demonstrated it.
  const writerAliases = useDecls.flatMap((decl) =>
    [...decl.matchAll(new RegExp(`\\b(?:${WRITER_BASE.join("|")})\\w*\\s+as\\s+(\\w+)`, "gu"))].map((m) => m[1]));
  const writerNames = [...WRITER_BASE, ...writerAliases];
  const writerPattern = new RegExp(`\\b(?:${writerNames.join("|")})\\w*`, "gu");
  const writerCallPattern = new RegExp(`\\b(?:${writerNames.join("|")})\\w*\\(\\s*&?[\\w.]+\\s*,\\s*([A-Z_]+)`, "gu");
  const writeCalls = [...executableSource.matchAll(writerCallPattern)].map((m) => m[1]);
  // EVERY MENTION, not every call. A `let w: fn(..) = persist_record;` alias writes the family while
  // the name never appears followed by `(`, so a call-site count silently dropped it — the exact
  // "cannot read it" case this assertion exists to turn RED. Counting bare mentions makes an alias
  // unresolvable rather than invisible.
  const allWriteSites = [...executableSource.matchAll(writerPattern)].length;
  const OWN_FAMILIES = ["KIND_PROPOSAL", "KIND_SAVED_SET"];
  ok("every record-writing call site in this module is RESOLVED to a family — a write the derivation cannot read is RED, not silently dropped, and the pattern matches suffixed writers like `persist_record_durable`",
    allWriteSites > 0 && writeCalls.length === allWriteSites,
    `${writeCalls.length} resolved of ${allWriteSites} write call sites`);
  // THE LABEL CLAIMS ONLY WHAT THIS CHECKS, and what it checks is a NAME CENSUS. A review defeated
  // the previous label — "writes ONLY its own two families" — with a writer this file never names:
  // `substrate_store::persist_promoted`, in an ALLOWLISTED module, which `persist_record` itself
  // delegates to. A name census cannot entail "no second writer exists"; the RUNTIME assertion
  // above is what entails it, and this is the bounded ratchet standing beside it.
  ok("every record write this module names by any of the KNOWN writer spellings resolves to one of its own two families, and both are named — a NAME CENSUS bounding the spellings it lists, and nothing more: it does not entail that no second writer exists, and neither does the journey observation above",
    writeCalls.length > 0
      && writeCalls.every((family) => OWN_FAMILIES.includes(family))
      && OWN_FAMILIES.every((family) => writeCalls.includes(family)),
    `writes ${[...new Set(writeCalls)].join(",") || "none"}`);
  // A `let` IS NOT A `const`. The value pin below counts `const KIND_PROPOSAL` occurrences, so a
  // `let KIND_PROPOSAL = "odk-domain-ontologies";` shadow type-checks, redirects a write to the
  // ontology family, and leaves "neither shadowed" green. A review demonstrated exactly that.
  ok("and neither family constant is REBOUND by a later `let` — the value pin counts `const` declarations, and a `let` shadow would redirect a write while leaving that pin untouched",
    !new RegExp(`\\b(?:let|static)\\s+(?:mut\\s+)?(?:${OWN_FAMILIES.join("|")})\\b`, "u").test(executableSource),
    "no let/static shadow of either family constant");
  ok("and those two constants really point at this module's OWN families — the derivation reads names, so the names are pinned to their values",
    /const KIND_PROPOSAL: &str = "odk-ontology-proposals";/u.test(workbenchSource)
      && /const KIND_SAVED_SET: &str = "odk-saved-object-sets";/u.test(workbenchSource)
      && (workbenchSource.match(/const KIND_PROPOSAL\b/gu) || []).length === 1
      && (workbenchSource.match(/const KIND_SAVED_SET\b/gu) || []).length === 1,
    "both constants pinned, neither shadowed");
  // AND NO RAW FILESYSTEM WRITE AT ALL, which is how a second spine evades any call-site census.
  // A DENYLIST, and named as one. It covers the filesystem entry points a second spine would
  // plausibly reach for — a review demonstrated `File::create`, `fs::copy`, `fs::rename`,
  // `fs::hard_link` and whitespace-separated paths slipping the previous four-name version — but a
  // denylist cannot entail "no raw write exists", and this label no longer claims that.
  ok("this module names NONE of the filesystem entry points a second spine would reach for — a denylist bounding a known attack, not a proof that no raw write exists",
    !/\bfs\s*::\s*(write|create|remove_file|remove_dir|copy|rename|hard_link|OpenOptions|File)/u.test(workbenchSource.replace(/\s*::\s*/gu, "::"))
      && !/\bFile\s*::\s*create/u.test(workbenchSource),
    "no denylisted fs entry point");
  // AND ITS CROSS-MODULE REACH IS A CLOSED SET, because a writer in another module is still a
  // second spine and no census of THIS file can see one.
  // Both spellings: `super::x::` in an expression AND a bare `use super::x;` that lets a later call
  // read `x::write(..)`. `mutation_event_foundation` was allowlisted and never referenced — an
  // allowlist entry nothing uses is a door held open, and it exports generic writers.
  // A MODULE ALLOWLIST IS TOO COARSE, and a review proved it with no trick at all: `substrate_store`
  // was allowlisted for its scope helpers, and it EXPORTS `persist_promoted` — the function
  // `persist_record` itself delegates to. The same durable write, one name earlier, inside an
  // allowed module. So the reach is pinned per SYMBOL, derived from the source: every cross-module
  // name this file actually reaches must be listed, and a new one fails CLOSED until justified.
  // Also parsed: brace imports (`use super::{a, b};`, which is how `persist_record` arrives today)
  // and workspace-crate paths, both of which the module-level patterns could not see at all.
  const braceImports = useDecls.flatMap((decl) => {
    const m = decl.match(/^super::\{(.+)\}$/u);
    return m ? m[1].split(",").map((s) => s.trim().split(/\s+as\s+/u)[0]).filter(Boolean) : [];
  });
  const crossSymbols = [...new Set([
    ...[...executableSource.matchAll(/\bsuper::(\w+)::(\w+)/gu)].map((m) => `${m[1]}::${m[2]}`),
    ...useDecls.flatMap((decl) => {
      const m = decl.match(/^super::(\w+)::(\w+)/u);
      return m ? [`${m[1]}::${m[2]}`] : [];
    }),
    ...braceImports.map((sym) => `super::${sym}`),
    ...useDecls.flatMap((decl) => (/^super::(\w+)$/u.test(decl) ? [`super::${decl.slice("super::".length)}`] : [])),
    ...[...executableSource.matchAll(/\bcrate::([\w:]+)/gu)].map((m) => `crate::${m[1]}`),
    ...useDecls.flatMap((decl) => {
      const m = decl.match(/^((?:ioi_|agentgres)\w*)::([\w:]+)/u);
      return m ? [`${m[1]}::${m[2]}`] : [];
    }),
    ...[...executableSource.matchAll(/\b((?:ioi_|agentgres)\w*)::([\w:]+)/gu)].map((m) => `${m[1]}::${m[2]}`),
  ])].sort();
  // Every entry is a NON-WRITING symbol: scope binding/authorization, identity resolution, the
  // record readers, the shared validator, and the ONE ontology writer this module is required to
  // call rather than reimplement. Nothing here persists a record on this module's behalf except
  // `odk_routes::apply_ontology_change`, which is the whole point.
  const ALLOWED_SYMBOLS = [
    "odk_routes::KIND_ONT", "odk_routes::KIND_ONT_RECEIPT", "odk_routes::apply_ontology_change",
    "odk_routes::check_expected_revision", "odk_routes::load", "odk_routes::nanos",
    "odk_routes::odk_scope_refusal", "odk_routes::validate_ontology_change",
    "substrate_store::authorize_request_resource_scope", "substrate_store::authorized_request_resource_refs",
    "substrate_store::bind_request_resource_scope", "substrate_store::read_request_scope",
    "substrate_store::resolve_request_identity", "substrate_store::RequestIdentity",
    "super::persist_record", "super::read_record_dir",
    "super::DaemonState", "super::iso_now",
  ];
  // AND THE IMPORT SET ITSELF IS CLOSED, because a symbol allowlist derives symbols and two kinds of
  // reach derive NONE. A review showed both: `use super::*;` matches no `super::x::y`, no
  // `super::{…}` and no `super::x` pattern, so a parent writer this file never names comes in for
  // free; and `use std::fs as sys;` then `sys::write(…)` is neither a `super::`/`crate::`/`ioi_*`
  // path nor the literal `fs::write` the denylist looks for. Pinning the declarations themselves is
  // the only closed world that covers a reach whose whole point is having no derivable name.
  const ALLOWED_USE_DECLS = [
    "std::sync::Arc",
    "axum::extract::{Path as AxumPath, Query, State}",
    "axum::http::{HeaderMap, StatusCode}",
    "axum::Json",
    "serde_json::{json, Value}",
    "std::collections::HashMap",
    "super::odk_routes::{ apply_ontology_change, check_expected_revision, load, nanos, odk_scope_refusal, validate_ontology_change, KIND_ONT, }",
    "super::{iso_now, persist_record, read_record_dir, DaemonState}",
  ];
  const unlistedDecls = useDecls.filter((d) => !ALLOWED_USE_DECLS.includes(d));
  ok("and this module's IMPORT SET is closed and pinned — a glob (`use super::*;`) and a renamed std path (`use std::fs as sys;`) each derive to NO symbol at all, so a symbol allowlist alone cannot fail closed on them and the declarations themselves are what is pinned",
    unlistedDecls.length === 0 && useDecls.length === ALLOWED_USE_DECLS.length,
    unlistedDecls.length ? `UNLISTED IMPORT: ${unlistedDecls.join(" ; ")}` : `${useDecls.length} declarations, all pinned`);
  const unlistedSymbols = crossSymbols.filter((s) => !ALLOWED_SYMBOLS.includes(s));
  ok("and this module's cross-module reach is a closed set of NAMED SYMBOLS, not of modules — an allowlisted module that exports a durable writer (`substrate_store::persist_promoted`, which `persist_record` delegates to) is a second spine wearing an approved module name, so a new symbol fails CLOSED",
    unlistedSymbols.length === 0 && crossSymbols.length > 0,
    unlistedSymbols.length ? `UNLISTED: ${unlistedSymbols.join(",")}` : `${crossSymbols.length} symbols, all listed`);
  // COUNTED OVER THE STRIPPED SOURCE, not the raw file: a doc-comment example writing
  // `apply_ontology_change(...)` would make this 2 and turn the assertion RED on a COMMENT.
  const applyCalls = (executableSource.match(/apply_ontology_change\(/gu) || []).length;
  ok("the ontology edit has exactly ONE writer across these two modules, which this one calls rather than reimplements",
    (odkSource.match(/fn apply_ontology_change\(/gu) || []).length === 1 && applyCalls === 1,
    `${applyCalls} call(s) to the one writer`);
  // THE WRITER MUST CALL IT, which is the whole claim. A review found `validate_ontology_change`
  // was a hand-maintained DUPLICATE that only the proposal plane called, while the writer kept its
  // own inline copy — two copies nothing held in agreement, and one had already diverged. An
  // assertion that checks only "the function exists and propose calls it" cannot fail on that.
  // AND THE WRITER MUST REFUSE ON IT. Replacing its `if let Err(..) { return .. }` with
  // `let _ = validate_ontology_change(body);` left every static assertion green, because a pinned
  // call literal matches the discarding form too. The refusing shape is what is pinned, and the
  // live probe below is what actually holds it.
  ok("propose and the WRITER run the SAME validator, and the writer REFUSES on it — one definition, called from both, in a form that returns",
    (odkSource.match(/fn validate_ontology_change\(/gu) || []).length === 1
      && /if let Err\(\(_status, error\)\) = validate_ontology_change\(body\) \{\s*\n\s*return \(StatusCode::OK, Json\(json!\(\{ "ok": false, "error": error \}\)\)\);/u.test(odkSource)
      && /validate_ontology_change\(&change\)/u.test(workbenchSource),
    "one definition, refusing in the writer, called by propose");

  const fails = results.filter((r) => !r.pass);
  for (const r of results) console.log(`${r.pass ? "PASS" : "FAIL"}  ${r.name}${r.detail ? ` — ${r.detail}` : ""}`);
  console.log(`\n${results.length - fails.length}/${results.length} passed`);
  emitVerifierCensus({ verifierId: "ontology-backend-families", sourceUrl: import.meta.url, results });
  cleanup();
  process.exit(fails.length ? 1 : 0);
}

run().catch((error) => {
  // NO CENSUS ON A CRASH: the floors gate reads a missing census as RED, which is the correct
  // reading of a run that did not finish.
  for (const r of results) console.log(`${r.pass ? "PASS" : "FAIL"}  ${r.name}${r.detail ? ` — ${r.detail}` : ""}`);
  console.log(`\n${results.filter((r) => r.pass).length}/${results.length} passed BEFORE THE RUN DIED (incomplete — no census emitted)`);
  console.error(`FAIL ontology-backend-families — ${error?.stack || error}`);
  cleanup();
  process.exit(1);
});
