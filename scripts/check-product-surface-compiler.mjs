#!/usr/bin/env node
//
// M08.8 — ONE REGISTRATION, FIVE PROJECTIONS, ELEVEN AXES.
//
// ACC-10 clause 1 says every click target resolves to exactly one designated surface. Clause 2 says
// shell, catalog, palette, contextual and API projections come from ONE registration over the
// independent axes. What this proves is that both are true of the running daemon and of the
// compiler that reads it — not that a document says so.
//
// WHAT WAS ACTUALLY WRONG, because the shape of the check follows from it:
//
//   * TWO OF THE FIVE PROJECTIONS DID NOT EXIST. The compiler's header claimed to feed "nav /
//     catalog / palette / launch state" from registration records and returned workspaces and
//     applications. Every palette and every contextual launcher downstream therefore kept a list of
//     its own — the hard-coded catalog clause 2 forbids, relocated rather than removed. An absent
//     projection is the easiest kind of defect to not see, because nothing reports it.
//
//   * TWO OF THE ELEVEN AXES WERE PROJECTED AS NULL. `surface_origin` and `surface_creation_method`
//     were named by canon and registered nowhere, so the daemon served explicit nulls with a
//     comment saying why. That was honest and it was not finished.
//
//   * MEMBERSHIP OF A RENDERED LANE CAME FROM A SCREENSHOT COMPARISON. Fourteen ported tool
//     surfaces appeared in the product because `shell_pixel_certified` was true for them in the
//     harvest parity matrix. Canon gives parity evidence "zero authority over registration class,
//     catalog membership, owner, capability, or maturity" (core-clients-surfaces.md :2006-2008).
//     The band had even been LABELLED `catalog_authority: false` while its membership stayed
//     parity-derived, and a verifier downstream had hardened that into an acceptance test reading
//     "catalog membership equals certified surfaces". A label is not a boundary.
//
// THE TWO MUTATION CLASSES THE UNIT NAMES are therefore hard-coded classification and
// parity-derived classification, and both are drilled below. They are drilled against PREDICATES
// rather than against the tree: every assertion here is a pure function of a projection object, so
// a drill feeds it a mutated projection and proves the predicate refuses. Nothing plants a defect
// in a tracked file, which means nothing can be left planted.
//
// The structural half cannot be drilled that way, and says so: the proof that parity evidence
// cannot decide membership is that no membership path READS the matrix. An unreadable input cannot
// be mutated into an influence.
import net from "node:net";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { spawn } from "node:child_process";
import { fileURLToPath } from "node:url";

const ROOT = path.dirname(path.dirname(fileURLToPath(import.meta.url)));
const RESULTS = [];
const ok = (label, pass, detail = "") => {
  RESULTS.push({ label, pass: !!pass, detail });
  console.log(`${pass ? "PASS" : "FAIL"}  ${label}${detail ? `  · ${detail}` : ""}`);
};
const drill = (label, predicateRefused, detail = "") =>
  ok(`DRILL ${label}`, predicateRefused, detail);

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const freePort = () => new Promise((resolve, reject) => {
  const srv = net.createServer();
  srv.listen(0, "127.0.0.1", () => { const { port } = srv.address(); srv.close(() => resolve(port)); });
  srv.on("error", reject);
});
const waitFor = async (url, ms) => {
  const until = Date.now() + ms;
  while (Date.now() < until) {
    try { const r = await fetch(url); if (r.status < 500) return true; } catch { /* not up yet */ }
    await sleep(300);
  }
  return false;
};

// ------------------------------------------------------------------------ the eleven axes, named
// Named here rather than counted, so a projection that drops one fails with the axis's name in the
// message instead of an off-by-one. These are the axes a consumer must be able to read
// INDEPENDENTLY — Non-Negotiable 36's whole point is that none may be inferred from another.
const ELEVEN_AXES = [
  "surface_class",
  "surface_availability",
  "surface_distribution",
  "surface_admission_state",
  "surface_package_disposition",
  "surface_installation_state",
  "surface_enablement_state",
  "surface_capability_depth",
  "surface_operational_state",
  "surface_origin",
  "surface_creation_method",
];

// ------------------------------------------------------------------------------- the predicates
// Each is a pure function of a projection. The live run feeds them the daemon's answer; the drills
// feed them a mutated copy. A predicate that only ever sees correct input has not been tested.

/** Every projection ACC-10 clause 2 names is present as an array. */
const hasFiveProjections = (p) =>
  Array.isArray(p?.workspace_entries)
  && Array.isArray(p?.application_entries)
  && Array.isArray(p?.command_palette_entries)
  && Array.isArray(p?.contextual_entries);

/**
 * THE ELEVEN AXES, IN TWO TIERS — because "all eleven non-null" is the wrong bar and enforcing it
 * would push the daemon into fabricating a release for a surface that has none.
 *
 * Four are fixed at REGISTRATION: class, availability, origin, creation method. A surface always has
 * these, so a null there is an unserved axis — the state `surface_origin` and
 * `surface_creation_method` were in before this unit, and the thing this check exists to refuse.
 *
 * Seven are JOIN-DERIVED: they come from the admitted release, the installation for this
 * organization and the serving binding. A `planned` surface has none of those records, so null is
 * the honest answer and inventing a value would be worse than absent. What is NOT acceptable is a
 * silent null, so a row with any join-derived axis missing must say WHY through its typed reason
 * codes.
 *
 * Every one of the eleven keys must be PRESENT on every row either way: a consumer can only tell
 * "registered as none" from "not registered" if the key is there and null rather than absent.
 */
const REGISTRATION_AXES = ["surface_class", "surface_availability", "surface_origin", "surface_creation_method"];
const JOIN_DERIVED_AXES = ELEVEN_AXES.filter((axis) => !REGISTRATION_AXES.includes(axis));
const elevenAxesServed = (p) => {
  const rows = p?.application_entries || [];
  if (rows.length === 0) return false;
  return rows.every((row) => {
    if (!ELEVEN_AXES.every((axis) => axis in row)) return false;
    if (!REGISTRATION_AXES.every((axis) => row[axis] !== null && row[axis] !== undefined)) return false;
    const unjoined = JOIN_DERIVED_AXES.filter((axis) => row[axis] === null || row[axis] === undefined);
    if (unjoined.length === 0) return true;
    return Array.isArray(row.disabled_reason_codes) && row.disabled_reason_codes.length > 0;
  });
};

/** ACC-10 clause 1: one click target, exactly one designated surface. */
const routesAreUnambiguous = (p) => {
  const routes = (p?.application_entries || []).map((row) => row.canonical_route).filter(Boolean);
  const workspaceRoutes = (p?.workspace_entries || []).map((row) => row.canonical_route).filter(Boolean);
  const all = [...routes, ...workspaceRoutes];
  return all.length > 0 && new Set(all).size === all.length;
};

/**
 * The palette serves EXACTLY the registrations declaring `command_palette` — no more (a hard-coded
 * extra) and no fewer (a hard-coded subset). Both directions matter: a compiler keeping its own
 * list is as likely to omit as to invent.
 */
const paletteIsDerived = (p) => {
  const expected = new Set((p?.application_entries || [])
    .filter((row) => (row.launch_modes || []).includes("command_palette"))
    .map((row) => row.identity_ref));
  const served = new Set((p?.command_palette_entries || []).map((row) => row.identity_ref));
  return expected.size > 0 && expected.size === served.size && [...expected].every((ref) => served.has(ref));
};

/** The contextual lane serves exactly the surfaces registering the requested kind AND the mode. */
const contextualIsDerived = (p) => {
  const kind = p?.requested_context_kind;
  if (!kind) return (p?.contextual_entries || []).length === 0;
  const expected = new Set((p?.application_entries || [])
    .filter((row) => (row.launch_modes || []).includes("contextual")
      && (row.supported_context_kinds || []).includes(kind))
    .map((row) => row.identity_ref));
  const served = new Set((p?.contextual_entries || []).map((row) => row.identity_ref));
  return expected.size === served.size && [...expected].every((ref) => served.has(ref));
};

/**
 * PERMISSION IS SUBTRACTION. A surface the caller may not see is absent from every projection, not
 * merely from the catalog. The palette is the dangerous one: it is a list of things you can DO, and
 * a palette computed from the registration records rather than from the filtered catalog would be a
 * second path to launch with its own idea of who may see what.
 */
const subtractionHolds = (narrowed, removedRef) =>
  !(narrowed?.application_entries || []).some((row) => row.identity_ref === removedRef)
  && !(narrowed?.command_palette_entries || []).some((row) => row.identity_ref === removedRef)
  && !(narrowed?.contextual_entries || []).some((row) => row.identity_ref === removedRef);

/** An empty contextual lane says WHICH empty it is. Two different situations, two codes. */
const absenceIsTyped = (p) => {
  const empty = (p?.contextual_entries || []).length === 0;
  if (!empty) return p?.contextual_absence_code === null || p?.contextual_absence_code === undefined;
  return p?.contextual_absence_code === "no_context_kind_requested"
    || p?.contextual_absence_code === "no_surface_registers_this_context_kind";
};

// ------------------------------------------------------------------------------ the daemon lane
const daemonBinary = path.resolve(ROOT, process.env.IOI_HYPERVISOR_DAEMON_BINARY ?? "target/debug/hypervisor-daemon");
let scratch = "";
let daemon = null;
let daemonLog = "";

function startDaemon(port, dataDir) {
  daemon = spawn(daemonBinary, [], {
    cwd: ROOT,
    env: {
      ...process.env,
      IOI_HYPERVISOR_DAEMON_ADDR: `127.0.0.1:${port}`,
      IOI_HYPERVISOR_DATA_DIR: dataDir,
      IOI_HYPERVISOR_MODEL_UPSTREAM: "http://127.0.0.1:1",
    },
    stdio: ["ignore", "pipe", "pipe"],
  });
  daemon.stdout.on("data", (c) => { daemonLog = `${daemonLog}${c}`.slice(-64000); });
  daemon.stderr.on("data", (c) => { daemonLog = `${daemonLog}${c}`.slice(-64000); });
}
function cleanup() {
  try { daemon?.kill("SIGTERM"); } catch { /* already gone */ }
  daemon = null;
  if (scratch) { try { fs.rmSync(scratch, { recursive: true, force: true }); } catch { /* best effort */ } }
}
process.on("exit", cleanup);
process.on("SIGINT", () => { cleanup(); process.exit(130); });
process.on("SIGTERM", () => { cleanup(); process.exit(143); });

async function projection(base, session, body) {
  const res = await fetch(`${base}/v1/hypervisor/product-surface-projections`, {
    method: "POST",
    headers: { "content-type": "application/json", ...(session ? { cookie: `ioi_session=${session}` } : {}) },
    body: JSON.stringify(body ?? {}),
  });
  return { status: res.status, json: await res.json().catch(() => null) };
}

// ------------------------------------------------------------------------------ the structural lane
function structuralChecks() {
  const compiler = fs.readFileSync(path.join(ROOT, "apps/hypervisor/scripts/surface-compiler.mjs"), "utf8");
  const catalog = fs.readFileSync(path.join(ROOT, "apps/hypervisor/scripts/app-catalog.mjs"), "utf8");
  const routes = fs.readFileSync(path.join(ROOT, "crates/node/src/bin/hypervisor_daemon_routes/lifecycle_routes.rs"), "utf8");

  // Comments are stripped before searching for evidence of a read. Searching a file that DISCUSSES
  // the parity matrix at length for the string "harvest-app-parity-matrix" would find its own
  // explanation of why it no longer reads one — a verifier tripping on the prose written to explain
  // it. (This exact mistake cost six false failures in an earlier unit of this program.)
  const code = (text) => text
    .replace(/\/\*[\s\S]*?\*\//gu, "")
    .split("\n")
    .filter((line) => !/^\s*(\/\/|#)/u.test(line))
    .join("\n");

  const compilerCode = code(compiler);
  const catalogCode = code(catalog);
  ok("no membership path reads the harvest parity matrix — parity cannot decide what the product offers",
    !/harvest-app-parity-matrix/u.test(compilerCode) && !/harvest-app-parity-matrix/u.test(catalogCode),
    "surface-compiler.mjs + app-catalog.mjs");
  ok("no membership path reads `shell_pixel_certified`",
    !/shell_pixel_certified/u.test(compilerCode) && !/shell_pixel_certified/u.test(catalogCode));
  ok("the compiler declares the five projections it compiles",
    /projections:\s*\[\s*"shell",\s*"catalog",\s*"command_palette",\s*"contextual",\s*"api"\s*\]/u.test(compilerCode));
  ok("the compiler passes the palette through rather than recomputing membership from launch modes",
    /payload\.command_palette_entries\.map/u.test(compilerCode)
      && !/applications[\s\S]{0,200}filter[\s\S]{0,120}command_palette/u.test(compilerCode));
  ok("the daemon derives the palette from the policy-filtered applications, not from the records",
    /let palette_entries: Vec<Value> = applications/u.test(routes));
  ok("the daemon derives the contextual lane from the same filtered applications",
    /Some\(kind\) => applications/u.test(routes));
  ok("the daemon projects no axis as a hard-coded null",
    !/"surface_origin":\s*Value::Null/u.test(routes) && !/"surface_creation_method":\s*Value::Null/u.test(routes));

  // The static fallback is the other place a hard-coded catalog hides: canon permits safe static
  // first-party INVENTORY when the daemon is unreachable, and a palette is not inventory.
  ok("the daemon-unavailable fallback serves no palette and no contextual lane",
    /palette:\s*\[\],/u.test(compilerCode)
      && /absence_code:\s*reasonCode/u.test(compilerCode));
}

// ------------------------------------------------------------------------------------ the drills
function runDrills(live) {
  const clone = () => JSON.parse(JSON.stringify(live));

  // HARD-CODED CLASSIFICATION, class 1: the palette carries a surface the registration never
  // declared for it. This is what a compiler-kept list looks like from outside.
  const invented = clone();
  invented.command_palette_entries.push({ identity_ref: "surface://hypervisor/__invented" });
  drill("a palette entry with no registered command_palette mode is refused",
    !paletteIsDerived(invented));

  // HARD-CODED CLASSIFICATION, class 2: the palette OMITS a surface that registered the mode. A
  // hand-kept list fails this way at least as often, and a one-directional check would miss it.
  const omitted = clone();
  omitted.command_palette_entries.pop();
  drill("a palette missing a registered command_palette surface is refused",
    !paletteIsDerived(omitted));

  // PARITY-DERIVED CLASSIFICATION: a surface enters a projection carrying parity evidence instead
  // of a registration. The axes are what a registration looks like; a certificate is not one.
  const parity = clone();
  parity.application_entries.push({
    identity_ref: "surface://hypervisor/__parity-certified",
    canonical_route: "/__ioi/__parity-certified",
    shell_pixel_certified: true,
    launch_modes: ["command_palette"],
  });
  drill("a surface admitted on a pixel certificate rather than the eleven axes is refused",
    !elevenAxesServed(parity));

  // The same defect wearing the other hat: parity evidence present AND the axes served, but the
  // palette then disagrees with the registration. Membership must follow the registration even when
  // the certificate is real.
  drill("and it cannot buy palette membership either", !paletteIsDerived(parity));

  // CLAUSE 1: two registrations on one click target.
  const collided = clone();
  collided.application_entries.push({
    ...collided.application_entries[0],
    identity_ref: "surface://hypervisor/__collides",
  });
  drill("two surfaces claiming one canonical route are refused", !routesAreUnambiguous(collided));

  // A NULL REGISTRATION AXIS. The state this unit began in: eleven axes named, nine served.
  const nulled = clone();
  nulled.application_entries[0].surface_origin = null;
  drill("a registration axis served as null is refused — a surface always has an origin",
    !elevenAxesServed(nulled));

  // A SILENT JOIN NULL. Null is legitimate for a surface with no release; null with nothing saying
  // so is a consumer reading "unknown" as "none". The difference is the reason code.
  const silent = clone();
  const planned = silent.application_entries.find((row) => row.surface_operational_state === null)
    ?? silent.application_entries[0];
  planned.surface_operational_state = null;
  planned.disabled_reason_codes = [];
  drill("a join-derived null with no reason code is refused", !elevenAxesServed(silent));

  // AN ABSENT KEY. Absence and registered-null are different answers and a consumer must be able to
  // tell them apart, so the key stays even when there is nothing to put in it.
  const dropped = clone();
  delete dropped.application_entries[0].surface_creation_method;
  drill("an axis whose key is absent entirely is refused", !elevenAxesServed(dropped));

  // PERMISSION AS ADDITION. The palette keeps a surface the catalog dropped.
  const leaked = clone();
  const victim = leaked.application_entries[0].identity_ref;
  leaked.application_entries = leaked.application_entries.filter((r) => r.identity_ref !== victim);
  drill("a surface subtracted from the catalog but left in the palette is refused",
    !subtractionHolds(leaked, victim));

  // UNTYPED ABSENCE. An empty lane that will not say which empty it is.
  const untyped = clone();
  untyped.contextual_entries = [];
  untyped.contextual_absence_code = null;
  untyped.requested_context_kind = "project";
  drill("an empty contextual lane with no reason code is refused", !absenceIsTyped(untyped));

  // A MISSING PROJECTION. The state two of the five were in.
  const missing = clone();
  delete missing.command_palette_entries;
  drill("a projection missing the palette lane is refused", !hasFiveProjections(missing));
}

async function main() {
  try { fs.accessSync(daemonBinary, fs.constants.X_OK); } catch {
    console.error(`BLOCKED: daemon binary not executable at ${daemonBinary}. Build it first: cargo build -p ioi-node --bin hypervisor-daemon`);
    process.exit(2);
  }
  // THE STALE-BINARY GUARD. A verifier that reads `target/debug/hypervisor-daemon` does not build
  // it, and measuring a binary older than the source it is meant to prove reports on code that is
  // not there. This cost a full false reading earlier in this program.
  const binaryAge = fs.statSync(daemonBinary).mtimeMs;
  const sourceAge = fs.statSync(path.join(ROOT, "crates/node/src/bin/hypervisor_daemon_routes/lifecycle_routes.rs")).mtimeMs;
  const recordsAge = fs.statSync(path.join(ROOT, "crates/node/src/bin/hypervisor_daemon_routes/hypervisor_surface_records.json")).mtimeMs;
  ok("PRECONDITION: the daemon binary is newer than the route source and the registration records it must serve",
    binaryAge >= sourceAge && binaryAge >= recordsAge,
    binaryAge >= sourceAge && binaryAge >= recordsAge ? "built from this tree" : "STALE — rebuild before trusting anything below");

  structuralChecks();

  scratch = fs.mkdtempSync(path.join(os.tmpdir(), "ioi-surface-compiler-"));
  const dataDir = path.join(scratch, "data");
  fs.mkdirSync(dataDir, { recursive: true });
  const port = await freePort();
  const base = `http://127.0.0.1:${port}`;
  startDaemon(port, dataDir);
  if (!await waitFor(`${base}/healthz`, 30000)) {
    ok("daemon comes up", false, daemonLog.slice(-400));
    return;
  }

  const bootToken = daemonLog.match(/ioi_bootstrap_[a-f0-9]{64}/gu)?.at(-1) ?? null;
  const bootRes = await fetch(`${base}/v1/hypervisor/auth/bootstrap`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ token: bootToken, password: "product-surface-compiler-v1" }),
  });
  const session = (await bootRes.json().catch(() => ({})))?.session_token ?? "";
  ok("PRECONDITION: an authenticated operator session exists", !!session);

  // IDENTITY BEFORE BODY, AND POSTURE BEFORE BOTH. This lane is `read_model_only`, so the estate's
  // documented `user://local-operator` read-lane convenience applies on a trusted local posture —
  // an anonymous loopback read projects the legacy operator scope and acquires nothing. What it
  // must NOT do is hand an organization's installed inventory to an anonymous caller on a daemon
  // reachable from outside, which is the same door the write lanes close with the same gate.
  //
  // Both are asserted because asserting either alone gets the posture wrong in one direction: a
  // flat 401 would break every local consumer, and a flat 200 is a disclosure.
  const anonLocal = await fetch(`${base}/v1/hypervisor/product-surface-projections`, { method: "POST" });
  ok("an anonymous LOOPBACK read projects the local-operator scope — the documented read-lane posture",
    anonLocal.status === 200, `status ${anonLocal.status}`);
  const anonExposed = await fetch(`${base}/v1/hypervisor/product-surface-projections`, {
    method: "POST",
    headers: { "x-forwarded-for": "203.0.113.7" },
  });
  const exposedBody = await anonExposed.json().catch(() => ({}));
  // The refusal comes from the enforcement layer, not from this handler — which is where it belongs,
  // because it closes the same door for every route at once. Asserted here anyway: this projection
  // serves an organization's installed inventory, and a check that only ever measured the loopback
  // case would not notice the day that layer stopped covering it.
  ok("an anonymous EXPOSED read is refused 401 — an exposed daemon projects no organization's inventory to nobody",
    anonExposed.status === 401 && exposedBody?.reason === "authentication_required",
    `status ${anonExposed.status} reason ${exposedBody?.reason ?? "(none)"}`);
  // And the refusal is about WHO, not about what was sent: the same exposed request WITH a session
  // is served, so the gate is identity and not the missing body.
  const sessionExposed = await fetch(`${base}/v1/hypervisor/product-surface-projections`, {
    method: "POST",
    headers: { "x-forwarded-for": "203.0.113.7", cookie: `ioi_session=${session}` },
  });
  ok("the same exposed request carrying a session is served — the 401 named identity, not the body",
    sessionExposed.status === 200, `status ${sessionExposed.status}`);

  const plain = await projection(base, session, {});
  ok("the projection answers an authenticated caller", plain.status === 200, `status ${plain.status}`);
  const live = plain.json || {};

  ok("all five projections ACC-10 clause 2 names are served", hasFiveProjections(live),
    `workspaces ${live.workspace_entries?.length} · applications ${live.application_entries?.length} · palette ${live.command_palette_entries?.length} · contextual ${live.contextual_entries?.length}`);
  ok("every catalog entry serves all eleven independent axes", elevenAxesServed(live),
    ELEVEN_AXES.join(" "));
  ok("every click target resolves to exactly one designated surface (ACC-10 clause 1)", routesAreUnambiguous(live));
  ok("the palette is exactly the registrations declaring command_palette", paletteIsDerived(live),
    `${live.command_palette_entries?.length} palette entries`);
  ok("no context kind requested yields an empty contextual lane with a typed reason",
    (live.contextual_entries || []).length === 0 && live.contextual_absence_code === "no_context_kind_requested");

  // Both classes are registered, and both appear: the catalog is not one class wearing two names.
  const classes = new Set((live.application_entries || []).map((row) => row.surface_class));
  ok("the catalog carries the registered classes, tool surfaces among them",
    classes.has("owner_application") && classes.has("tool_surface"),
    [...classes].join(","));
  // The axis that had no home, doing work on its first day.
  const methods = new Set((live.application_entries || []).map((row) => row.surface_creation_method));
  ok("surface_creation_method distinguishes hand-authored surfaces from adapted ports",
    methods.has("hand_authored") && methods.has("adapted"),
    [...methods].join(","));

  const withContext = await projection(base, session, { context: { context_kind: "project" } });
  const ctx = withContext.json || {};
  ok("a typed context yields exactly the surfaces registering it", contextualIsDerived(ctx),
    `${ctx.contextual_entries?.length} entries for project`);
  ok("and every one of them names the kind it matched",
    (ctx.contextual_entries || []).length > 0
      && (ctx.contextual_entries).every((row) => row.matched_context_kind === "project"));

  const unclaimed = await projection(base, session, { context: { context_kind: "outcome_room" } });
  ok("a context kind no surface registers is an empty lane with its own reason code",
    (unclaimed.json?.contextual_entries || []).length === 0
      && unclaimed.json?.contextual_absence_code === "no_surface_registers_this_context_kind",
    unclaimed.json?.contextual_absence_code || "(none)");
  ok("absence is typed in every case observed", absenceIsTyped(live) && absenceIsTyped(unclaimed.json || {}));

  // PERMISSION IS SUBTRACTION, measured rather than reasoned about.
  const paletteRef = (live.command_palette_entries || [])[0]?.identity_ref;
  const keep = (live.application_entries || [])
    .map((row) => row.identity_ref)
    .filter((ref) => ref !== paletteRef);
  const narrowed = await projection(base, session, {
    context: { context_kind: "project" },
    allowed_surface_refs: keep,
  });
  ok("a surface subtracted by permission is absent from the catalog, the palette AND the contextual lane",
    !!paletteRef && subtractionHolds(narrowed.json || {}, paletteRef), paletteRef || "(no palette entry)");
  ok("and the narrowed projection is still internally derived, not a filtered snapshot",
    paletteIsDerived(narrowed.json || {}) && contextualIsDerived(narrowed.json || {}));

  runDrills(live);
}

main()
  .catch((error) => { ok("verifier ran to completion", false, String(error?.message || error)); })
  .finally(() => {
    cleanup();
    const failed = RESULTS.filter((r) => !r.pass);
    console.log(`\n${failed.length === 0 ? "PASS" : "FAIL"} check:product-surface-compiler — ${RESULTS.length - failed.length}/${RESULTS.length} assertion(s)`
      + (failed.length ? ` · failing: ${failed.map((r) => r.label).join(" | ")}` : ""));
    process.exit(failed.length === 0 ? 0 : 1);
  });
