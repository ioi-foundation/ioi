#!/usr/bin/env node
// Model-route registry AUTHORITY verifier — who may mutate, and who may USE, a model route.
//
// The defect this gate exists for was filed OPEN on 2026-08-13 (`canon-to-code-delta.md`, "the
// model-route registry mutation surface is unauthenticated"): every mutation handler authenticated
// only at the global auth gate, never per request, because a route record carried no owner at all.
// Under the default `auto` posture that gate is false for the estate's own loopback-behind-`serve`
// topology, so on the documented exposed deployment those mutations were reachable by anyone.
//
// THE FIXTURE IS THE PRODUCT SHAPE, AND THAT IS THE POINT. The first cut of this leg scoped route
// ownership to the caller's TENANT and proved it with a second principal hand-placed in its own
// `project://` tenant. That fixture passed 42/42 and the gate isolated NOTHING: this deployment can
// construct exactly one organization (`org://local`), and every product onboarding lane — OIDC/SSO
// auto-join, SCIM provisioning, org-invite accept — grants that same ref, so a tenant check is true
// for every principal in the deployment. An adversarial review found it; the green fixture could
// not, because it was built in a shape the product never produces. Principals B and C below are
// therefore BOTH in `org://local`, that sameness is asserted rather than assumed, and the isolation
// proofs run between them.
//
// The other discipline this file is written under:
//   - CLOSED WORLD, DERIVED. The mutating endpoint list is re-derived from the daemon's own router
//     source on every run, not hand-listed, so a mutation added later is covered or this goes red.
//   - COUNT THE THING ITSELF. A refusal's status code proves nothing about CONTACT or SIDE EFFECT.
//     The exploit chain points a route at a listener that only counts TCP connections and asserts
//     ZERO — paired with a live-instrument check, because a zero from a dead counter is not a
//     refusal. Every refusal is re-checked against the DURABLE RECORD BYTES rather than the reply.
//   - ASSERT THE DELTA YOU OWN. Record counts and file digests are snapshotted before and compared
//     after, so an assertion fires for the change it names and not for unrelated drift.
//   - NO DISJUNCTIONS ON A REFUSAL. A status-or-status assertion passes when the fixture is broken.
//
// Exit: 0 pass · 1 fail · 2 blocked (daemon binary missing).
//   IOI_HYPERVISOR_DAEMON_BINARY  default target/debug/hypervisor-daemon

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
const code = (j) => j?.code ?? j?.error?.code ?? "";

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
    try { const r = await fetch(url); if (r.status < 500) return; } catch { /* not up yet */ }
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

const dataDir = fs.mkdtempSync(path.join(os.tmpdir(), "ioi-model-route-authority-"));
let daemon = null;
let DAEMON = "";

// A = bootstrap operator (role admin, org://local). B and C = ordinary members, BOTH in org://local
// — the shape SSO / SCIM / invite onboarding actually produces.
const P = { A: { session: "", owner: "", ref: "" }, B: { session: "", owner: "", ref: "" }, C: { session: "", owner: "", ref: "" } };

const jd = (method, p, body, { as = "A", owner = null, idem = null } = {}) => {
  const session = as ? P[as]?.session ?? "" : "";
  const payload = body && idem
    ? { owner_ref: owner ?? P[as]?.owner ?? "", idempotency_key: idem, ...body }
    : body;
  return fetch(`${DAEMON}${p}`, {
    method,
    headers: {
      ...(payload ? { "content-type": "application/json" } : {}),
      ...(session ? { cookie: `ioi_session=${session}` } : {}),
    },
    ...(payload ? { body: JSON.stringify(payload) } : {}),
  }).then(async (r) => {
    const text = await r.text();
    let j = null;
    try { j = JSON.parse(text); } catch { /* non-json */ }
    return { status: r.status, j, text };
  }).catch((e) => ({ status: 0, j: { transport_error: String(e) }, text: String(e) }));
};

const registryDir = () => path.join(dataDir, "model-route-registry");
const routeFile = (id) => {
  try { return fs.readFileSync(path.join(registryDir(), `${id}.json`), "utf8"); } catch { return ""; }
};
const routeRecord = (id) => {
  const raw = routeFile(id);
  if (!raw) return null;
  try { return JSON.parse(raw); } catch { return null; }
};
const countFiles = (subdir) => {
  try { return fs.readdirSync(path.join(dataDir, subdir)).length; } catch { return 0; }
};
const routeFileCount = () => countFiles("model-route-registry");
const receiptCount = () => countFiles("model-route-registry-receipts");
const bindingCount = () => countFiles("model-route-session-bindings");

/** Every byte the daemon durably wrote under `subdir`. Asking the API is not evidence. */
const allDurableBytes = (subdir) => {
  const out = [];
  const walk = (dir) => {
    let entries = [];
    try { entries = fs.readdirSync(dir, { withFileTypes: true }); } catch { return; }
    for (const entry of entries) {
      const full = path.join(dir, entry.name);
      if (entry.isDirectory()) walk(full);
      else { try { out.push(fs.readFileSync(full, "utf8")); } catch { /* binary or gone */ } }
    }
  };
  walk(path.join(dataDir, subdir));
  return out.join("\n");
};

/**
 * THE CLOSED WORLD, DERIVED FROM THE ENFORCING ARTIFACT.
 *
 * Re-reads the daemon's router source and returns every model-route endpoint registered with a
 * MUTATING method. A hand-written list would be a literal compared against a literal — it could not
 * fail, and it would silently stop covering the surface the first time a handler was added. This is
 * the `check:verifier-floors` closed-world idiom applied to a route table.
 */
const routerMutationCensus = () => {
  const src = fs.readFileSync(path.join(ROOT, "crates/node/src/bin/hypervisor-daemon.rs"), "utf8");
  const found = [];
  for (const chunk of src.split(".route(")) {
    const pathMatch = chunk.match(/^\s*"(\/v1\/hypervisor\/model-routes[^"]*)"/u);
    if (!pathMatch) continue;
    // Only the registration body, up to the end of this .route(...) call.
    const body = chunk.slice(0, chunk.indexOf("\n        )"));
    for (const method of ["post", "patch", "delete"]) {
      if (new RegExp(`(^|[^a-z_])${method}\\(`, "u").test(body)) {
        found.push({ method: method.toUpperCase(), path: pathMatch[1] });
      }
    }
  }
  return found;
};

function cleanup() {
  try { daemon?.kill("SIGTERM"); } catch { /* already gone */ }
  try { fs.rmSync(dataDir, { recursive: true, force: true }); } catch { /* best effort */ }
}

/** A concrete anonymous request for each censused endpoint. */
const anonRequestFor = ({ method, path: p }, id) => {
  const concrete = p.replace(":id", id);
  if (method === "POST" && p.endsWith("/model-routes")) {
    return { method, path: concrete, body: { model_id: "anon", transport: "ollama", base_url: "http://127.0.0.1:11434" } };
  }
  if (method === "PATCH") return { method, path: concrete, body: { display_name: "anon-owned" } };
  if (p.endsWith("/session-bindings")) return { method, path: concrete, body: { session_ref: "session:anon" } };
  if (p.endsWith("/invoke")) return { method, path: concrete, body: { prompt: "hello" } };
  if (p.endsWith("/credential") && method === "POST") return { method, path: concrete, body: { token: "anon-token" } };
  if (p.endsWith("/credential") && method === "DELETE") return { method, path: concrete, body: { reason: "anon" } };
  return { method, path: concrete, body: null };
};

async function makeMember(letter, email) {
  const created = await jd("POST", "/v1/hypervisor/principals",
    { email, name: `Member ${letter}`, role: "member", password: `authority-${letter}-v1` }, { as: "A" });
  const id = created.j?.principal?.principal_id ?? "";
  // org://local is the ONLY organization this deployment can construct, and it is what every
  // product onboarding lane grants. Putting B and C here is what makes the isolation proof real.
  await jd("POST", `/v1/hypervisor/principals/${id}/tenant-memberships`, {
    tenant_ref: "org://local",
    expected_revision: 0,
    idempotency_key: `authority-grant-${letter}-1`,
    reason: "verifier fixture: an ordinary member onboarded into the deployment's only organization",
  }, { as: "A" });
  const login = await jd("POST", "/v1/hypervisor/auth/login", { email, password: `authority-${letter}-v1` }, { as: null });
  P[letter].session = login.j?.session_token ?? "";
  const who = (await jd("GET", "/v1/hypervisor/auth/whoami", null, { as: letter })).j || {};
  P[letter].owner = (who.principal?.tenant_refs || []).find((t) => t === "org://local") || "";
  P[letter].ref = who.principal?.principal_ref ?? "";
  return who;
}

async function run() {
  const daemonPort = await freePort();
  DAEMON = `http://127.0.0.1:${daemonPort}`;
  daemon = spawn(daemonBinary, [], {
    cwd: ROOT,
    env: {
      ...process.env,
      IOI_HYPERVISOR_DAEMON_ADDR: `127.0.0.1:${daemonPort}`,
      IOI_HYPERVISOR_DATA_DIR: dataDir,
      IOI_HYPERVISOR_MODEL_UPSTREAM: "http://127.0.0.1:1",
    },
    stdio: ["ignore", "pipe", "pipe"],
  });
  let log = "";
  daemon.stdout.on("data", (c) => { log = `${log}${c}`.slice(-64000); });
  daemon.stderr.on("data", (c) => { log = `${log}${c}`.slice(-64000); });
  await waitFor(`${DAEMON}/healthz`, 30000);

  // ---------------------------------------------------------------- principals
  const bootToken = log.match(/ioi_bootstrap_[a-f0-9]{64}/gu)?.at(-1) ?? null;
  const boot = await jd("POST", "/v1/hypervisor/auth/bootstrap",
    { token: bootToken, password: "model-route-authority-v1" }, { as: null });
  P.A.session = boot.j?.session_token ?? "";
  ok("operator bootstrap yields an authenticated admin session (principal A)",
    P.A.session.startsWith("ioi_sess_"), P.A.session.slice(0, 12));

  // whoami answers 200 with `authenticated: false` and the OPERATOR as a fallback when enforcement
  // is off, so a bare 200 would certify a session that does not exist. Assert the flag.
  const whoA = (await jd("GET", "/v1/hypervisor/auth/whoami", null, { as: "A" })).j || {};
  P.A.owner = (whoA.principal?.tenant_refs || []).find((t) => typeof t === "string" && t.startsWith("org://")) || "";
  P.A.ref = whoA.principal?.principal_ref ?? "";
  ok("principal A is a REAL authenticated session, is the deployment administrator, and holds the org tenant",
    whoA.authenticated === true && whoA.principal?.role === "admin" && P.A.owner === "org://local",
    `authenticated ${whoA.authenticated} role ${whoA.principal?.role} owner ${P.A.owner}`);

  const whoB = await makeMember("B", "authority-b@ioi.local");
  const whoC = await makeMember("C", "authority-c@ioi.local");
  ok("principal B is a REAL, non-admin session", whoB.authenticated === true && whoB.principal?.role !== "admin", `role ${whoB.principal?.role}`);
  ok("principal C is a REAL, non-admin session", whoC.authenticated === true && whoC.principal?.role !== "admin", `role ${whoC.principal?.role}`);

  // THE PRECONDITION THAT MAKES EVERY ISOLATION ASSERTION BELOW MEAN SOMETHING. B and C are in the
  // SAME tenant — the product shape. If ownership were scoped to the tenant, every 403 below would
  // be a 200. The first cut of this leg failed exactly here and its fixture could not see it.
  ok("B and C are ordinary members of the SAME tenant — so tenant membership cannot be what isolates them",
    P.B.owner === "org://local" && P.C.owner === "org://local" && P.B.ref !== P.C.ref && !!P.B.ref,
    `B ${P.B.owner}/${P.B.ref} C ${P.C.owner}/${P.C.ref}`);

  // ---------------------------------------------------------------- the seed is system-owned
  await jd("GET", "/v1/hypervisor/model-routes", null, { as: "A" });
  const seed = routeRecord("mrt_local_default");
  ok("the seeded route is typed SYSTEM-owned in its durable record, not left ownerless",
    seed?.owner_ref === "system://hypervisor" && seed?.owner_kind === "system",
    `owner_ref ${seed?.owner_ref} owner_kind ${seed?.owner_kind}`);

  // ---------------------------------------------------------------- B owns a route
  const mk = await jd("POST", "/v1/hypervisor/model-routes", {
    model_id: "authority-target", transport: "ollama",
    base_url: "http://127.0.0.1:1", display_name: "B's route",
  }, { as: "B", idem: "authority-target-create" });
  const rid = mk.j?.route?.route_id ?? "";
  ok("an authenticated create succeeds", mk.status === 201 && !!rid, `status ${mk.status} ${rid}`);
  const mkRec = routeRecord(rid);
  ok("the created record carries the caller's tenant as a typed owner",
    mkRec?.owner_ref === P.B.owner && mkRec?.owner_kind === "tenant",
    `owner_ref ${mkRec?.owner_ref} owner_kind ${mkRec?.owner_kind}`);

  // THE PIN IS WHAT AUTHORIZES, AND IT NAMES A PRINCIPAL. The record's `owner_ref` is only the
  // tenant, which every principal here shares; the substrate scope binds the route to B's principal
  // ref, and `authorize_route_owner` reads THAT. This assertion is the durable evidence of it.
  const pinEvent = (() => {
    const chunks = allDurableBytes("substrate").split('{"frame"');
    return chunks.find((c) => c.includes(`"resource_ref":"model-route://${rid}"`)) ?? "";
  })();
  ok("creating a route PINS it to the creating PRINCIPAL in the substrate — not merely to a tenant",
    pinEvent.includes('"op_kind":"event_stream.request_resource_scope_bound"')
      && pinEvent.includes(`"principal_ref":"${P.B.ref}"`)
      && pinEvent.includes('"resource_kind":"model-route-registry"'),
    pinEvent ? `bound to ${P.B.ref}` : "no scope event names this route");

  // ---------------------------------------------------------------- anonymous: the whole surface
  const census = routerMutationCensus();
  ok("CLOSED WORLD: the mutating model-route endpoints are re-derived from the daemon's own router source",
    census.length >= 11 && census.some((c) => c.path.endsWith("/session-bindings")) && census.some((c) => c.path.endsWith("/invoke"))
      && census.some((c) => c.path.endsWith("/credential")),
    `${census.length} mutating endpoint(s): ${census.map((c) => `${c.method} ${c.path.replace("/v1/hypervisor/model-routes", "")}`).join(" ")}`);

  const beforeAnonBytes = routeFile(rid);
  const beforeAnonRoutes = routeFileCount();
  const beforeAnonReceipts = receiptCount();
  const beforeAnonBindings = bindingCount();
  const anonStatuses = [];
  for (const endpoint of census) {
    const req = anonRequestFor(endpoint, rid);
    const r = await jd(req.method, req.path, req.body, { as: null });
    anonStatuses.push({ name: `${endpoint.method} ${endpoint.path.replace("/v1/hypervisor/model-routes", "") || "/"}`, status: r.status });
  }
  ok("EVERY censused mutation is refused 401 anonymously — no endpoint on the surface is exempt",
    anonStatuses.length === census.length && anonStatuses.every((a) => a.status === 401),
    anonStatuses.map((a) => `${a.name}:${a.status}`).join(" "));

  const ghost = await jd("PATCH", "/v1/hypervisor/model-routes/mrt_does_not_exist_ever", { display_name: "x" }, { as: null });
  ok("rule E: an anonymous mutation on a NON-EXISTENT route answers 401, never a 404 existence oracle",
    ghost.status === 401, `status ${ghost.status} code ${code(ghost.j)}`);

  ok("the anonymous attempts left the target record's durable bytes byte-for-byte unchanged",
    routeFile(rid) === beforeAnonBytes && beforeAnonBytes.length > 0);
  ok("the anonymous attempts wrote NOTHING: no route, no receipt, no session binding (delta 0 on all three)",
    routeFileCount() === beforeAnonRoutes && receiptCount() === beforeAnonReceipts && bindingCount() === beforeAnonBindings,
    `routes ${beforeAnonRoutes}->${routeFileCount()} receipts ${beforeAnonReceipts}->${receiptCount()} bindings ${beforeAnonBindings}->${bindingCount()}`);

  // ---------------------------------------------------------------- SAME-TENANT ISOLATION
  const beforeC = routeFile(rid);
  const beforeCReceipts = receiptCount();
  const cAttempts = [
    { name: "patch", r: await jd("PATCH", `/v1/hypervisor/model-routes/${rid}`, { display_name: "seized" }, { as: "C" }) },
    { name: "probe", r: await jd("POST", `/v1/hypervisor/model-routes/${rid}/probe`, null, { as: "C" }) },
    { name: "enable", r: await jd("POST", `/v1/hypervisor/model-routes/${rid}/enable`, null, { as: "C" }) },
    { name: "disable", r: await jd("POST", `/v1/hypervisor/model-routes/${rid}/disable`, null, { as: "C" }) },
    { name: "delete", r: await jd("DELETE", `/v1/hypervisor/model-routes/${rid}`, null, { as: "C" }) },
    { name: "session-bindings", r: await jd("POST", `/v1/hypervisor/model-routes/${rid}/session-bindings`, { session_ref: "session:c" }, { as: "C" }) },
  ];
  ok("a SAME-TENANT principal cannot patch/probe/enable/disable/delete/bind another principal's route",
    cAttempts.every((a) => a.r.status === 403 && code(a.r.j) === "model_route_owner_mismatch"),
    cAttempts.map((a) => `${a.name}:${a.r.status}/${code(a.r.j)}`).join(" "));
  ok("C's refused attempts moved nothing: the record is byte-identical and no receipt was appended",
    routeFile(rid) === beforeC && receiptCount() === beforeCReceipts);

  const cForge = await jd("PATCH", `/v1/hypervisor/model-routes/${rid}`,
    { display_name: "seized-by-declaration", owner_ref: P.C.owner }, { as: "C" });
  ok("a caller cannot NAME the owner of a route it is mutating: a body-supplied owner_ref is still refused",
    cForge.status === 403 && code(cForge.j) === "model_route_owner_mismatch",
    `status ${cForge.status} code ${code(cForge.j)}`);
  ok("the forged-owner attempt left the durable record unchanged", routeFile(rid) === beforeC);
  ok("the refusal does not disclose the owning principal (no ownership oracle)",
    !cForge.text.includes(P.B.ref), P.B.ref);

  // ---------------------------------------------------------------- THE FILED EXPLOIT CHAIN
  let attackerConnections = 0;
  const attackerPort = await freePort();
  const attacker = net.createServer((c) => { attackerConnections += 1; c.destroy(); });
  await new Promise((resolve) => attacker.listen(attackerPort, "127.0.0.1", resolve));
  const attackerUrl = `http://127.0.0.1:${attackerPort}`;

  const beforeRepoint = routeRecord(rid)?.provider_binding?.base_url ?? "";
  const anonRepoint = await jd("PATCH", `/v1/hypervisor/model-routes/${rid}`, { base_url: attackerUrl }, { as: null });
  ok("EXPLOIT LINK 1 (anonymous): the repoint of an uncredentialed route is refused",
    anonRepoint.status === 401, `status ${anonRepoint.status}`);
  const cRepoint = await jd("PATCH", `/v1/hypervisor/model-routes/${rid}`, { base_url: attackerUrl }, { as: "C" });
  ok("EXPLOIT LINK 1 (same-tenant, authenticated): the repoint is refused by OWNERSHIP",
    cRepoint.status === 403 && code(cRepoint.j) === "model_route_owner_mismatch",
    `status ${cRepoint.status} code ${code(cRepoint.j)}`);
  ok("EXPLOIT LINK 1 (durable): the base_url in the STORED RECORD never moved",
    (routeRecord(rid)?.provider_binding?.base_url ?? "") === beforeRepoint && !beforeRepoint.includes(String(attackerPort)),
    `${beforeRepoint}`);

  // Counting connections on the route the repoint FAILED to move would be decorative: it still
  // points at its original host, so the counter reads zero whether the probe gate exists or not.
  // The contact proof needs a route that GENUINELY aims at the listener, which only its owner makes.
  const aimed = await jd("POST", "/v1/hypervisor/model-routes", {
    model_id: "aimed-at-attacker", transport: "ollama",
    base_url: attackerUrl, display_name: "owner-aimed route",
  }, { as: "B", idem: "aimed-create" });
  const aimedId = aimed.j?.route?.route_id ?? "";
  ok("a route genuinely aimed at the counting listener exists, so a leaked probe WOULD be observable",
    aimed.status === 201 && (routeRecord(aimedId)?.provider_binding?.base_url ?? "").includes(String(attackerPort)),
    routeRecord(aimedId)?.provider_binding?.base_url);

  const anonAimed = await jd("POST", `/v1/hypervisor/model-routes/${aimedId}/probe`, null, { as: null });
  ok("EXPLOIT LINK 2: the anonymous probe of the aimed route is refused", anonAimed.status === 401, `status ${anonAimed.status}`);
  const cAimed = await jd("POST", `/v1/hypervisor/model-routes/${aimedId}/probe`, null, { as: "C" });
  ok("EXPLOIT LINK 2: a same-tenant non-owner probe of the aimed route is refused",
    cAimed.status === 403 && code(cAimed.j) === "model_route_owner_mismatch", `status ${cAimed.status}`);
  ok("EXPLOIT LINK 2 (contact): the refused probes opened ZERO connections to the attacker-controlled host",
    attackerConnections === 0, `${attackerConnections} connection(s)`);
  const ownerAimed = await jd("POST", `/v1/hypervisor/model-routes/${aimedId}/probe`, null, { as: "B" });
  ok("the counter is LIVE: the owner's own probe does reach the listener, so the zero above is a refusal and not a dead instrument",
    ownerAimed.status === 200 && attackerConnections > 0,
    `status ${ownerAimed.status} connections ${attackerConnections}`);
  attacker.close();

  // ---------------------------------------------------------------- THE OTHER DOORS INTO THE REGISTRY
  // Three surfaces reach a route's records from outside the mutation handlers. Each was found by
  // adversarial review after the first cut declared the surface closed.
  const beforeBindings = bindingCount();
  // No `idem` here on purpose: session create resolves its owner daemon-side and REFUSES a body
  // carrying `owner_ref` (INV-37), so injecting one would 400 on request shape and this assertion
  // would never reach the binding path it exists to test.
  const cSession = await jd("POST", "/v1/hypervisor/sessions",
    { model_route_ref: `model-route:${rid}`, title: "c-steals-b-route", idempotency_key: "c-session-bind" }, { as: "C" });
  ok("BYPASS 1 — session create: binding ANOTHER principal's route into a session is refused",
    cSession.status === 403 && code(cSession.j) === "model_route_owner_mismatch",
    `status ${cSession.status} code ${code(cSession.j)}`);
  // The consequence, not just the code: a binding permanently blocks its route's deletion and no
  // revocation surface exists, so an admitted bind here is an unremovable denial of service.
  ok("BYPASS 1 (durable): no session binding was written against the victim's route (delta 0)",
    bindingCount() === beforeBindings, `${beforeBindings} -> ${bindingCount()}`);

  const cCredBind = await jd("POST", `/v1/hypervisor/model-routes/${rid}/credential`,
    { token: "sk-not-mine" }, { as: "C", idem: "c-cred-bind" });
  ok("BYPASS 2 — credential bind: claiming the credential slot of another principal's route is refused",
    cCredBind.status === 403 && code(cCredBind.j) === "model_route_owner_mismatch",
    `status ${cCredBind.status} code ${code(cCredBind.j)}`);
  const cCredRevoke = await jd("DELETE", `/v1/hypervisor/model-routes/${rid}/credential`,
    { reason: "not mine" }, { as: "C", idem: "c-cred-revoke" });
  ok("BYPASS 2 — credential revoke: refused by ownership BEFORE the untouched-slot no-op could answer (no bind-state oracle)",
    cCredRevoke.status === 403 && code(cCredRevoke.j) === "model_route_owner_mismatch",
    `status ${cCredRevoke.status} code ${code(cCredRevoke.j)}`);

  const cInvoke = await jd("POST", `/v1/hypervisor/model-routes/${rid}/invoke`,
    { prompt: "spend someone else's route" }, { as: "C", idem: "c-invoke" });
  ok("BYPASS 3 — invoke: USING another principal's route is refused, not merely configuring it",
    cInvoke.status === 403 && code(cInvoke.j) === "model_route_owner_mismatch",
    `status ${cInvoke.status} code ${code(cInvoke.j)}`);

  // ---------------------------------------------------------------- the deployment's own records
  const bSeedProbe = await jd("POST", "/v1/hypervisor/model-routes/mrt_local_default/probe", null, { as: "B" });
  ok("an ordinary authenticated principal may NOT mutate the deployment's seeded route",
    bSeedProbe.status === 403 && code(bSeedProbe.j) === "model_route_deployment_admin_required",
    `status ${bSeedProbe.status} code ${code(bSeedProbe.j)}`);
  const aSeedProbe = await jd("POST", "/v1/hypervisor/model-routes/mrt_local_default/probe", null, { as: "A" });
  ok("the deployment administrator MAY mutate the seeded route (the gate refuses the wrong caller, not everyone)",
    aSeedProbe.status === 200, `status ${aSeedProbe.status}`);

  const beforeDefault = (await jd("GET", "/v1/hypervisor/model-routes", null, { as: "A" })).j?.default_route_ref ?? "";
  const bSelfDefault = await jd("POST", `/v1/hypervisor/model-routes/${rid}/select-default`, null, { as: "B" });
  ok("selecting the default is DEPLOYMENT-scoped: the route's OWNER is refused on their OWN route, by the admin gate",
    bSelfDefault.status === 403 && code(bSelfDefault.j) === "model_route_deployment_admin_required",
    `status ${bSelfDefault.status} code ${code(bSelfDefault.j)}`);
  const afterDefault = (await jd("GET", "/v1/hypervisor/model-routes", null, { as: "A" })).j?.default_route_ref ?? "";
  ok("the refused select-default did not move the deployment's default (delta 0)",
    afterDefault === beforeDefault, `${beforeDefault} -> ${afterDefault}`);
  const aSelects = await jd("POST", `/v1/hypervisor/model-routes/${rid}/select-default`, null, { as: "A" });
  const listAfter = (await jd("GET", "/v1/hypervisor/model-routes", null, { as: "A" })).j ?? {};
  ok("the deployment administrator may set the default, and exactly one default survives it",
    aSelects.status === 200 && (listAfter.routes || []).filter((r) => r.default_route === true).length === 1,
    `status ${aSelects.status}`);

  // ---------------------------------------------------------------- create validates the owner
  const beforeForgeRoutes = routeFileCount();
  const forged = await jd("POST", "/v1/hypervisor/model-routes", {
    model_id: "forged", transport: "ollama", base_url: "http://127.0.0.1:1",
  }, { as: "C", owner: "project://a-tenant-c-does-not-belong-to", idem: "forged-owner-create" });
  ok("a create declaring a tenant the caller does not authorize is refused by the shared write path",
    forged.status === 403 && code(forged.j) === "request_tenant_authority_required",
    `status ${forged.status} code ${code(forged.j)}`);
  ok("the refused create persisted NO route record (delta 0)",
    routeFileCount() === beforeForgeRoutes, `${beforeForgeRoutes} -> ${routeFileCount()}`);

  // ---------------------------------------------------------------- legacy ownerless records
  const legacyId = "mrt_legacy_ownerless";
  const legacy = routeRecord("mrt_local_default") ?? {};
  delete legacy.owner_ref;
  delete legacy.owner_kind;
  legacy.route_id = legacyId;
  legacy.route_ref = `model-route:${legacyId}`;
  legacy.default_route = false;
  fs.writeFileSync(path.join(registryDir(), `${legacyId}.json`), JSON.stringify(legacy));
  const bLegacy = await jd("PATCH", `/v1/hypervisor/model-routes/${legacyId}`, { display_name: "adopted" }, { as: "B" });
  ok("an OWNERLESS legacy record is not open season: an ordinary principal is refused, and told the owner is unset",
    bLegacy.status === 403 && code(bLegacy.j) === "model_route_deployment_admin_required"
      && bLegacy.j?.error?.details?.owner_unset === true,
    `status ${bLegacy.status} code ${code(bLegacy.j)} owner_unset ${bLegacy.j?.error?.details?.owner_unset}`);
  const aLegacy = await jd("PATCH", `/v1/hypervisor/model-routes/${legacyId}`, { display_name: "adopted" }, { as: "A" });
  ok("the deployment administrator can still dispose of a legacy ownerless record (recoverable, not stranded)",
    aLegacy.status === 200, `status ${aLegacy.status}`);
  ok("disposing of a legacy record BACKFILLS its typed owner under the registry lock, so the record states what the gate enforces",
    routeRecord(legacyId)?.owner_ref === "system://hypervisor" && routeRecord(legacyId)?.owner_kind === "system",
    `${routeRecord(legacyId)?.owner_ref}`);

  // ---------------------------------------------------------------- scope honesty
  const anonRead = await jd("GET", "/v1/hypervisor/model-routes", null, { as: null });
  ok("RESIDUAL, recorded not hidden: registry READS remain unauthenticated (this leg closed mutation and use)",
    anonRead.status === 200, `status ${anonRead.status}`);

  const fails = results.filter((r) => !r.pass);
  for (const r of results) console.log(`${r.pass ? "PASS" : "FAIL"}  ${r.name}${r.detail ? ` — ${r.detail}` : ""}`);
  console.log(`\n${results.length - fails.length}/${results.length} passed`);
  emitVerifierCensus({ verifierId: "model-route-authority", sourceUrl: import.meta.url, results });
  cleanup();
  process.exit(fails.length ? 1 : 0);
}

run().catch((error) => {
  console.error(`FAIL model-route-authority — ${error?.stack || error}`);
  cleanup();
  process.exit(1);
});
