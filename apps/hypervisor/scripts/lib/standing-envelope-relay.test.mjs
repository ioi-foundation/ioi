// Master guide G5 follow-on — the STANDING envelope is decided through the daemon, and nothing outside the deployment
// authority holds a signing key. End to end against a REAL sealed deployment authority node (wall clock), an isolated
// daemon and an isolated serve, all in temp dirs on their own ports:
//
//   the operator sets limits on a connection through the SERVE's standing-envelope route with the passphrase → the serve
//   relays the bounds and the passphrase to the daemon and keeps nothing → a missing or wrong passphrase, or a body that
//   names coordinates, records nothing → the right passphrase makes the daemon run the sealed authority's
//   `record-standing-approval` (mint mode) and bind the grant → a session naming the connection executes WITHOUT a per-run
//   decision (a silent standing draw) → the next execute is beyond the envelope's one usage and refuses typed with
//   NOTHING parked (no per-run approval past the limits) → revoking through the serve with the passphrase revokes on the
//   authority node and fences the connection → the next execute refuses (standing_lease_revoked). The passphrase is in no
//   file, log or environment.
//
//   IOI_HYPERVISOR_DAEMON_BINARY=<daemon> node --test apps/hypervisor/scripts/lib/standing-envelope-relay.test.mjs
//
// Needs the built `wallet-network-local-authority` (target/debug, or IOI_WALLET_AUTHORITY_BINARY) and the daemon (built
// on demand unless IOI_HYPERVISOR_DAEMON_BINARY names one). Several minutes: the authority node starts a chain, and every
// unseal runs Argon2id in a debug build.
import test, { after } from "node:test";
import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { randomBytes } from "node:crypto";
import fs from "node:fs";
import http from "node:http";
import net from "node:net";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { OPERATOR_PASS_ENV, startLocalAuthority } from "./wallet-network-local-authority.mjs";
import { isolatedOperatorSession, sanitizedVerifierBaseEnv, startIsolatedPlane } from "./isolated-daemon.mjs";

const HERE = path.dirname(fileURLToPath(import.meta.url));
const APP = path.resolve(HERE, "..", "..");
// Unique per run, so a scan for it anywhere can only find THIS test's passphrase.
const OPERATOR = `standing-operator-${randomBytes(12).toString("hex")}`;
const WRONG = `wrong-operator-${randomBytes(12).toString("hex")}`;
const quiet = () => {};
const tempDirs = [];
after(() => { for (const dir of tempDirs) fs.rmSync(dir, { recursive: true, force: true }); });
delete process.env[OPERATOR_PASS_ENV];

/** JSON over node:http with no client-side timeout (an authority act can outlast fetch's header timeout). */
function request(base, method, route, { body, cookie, form = false } = {}) {
  const url = new URL(route, base);
  const text = body === undefined ? null : form ? new URLSearchParams(body).toString() : typeof body === "string" ? body : JSON.stringify(body);
  const payload = text === null ? null : Buffer.from(text);
  const contentType = form ? "application/x-www-form-urlencoded" : "application/json";
  return new Promise((resolve, reject) => {
    const req = http.request(url, { method, headers: { ...(payload ? { "content-type": contentType, "content-length": payload.length } : {}), ...(cookie ? { cookie } : {}), accept: "application/json, text/html" } }, (res) => {
      const chunks = [];
      res.on("data", (c) => chunks.push(c));
      res.on("end", () => {
        const raw = Buffer.concat(chunks).toString("utf8");
        let json = null;
        try { json = raw ? JSON.parse(raw) : null; } catch { json = null; }
        resolve({ status: res.statusCode, body: json, text: raw, headers: res.headers });
      });
    });
    req.on("error", reject);
    if (payload) req.write(payload);
    req.end();
  });
}

function allFiles(dir) {
  const out = [];
  for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
    const full = path.join(dir, entry.name);
    if (entry.isDirectory()) out.push(...allFiles(full));
    else if (entry.isFile()) out.push(full);
  }
  return out;
}
const filesContaining = (dir, needle) => allFiles(dir).filter((file) => { try { return fs.readFileSync(file).includes(Buffer.from(needle)); } catch { return false; } });
const freePort = () => new Promise((resolve, reject) => {
  const srv = net.createServer();
  srv.listen(0, "127.0.0.1", () => { const { port } = srv.address(); srv.close(() => resolve(port)); });
  srv.on("error", reject);
});

async function startServe({ daemonUrl, serveEnv, logPath }) {
  const port = await freePort();
  const productUiPort = await freePort();
  const logFd = fs.openSync(logPath, "w");
  // The serve gets ONLY the public principal/host refs from the authority's serve.env: no authority binary, no state
  // dir, no guardian pass, no key path.
  const env = {
    ...sanitizedVerifierBaseEnv(process.env),
    ...serveEnv,
    PORT: String(port),
    PRODUCT_UI_PORT: String(productUiPort),
    IOI_HYPERVISOR_DAEMON_URL: daemonUrl,
    IOI_PRODUCT_UI_PUBLIC: path.join(APP, "product-ui", "owned", "public"),
    IOI_WALLET_TEST_SIGNER: "",
  };
  for (const name of [OPERATOR_PASS_ENV, "IOI_WALLET_FIXTURE_APPROVER", "IOI_WALLET_AUTHORITY_BINARY", "IOI_HYPERVISOR_LOCAL_AUTHORITY_STATE_DIR", "IOI_GUARDIAN_KEY_PASS"]) delete env[name];
  const child = spawn(process.execPath, [path.join(APP, "scripts", "serve-product-ui.mjs")], { env, stdio: ["ignore", logFd, logFd] });
  fs.closeSync(logFd);
  const url = `http://127.0.0.1:${port}`;
  const until = Date.now() + 180_000;
  while (Date.now() < until) {
    if (child.exitCode !== null) throw new Error(`the serve exited (${child.exitCode}): ${fs.readFileSync(logPath, "utf8").slice(-2000)}`);
    try { const r = await fetch(`${url}/__ioi/login`); if (r.status < 500) break; } catch { /* not up */ }
    await new Promise((r) => setTimeout(r, 400));
  }
  const stop = async () => {
    if (child.exitCode !== null) return;
    const exited = new Promise((r) => child.once("exit", r));
    child.kill("SIGTERM");
    await Promise.race([exited, new Promise((r) => setTimeout(r, 5_000))]);
    if (child.exitCode === null) { try { child.kill("SIGKILL"); } catch { /* gone */ } }
  };
  return { url, pid: child.pid, env, stop };
}

test("the operator's standing envelope goes through the daemon: set with the passphrase, draw silently, park beyond, revoke", async (t) => {
  const stateDir = fs.mkdtempSync(path.join(os.tmpdir(), "ioi-standing-authority-"));
  const scratch = fs.mkdtempSync(path.join(os.tmpdir(), "ioi-standing-serve-"));
  tempDirs.push(stateDir, scratch);
  // ADR 0052 §7: a deployment that mints standing envelopes runs its authority on the wall clock.
  const authority = await startLocalAuthority({ stateDir, principalRef: "domain://standing-relay", wallClock: true, operatorPass: OPERATOR, log: quiet });
  t.after(async () => { try { await authority.stop(); } catch { /* stopped */ } });
  assert.equal(authority.keyCustody, "sealed");
  assert.equal(authority.approverKeyPath, null, "a sealed node publishes no signing path");

  const plane = await startIsolatedPlane({
    baseEnv: sanitizedVerifierBaseEnv(process.env),
    env: { ...authority.daemonEnv, IOI_HYPERVISOR_MODEL_UPSTREAM: "http://127.0.0.1:9/v1", IOI_WALLET_TEST_SIGNER: "" },
  });
  assert.ok(plane, "the isolated daemon started");
  t.after(async () => { try { await plane.stop(); } catch { /* stopped */ } });
  const serveLog = path.join(scratch, "serve.log");
  const serve = await startServe({ daemonUrl: plane.daemonUrl, serveEnv: authority.serveEnv, logPath: serveLog });
  t.after(async () => { try { await serve.stop(); } catch { /* stopped */ } });
  const cookie = `ioi_session=${await isolatedOperatorSession(plane)}`;
  const jd = (method, route, body, auth = cookie) => request(plane.daemonUrl, method, route, { body, cookie: auth });
  const js = (method, route, body, opts = {}) => request(serve.url, method, route, { body, cookie, ...opts });

  // A connection, and an environment with a workspace for the session.
  const registered = await jd("POST", "/v1/hypervisor/connectors", { service: "ping-service", name: "standing-relay", base_url: "http://127.0.0.1:9/api", kind: "bearer", requires_credential: false, allowed_tools: [{ name: "ping", method: "GET", path: "/ping" }] });
  const connectorId = registered.body?.connector?.connector_id;
  assert.match(String(connectorId), /^conn_[0-9a-f]{16}$/u, `connector registered: ${registered.status} ${registered.text.slice(0, 200)}`);
  const leaseRoute = `/__ioi/connections/${encodeURIComponent(connectorId)}/standing-lease`;
  const connectorLease = async () => ((await jd("GET", "/v1/hypervisor/connectors")).body?.connectors || []).find((c) => c.connector_id === connectorId)?.standing_lease || null;
  const envelopeRecords = async () => (await jd("GET", "/v1/hypervisor/authority/standing-envelopes")).body?.standing_envelopes || [];

  await t.test("the Connections card asks for the operator passphrase in a password field", async () => {
    const page = await request(serve.url, "GET", "/__ioi/connections", { cookie });
    assert.equal(page.status, 200);
    assert.match(page.text, new RegExp(`action="/__ioi/connections/${connectorId}/standing-lease"[^>]*>[^]*?<input name="operator_passphrase" type="password"`, "u"), "the Set limits form carries a password field");
    assert.ok(page.text.includes('data-ioi-standing-lease="absent"'));
  });

  await t.test("no passphrase, a wrong passphrase, nobody, or a coordinate-carrying body record nothing", async () => {
    const bare = await js("POST", leaseRoute, { max_usages: 1, budget_usd: 0.01, expires_hours: 2 });
    assert.equal(bare.status, 400, bare.text.slice(0, 300));
    assert.equal(bare.body?.code, "operator_passphrase_required");
    const wrong = await js("POST", leaseRoute, { max_usages: 1, budget_usd: 0.01, expires_hours: 2, operator_passphrase: WRONG });
    assert.equal(wrong.status, 403, wrong.text.slice(0, 300));
    assert.equal(wrong.body?.code, "operator_passphrase_refused");
    assert.ok(!wrong.text.includes(WRONG), "the refusal never echoes the passphrase");
    // The daemon route itself: nobody, and a body naming coordinates the daemon derives.
    const anonymous = await jd("POST", "/v1/hypervisor/authority/standing-envelopes", { connector_id: connectorId, max_usages: 1, operator_passphrase: OPERATOR }, "");
    assert.equal(anonymous.status, 401);
    for (const field of ["policy_hash", "envelope", "grant", "audience", "expires_at_ms"]) {
      const foreign = await jd("POST", "/v1/hypervisor/authority/standing-envelopes", { connector_id: connectorId, max_usages: 1, operator_passphrase: OPERATOR, [field]: field === "envelope" || field === "grant" ? {} : `sha256:${"ab".repeat(32)}` });
      assert.equal(foreign.status, 400, field);
      assert.equal(foreign.body?.error?.code, "standing_envelope_coordinates_are_daemon_owned", field);
    }
    assert.deepEqual(await envelopeRecords(), [], "the daemon stored no envelope");
    assert.equal(await connectorLease(), null, "the connection stays unbounded");
  });

  let envelopeId = null;
  await t.test("the right passphrase: the daemon runs the sealed authority's record-standing-approval and binds the grant", async () => {
    const started = Date.now();
    const set = await js("POST", leaseRoute, { max_usages: 1, budget_usd: 0.01, expires_hours: 2, operator_passphrase: OPERATOR });
    assert.equal(set.status, 200, set.text.slice(0, 600));
    assert.equal(set.body?.ok, true);
    assert.equal(set.body?.recorder, "daemon");
    assert.equal(set.body?.recorded_on_authority, "committed");
    envelopeId = set.body.standing_envelope_id;
    assert.match(String(envelopeId), /^sse_[0-9a-f]{32}$/u);
    assert.ok(!set.text.includes(OPERATOR), "the reply never echoes the passphrase");
    t.diagnostic(`standing decision took ${Math.round((Date.now() - started) / 1000)} s`);
    const lease = await connectorLease();
    assert.equal(lease?.status, "active");
    assert.equal(lease?.standing_envelope_id, envelopeId);
    assert.equal(lease?.bounds?.max_usages, 1);
    assert.equal(lease?.bounds?.max_cumulative_spend_microusd, 10_000);
    const record = (await jd("GET", `/v1/hypervisor/authority/standing-envelopes/${envelopeId}`)).body?.standing_envelope;
    assert.equal(record?.status, "active");
    assert.equal(record?.auth_factor_receipt?.factor_kind, "deployment_local_operator");
    assert.equal(record?.envelope?.principal_ref, "domain://standing-relay");
    assert.equal(record?.remaining?.usages, 1);
    assert.equal(record?.grant_hash_ref, lease.grant_hash_ref);
    const page = await request(serve.url, "GET", "/__ioi/connections", { cookie });
    assert.ok(page.text.includes('data-ioi-standing-lease="active"') && page.text.includes('data-ioi-standing-usages="1"'), "the card renders the bounds from the daemon record");
    assert.match(page.text, new RegExp(`standing-lease/revoke"[^>]*><input name="operator_passphrase" type="password"`, "u"), "Remove limits asks for the passphrase");
  });

  // A session bound to a started environment, naming the bounded connection.
  const created = await jd("POST", "/v1/hypervisor/environments", { spec: { environment_class_id: "local-workspace-v0", project_id: "standing-relay" } });
  const envId = created.body?.environment?.id;
  assert.ok(envId, `environment created: ${created.status} ${created.text.slice(0, 200)}`);
  await jd("POST", `/v1/hypervisor/environments/${encodeURIComponent(envId)}/start`);
  let workspaceRoot = null;
  for (let i = 0; i < 60 && !workspaceRoot; i += 1) {
    workspaceRoot = (await jd("GET", `/v1/hypervisor/environments/${encodeURIComponent(envId)}`)).body?.environment?.status?.workspace_root || null;
    if (!workspaceRoot) await new Promise((r) => setTimeout(r, 500));
  }
  assert.ok(workspaceRoot, "the environment has a workspace");
  const sessionRef = "session:standing-envelope-relay";
  const session = await jd("POST", "/v1/hypervisor/sessions", { session_ref: sessionRef, project_ref: "project:standing", environment_id: envId, authority_profile: { connection_refs: [`connector:${connectorId}`] } });
  assert.ok(session.status < 300, `session created: ${session.status} ${session.text.slice(0, 300)}`);
  const executePath = `/v1/hypervisor/sessions/${encodeURIComponent(sessionRef)}/execute`;
  const execute = (what) => jd("POST", executePath, { intent: what, lane: "native_local" });

  await t.test("a session execute within the envelope runs WITHOUT a per-run decision (a silent standing draw)", async () => {
    const ran = await execute("create a file named STANDING.md");
    assert.equal(ran.status, 200, ran.text.slice(0, 500));
    assert.match(String(ran.body?.capability_lease_ref || ""), /authority-admission-intents\//u);
    assert.ok(!ran.body?.approval_challenge, "no challenge was parked");
    const challenges = (await jd("GET", "/v1/hypervisor/authority/challenges")).body?.challenges || [];
    assert.equal(challenges.filter((c) => c.subject_ref === sessionRef).length, 0, "nothing awaits a per-run decision");
    const record = (await jd("GET", `/v1/hypervisor/authority/standing-envelopes/${envelopeId}`)).body?.standing_envelope;
    assert.equal(record?.drawn?.uses, 1, "the draw is counted on the envelope");
    assert.equal(record?.remaining?.usages, 0);
    assert.deepEqual(record?.drawn?.draw_refs, [ran.body.capability_lease_ref]);
  });

  await t.test("an execute beyond the envelope refuses typed and parks nothing (no per-run approval past the limits)", async () => {
    const beyond = await execute("create a file named BEYOND.md");
    assert.equal(beyond.status, 403, beyond.text.slice(0, 500));
    assert.equal(beyond.body?.reason, "standing_envelope_exceeded");
    assert.equal(beyond.body?.refused_bound, "max_usages");
    assert.equal(beyond.body?.posture, "refused_outside_envelope");
    assert.equal(beyond.body?.approval_challenge ?? null, null, "no challenge is parked past the limits");
    assert.equal(beyond.body?.approval ?? null, null, "no per-run approval is offered past the limits");
    const challenges = (await jd("GET", "/v1/hypervisor/authority/challenges")).body?.challenges || [];
    assert.equal(challenges.filter((c) => c.subject_ref === sessionRef && c.state === "pending").length, 0, "nothing awaits a per-run decision");
  });

  await t.test("revoking through the serve needs the passphrase, revokes on the authority node, and the next execute refuses", async () => {
    const wrong = await js("POST", `${leaseRoute}/revoke`, { operator_passphrase: WRONG });
    assert.equal(wrong.status, 403, wrong.text.slice(0, 300));
    assert.equal(wrong.body?.code, "operator_passphrase_refused");
    assert.equal((await connectorLease())?.status, "active", "a wrong passphrase revokes nothing");
    const revoked = await js("POST", `${leaseRoute}/revoke`, { operator_passphrase: OPERATOR, reason: "standing relay test" });
    assert.equal(revoked.status, 200, revoked.text.slice(0, 500));
    assert.equal(revoked.body?.revocation?.chain_revocation, "committed");
    assert.equal((await connectorLease())?.status, "revoked");
    const record = (await jd("GET", `/v1/hypervisor/authority/standing-envelopes/${envelopeId}`)).body?.standing_envelope;
    assert.equal(record?.status, "revoked");
    assert.equal(record?.revocation?.connection_fenced, true);
    const after = await execute("create a file named AFTER_REVOKE.md");
    assert.equal(after.status, 403, after.text.slice(0, 400));
    assert.equal(after.body?.reason, "standing_lease_revoked");
    assert.ok(!after.body?.approval_challenge, "a revoked envelope parks nothing");
    const page = await request(serve.url, "GET", "/__ioi/connections", { cookie });
    assert.ok(page.text.includes('data-ioi-standing-lease="revoked"'));
  });

  await t.test("the passphrase is in no file, log or environment", async () => {
    assert.deepEqual(filesContaining(plane.dataDir, OPERATOR), [], "the passphrase reached the daemon's data dir or log");
    assert.deepEqual(filesContaining(plane.dataDir, WRONG), [], "the wrong passphrase reached the daemon's data dir or log");
    assert.deepEqual(filesContaining(stateDir, OPERATOR), [], "the passphrase reached the authority's state dir");
    assert.deepEqual(filesContaining(scratch, OPERATOR), [], "the passphrase reached the serve's log");
    for (const pid of [plane.daemonPid, serve.pid]) {
      const environ = fs.readFileSync(`/proc/${pid}/environ`);
      assert.ok(!environ.includes(Buffer.from(OPERATOR)) && !environ.includes(Buffer.from(OPERATOR_PASS_ENV)), `process ${pid}'s environment carries the passphrase`);
    }
    assert.ok(!("IOI_WALLET_AUTHORITY_BINARY" in serve.env) && !("IOI_HYPERVISOR_LOCAL_AUTHORITY_STATE_DIR" in serve.env), "the serve names no authority binary or state dir");
    const leftovers = fs.readdirSync(os.tmpdir()).filter((name) => name.startsWith("ioi-standing-evidence-")).filter((name) => filesContaining(path.join(os.tmpdir(), name), OPERATOR).length > 0);
    assert.deepEqual(leftovers, [], "no evidence hand-over carries the passphrase");
  });
});
