// Master guide G5 / W0.2 part 2 — the in-app approval goes THROUGH THE DAEMON, and nothing outside the deployment
// authority holds a signing key. End to end against a REAL sealed deployment authority node and an isolated daemon,
// both in temp dirs on their own ports:
//
//   a session execute parks → the daemon keeps the challenge (and the approvals inbox shows it) → a decision that
//   names coordinates, carries no passphrase, a wrong passphrase, or comes from nobody signs nothing and records
//   nothing → the right passphrase makes the daemon run the authority's `approve` → the retry naming approval_ref
//   executes → the grant is consumed once and never admits again. A denial parks nothing to sign. The passphrase is
//   in no file of the daemon's data dir, not in its log and not in its environment.
//
//   IOI_HYPERVISOR_DAEMON_BINARY=<daemon> node --test apps/hypervisor/scripts/lib/authority-challenge-relay.test.mjs
//
// Needs the built `wallet-network-local-authority` (target/debug, or IOI_WALLET_AUTHORITY_BINARY) and the daemon
// (built on demand unless IOI_HYPERVISOR_DAEMON_BINARY names one). Several minutes: the authority node starts a chain,
// and every unseal runs Argon2id in a debug build.
import test, { after } from "node:test";
import assert from "node:assert/strict";
import { randomBytes } from "node:crypto";
import fs from "node:fs";
import http from "node:http";
import os from "node:os";
import path from "node:path";
import { OPERATOR_PASS_ENV, startLocalAuthority } from "./wallet-network-local-authority.mjs";
import { isolatedOperatorSession, sanitizedVerifierBaseEnv, startIsolatedPlane } from "./isolated-daemon.mjs";

// Unique per run, so a scan for it anywhere can only find THIS test's passphrase.
const OPERATOR = `relay-operator-${randomBytes(12).toString("hex")}`;
const WRONG = `wrong-operator-${randomBytes(12).toString("hex")}`;
const quiet = () => {};
const tempDirs = [];
after(() => { for (const dir of tempDirs) fs.rmSync(dir, { recursive: true, force: true }); });
delete process.env[OPERATOR_PASS_ENV];

/** JSON over node:http with no client-side timeout (an approve can outlast fetch's header timeout). */
function request(base, method, route, { body, cookie } = {}) {
  const url = new URL(route, base);
  const payload = body === undefined ? null : Buffer.from(typeof body === "string" ? body : JSON.stringify(body));
  return new Promise((resolve, reject) => {
    const req = http.request(url, { method, headers: { ...(payload ? { "content-type": "application/json", "content-length": payload.length } : {}), ...(cookie ? { cookie } : {}) } }, (res) => {
      const chunks = [];
      res.on("data", (c) => chunks.push(c));
      res.on("end", () => {
        const text = Buffer.concat(chunks).toString("utf8");
        let json = null;
        try { json = text ? JSON.parse(text) : null; } catch { json = null; }
        resolve({ status: res.statusCode, body: json, text });
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

test("the operator's approval goes through the daemon: park, decide with the passphrase, retry once", async (t) => {
  const stateDir = fs.mkdtempSync(path.join(os.tmpdir(), "ioi-g5-authority-"));
  tempDirs.push(stateDir);
  const authority = await startLocalAuthority({ stateDir, principalRef: "domain://g5-approval-relay", operatorPass: OPERATOR, log: quiet });
  t.after(async () => { try { await authority.stop(); } catch { /* stopped */ } });
  assert.equal(authority.keyCustody, "sealed");
  assert.equal(authority.approverKeyPath, null, "a sealed node publishes no signing path");
  assert.equal(authority.daemonEnv.IOI_HYPERVISOR_LOCAL_AUTHORITY_STATE_DIR, stateDir);
  assert.ok(!("IOI_HYPERVISOR_LOCAL_AUTHORITY_STATE_DIR" in authority.serveEnv) && !("IOI_WALLET_AUTHORITY_BINARY" in authority.serveEnv), "serve.env names no authority binary or state dir");

  const plane = await startIsolatedPlane({
    baseEnv: sanitizedVerifierBaseEnv(process.env),
    env: { ...authority.daemonEnv, IOI_HYPERVISOR_MODEL_UPSTREAM: "http://127.0.0.1:9/v1", IOI_WALLET_TEST_SIGNER: "" },
  });
  assert.ok(plane, "the isolated daemon started");
  t.after(async () => { try { await plane.stop(); } catch { /* stopped */ } });
  const DAEMON = plane.daemonUrl;
  const cookie = `ioi_session=${await isolatedOperatorSession(plane)}`;
  const jd = (method, route, body, auth = cookie) => request(DAEMON, method, route, { body, cookie: auth });

  // A session bound to a started environment's workspace.
  const created = await jd("POST", "/v1/hypervisor/environments", { spec: { environment_class_id: "local-workspace-v0", project_id: "g5-relay" } });
  const envId = created.body?.environment?.id;
  assert.ok(envId, `environment created: ${created.status} ${created.text.slice(0, 200)}`);
  await jd("POST", `/v1/hypervisor/environments/${encodeURIComponent(envId)}/start`);
  let workspaceRoot = null;
  for (let i = 0; i < 60 && !workspaceRoot; i += 1) {
    workspaceRoot = (await jd("GET", `/v1/hypervisor/environments/${encodeURIComponent(envId)}`)).body?.environment?.status?.workspace_root || null;
    if (!workspaceRoot) await new Promise((r) => setTimeout(r, 500));
  }
  assert.ok(workspaceRoot, "the environment has a workspace");
  const sessionRef = "session:g5-approval-relay";
  const session = await jd("POST", "/v1/hypervisor/sessions", { session_ref: sessionRef, project_ref: "project:g5", environment_id: envId });
  assert.ok(session.status < 300, `session created: ${session.status} ${session.text.slice(0, 200)}`);
  const executePath = `/v1/hypervisor/sessions/${encodeURIComponent(sessionRef)}/execute`;
  const intent = "create a file named RELAYED.md";
  const execute = (extra = {}, what = intent) => jd("POST", executePath, { intent: what, lane: "native_local", ...extra });

  // ---- park ----
  const parked = await execute();
  const challenge = parked.body?.approval_challenge;
  const challengeId = challenge?.challenge_id;
  const challengeRoute = `/v1/hypervisor/authority/challenges/${challengeId}`;
  const decisionRoute = `${challengeRoute}/decision`;
  const readChallenge = async () => (await jd("GET", challengeRoute)).body?.challenge;

  await t.test("a session execute without a grant parks ONE challenge on the daemon, decidable here", async () => {
    assert.equal(parked.status, 403, parked.text.slice(0, 300));
    assert.equal(parked.body?.reason, "execution_authority_required");
    assert.match(String(challengeId), /^wac_[0-9a-f]{32}$/u);
    assert.equal(challenge.challenge_state, "pending");
    assert.equal(challenge.decidable, true);
    assert.equal(challenge.decision_route, decisionRoute);
    const again = await execute();
    assert.equal(again.body?.approval_challenge?.challenge_id, challengeId, "a re-park of the same exact effect is the same challenge");
    const record = await readChallenge();
    assert.equal(record.state, "pending");
    assert.equal(record.policy_hash, parked.body.approval.policy_hash);
    assert.equal(record.request_hash, parked.body.approval.request_hash);
    assert.equal(record.audience, parked.body.approval.audience);
    assert.equal(record.target_scope, "scope:hypervisor.live-route.session-execute");
    assert.equal(record.published_preimage?.request_preimage?.intent, intent);
    assert.match(String(record.requester_ref), /^user:\/\//u);
    assert.ok(!("grant" in record), "the public view never carries a grant");
  });

  await t.test("the approvals inbox lists the pending challenge with its decision route", async () => {
    const inbox = await jd("GET", "/v1/hypervisor/governance/approvals-inbox");
    const row = (inbox.body?.items || []).find((item) => item.source_plane === "wallet_approval_challenge" && item.challenge_id === challengeId);
    assert.ok(row, "inbox row present");
    assert.equal(row.decide.route, decisionRoute);
    assert.deepEqual(row.decide.transitions, ["approve", "deny"]);
    assert.equal(row.request_hash, parked.body.approval.request_hash);
    const plane7 = (inbox.body?.planes || []).find((p) => p.plane === "wallet_approval_challenge");
    assert.ok(plane7 && plane7.pending >= 1 && plane7.decidable === true, JSON.stringify(plane7));
  });

  await t.test("nobody, a coordinate-carrying body and a missing passphrase sign nothing", async () => {
    const anonymous = await jd("POST", decisionRoute, { decision: "approve", operator_passphrase: OPERATOR }, "");
    assert.equal(anonymous.status, 401);
    const foreign = await jd("POST", decisionRoute, { decision: "approve", operator_passphrase: OPERATOR, request_hash: `sha256:${"ab".repeat(32)}`, policy_hash: `sha256:${"cd".repeat(32)}` });
    assert.equal(foreign.status, 400);
    assert.equal(foreign.body?.error?.code, "challenge_coordinates_are_daemon_owned");
    const scoped = await jd("POST", decisionRoute, { decision: "approve", operator_passphrase: OPERATOR, target_scope: "scope:hypervisor.live-route.provider-op" });
    assert.equal(scoped.body?.error?.code, "challenge_coordinates_are_daemon_owned");
    const bare = await jd("POST", decisionRoute, { decision: "approve" });
    assert.equal(bare.status, 400);
    assert.equal(bare.body?.error?.code, "operator_passphrase_required");
    const record = await readChallenge();
    assert.equal(record.state, "pending");
    assert.equal(record.decision, null);
    assert.equal(record.grant_ref, null);
  });

  await t.test("a wrong passphrase is refused and records nothing", async () => {
    const wrong = await jd("POST", decisionRoute, { decision: "approve", operator_passphrase: WRONG });
    assert.equal(wrong.status, 403, wrong.text.slice(0, 300));
    assert.equal(wrong.body?.error?.code, "operator_passphrase_refused");
    assert.ok(!wrong.text.includes(WRONG), "the refusal never echoes the passphrase");
    const record = await readChallenge();
    assert.equal(record.state, "pending");
    assert.equal(record.decision, null);
    assert.equal(record.grant_ref, null);
    const stillParked = await execute({ approval_ref: `wallet-approval-challenge://${challengeId}` });
    assert.equal(stillParked.status, 403);
    assert.equal(stillParked.body?.reason, "approval_ref_not_approved");
  });

  let approvalRef = null;
  await t.test("the right passphrase: the daemon runs the authority's approve for ITS record and answers approval_ref", async () => {
    const approved = await jd("POST", decisionRoute, { decision: "approve", reason: "g5 relay test", operator_passphrase: OPERATOR });
    assert.equal(approved.status, 200, approved.text.slice(0, 400));
    assert.equal(approved.body?.ok, true);
    approvalRef = approved.body.approval_ref;
    assert.equal(approvalRef, `wallet-approval-challenge://${challengeId}`);
    assert.match(String(approved.body.grant_ref), /^wallet\.network:\/\/grant\/approval\/[0-9a-f]{64}$/u);
    assert.ok(!approved.text.includes(OPERATOR), "the reply never echoes the passphrase");
    assert.ok(!("approval_grant" in approved.body) && !approved.text.includes("approver_sig"), "the reply carries no grant bytes");
    const record = await readChallenge();
    assert.equal(record.state, "approved");
    assert.equal(record.decision?.decision, "approve");
    // `committed`, not `existing`: the refused attempts before this one recorded nothing on the authority node.
    assert.equal(record.decision?.recorded_on_authority, "committed");
    const twice = await jd("POST", decisionRoute, { decision: "approve", operator_passphrase: OPERATOR });
    assert.equal(twice.status, 409);
    assert.equal(twice.body?.error?.code, "challenge_already_approved");
    assert.equal(twice.body?.approval_ref, approvalRef);
  });

  await t.test("the approval_ref admits only the exact effect it was parked for", async () => {
    const other = await execute({ approval_ref: approvalRef }, "a different intent entirely");
    assert.equal(other.status, 403);
    assert.equal(other.body?.reason, "approval_ref_coordinates_mismatch");
    assert.equal((await readChallenge()).state, "approved", "a refused presentation leaves the approval usable");
  });

  await t.test("the retry naming approval_ref executes, and the grant is consumed once", async () => {
    const ran = await execute({ approval_ref: approvalRef });
    assert.equal(ran.status, 200, ran.text.slice(0, 400));
    assert.match(String(ran.body?.capability_lease_ref || ""), /authority-admission-intents\//u);
    const record = await readChallenge();
    assert.equal(record.state, "consumed");
    assert.equal(record.consumed_by, ran.body.capability_lease_ref);
    const replay = await execute({ approval_ref: approvalRef });
    assert.equal(replay.status, 403);
    assert.equal(replay.body?.reason, "approval_ref_consumed");
    const reDecide = await jd("POST", decisionRoute, { decision: "approve", operator_passphrase: OPERATOR });
    assert.equal(reDecide.status, 409);
    assert.equal(reDecide.body?.error?.code, "challenge_consumed");
    const inbox = await jd("GET", "/v1/hypervisor/governance/approvals-inbox");
    assert.ok(!(inbox.body?.items || []).some((item) => item.challenge_id === challengeId), "a consumed challenge leaves the inbox");
  });

  await t.test("a denial records the refusal and nothing can run under it", async () => {
    const denyIntent = "create a file named DENIED.md";
    const parkedB = await execute({}, denyIntent);
    const idB = parkedB.body?.approval_challenge?.challenge_id;
    assert.ok(idB && idB !== challengeId);
    const denied = await jd("POST", `/v1/hypervisor/authority/challenges/${idB}/decision`, { decision: "deny", reason: "not this one" });
    assert.equal(denied.status, 200, denied.text.slice(0, 300));
    assert.equal(denied.body?.state, "denied");
    const refused = await execute({ approval_ref: `wallet-approval-challenge://${idB}` }, denyIntent);
    assert.equal(refused.status, 403);
    assert.equal(refused.body?.reason, "approval_ref_denied");
    const record = (await jd("GET", `/v1/hypervisor/authority/challenges/${idB}`)).body?.challenge;
    assert.equal(record.state, "denied");
    assert.equal(record.grant_ref, null);
  });

  await t.test("the passphrase is in no daemon file, log or environment", async () => {
    assert.deepEqual(filesContaining(plane.dataDir, OPERATOR), [], "the passphrase reached the daemon's data dir or log");
    assert.deepEqual(filesContaining(plane.dataDir, WRONG), [], "the wrong passphrase reached the daemon's data dir or log");
    assert.deepEqual(filesContaining(stateDir, OPERATOR), [], "the passphrase reached the authority's state dir");
    const environ = fs.readFileSync(`/proc/${plane.daemonPid}/environ`);
    assert.ok(!environ.includes(Buffer.from(OPERATOR)) && !environ.includes(Buffer.from(OPERATOR_PASS_ENV)), "the daemon's environment carries the passphrase");
  });
});
