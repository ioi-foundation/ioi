// The deployment authority's approval and root keys are SEALED under the operator passphrase (owner decision
// 2026-09-28). End to end against a REAL single-validator node in temp dirs only: first bring-up, resume with no
// passphrase, `approve` (right / wrong / guardian / empty passphrase; the approver's named scope allowlist), rotate +
// revoke, the `seal-keys` migration, and scans of argv, stdout, every state file and every /proc/<pid>/environ for the
// passphrase and the seeds.
//
//   node --test apps/hypervisor/scripts/lib/wallet-network-local-authority.test.mjs
//
// Needs the built `wallet-network-local-authority` binary (target/debug, or IOI_WALLET_AUTHORITY_BINARY). Set
// IOI_NODE_BINARY_DIR to prebuilt node binaries to skip the node-profile build. Several minutes: each bring-up
// starts a chain, and every seal/unseal runs Argon2id (64 MiB) in a debug build.
import test, { after } from "node:test";
import assert from "node:assert/strict";
import { spawn, spawnSync } from "node:child_process";
import { randomBytes } from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import {
  approveGrant, authorityAct, isFreshStateDir, OPERATOR_PASS_ENV, readEnvFile, resolveBinary, startLocalAuthority,
} from "./wallet-network-local-authority.mjs";

const HERE = path.dirname(fileURLToPath(import.meta.url));
const CLI = path.resolve(HERE, "..", "wallet-network-authority.mjs");
// Unique per run, so a scan for it anywhere on the host can only find THIS test's passphrase.
const OPERATOR = `sealed-operator-${randomBytes(12).toString("hex")}`;
const SCOPE = "scope:hypervisor.live-route.session-execute";
// The deployment approver's allowlist (owner approval 2026-09-29): the live-route family plus the System lifecycle scopes
// the daemon asks of a System's governing authority, each named exactly — never a scope:autonomous_system.* wildcard.
const SYSTEM_SCOPES = [
  "genesis_admit", "genesis_materialize", "lifecycle.initialize", "lifecycle.activate", "lifecycle.amend_constitution",
  "governance.approve_constitution_amendment",
  ...["pause", "resume", "suspend", "reinstate", "enter_dormancy", "wake", "begin_recovery", "complete_recovery", "quarantine",
    "release_quarantine", "retire", "archive", "revoke", "decommission"].map((op) => `lifecycle.${op}`),
  ...["initiate_succession", "complete_succession", "migrate", "migration_destination_acknowledge", "initiate_dissolution",
    "open_dissolution_disposition", "record_dissolution_domain_outcome", "complete_dissolution"].map((op) => `continuity.${op}`),
  "network_enrollment.local.enroll", "network_enrollment.local.exit", "network_enrollment_change",
].map((tail) => `scope:autonomous_system.${tail}`);
const APPROVER_SCOPES = ["scope:hypervisor.live-route.*", ...SYSTEM_SCOPES];
const OUTSIDE = /outside the deployment approver's allowlist/u;
const quiet = () => {};
const hex32 = () => randomBytes(32).toString("hex");
const bytesHex = (value) => Buffer.from(value).toString("hex");
const mode = (file) => fs.statSync(file).mode & 0o777;
const tempDirs = [];
const tempStateDir = (label) => { const dir = fs.mkdtempSync(path.join(os.tmpdir(), `ioi-sealed-authority-${label}-`)); tempDirs.push(dir); return dir; };
// Every node is stopped by its own test before this runs; the temp state dirs (test keys only) go with them.
after(() => { for (const dir of tempDirs) fs.rmSync(dir, { recursive: true, force: true }); });

delete process.env[OPERATOR_PASS_ENV];

function allFiles(dir) {
  const out = [];
  for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
    const full = path.join(dir, entry.name);
    if (entry.isDirectory()) out.push(...allFiles(full));
    else if (entry.isFile()) out.push(full);
  }
  return out;
}

/** Every file under the state dir that carries `needle` (bytes). */
function filesContaining(dir, needle) {
  const bytes = Buffer.from(needle);
  return allFiles(dir).filter((file) => { try { return fs.readFileSync(file).includes(bytes); } catch { return false; } });
}

/** Every process on this host whose environment block carries `needle`. */
function processesWithEnvContaining(needle) {
  const hits = [];
  for (const pid of fs.readdirSync("/proc").filter((name) => /^\d+$/u.test(name))) {
    try { if (fs.readFileSync(`/proc/${pid}/environ`).includes(Buffer.from(needle))) hits.push(Number(pid)); } catch { /* gone or not ours */ }
  }
  return hits;
}

const procText = (pid, what) => { try { return fs.readFileSync(`/proc/${pid}/${what}`).toString("latin1"); } catch { return null; } };
const guardianPassOf = (stateDir) => fs.readFileSync(path.join(stateDir, "keys", "guardian.pass"), "utf8").trim();
const publicKeyOf = (stateDir, name) => fs.readFileSync(path.join(stateDir, "keys", name), "utf8").trim();

/**
 * Run `approve` as a child the test can WATCH: /proc/<pid>/cmdline and /proc/<pid>/environ are sampled for its
 * whole life. Returns its exit, stdout, stderr and the samples.
 */
function watchedApprove(stateDir, { operatorPass, policyHash, requestHash, audience }) {
  const bin = resolveBinary(undefined, { build: false });
  const env = { ...process.env, IOI_GUARDIAN_KEY_PASS: guardianPassOf(stateDir), CARGO_TERM_COLOR: "never" };
  delete env[OPERATOR_PASS_ENV];
  if (operatorPass !== undefined) env[OPERATOR_PASS_ENV] = operatorPass;
  const child = spawn(bin, ["approve", "--state-dir", stateDir, "--policy-hash", policyHash, "--request-hash", requestHash, "--audience", audience, "--target-scope", SCOPE], { env, stdio: ["ignore", "pipe", "pipe"] });
  const started = Date.now();
  const samples = [];
  let stdout = "";
  let stderr = "";
  child.stdout.on("data", (chunk) => { stdout += chunk; });
  child.stderr.on("data", (chunk) => { stderr += chunk; });
  const timer = setInterval(() => {
    const cmdline = procText(child.pid, "cmdline");
    const environ = procText(child.pid, "environ");
    if (cmdline !== null) samples.push({ at: Date.now() - started, cmdline, environ: environ ?? "" });
  }, 15);
  return new Promise((resolve) => child.once("exit", (code) => { clearInterval(timer); resolve({ code, stdout, stderr, samples }); }));
}

test("the operator CLI refuses a passphrase or key on argv before doing anything", () => {
  for (const flag of ["--operator-pass", "--passphrase", "--seed"]) {
    const result = spawnSync(process.execPath, [CLI, "approve", "--state-dir", os.tmpdir(), flag, "x"], { encoding: "utf8" });
    assert.equal(result.status, 2, `${flag}: ${result.stderr}`);
    assert.match(result.stderr, /refused/u);
  }
});

test("a fresh SEALED bring-up without the passphrase is refused before the node starts", async () => {
  const stateDir = tempStateDir("nopass");
  await assert.rejects(startLocalAuthority({ stateDir, principalRef: "domain://sealed-nopass", log: quiet }), /fresh state dir/u);
  assert.ok(isFreshStateDir(stateDir));
  assert.deepEqual(fs.readdirSync(path.join(stateDir, "keys")), [], "nothing was generated");
});

test("sealed custody end to end: bring-up, resume without the passphrase, approve, rotate, revoke", async (t) => {
  const stateDir = tempStateDir("sealed");
  const principalRef = "domain://sealed-authority-test";
  const keysDir = path.join(stateDir, "keys");
  let node = await startLocalAuthority({ stateDir, principalRef, operatorPass: OPERATOR, log: quiet });
  t.after(async () => { try { await node?.stop(); } catch { /* stopped */ } });

  await t.test("(a) keys/ holds no plaintext root or approver seed; the sealed files are 0600", () => {
    const names = fs.readdirSync(keysDir).sort();
    assert.ok(!names.includes("approver.seed") && !names.includes("root.seed"), names.join(","));
    for (const sealed of ["root.seed.sealed", "approver.seed.sealed"]) {
      assert.ok(names.includes(sealed), `${sealed} missing`);
      assert.equal(mode(path.join(keysDir, sealed)), 0o600, sealed);
    }
    for (const pub of ["root.pub", "approver.pub"]) assert.match(publicKeyOf(stateDir, pub), /^[0-9a-f]{64}$/u, pub);
    assert.equal(publicKeyOf(stateDir, "approver.pub"), node.readAuthorityRecord().approver_public_key);
    assert.equal(node.keyCustody, "sealed");
    assert.deepEqual(node.readAuthorityRecord().approver_scope_allowlist, APPROVER_SCOPES, "the approver is registered with exactly the named list");
    assert.equal(node.approverKeyPath, null, "no signing path is published for a sealed node");
    assert.ok(!("approver_key_path" in node.ready), "ready.json names no approver seed path");
  });

  await t.test("serve.env gives the served App no signing key and no path to one; no file holds the passphrase", () => {
    const serveEnv = readEnvFile(path.join(stateDir, "serve.env"));
    assert.deepEqual(Object.keys(serveEnv).sort(), ["IOI_HYPERVISOR_AUTHORITY_HOST_REF", "IOI_HYPERVISOR_AUTHORITY_PRINCIPAL_REF"]);
    const daemonEnv = readEnvFile(path.join(stateDir, "daemon.env"));
    assert.ok(!(OPERATOR_PASS_ENV in daemonEnv) && !Object.values(daemonEnv).includes(OPERATOR));
    assert.notEqual(daemonEnv.IOI_GUARDIAN_KEY_PASS, OPERATOR);
    // G5: the daemon's approval decision route runs THIS node's `approve`; serve.env names neither.
    assert.equal(daemonEnv.IOI_HYPERVISOR_LOCAL_AUTHORITY_STATE_DIR, stateDir);
    assert.ok(fs.existsSync(daemonEnv.IOI_WALLET_AUTHORITY_BINARY), "daemon.env names the authority binary");
    assert.deepEqual(filesContaining(stateDir, OPERATOR), [], "the passphrase was written to disk");
  });

  await t.test("the node took the passphrase OUT of its environment: no process on the host carries it", () => {
    const environ = procText(node.pid, "environ");
    assert.ok(environ !== null, "the node's environ is readable to its owner");
    assert.ok(!environ.includes(OPERATOR), "the serving node's /proc/<pid>/environ still holds the passphrase");
    assert.ok(!procText(node.pid, "cmdline").includes(OPERATOR));
    assert.deepEqual(processesWithEnvContaining(OPERATOR), [], "some process (a validator child?) inherited the passphrase");
  });

  await node.stop();
  node = await startLocalAuthority({ stateDir, principalRef, log: quiet });

  await t.test("(b) serve resumes with no operator passphrase in its environment", () => {
    const environ = procText(node.pid, "environ");
    assert.ok(!environ.split("\0").some((entry) => entry.startsWith(`${OPERATOR_PASS_ENV}=`)), "the resumed node was handed the passphrase variable");
    const record = node.readAuthorityRecord();
    assert.equal(record.binding_status, "active");
    assert.equal(record.binding_version, 1);
  });

  const audience = node.ready.capability_account_id;
  const approve = (operatorPass, requestHash, policyHash = hex32()) =>
    approveGrant({ stateDir, operatorPass, policyHash, requestHash, audience, targetScope: SCOPE });

  const requestHash = hex32();
  const policyHash = hex32();
  await t.test("(c) a wrong, guardian or empty passphrase is refused and records nothing", () => {
    const wrong = approve("definitely-the-wrong-passphrase", requestHash, policyHash);
    assert.equal(wrong.ok, false);
    assert.match(wrong.stderr, /does not open/u);
    const guardian = approve(guardianPassOf(stateDir), requestHash, policyHash);
    assert.equal(guardian.ok, false);
    assert.match(guardian.stderr, /must differ/u);
    const bin = resolveBinary(undefined, { build: false });
    const empty = spawnSync(bin, ["approve", "--state-dir", stateDir, "--policy-hash", policyHash, "--request-hash", requestHash, "--audience", audience, "--target-scope", SCOPE],
      { encoding: "utf8", stdio: ["ignore", "pipe", "pipe"], env: { ...process.env, IOI_GUARDIAN_KEY_PASS: guardianPassOf(stateDir), [OPERATOR_PASS_ENV]: "" } });
    assert.notEqual(empty.status, 0);
    assert.match(empty.stderr, /cannot be empty/u);
  });

  await t.test("(c) the right passphrase records ONE one-use grant signed by approver.pub, for exactly these hashes", () => {
    const before = Date.now();
    const result = approve(OPERATOR, requestHash, policyHash);
    assert.equal(result.ok, true, result.stderr);
    // "committed", not "existing": none of the refused attempts above recorded anything for this request.
    assert.equal(result.outcome.recorded, "committed");
    const grant = result.grant;
    assert.equal(bytesHex(grant.approver_public_key), publicKeyOf(stateDir, "approver.pub"));
    assert.equal(bytesHex(grant.authority_id), node.readAuthorityRecord().approver_authority_id);
    assert.equal(bytesHex(grant.audience), audience);
    assert.equal(bytesHex(grant.request_hash), requestHash);
    assert.equal(bytesHex(grant.policy_hash), policyHash);
    assert.equal(grant.max_usages, 1);
    assert.equal(grant.approver_sig.length, 64);
    assert.notEqual(bytesHex(grant.nonce), "04".repeat(32), "not the fixture minter's constant nonce");
    assert.ok(grant.expires_at > before && grant.expires_at <= Date.now() + 900_000, `expires_at ${grant.expires_at}`);
    assert.match(result.outcome.grant_ref, /^wallet\.network:\/\/grant\/approval\/[0-9a-f]{64}$/u);
    assert.ok(!result.stdout.includes(OPERATOR) && !result.stderr.includes(OPERATOR));
    const again = approve(OPERATOR, hex32());
    assert.equal(again.ok, true, again.stderr);
    assert.notEqual(bytesHex(again.grant.nonce), bytesHex(grant.nonce), "every grant carries a fresh nonce");
  });

  await t.test("(c) a System lifecycle scope is signable; an unlisted sibling or a near miss is refused before any key is opened", () => {
    const system = approveGrant({ stateDir, operatorPass: OPERATOR, policyHash: hex32(), requestHash: hex32(), audience, targetScope: "scope:autonomous_system.genesis_admit" });
    assert.equal(system.ok, true, system.stderr);
    assert.equal(system.outcome.recorded, "committed", "the chain recorded an approval under a named System scope");
    for (const targetScope of ["scope:autonomous_system.genesis_admitX", "scope:autonomous_system.ordering.recover", "scope:autonomous_system.*", "scope:hypervisor.live-route."]) {
      // A WRONG passphrase still meets the allowlist refusal, never "does not open": the scope is refused before the unseal.
      const early = approveGrant({ stateDir, operatorPass: "definitely-the-wrong-passphrase", policyHash: hex32(), requestHash: hex32(), audience, targetScope });
      assert.equal(early.ok, false, targetScope);
      assert.match(early.stderr, OUTSIDE, `${targetScope}: ${early.stderr}`);
      assert.doesNotMatch(early.stderr, /does not open/u, targetScope);
      const right = approveGrant({ stateDir, operatorPass: OPERATOR, policyHash: hex32(), requestHash: hex32(), audience, targetScope });
      assert.equal(right.ok, false, targetScope);
      assert.match(right.stderr, OUTSIDE, `${targetScope}: ${right.stderr}`);
    }
  });

  await t.test("status reports sealed custody from public keys only", () => {
    const status = authorityAct("status", { stateDir });
    assert.equal(status.ok, true, status.stderr);
    const body = JSON.parse(status.stdout);
    assert.equal(body.key_custody, "sealed");
    assert.equal(body.approver_public_key, publicKeyOf(stateDir, "approver.pub"));
  });

  await t.test("rotate unseals the root with the passphrase; the retired key stays verifiable, still sealed", () => {
    const refused = authorityAct("rotate", { stateDir, operatorPass: "definitely-the-wrong-passphrase" });
    assert.equal(refused.ok, false);
    assert.equal(node.readAuthorityRecord().binding_version, 1, "a refused rotate changed the chain");
    const oldPublic = publicKeyOf(stateDir, "approver.pub");
    const rotated = authorityAct("rotate", { stateDir, operatorPass: OPERATOR });
    assert.equal(rotated.ok, true, rotated.stderr);
    const record = node.readAuthorityRecord();
    assert.equal(record.binding_version, 2);
    assert.equal(record.binding_status, "active");
    const newPublic = publicKeyOf(stateDir, "approver.pub");
    assert.notEqual(newPublic, oldPublic);
    assert.equal(record.approver_public_key, newPublic);
    assert.deepEqual(record.approver_scope_allowlist, APPROVER_SCOPES, "rotate registers the new key with exactly the named list");
    assert.equal(publicKeyOf(stateDir, "approver.pub.v1"), oldPublic, "the retired public key is kept");
    assert.equal(mode(path.join(keysDir, "approver.seed.sealed.v1")), 0o400);
    assert.ok(!fs.readdirSync(keysDir).some((name) => /^(approver|root)\.seed(\.v\d+|\.next)?$/u.test(name)), fs.readdirSync(keysDir).join(","));
    const approved = approve(OPERATOR, hex32());
    assert.equal(approved.ok, true, approved.stderr);
    assert.equal(bytesHex(approved.grant.approver_public_key), newPublic, "grants are signed by the rotated key");
  });

  await t.test("revoke unseals the root with the passphrase; afterwards nothing can be approved", () => {
    const revoked = authorityAct("revoke", { stateDir, operatorPass: OPERATOR, reason: "sealed-custody test" });
    assert.equal(revoked.ok, true, revoked.stderr);
    assert.equal(node.readAuthorityRecord().binding_status, "revoked");
    const after = approve(OPERATOR, hex32());
    assert.equal(after.ok, false);
    assert.match(after.stderr, /revoked/u);
  });

  await t.test("after every act, still no plaintext seed and no passphrase anywhere", () => {
    assert.deepEqual(filesContaining(stateDir, OPERATOR), []);
    assert.deepEqual(processesWithEnvContaining(OPERATOR), []);
  });
});

test("migration: a plaintext state dir is refused in deployment mode until seal-keys converts it; (d) argv and stdout never carry a seed", async (t) => {
  const stateDir = tempStateDir("migrate");
  const principalRef = "domain://sealed-migration-test";
  const keysDir = path.join(stateDir, "keys");
  let node = await startLocalAuthority({ stateDir, principalRef, plaintextKeys: true, log: quiet });
  t.after(async () => { try { await node?.stop(); } catch { /* stopped */ } });
  assert.equal(node.keyCustody, "plaintext");
  assert.equal(node.approverKeyPath, path.join(keysDir, "approver.seed"));
  await node.stop();
  node = null;
  // The test knows the seeds ONLY because this dir began as a dev/test plaintext dir.
  const rootSeed = fs.readFileSync(path.join(keysDir, "root.seed"), "utf8").trim();
  const approverSeed = fs.readFileSync(path.join(keysDir, "approver.seed"), "utf8").trim();
  const approverPublic = publicKeyOf(stateDir, "approver.pub");

  await t.test("deployment mode refuses to serve the plaintext dir, naming seal-keys", async () => {
    await assert.rejects(startLocalAuthority({ stateDir, principalRef, log: quiet }), /seal-keys/u);
  });

  await t.test("seal-keys seals both seeds with the passphrase and removes the plaintext files", () => {
    const refused = authorityAct("seal-keys", { stateDir, operatorPass: guardianPassOf(stateDir) });
    assert.equal(refused.ok, false, "the guardian pass must not seal the keys");
    assert.ok(fs.existsSync(path.join(keysDir, "root.seed")), "a refused conversion removed plaintext");
    const sealed = authorityAct("seal-keys", { stateDir, operatorPass: OPERATOR });
    assert.equal(sealed.ok, true, sealed.stderr);
    assert.ok(!fs.existsSync(path.join(keysDir, "root.seed")) && !fs.existsSync(path.join(keysDir, "approver.seed")));
    assert.equal(mode(path.join(keysDir, "root.seed.sealed")), 0o600);
    assert.equal(mode(path.join(keysDir, "approver.seed.sealed")), 0o600);
    assert.equal(publicKeyOf(stateDir, "approver.pub"), approverPublic);
    for (const seed of [rootSeed, approverSeed]) assert.deepEqual(filesContaining(stateDir, seed), [], "a seed survived on disk in hex");
    assert.ok(!sealed.stdout.includes(rootSeed) && !sealed.stdout.includes(approverSeed));
  });

  node = await startLocalAuthority({ stateDir, principalRef, log: quiet });
  const audience = node.ready.capability_account_id;

  await t.test("the converted dir resumes SEALED with no passphrase", () => {
    assert.equal(node.keyCustody, "sealed");
    assert.equal(node.approverKeyPath, null);
    for (const seed of [rootSeed, approverSeed]) assert.ok(!procText(node.pid, "cmdline").includes(seed));
  });

  await t.test("(d) approve: no seed and no passphrase on its argv or stdout; its environ is scrubbed once it runs", async () => {
    const watched = await watchedApprove(stateDir, { operatorPass: OPERATOR, policyHash: hex32(), requestHash: hex32(), audience });
    assert.equal(watched.code, 0, watched.stderr);
    assert.ok(watched.samples.length > 10, `only ${watched.samples.length} /proc samples of the approve child`);
    for (const sample of watched.samples) {
      for (const secret of [rootSeed, approverSeed, OPERATOR]) assert.ok(!sample.cmdline.includes(secret), "a secret rode approve's argv");
    }
    // The process image starts with the variable the operator set; within the first moments main() overwrites it.
    const late = watched.samples.filter((sample) => sample.at >= 1_000);
    assert.ok(late.length > 0, "approve exited before a late sample");
    for (const sample of late) assert.ok(!sample.environ.includes(OPERATOR), `approve's environ still held the passphrase at ${sample.at} ms`);
    for (const secret of [rootSeed, approverSeed, OPERATOR]) {
      assert.ok(!watched.stdout.includes(secret) && !watched.stderr.includes(secret), "a secret reached approve's output");
    }
    const outcome = JSON.parse(watched.stdout.trim().split("\n").reverse().find((line) => line.startsWith("{")));
    assert.equal(outcome.recorded, "committed");
    assert.equal(bytesHex(outcome.approval_grant.approver_public_key), approverPublic, "the migrated approver key signed");
  });
});
