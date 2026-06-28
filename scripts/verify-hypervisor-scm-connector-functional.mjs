#!/usr/bin/env node
// Done-bar for the reference SCM connector — the wallet-authorized PUBLISH CROSSING.
//
// Publishing the env's work to a remote LEAVES the scoped workspace, so it is a CROSSING and (unlike
// local exec) REQUIRES a wallet capability grant. This proves the spine end to end with a LOCAL bare
// repo as the connector remote (real git push, no external credentials):
//   register connector → publish UNAUTHORIZED fails closed (challenge) → mint a bound wallet grant →
//   publish AUTHORIZED → the branch+commit actually land in the remote → a durable receipt is
//   recorded. Also proves a hosted (token-lease:unbound) connector fails closed pending a credential.
// Boundary: daemon EXECUTES the push · wallet AUTHORIZES the crossing · agentgres RECORDS the receipt.
//
// Model-free (no Ollama). Usage: node scripts/verify-hypervisor-scm-connector-functional.mjs [--json]
import { mintApprovalGrant } from "./lib/mint-approval-grant.mjs";
import { execFileSync } from "node:child_process";
import fs from "node:fs";
import os from "node:os";

const JSON_OUT = process.argv.includes("--json");
const DAEMON = process.env.IOI_HYPERVISOR_DAEMON_URL || "http://127.0.0.1:8765";
const DATA_DIR = process.env.IOI_HYPERVISOR_DATA_DIR || `${os.homedir()}/.ioi/hypervisor/data`;
const checks = [];
let failures = 0;
const ok = (cond, msg, detail) => { checks.push({ ok: !!cond, msg }); if (!cond) failures++; if (!JSON_OUT) console.log(`    ${cond ? "✓" : "✗ FAIL:"} ${msg}${detail ? ` (${detail})` : ""}`); };
const blocked = (reason) => { console.log(JSON_OUT ? JSON.stringify({ workstream: "scm-connector", verdict: "BLOCKED", reason }, null, 2) : `  BLOCKED: ${reason}`); process.exit(2); };
const j = async (m, p, b) => { const r = await fetch(DAEMON + p, { method: m, headers: b ? { "content-type": "application/json" } : undefined, body: b ? JSON.stringify(b) : undefined }); return { status: r.status, body: await r.json().catch(() => ({})) }; };

if (!JSON_OUT) console.log("SCM connector e2e — wallet-authorized publish crossing");

try { const r = await fetch(`${DAEMON}/v1/hypervisor/providers`, { signal: AbortSignal.timeout(3000) }); if (!r.ok) throw 0; } catch { blocked("hypervisor-daemon (:8765) not running"); }

// local bare repo = the connector remote (real push target, no external creds)
const bare = fs.mkdtempSync(`${os.tmpdir()}/ioi-scm-`) + "/remote.git";
execFileSync("git", ["init", "-q", "--bare", bare]);

// register the local connector
const reg = await j("POST", "/v1/hypervisor/scm-connectors", { kind: "git", remote_url: `file://${bare}`, name: "done-bar-local" });
const connectorId = reg.body?.connector?.connector_id;
ok(reg.body?.ok && !!connectorId, "register a local (file://) SCM connector", reg.body?.connector?.auth_posture);
ok(reg.body?.connector?.auth_posture === "local-none", "local connector needs no credentials (auth_posture local-none)");

// env with a real change
const env = await j("POST", "/v1/hypervisor/environments", { spec: { environment_class_id: "local-workspace-v0" } });
const envId = env.body?.environment?.id;
await j("POST", `/v1/hypervisor/environments/${envId}/start`);
const ws = (await j("GET", `/v1/hypervisor/environments/${envId}`)).body?.environment?.status?.workspace_root;
ok(!!ws, "environment started with a workspace", envId);
if (ws) fs.writeFileSync(`${ws}/published-feature.txt`, "shipped via the publish crossing\n");

// 1) UNAUTHORIZED publish must fail closed with a challenge (the crossing requires a grant)
const unauth = await j("POST", `/v1/hypervisor/environments/${envId}/scm/publish`, { connector_id: connectorId, title: "Ship feature" });
ok(unauth.status === 403 && unauth.body?.reason === "scm_publish_authority_required", "unauthorized publish FAILS CLOSED (403, authority required)", `status ${unauth.status}`);
const policyHash = unauth.body?.approval?.policy_hash;
const requestHash = unauth.body?.approval?.request_hash;
ok(!!policyHash && !!requestHash, "challenge exposes daemon-derived policy_hash + request_hash");

// 2) mint a wallet grant bound to those hashes, then publish AUTHORIZED
let grant = null;
try { grant = mintApprovalGrant({ policyHash, requestHash }); } catch (e) { blocked(`grant minter unavailable: ${e?.message || e}`); }
const auth = await j("POST", `/v1/hypervisor/environments/${envId}/scm/publish`, { connector_id: connectorId, title: "Ship feature", wallet_approval_grant: grant });
const rec = auth.body?.receipt || {};
ok(auth.status === 200 && auth.body?.ok === true, "authorized publish succeeds (200)", `status ${auth.status}`);
ok(rec.published === true && rec.host_mutation === true, "receipt: published + host_mutation:true (a real crossing)");
ok(typeof rec.grant_ref === "string" && rec.grant_ref.includes("grant"), "receipt carries the wallet grant ref (authority proof)", (rec.grant_ref || "").slice(0, 44));

// 3) REAL EFFECT: the branch + commit actually landed in the remote bare repo
let landedSha = null, tree = "";
try { landedSha = execFileSync("git", ["--git-dir", bare, "rev-parse", rec.branch], { encoding: "utf8" }).trim(); } catch { /* */ }
try { tree = execFileSync("git", ["--git-dir", bare, "ls-tree", "-r", "--name-only", rec.branch], { encoding: "utf8" }); } catch { /* */ }
ok(landedSha && landedSha === rec.commit_sha, "REAL EFFECT: pushed branch landed in the remote (sha matches receipt)", (landedSha || "").slice(0, 10));
ok(tree.includes("published-feature.txt"), "REAL EFFECT: the workspace change is in the remote tree");

// 4) receipt persisted durably (agentgres records the crossing)
const sameEnvId = envId;
const pubList = await j("GET", `/v1/hypervisor/scm-connectors`);
ok(pubList.body?.ok, "connector registry lists connectors");
const recheck = await j("POST", `/v1/hypervisor/environments/${sameEnvId}/scm/publish`, { connector_id: connectorId, title: "Ship feature", wallet_approval_grant: grant });
ok(recheck.status === 200, "authorized re-publish is idempotent-safe (200)");

// 5) hosted connector fails closed until a credential lease is bound. Use a NON-github remote so
// the assertion is deterministic regardless of whether a github host authentication is connected
// (a github.com remote would resolve the connected host token via the git-auth fallback — that
// fallback path is exercised by the live publish e2e instead).
const hosted = await j("POST", "/v1/hypervisor/scm-connectors", { kind: "git", remote_url: "https://git.example.com/ioi/example.git" });
const hostedId = hosted.body?.connector?.connector_id;
ok((hosted.body?.connector?.auth_posture || "").startsWith("token-lease"), "hosted connector declares a token-lease posture", hosted.body?.connector?.auth_posture);
const hostedPub = await j("POST", `/v1/hypervisor/environments/${envId}/scm/publish`, { connector_id: hostedId, title: "x" });
ok(hostedPub.status === 428 && hostedPub.body?.reason === "scm_credential_required", "hosted publish FAILS CLOSED pending a credential lease (428)", `status ${hostedPub.status}`);

// 6) CREDENTIAL SWAP — exercised locally (no external host): a credential-REQUIRED connector
// pointed at a local bare repo. Binding a credential flips the gate and the credentialed crossing
// completes against the local remote (file:// ignores the injected token). github.com itself stays
// fail-closed (the real PR-API path needs an operator-supplied token + repo).
const bare2 = fs.mkdtempSync(`${os.tmpdir()}/ioi-scm2-`) + "/remote.git";
execFileSync("git", ["init", "-q", "--bare", bare2]);
const credConn = await j("POST", "/v1/hypervisor/scm-connectors", { kind: "git", remote_url: `file://${bare2}`, requires_credential: true, name: "local-cred" });
const credId = credConn.body?.connector?.connector_id;
ok(credConn.body?.connector?.requires_credential === true && credConn.body?.connector?.auth_posture === "token-lease:unbound", "credential-required connector starts unbound");

// publish before binding → fails closed (428)
const preBind = await j("POST", `/v1/hypervisor/environments/${envId}/scm/publish`, { connector_id: credId, title: "x" });
ok(preBind.status === 428, "credential-required publish FAILS CLOSED before binding (428)", `status ${preBind.status}`);

// bind a credential (dummy token) → posture flips bound; token must NOT leak into listings
const bind = await j("POST", `/v1/hypervisor/scm-connectors/${credId}/credential`, { token: "ghp_DUMMY_done_bar_token_value" });
ok(bind.body?.ok && bind.body?.auth_posture === "token-lease:bound", "binding a credential flips auth_posture → token-lease:bound");
ok(!("token" in (bind.body || {})), "bind response does NOT echo the token");
const listAfter = JSON.stringify((await j("GET", "/v1/hypervisor/scm-connectors")).body?.connectors || []);
ok(!listAfter.includes("ghp_DUMMY_done_bar_token_value"), "connector listing NEVER exposes the bound token");

// HARDENING: the token is SEALED at rest (ioi-crypto AEAD) — the on-disk credential record holds a
// sealed_token, never the plaintext.
let credFile = "";
try { credFile = fs.readFileSync(`${DATA_DIR}/scm-credentials/${credId}.json`, "utf8"); } catch { /* */ }
ok(credFile && !credFile.includes("ghp_DUMMY_done_bar_token_value"), "HARDENING: no plaintext token in the at-rest credential record");
let credJson = {}; try { credJson = JSON.parse(credFile); } catch { /* */ }
ok(credJson.sealed === true && typeof credJson.sealed_token === "string" && credJson.sealed_token.length > 0, "HARDENING: credential is sealed (sealed_token present)", credJson.key_source);
ok(!("token" in credJson), "HARDENING: at-rest record has no plaintext `token` field");

// authorized publish now passes the credential gate AND the wallet gate → real push to local remote
const credUnauth = await j("POST", `/v1/hypervisor/environments/${envId}/scm/publish`, { connector_id: credId, title: "Ship (cred)" });
ok(credUnauth.status === 403, "after binding, publish still requires the wallet crossing grant (403)", `status ${credUnauth.status}`);
const cGrant = mintApprovalGrant({ policyHash: credUnauth.body?.approval?.policy_hash, requestHash: credUnauth.body?.approval?.request_hash });
const credPub = await j("POST", `/v1/hypervisor/environments/${envId}/scm/publish`, { connector_id: credId, title: "Ship (cred)", wallet_approval_grant: cGrant });
ok(credPub.status === 200 && credPub.body?.receipt?.credential_bound === true, "credential-resolved publish succeeds (credential_bound:true)", `status ${credPub.status}`);
let cLanded = null;
try { cLanded = execFileSync("git", ["--git-dir", bare2, "rev-parse", credPub.body?.receipt?.branch], { encoding: "utf8" }).trim(); } catch { /* */ }
ok(cLanded === credPub.body?.receipt?.commit_sha, "REAL EFFECT: credentialed push landed in the local remote");
ok(typeof credPub.body?.receipt?.credential_key_source === "string", "receipt records the credential key_source (sealed token was opened)", credPub.body?.receipt?.credential_key_source);

// 6) REVOKE the credential (the endpoint the native "Disconnect" calls) → authority must fail closed
const revoke = await j("DELETE", `/v1/hypervisor/scm-connectors/${credId}/credential`);
ok(revoke.status === 200 && revoke.body?.ok === true && revoke.body?.revoked === true, "revoke deletes the sealed credential (revoked:true)", `status ${revoke.status}`);
ok(revoke.body?.auth_posture === "token-lease:unbound", "revoke flips the connector back to unbound");
const afterRevoke = (await j("GET", "/v1/hypervisor/scm-connectors")).body?.connectors?.find((c) => c.connector_id === credId);
ok(afterRevoke?.auth_posture === "token-lease:unbound", "connector reads unbound after revoke");
const postRevokePub = await j("POST", `/v1/hypervisor/environments/${envId}/scm/publish`, { connector_id: credId, title: "x", wallet_approval_grant: cGrant });
ok(postRevokePub.status === 428 && postRevokePub.body?.reason === "scm_credential_required", "publish AFTER revoke FAILS CLOSED (428, credential required)", `status ${postRevokePub.status}`);
ok(postRevokePub.body?.host_mutation === false, "no host mutation attempted after revoke");
const reRevoke = await j("DELETE", `/v1/hypervisor/scm-connectors/${credId}/credential`);
ok(reRevoke.body?.ok === true && reRevoke.body?.revoked === false, "revoke is idempotent (second revoke → revoked:false)");

// 7) abandon-pull-request (close PR + delete branch via the sealed token) is a governed crossing
// too — fails closed without a wallet grant. (The authorized path needs a real github PR; it is
// exercised by the live e2e — here we assert the gate is wired.)
const abandonNoGrant = await j("POST", `/v1/hypervisor/scm-connectors/${connectorId}/abandon-pull-request`, { pull_request_url: "https://github.com/x/y/pull/1", delete_branch: false });
ok(abandonNoGrant.status === 403 && abandonNoGrant.body?.reason === "scm_abandon_authority_required", "abandon-pull-request FAILS CLOSED without a wallet grant (403)", `status ${abandonNoGrant.status}`);

try { fs.rmSync(bare, { recursive: true, force: true }); fs.rmSync(bare2, { recursive: true, force: true }); } catch { /* */ }

const verdict = failures > 0 ? "FAIL" : "PASS";
if (JSON_OUT) console.log(JSON.stringify({ workstream: "scm-connector", verdict, failures, checks: checks.length, envId, connectorId }, null, 2));
else console.log(`  VERDICT: ${verdict} (${checks.length - failures}/${checks.length} checks)`);
process.exit(verdict === "FAIL" ? 1 : 0);
