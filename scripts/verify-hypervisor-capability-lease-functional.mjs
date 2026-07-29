#!/usr/bin/env node
// Done-bar for the generic CapabilityLease primitive (master-guide #3) — the SINGLE authority
// crossing every connector flows through. Proves the 9-field use-only lease is derived, persisted,
// bound into the committed effect, and that it carries NO credential, with fail-closed semantics.
//
// WHAT THIS BAR USED TO CERTIFY (and no longer does). The previous version drove the lease through
// `POST /v1/hypervisor/environments/{id}/scm/publish` with a body of only `{connector_id, title}`
// and read the descriptor out of `receipt.capability_lease` on a 200 response. That publish shape
// was the unbound-destination / whole-workspace / force-push route the rebuilt
// `ScmPublicationEffect` contract makes unrepresentable, and its lease was scoped to a
// CALLER-SUPPLIED remote string. Those assertions were pinned to the defect. Nothing is weakened:
// every lease property the old bar proved is still proved here, and the lease is now read from the
// durable authority audit trail and cross-checked against the committed publication effect.
//
// WHAT IT CERTIFIES NOW. The crossing resolves its ADMITTED destination binding BEFORE authority,
// so the challenge — and the lease derived from it — are scoped to that exact destination and to
// the publication scope family, and a grant minted for one destination authorizes no other. The
// agent receives USE-ONLY authority (scoped tools + resources + receipt + revocation), never the
// underlying credential. Verified through the real publication crossing against a LOCAL bare repo,
// plus a credential-backed destination whose sealed token is resolved but whose remote is
// unreachable — proving the lease is authority, never a claim that anything landed.
//   node scripts/verify-hypervisor-capability-lease-functional.mjs [--json]
import { mintApprovalGrant } from "./lib/mint-approval-grant.mjs";
import { execFileSync } from "node:child_process";
import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";

const JSON_OUT = process.argv.includes("--json");
const DAEMON = process.env.IOI_HYPERVISOR_DAEMON_URL || "http://127.0.0.1:8765";
const checks = [];
let failures = 0;
const ok = (cond, msg, detail) => { checks.push({ ok: !!cond, msg }); if (!cond) failures++; if (!JSON_OUT) console.log(`    ${cond ? "✓" : "✗ FAIL:"} ${msg}${detail ? ` (${detail})` : ""}`); };
const blocked = (reason) => { console.log(JSON_OUT ? JSON.stringify({ workstream: "capability-lease", verdict: "BLOCKED", reason }, null, 2) : `  BLOCKED: ${reason}`); process.exit(2); };
const j = async (m, p, b) => { const r = await fetch(DAEMON + p, { method: m, headers: b ? { "content-type": "application/json" } : undefined, body: b ? JSON.stringify(b) : undefined }); return { status: r.status, body: await r.json().catch(() => ({})) }; };
const sha256 = (buf) => `sha256:${crypto.createHash("sha256").update(buf).digest("hex")}`;
const git = (args) => execFileSync("git", args, { encoding: "utf8", stdio: ["ignore", "pipe", "pipe"] }).trim();
const tryGit = (args) => { try { return git(args); } catch { return null; } };
const SECRET = /sealed_token|ghp_|"token":/;

const PUBLICATION_SCOPES = ["scope:scm.publication.advance-target-ref", "scope:scm.publication.open-review-request"];
const NINE = ["authority_provider_ref", "backing_provider", "allowed_tools", "resource_refs", "policy_hash", "request_hash", "expires_at", "receipt_required", "revocation_ref"];

if (!JSON_OUT) console.log("CapabilityLease primitive e2e — the single authority crossing");
try { const r = await fetch(`${DAEMON}/v1/hypervisor/providers`, { signal: AbortSignal.timeout(3000) }); if (!r.ok) throw 0; } catch { blocked("hypervisor-daemon (:8765) not running"); }

// A connector's identity derives from its remote, and the publication plane is durable and
// estate-wide, so every identity this run touches carries a fresh nonce.
const NONCE = crypto.randomBytes(4).toString("hex");
const REPO = `ioi/lease-bar-${NONCE}`;
const TOKEN = `ghp_lease_done_bar_${NONCE}`;

// --- the admitted remote: a local bare repo with a real base ref -------------------------------
const root = fs.mkdtempSync(`${os.tmpdir()}/ioi-lease-`);
const bare = `${root}/remote.git`;
git(["init", "-q", "--bare", bare]);
const seed = `${root}/seed`;
fs.mkdirSync(seed);
git(["-C", seed, "init", "-q"]);
fs.writeFileSync(`${seed}/README.md`, "base\n");
git(["-C", seed, "add", "README.md"]);
git(["-C", seed, "-c", "user.email=bar@ioi.local", "-c", "user.name=bar", "commit", "-qm", "base"]);
const baseSha = git(["-C", seed, "rev-parse", "HEAD"]);
git(["-C", seed, "push", "-q", bare, "HEAD:refs/heads/integration"]);

const localConn = await j("POST", "/v1/hypervisor/scm-connectors", { kind: "git", remote_url: `file://${bare}`, name: `lease-local-${NONCE}` });
const localId = localConn.body?.connector?.connector_id;
ok(!!localId, "register the local connector the crossing publishes through", localConn.body?.connector?.auth_posture);

const admitBinding = async (ref, connectorId, remoteUrl) => j("POST", "/v1/hypervisor/scm-destination-bindings", {
  destination_binding_ref: ref,
  connector_ref: `connector://${connectorId}`,
  connector_revision_hash: sha256(`${connectorId}:${remoteUrl}`),
  repository_ref: `repository://${REPO}`,
  base_ref: `scm-ref://${REPO}/heads/integration`,
  target_ref_namespace: `scm-ref://${REPO}/heads/`,
  remote_url: remoteUrl,
  admission_receipt_ref: `receipt://${REPO}/scm-publication/admission/${ref.split("/").pop()}`,
});
const bindingRef = `scm-destination-binding://${REPO}/revision/0001`;
const bindAdmit = await admitBinding(bindingRef, localId, `file://${bare}`);
ok(bindAdmit.status === 200 && bindAdmit.body?.ok === true, "admit the destination binding the crossing is scoped to", `status ${bindAdmit.status}`);

const env = await j("POST", "/v1/hypervisor/environments", { spec: { environment_class_id: "local-workspace-v0" } });
const envId = env.body?.environment?.id;
await j("POST", `/v1/hypervisor/environments/${envId}/start`);
const ws = (await j("GET", `/v1/hypervisor/environments/${envId}`)).body?.environment?.status?.workspace_root;
if (!ws) blocked("environment did not provision a workspace");
const bytes = "via the capability-lease crossing\n";
fs.writeFileSync(`${ws}/lease.txt`, bytes);

const proposalRef = `proposal://${REPO}/change/0001`;
const workRunRef = `work-run://${REPO}/0001`;
await j("POST", "/v1/hypervisor/scm-publication-proposals", {
  proposal_ref: proposalRef,
  base_revision_id: `scm-revision:${baseSha}`,
  files: [{ path: "lease.txt", change_kind: "added", content_digest: sha256(bytes), proposal_ref: proposalRef }],
  work_run_ref: workRunRef,
});

const PUBLISH = `/v1/hypervisor/environments/${envId}/scm/publish`;
const submission = { destination_binding_ref: bindingRef, proposal_ref: proposalRef, work_run_ref: workRunRef, target_ref_name: "lease-0001", title: "lease" };

// =============================================================================================
// 1) The challenge — derived hashes, scoped to the ADMITTED destination
// =============================================================================================
const ch = await j("POST", PUBLISH, submission);
ok(ch.status === 403 && ch.body?.reason === "scm_publish_authority_required", "unauthorized crossing FAILS CLOSED (403 authority challenge)", `status ${ch.status}`);
ok(!!ch.body?.approval?.policy_hash && !!ch.body?.approval?.request_hash, "challenge exposes daemon-derived policy + request hashes");
ok(Array.isArray(ch.body?.allowed_tools) && ch.body.allowed_tools.includes("scm.publish"), "challenge declares allowed_tools (scm.publish)");
ok(Array.isArray(ch.body?.resource_refs) && ch.body.resource_refs.length > 0, "challenge declares resource_refs");
ok(JSON.stringify(ch.body?.resource_refs) === JSON.stringify([bindingRef, envId]),
  "the crossing is scoped to the ADMITTED DESTINATION and the environment — never to caller-supplied remote text",
  JSON.stringify(ch.body?.resource_refs));
{
  const scopes = ch.body?.required_scopes || [];
  ok(scopes.length === PUBLICATION_SCOPES.length && PUBLICATION_SCOPES.every((s) => scopes.includes(s)),
    "the challenge demands the publication scope family (advance-target-ref + open-review-request)", JSON.stringify(scopes));
  ok(scopes.every((s) => String(s).startsWith("scope:scm.publication.")),
    "no scope outside the publication family is consumed (disjoint from lifecycle/environment/legacy scm_push)");
}
ok(ch.body?.host_mutation === false, "the challenge claims no host mutation");

// =============================================================================================
// 2) The authorized crossing issues the lease and the effect names it
// =============================================================================================
const grant = mintApprovalGrant({ policyHash: ch.body.approval.policy_hash, requestHash: ch.body.approval.request_hash });
const pub = await j("POST", PUBLISH, { ...submission, wallet_approval_grant: grant });
const effect = pub.body?.publication_effect || {};
ok(pub.status === 200 && pub.body?.ok === true, "authorized crossing succeeds (200)", `status ${pub.status}`);
ok(tryGit(["--git-dir", bare, "rev-parse", "refs/heads/lease-0001"]) === String(effect?.change_set?.resulting_revision_id || "").replace("scm-revision:", ""),
  "REAL EFFECT: the authorized crossing actually landed on the remote");

const leaseRef = effect?.authority?.capability_lease_ref;
ok(typeof leaseRef === "string" && leaseRef.startsWith("lease://"), "the committed effect NAMES the capability lease it crossed under", leaseRef);
const leaseId = String(leaseRef || "").replace("lease://", "");
const list = await j("GET", "/v1/hypervisor/capability-leases");
const leases = list.body?.leases || [];
ok(list.status === 200 && Array.isArray(leases) && leases.length > 0, "GET /capability-leases returns the audit trail", `count ${leases.length}`);
const lease = leases.find((l) => l.lease_id === leaseId);
ok(!!lease, "the lease the effect names RESOLVES in the durable audit trail", leaseId);

// --- the 9-field generic shape ------------------------------------------------------------------
const missing = NINE.filter((k) => !(lease && k in lease));
ok(missing.length === 0, "lease has all 9 generic fields", missing.length ? `missing: ${missing}` : "");
ok(Array.isArray(lease?.allowed_tools) && lease.allowed_tools.includes("scm.publish"), "allowed_tools is use-only scoped (scm.publish)");
ok(typeof lease?.revocation_ref === "string" && lease.revocation_ref.includes(localId), "revocation_ref points at the credential surface", lease?.revocation_ref);
ok(typeof lease?.authority_provider_ref === "string" && lease.authority_provider_ref.length > 0, "authority_provider_ref present (wallet authority)", lease?.authority_provider_ref);
ok(lease?.policy_hash === ch.body.approval.policy_hash && lease?.request_hash === ch.body.approval.request_hash, "lease binds to the SAME hashes the grant authorized (no rebinding)");
ok(JSON.stringify(lease?.resource_refs) === JSON.stringify([bindingRef, envId]), "the ISSUED lease is scoped to the admitted destination + environment", JSON.stringify(lease?.resource_refs));
ok(lease?.backing_provider === "none",
  "an authority-only destination issues a lease that claims NO backing credential", lease?.backing_provider);
ok(lease?.receipt_required === true, "the lease requires a receipt for the crossing");

// --- the effect's authority block agrees with the lease -----------------------------------------
ok(JSON.stringify(effect?.authority?.authority_scope_refs) === JSON.stringify(PUBLICATION_SCOPES),
  "the effect records the exact publication scopes the crossing consumed", JSON.stringify(effect?.authority?.authority_scope_refs));
ok(Array.isArray(effect?.authority?.authority_grant_refs)
  && effect.authority.authority_grant_refs.some((g) => g === `grant://${lease?.grant_ref}`),
  "the effect names the exact wallet grant the lease bound", (effect?.authority?.authority_grant_refs || [])[0]?.slice(0, 48));
ok(typeof effect?.authority?.admission_receipt_ref === "string" && effect.authority.admission_receipt_ref.includes(leaseId),
  "the effect carries the admission receipt of the authority crossing", effect?.authority?.admission_receipt_ref);
ok((pub.body?.receipts || []).every((r) => r.capability_lease_ref === leaseRef),
  "every sub-effect receipt binds the same capability lease");

// --- USE-ONLY: the lease never carries a credential/secret --------------------------------------
// (grant_ref/credential_source are references, not secrets — only a sealed_token or a raw token
// would be a leak.)
ok(!SECRET.test(JSON.stringify(lease || {})), "lease descriptor carries NO secret material (use-only)");
ok(!SECRET.test(JSON.stringify(leases)), "no lease in the audit trail leaks a secret");
ok(!SECRET.test(JSON.stringify(effect)), "the committed publication effect carries no secret material");

// =============================================================================================
// 3) A lease authorizes ONE destination — a grant is not transferable
// =============================================================================================
const otherBindingRef = `scm-destination-binding://${REPO}/revision/0002`;
await admitBinding(otherBindingRef, localId, `file://${bare}`);
const misdirected = await j("POST", PUBLISH, { ...submission, destination_binding_ref: otherBindingRef, wallet_approval_grant: grant });
ok(misdirected.status === 403 && misdirected.body?.reason === "scm_publish_authority_required",
  "the grant that authorized THIS destination authorizes no other destination (403)", `status ${misdirected.status}`);
ok(!leases.some((l) => l.resource_refs?.[0] === otherBindingRef), "no lease was issued for the destination the grant did not cover");

// =============================================================================================
// 4) A credential-backed destination: the sealed credential gates the lease, and the lease is
//    authority — never a claim that the crossing landed
// =============================================================================================
const HOSTED_REMOTE = `https://127.0.0.1:1/ioi/hosted-${NONCE}.git`;
const credConn = await j("POST", "/v1/hypervisor/scm-connectors", { kind: "git", remote_url: HOSTED_REMOTE, requires_credential: true, name: `lease-cred-${NONCE}` });
const credId = credConn.body?.connector?.connector_id;
ok(credConn.body?.connector?.auth_posture === "token-lease:unbound", "register a credential-required connector (starts unbound)", credConn.body?.connector?.auth_posture);
const credBindingRef = `scm-destination-binding://${REPO}/revision/hosted`;
await admitBinding(credBindingRef, credId, HOSTED_REMOTE);
const credSubmission = { destination_binding_ref: credBindingRef, proposal_ref: proposalRef, work_run_ref: workRunRef, target_ref_name: "hosted-0001", title: "hosted" };

const preBind = await j("POST", PUBLISH, credSubmission);
ok(preBind.status === 428 && preBind.body?.reason === "scm_credential_required",
  "the CREDENTIAL gate precedes the wallet gate: no resolvable credential → 428, before any authority", `status ${preBind.status}`);
ok(preBind.body?.backing_provider === `scm:connector:${credId}` && preBind.body?.host_mutation === false,
  "the 428 names the backing provider it could not resolve, and claims no host mutation");

await j("POST", `/v1/hypervisor/scm-connectors/${credId}/credential`, { token: TOKEN });
const credCh = await j("POST", PUBLISH, credSubmission);
ok(credCh.status === 403 && credCh.body?.reason === "scm_publish_authority_required",
  "with the credential bound the crossing STILL requires the wallet grant (403)", `status ${credCh.status}`);
const credGrant = mintApprovalGrant({ policyHash: credCh.body?.approval?.policy_hash, requestHash: credCh.body?.approval?.request_hash });
const credPub = await j("POST", PUBLISH, { ...credSubmission, wallet_approval_grant: credGrant });
ok(credPub.status === 502 && credPub.body?.reason === "scm_publication_remote_unobservable" && credPub.body?.fail_closed === true,
  "the credentialed crossing fails closed at an unobservable remote (502) — a lease is never an effect claim", `status ${credPub.status}`);

const credLeases = (await j("GET", "/v1/hypervisor/capability-leases")).body?.leases || [];
const credLease = credLeases.find((l) => l.backing_provider === `scm:connector:${credId}`);
ok(!!credLease, "the credentialed crossing issued its own lease", credLease?.lease_id);
ok(credLease?.backing_provider === `scm:connector:${credId}`, "backing_provider names the sealed credential source", credLease?.backing_provider);
ok(typeof credLease?.credential_source === "string" && credLease.credential_source.length > 0,
  "the lease records the credential source (the sealed token was opened for the daemon to USE)", credLease?.credential_source);
ok(NINE.every((k) => k in (credLease || {})), "the credential-backed lease carries the same 9 generic fields");
ok(JSON.stringify(credLease?.resource_refs) === JSON.stringify([credBindingRef, envId]), "the credential-backed lease is scoped to its own destination");
ok(!JSON.stringify(credLease || {}).includes(TOKEN) && !SECRET.test(JSON.stringify(credLease || {})),
  "the credential-backed lease carries NO secret material (use-only)");
ok(!JSON.stringify(credLeases).includes(TOKEN), "no lease in the audit trail exposes the bound token");

// Revoking the backing credential closes the crossing again: authority does not outlive it.
const revoke = await j("DELETE", `/v1/hypervisor/scm-connectors/${credId}/credential`);
ok(revoke.body?.ok === true && revoke.body?.revoked === true, "revoking the credential closes the backing surface");
const afterRevoke = await j("POST", PUBLISH, { ...credSubmission, wallet_approval_grant: credGrant });
ok(afterRevoke.status === 428 && afterRevoke.body?.reason === "scm_credential_required",
  "an already-issued grant does NOT survive credential revocation (428)", `status ${afterRevoke.status}`);
ok(afterRevoke.body?.host_mutation === false, "no host mutation is attempted after revocation");

try { fs.rmSync(root, { recursive: true, force: true }); } catch { /* */ }
const verdict = failures > 0 ? "FAIL" : "PASS";
if (JSON_OUT) console.log(JSON.stringify({ workstream: "capability-lease", verdict, failures, checks: checks.length, leaseId, bindingRef }, null, 2));
else console.log(`  VERDICT: ${verdict} (${checks.length - failures}/${checks.length} checks)`);
process.exit(verdict === "FAIL" ? 1 : 0);
