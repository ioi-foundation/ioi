#!/usr/bin/env node
// Done-bar for the generic CapabilityLease primitive (master-guide #3) — the SINGLE authority
// crossing every connector flows through. Proves the 9-field use-only lease is derived, persisted,
// and embedded in receipts, that it carries NO credential, and that fail-closed semantics hold.
//
// The agent receives USE-ONLY authority (scoped tools + resources + receipt + revocation), never the
// underlying credential. Verified through the SCM publish crossing with a LOCAL bare repo + a bound
// credential (real push, no external creds, model-free).
//   node scripts/verify-hypervisor-capability-lease-functional.mjs [--json]
import { mintApprovalGrant } from "./lib/mint-approval-grant.mjs";
import { execFileSync } from "node:child_process";
import fs from "node:fs";
import os from "node:os";

const JSON_OUT = process.argv.includes("--json");
const DAEMON = process.env.IOI_HYPERVISOR_DAEMON_URL || "http://127.0.0.1:8765";
const checks = [];
let failures = 0;
const ok = (cond, msg, detail) => { checks.push({ ok: !!cond, msg }); if (!cond) failures++; if (!JSON_OUT) console.log(`    ${cond ? "✓" : "✗ FAIL:"} ${msg}${detail ? ` (${detail})` : ""}`); };
const blocked = (reason) => { console.log(JSON_OUT ? JSON.stringify({ workstream: "capability-lease", verdict: "BLOCKED", reason }, null, 2) : `  BLOCKED: ${reason}`); process.exit(2); };
const j = async (m, p, b) => { const r = await fetch(DAEMON + p, { method: m, headers: b ? { "content-type": "application/json" } : undefined, body: b ? JSON.stringify(b) : undefined }); return { status: r.status, body: await r.json().catch(() => ({})) }; };

if (!JSON_OUT) console.log("CapabilityLease primitive e2e — the single authority crossing");
try { const r = await fetch(`${DAEMON}/v1/hypervisor/providers`, { signal: AbortSignal.timeout(3000) }); if (!r.ok) throw 0; } catch { blocked("hypervisor-daemon (:8765) not running"); }

// local bare repo = connector remote; bind a credential so the lease has a backing_provider
const bare = fs.mkdtempSync(`${os.tmpdir()}/ioi-lease-`) + "/remote.git";
execFileSync("git", ["init", "-q", "--bare", bare]);
const reg = await j("POST", "/v1/hypervisor/scm-connectors", { kind: "git", remote_url: `file://${bare}`, requires_credential: true, name: "lease-done-bar" });
const connectorId = reg.body?.connector?.connector_id;
ok(!!connectorId, "register a credential-required connector", reg.body?.connector?.auth_posture);
await j("POST", `/v1/hypervisor/scm-connectors/${connectorId}/credential`, { token: "lease-done-bar-token" });

const env = await j("POST", "/v1/hypervisor/environments", { spec: { environment_class_id: "local-workspace-v0" } });
const envId = env.body?.environment?.id;
await j("POST", `/v1/hypervisor/environments/${envId}/start`);
const ws = (await j("GET", `/v1/hypervisor/environments/${envId}`)).body?.environment?.status?.workspace_root;
if (ws) fs.writeFileSync(`${ws}/lease.txt`, "via the capability-lease crossing\n");

// 1) UNAUTHORIZED publish → the gateway's 403 challenge exposes the canonical hashes + lease facets
const path = `/v1/hypervisor/environments/${envId}/scm/publish`;
const ch = await j("POST", path, { connector_id: connectorId, title: "lease" });
ok(ch.status === 403 && ch.body?.reason === "scm_publish_authority_required", "unauthorized crossing FAILS CLOSED (403 authority challenge)", `status ${ch.status}`);
ok(!!ch.body?.approval?.policy_hash && !!ch.body?.approval?.request_hash, "challenge exposes daemon-derived policy + request hashes");
ok(Array.isArray(ch.body?.allowed_tools) && ch.body.allowed_tools.includes("scm.publish"), "challenge declares allowed_tools (scm.publish)");
ok(Array.isArray(ch.body?.resource_refs) && ch.body.resource_refs.length > 0, "challenge declares resource_refs");

// 2) mint a grant bound to those hashes → AUTHORIZED publish issues a lease
const grant = mintApprovalGrant({ policyHash: ch.body.approval.policy_hash, requestHash: ch.body.approval.request_hash });
const pub = await j("POST", path, { connector_id: connectorId, title: "lease", wallet_approval_grant: grant });
ok(pub.status === 200 && pub.body?.ok === true, "authorized crossing succeeds (200)", `status ${pub.status}`);
const lease = pub.body?.receipt?.capability_lease;
ok(!!lease, "receipt embeds a capability_lease descriptor");

// 3) the lease carries EXACTLY the 9-field generic shape
const NINE = ["authority_provider_ref", "backing_provider", "allowed_tools", "resource_refs", "policy_hash", "request_hash", "expires_at", "receipt_required", "revocation_ref"];
const missing = NINE.filter((k) => !(lease && k in lease));
ok(missing.length === 0, "lease has all 9 generic fields", missing.length ? `missing: ${missing}` : "");
ok(lease?.backing_provider === `scm:connector:${connectorId}`, "backing_provider names the sealed credential source", lease?.backing_provider);
ok(Array.isArray(lease?.allowed_tools) && lease.allowed_tools.includes("scm.publish"), "allowed_tools is use-only scoped (scm.publish)");
ok(typeof lease?.revocation_ref === "string" && lease.revocation_ref.includes(connectorId), "revocation_ref points at the credential surface", lease?.revocation_ref);
ok(typeof lease?.authority_provider_ref === "string" && lease.authority_provider_ref.length > 0, "authority_provider_ref present (wallet authority)", lease?.authority_provider_ref);
ok(lease?.policy_hash === ch.body.approval.policy_hash && lease?.request_hash === ch.body.approval.request_hash, "lease binds to the SAME hashes the grant authorized (no rebinding)");

// 4) USE-ONLY: the lease never carries a credential/secret (grant_ref/credential_source are
// references, not secrets — only a sealed_token / raw token would be a leak)
const leaseStr = JSON.stringify(lease || {});
ok(!/sealed_token|ghp_|"token":/.test(leaseStr), "lease descriptor carries NO secret material (use-only)");

// 5) the authority audit trail lists the issued lease, and NONE leak a secret
const list = await j("GET", "/v1/hypervisor/capability-leases");
const leases = list.body?.leases || [];
ok(list.status === 200 && Array.isArray(leases) && leases.length > 0, "GET /capability-leases returns the audit trail", `count ${leases.length}`);
ok(leases.some((l) => l.policy_hash === lease.policy_hash && l.request_hash === lease.request_hash), "the issued lease is in the audit trail");
ok(!/sealed_token|ghp_|"token":/.test(JSON.stringify(leases)), "no lease in the audit trail leaks a secret");

try { fs.rmSync(bare, { recursive: true, force: true }); } catch { /* */ }
const verdict = failures > 0 ? "FAIL" : "PASS";
if (JSON_OUT) console.log(JSON.stringify({ workstream: "capability-lease", verdict, failures, checks: checks.length }, null, 2));
else console.log(`  VERDICT: ${verdict} (${checks.length - failures}/${checks.length} checks)`);
process.exit(verdict === "FAIL" ? 1 : 0);
