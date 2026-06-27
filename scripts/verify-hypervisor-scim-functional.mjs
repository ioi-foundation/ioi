#!/usr/bin/env node
// Done-bar for SCIM 2.0 provisioning (multi-user IdP, Phase 3). Exercises the SCIM server an external
// IdP (Okta/Azure AD) drives — through the PUBLIC /scim/v2 endpoint (serve proxy → daemon) with the
// minted SCIM bearer: ServiceProviderConfig, Users CRUD (provision → filter → deprovision), Groups.
// Provisioned Users map onto the principals plane (source: scim); the SCIM token is hash-only at rest.
// Usage: node scripts/verify-hypervisor-scim-functional.mjs [--json]
import { readFileSync, existsSync } from "node:fs";
import { join } from "node:path";

const JSON_OUT = process.argv.includes("--json");
const SERVE = process.env.IOI_HYPERVISOR_SERVE_URL || "http://127.0.0.1:4173";
const DAEMON = process.env.IOI_HYPERVISOR_DAEMON_URL || "http://127.0.0.1:8765";
const DATA_DIR = process.env.IOI_HYPERVISOR_DATA_DIR || "/home/heathledger/.ioi/hypervisor/data";
const EMAIL = "scim.user@papabearcarwash.com";

const checks = [];
let failures = 0;
const ok = (cond, msg, detail) => { checks.push({ ok: !!cond, msg }); if (!cond) failures++; if (!JSON_OUT) console.log(`    ${cond ? "✓" : "✗ FAIL:"} ${msg}${detail ? ` (${detail})` : ""}`); };
const blocked = (reason) => { console.log(JSON_OUT ? JSON.stringify({ workstream: "scim", verdict: "BLOCKED", reason }, null, 2) : `  BLOCKED: ${reason}`); process.exit(2); };
const ja = async (rpc, b) => { const r = await fetch(`${SERVE}/api/gitpod.v1.OrganizationService/${rpc}`, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify(b || {}) }); const t = await r.text(); return { status: r.status, body: t ? JSON.parse(t) : {} }; };
const scim = async (m, p, tok, b) => { const r = await fetch(`${SERVE}/scim/v2${p}`, { method: m, headers: { ...(tok ? { Authorization: `Bearer ${tok}` } : {}), "Content-Type": "application/scim+json" }, body: b ? JSON.stringify(b) : undefined }); const t = await r.text(); return { status: r.status, body: t ? JSON.parse(t) : {} }; };

if (!JSON_OUT) console.log("SCIM 2.0 e2e — provision/deprovision via the public /scim/v2 endpoint");
try { const r = await fetch(`${SERVE}/ai`, { signal: AbortSignal.timeout(3000) }); if (!r.ok) throw 0; } catch { blocked("serve (:4173) not running"); }
try { const r = await fetch(`${DAEMON}/v1/hypervisor/auth/whoami`, { signal: AbortSignal.timeout(3000) }); if (!r.ok) throw 0; } catch { blocked("hypervisor-daemon (:8765) not running"); }

// self-heal any residue from a prior run (SCIM create is conflict-on-exists)
{ const r = await fetch(`${DAEMON}/v1/hypervisor/principals`); const d = await r.json().catch(() => ({})); for (const p of (d.principals || [])) if (p.email === EMAIL) await fetch(`${DAEMON}/v1/hypervisor/principals/${p.principal_id}?purge=true`, { method: "DELETE" }); }

// 1) Provision a SCIM connection → bearer token returned ONCE.
const create = await ja("CreateSCIMConfiguration", { name: "Okta" });
const token = create.body?.scimConfiguration?.bearerToken;
ok(create.status === 200 && typeof token === "string" && token.startsWith("scim_"), "CreateSCIMConfiguration mints a SCIM bearer token (once)");
// token must be hash-only at rest
const list = await ja("ListSCIMConfigurations", {});
ok(JSON.stringify(list.body).indexOf(token) === -1, "SCIM token never appears in config listings");
if (existsSync(DATA_DIR)) {
  const f = join(DATA_DIR, "scim-configurations", "scim-config.json");
  ok(existsSync(f) && !readFileSync(f, "utf8").includes(token) && readFileSync(f, "utf8").includes("token_hash"), "on-disk SCIM config stores only the token hash");
} else ok(true, "on-disk token-hash check skipped");

// 2) Auth: SPC requires the bearer.
ok((await scim("GET", "/ServiceProviderConfig", "")).status === 401, "SCIM endpoint without token → 401");
ok((await scim("GET", "/ServiceProviderConfig", token)).status === 200, "SCIM endpoint with token → 200");

// 3) Provision a user → 201; creates a principal (source scim).
const cu = await scim("POST", "/Users", token, { schemas: ["urn:ietf:params:scim:schemas:core:2.0:User"], userName: EMAIL, name: { givenName: "Scim", familyName: "User" }, emails: [{ value: EMAIL, primary: true }], active: true, externalId: "ext-123" });
const uid = cu.body?.id;
ok(cu.status === 201 && cu.body?.userName === EMAIL && cu.body?.active === true && !!uid, "POST /Users provisions a user (201)", uid);

// 4) Filter + get.
const filtered = await scim("GET", `/Users?filter=${encodeURIComponent(`userName eq "${EMAIL}"`)}`, token);
ok((filtered.body?.Resources || []).some((u) => u.id === uid), "GET /Users?filter resolves the provisioned user");
ok((await scim("GET", `/Users/${uid}`, token)).body?.id === uid, "GET /Users/:id returns the user");

// 5) The provisioned user appears in the org roster (ListMembers) while active.
const members1 = await ja("ListMembers", {});
ok((members1.body?.members || []).some((m) => m.email === EMAIL), "provisioned user appears in ListMembers (active)");

// 6) Deprovision via PATCH active:false → principal deactivated → drops from the roster.
const patch = await scim("PATCH", `/Users/${uid}`, token, { schemas: ["urn:ietf:params:scim:api:messages:2.0:PatchOp"], Operations: [{ op: "replace", path: "active", value: false }] });
ok(patch.status === 200 && patch.body?.active === false, "PATCH active:false deprovisions the user");
const members2 = await ja("ListMembers", {});
ok(!(members2.body?.members || []).some((m) => m.email === EMAIL), "deprovisioned user drops from ListMembers");

// 7) Groups: create → list → delete.
const cg = await scim("POST", "/Groups", token, { schemas: ["urn:ietf:params:scim:schemas:core:2.0:Group"], displayName: "Engineering", members: [{ value: uid }] });
const gid = cg.body?.id;
ok(cg.status === 201 && cg.body?.displayName === "Engineering", "POST /Groups creates a group");
ok((await scim("GET", "/Groups", token)).body?.Resources?.some((g) => g.id === gid), "GET /Groups lists the group");
ok((await scim("DELETE", `/Groups/${gid}`, token)).status === 204, "DELETE /Groups/:id removes the group (204)");

// 8) operator is not SCIM-managed.
ok((await scim("DELETE", "/Users/00000000-0000-4000-8000-000000000001", token)).status === 403, "the operator principal is not SCIM-deletable (403)");

// cleanup
await fetch(`${DAEMON}/v1/hypervisor/principals/${uid}?purge=true`, { method: "DELETE" }).catch(() => {});
await ja("DeleteSCIMConfiguration", { scimConfigurationId: "scim-config" });

const passed = checks.length - failures;
if (JSON_OUT) console.log(JSON.stringify({ workstream: "scim", verdict: failures ? "FAIL" : "PASS", passed, total: checks.length }, null, 2));
else console.log(`\n  ${failures ? "✗" : "✓"} scim ${passed}/${checks.length}`);
process.exit(failures ? 1 : 0);
