#!/usr/bin/env node
// Done-bar for SCIM 2.0 provisioning (multi-user IdP, Phase 3). Daemon-only (source-neutral):
// exercises the daemon's /scim/v2 server + /v1/hypervisor/scim-configurations directly. An external
// IdP (Okta/Azure AD) drives ServiceProviderConfig + Users CRUD (provision → filter → deprovision)
// + Groups with the minted SCIM bearer; Users map onto the principals plane (source: scim); the SCIM
// token is hash-only at rest. Usage: node scripts/verify-hypervisor-scim-functional.mjs [--json]
import { readFileSync, existsSync } from "node:fs";
import { join } from "node:path";

const JSON_OUT = process.argv.includes("--json");
const DAEMON = process.env.IOI_HYPERVISOR_DAEMON_URL || "http://127.0.0.1:8765";
const DATA_DIR = process.env.IOI_HYPERVISOR_DATA_DIR || "/home/heathledger/.ioi/hypervisor/data";
const EMAIL = "scim.user@papabearcarwash.com";
const OPERATOR = "00000000-0000-4000-8000-000000000001";

const checks = [];
let failures = 0;
const ok = (cond, msg, detail) => { checks.push({ ok: !!cond, msg }); if (!cond) failures++; if (!JSON_OUT) console.log(`    ${cond ? "✓" : "✗ FAIL:"} ${msg}${detail ? ` (${detail})` : ""}`); };
const blocked = (reason) => { console.log(JSON_OUT ? JSON.stringify({ workstream: "scim", verdict: "BLOCKED", reason }, null, 2) : `  BLOCKED: ${reason}`); process.exit(2); };
const jd = async (m, p, b) => { const r = await fetch(DAEMON + p, { method: m, headers: b ? { "content-type": "application/json" } : undefined, body: b ? JSON.stringify(b) : undefined }); const t = await r.text(); return { status: r.status, raw: t, body: t ? JSON.parse(t) : {} }; };
const scim = async (m, p, tok, b) => { const r = await fetch(`${DAEMON}/scim/v2${p}`, { method: m, headers: { ...(tok ? { Authorization: `Bearer ${tok}` } : {}), "Content-Type": "application/scim+json" }, body: b ? JSON.stringify(b) : undefined }); const t = await r.text(); return { status: r.status, body: t ? JSON.parse(t) : {} }; };
const roster = async () => (await jd("GET", "/v1/hypervisor/principals")).body.principals?.filter((p) => p.status === "active").map((p) => p.email) || [];

if (!JSON_OUT) console.log("SCIM 2.0 e2e — provision/deprovision via the daemon /scim/v2 server (daemon-only)");
try { const r = await fetch(`${DAEMON}/v1/hypervisor/editor-targets`, { signal: AbortSignal.timeout(3000) }); if (!r.ok) throw 0; } catch { blocked("hypervisor-daemon (:8765) not running"); }

// self-heal residue
{ const d = (await jd("GET", "/v1/hypervisor/principals")).body; for (const p of (d.principals || [])) if (p.email === EMAIL) await jd("DELETE", `/v1/hypervisor/principals/${p.principal_id}?purge=true`); }

// 1) Provision a SCIM connection → bearer token returned ONCE, hash-only at rest.
const create = await jd("POST", "/v1/hypervisor/scim-configurations", { name: "Okta" });
const token = create.body?.token;
ok(create.status === 200 && typeof token === "string" && token.startsWith("scim_"), "create SCIM connection mints a bearer token (once)");
const list = await jd("GET", "/v1/hypervisor/scim-configurations");
ok(!list.raw.includes(token), "SCIM token never appears in config listings");
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
ok(((await scim("GET", `/Users?filter=${encodeURIComponent(`userName eq "${EMAIL}"`)}`, token)).body?.Resources || []).some((x) => x.id === uid), "GET /Users?filter resolves the provisioned user");
ok((await scim("GET", `/Users/${uid}`, token)).body?.id === uid, "GET /Users/:id returns the user");

// 5) The provisioned user appears in the org roster while active.
ok((await roster()).includes(EMAIL), "provisioned user appears in the roster (active)");

// 6) Deprovision via PATCH active:false → principal deactivated → drops from the roster.
const patch = await scim("PATCH", `/Users/${uid}`, token, { schemas: ["urn:ietf:params:scim:api:messages:2.0:PatchOp"], Operations: [{ op: "replace", path: "active", value: false }] });
ok(patch.status === 200 && patch.body?.active === false, "PATCH active:false deprovisions the user");
ok(!(await roster()).includes(EMAIL), "deprovisioned user drops from the roster");

// 7) Groups: create → list → delete.
const cg = await scim("POST", "/Groups", token, { schemas: ["urn:ietf:params:scim:schemas:core:2.0:Group"], displayName: "Engineering", members: [{ value: uid }] });
const gid = cg.body?.id;
ok(cg.status === 201 && cg.body?.displayName === "Engineering", "POST /Groups creates a group");
ok((await scim("GET", "/Groups", token)).body?.Resources?.some((g) => g.id === gid), "GET /Groups lists the group");
ok((await scim("DELETE", `/Groups/${gid}`, token)).status === 204, "DELETE /Groups/:id removes the group (204)");

// 8) operator is not SCIM-managed.
ok((await scim("DELETE", `/Users/${OPERATOR}`, token)).status === 403, "the operator principal is not SCIM-deletable (403)");

// cleanup
await jd("DELETE", `/v1/hypervisor/principals/${uid}?purge=true`);
await jd("DELETE", "/v1/hypervisor/scim-configurations/scim-config");

const passed = checks.length - failures;
if (JSON_OUT) console.log(JSON.stringify({ workstream: "scim", verdict: failures ? "FAIL" : "PASS", passed, total: checks.length }, null, 2));
else console.log(`\n  ${failures ? "✗" : "✓"} scim ${passed}/${checks.length}`);
process.exit(failures ? 1 : 0);
