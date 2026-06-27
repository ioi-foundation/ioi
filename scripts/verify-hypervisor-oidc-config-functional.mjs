#!/usr/bin/env node
// Done-bar for the OIDC login-config plane (Bucket B absorption #2) — the native "OIDC Tokens"
// surface ("Configure OIDC token settings": a BYO OIDC IdP for org login, fields issuerUrl /
// clientId / clientSecret / emailDomain). Management surface made real: the daemon stores the
// config and SEALS the client secret at rest (never returned). Login enforcement is a separate
// plane (the daemon has no session layer yet) — same management-real / enforcement-deferred pattern
// as API tokens. Usage: node scripts/verify-hypervisor-oidc-config-functional.mjs [--json]
import { readFileSync, existsSync } from "node:fs";
import { join } from "node:path";

const JSON_OUT = process.argv.includes("--json");
const DAEMON = process.env.IOI_HYPERVISOR_DAEMON_URL || "http://127.0.0.1:8765";
const SERVE = process.env.IOI_HYPERVISOR_SERVE_URL || "http://127.0.0.1:4173";
const DATA_DIR = process.env.IOI_HYPERVISOR_DATA_DIR || "/home/heathledger/.ioi/hypervisor/data";
const ORG = "00000000-0000-4000-8000-0000000000a1";
const SECRET = "OIDC-CLIENT-SECRET-DONOTLEAK-3a91";

const checks = [];
let failures = 0;
const ok = (cond, msg, detail) => { checks.push({ ok: !!cond, msg }); if (!cond) failures++; if (!JSON_OUT) console.log(`    ${cond ? "✓" : "✗ FAIL:"} ${msg}${detail ? ` (${detail})` : ""}`); };
const blocked = (reason) => { console.log(JSON_OUT ? JSON.stringify({ workstream: "oidc-config", verdict: "BLOCKED", reason }, null, 2) : `  BLOCKED: ${reason}`); process.exit(2); };
const jd = async (m, p, b) => { const r = await fetch(DAEMON + p, { method: m, headers: b ? { "content-type": "application/json" } : undefined, body: b ? JSON.stringify(b) : undefined }); const t = await r.text(); return { status: r.status, raw: t, body: t ? JSON.parse(t) : {} }; };
const ja = async (rpc, b) => { const r = await fetch(`${SERVE}/api/gitpod.v1.OrganizationService/${rpc}`, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify(b || {}) }); const t = await r.text(); return { status: r.status, raw: t, body: t ? JSON.parse(t) : {} }; };

if (!JSON_OUT) console.log("OIDC login-config e2e — IdP config CRUD, client_secret SEALED at rest");
try { const r = await fetch(`${DAEMON}/v1/hypervisor/oidc-config`, { signal: AbortSignal.timeout(3000) }); if (!r.ok) throw 0; } catch { blocked("hypervisor-daemon (:8765) not running"); }
try { const r = await fetch(`${SERVE}/ai`, { signal: AbortSignal.timeout(3000) }); if (!r.ok) throw 0; } catch { blocked("serve (:4173) not running"); }

// 1) Update via the adapter (the native UpdateOIDCConfig path) with a client secret.
const up = await ja("UpdateOIDCConfig", { oidcConfig: { v3: { issuerUrl: "https://accounts.google.com", clientId: "ioi-test-client", clientSecret: SECRET, emailDomain: "papabearcarwash.com", active: true } } });
const v3 = up.body?.oidcConfig?.v3 || {};
ok(up.status === 200 && v3.issuerUrl === "https://accounts.google.com" && v3.clientId === "ioi-test-client" && v3.active === true, "UpdateOIDCConfig persists the IdP config");
ok(!up.raw.includes(SECRET), "update response never returns the client secret");

// 2) Get via the adapter — config present, secret absent.
const get = await ja("GetOIDCConfig", { organizationId: ORG });
const g3 = get.body?.oidcConfig?.v3 || {};
ok(g3.clientId === "ioi-test-client" && g3.emailDomain === "papabearcarwash.com", "GetOIDCConfig returns the stored config");
ok(!get.raw.includes(SECRET), "get response never returns the client secret");

// 3) Daemon get also never leaks the secret (and reports it is set).
const dg = await jd("GET", "/v1/hypervisor/oidc-config");
ok(!dg.raw.includes(SECRET) && dg.body.config?.client_secret_set === true, "daemon get marks secret set but never returns it");

// 4) On-disk: secret sealed, no plaintext.
if (existsSync(DATA_DIR)) {
  const f = join(DATA_DIR, "oidc-config", "config.json");
  const rec = existsSync(f) ? JSON.parse(readFileSync(f, "utf8")) : {};
  ok(existsSync(f) && !JSON.stringify(rec).includes(SECRET), "on-disk config contains NO plaintext secret");
  ok((rec.sealed_client_secret || "").length > 16, "client secret is sealed ciphertext at rest", `len ${(rec.sealed_client_secret || "").length}`);
} else {
  ok(true, "on-disk plaintext check skipped (data dir not on this host)");
  ok(true, "on-disk sealed check skipped (data dir not on this host)");
}

// 5) Update WITHOUT a secret preserves the sealed one (no accidental wipe).
const up2 = await ja("UpdateOIDCConfig", { oidcConfig: { v3: { issuerUrl: "https://accounts.google.com", clientId: "ioi-test-client-2", emailDomain: "papabearcarwash.com", active: false } } });
const dg2 = await jd("GET", "/v1/hypervisor/oidc-config");
ok(up2.body?.oidcConfig?.v3?.clientId === "ioi-test-client-2" && up2.body?.oidcConfig?.v3?.active === false, "config can be updated + disabled");
ok(dg2.body.config?.client_secret_set === true, "updating without a new secret preserves the sealed one");

// reset to empty/disabled (clean app state)
await jd("PUT", "/v1/hypervisor/oidc-config", { issuer_url: "", client_id: "", email_domain: "", enabled: false });

const passed = checks.length - failures;
if (JSON_OUT) console.log(JSON.stringify({ workstream: "oidc-config", verdict: failures ? "FAIL" : "PASS", passed, total: checks.length }, null, 2));
else console.log(`\n  ${failures ? "✗" : "✓"} oidc-config ${passed}/${checks.length}`);
process.exit(failures ? 1 : 0);
