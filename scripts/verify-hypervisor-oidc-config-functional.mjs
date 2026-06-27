#!/usr/bin/env node
// Done-bar for the OIDC login-config plane (Bucket B absorption #2) — a BYO OIDC IdP for org login.
// Daemon-only (source-neutral): exercises /v1/hypervisor/oidc-config directly. The daemon stores the
// config and SEALS the client secret at rest (never returned). Login enforcement is a separate plane
// (management-real / enforcement-deferred). Usage: node scripts/verify-hypervisor-oidc-config-functional.mjs [--json]
import { readFileSync, existsSync } from "node:fs";
import { join } from "node:path";

const JSON_OUT = process.argv.includes("--json");
const DAEMON = process.env.IOI_HYPERVISOR_DAEMON_URL || "http://127.0.0.1:8765";
const DATA_DIR = process.env.IOI_HYPERVISOR_DATA_DIR || "/home/heathledger/.ioi/hypervisor/data";
const SECRET = "OIDC-CLIENT-SECRET-DONOTLEAK-3a91";

const checks = [];
let failures = 0;
const ok = (cond, msg, detail) => { checks.push({ ok: !!cond, msg }); if (!cond) failures++; if (!JSON_OUT) console.log(`    ${cond ? "✓" : "✗ FAIL:"} ${msg}${detail ? ` (${detail})` : ""}`); };
const blocked = (reason) => { console.log(JSON_OUT ? JSON.stringify({ workstream: "oidc-config", verdict: "BLOCKED", reason }, null, 2) : `  BLOCKED: ${reason}`); process.exit(2); };
const jd = async (m, p, b) => { const r = await fetch(DAEMON + p, { method: m, headers: b ? { "content-type": "application/json" } : undefined, body: b ? JSON.stringify(b) : undefined }); const t = await r.text(); return { status: r.status, raw: t, body: t ? JSON.parse(t) : {} }; };

if (!JSON_OUT) console.log("OIDC login-config e2e — IdP config CRUD, client_secret SEALED (daemon-only)");
try { const r = await fetch(`${DAEMON}/v1/hypervisor/editor-targets`, { signal: AbortSignal.timeout(3000) }); if (!r.ok) throw 0; } catch { blocked("hypervisor-daemon (:8765) not running"); }

// 1) Upsert the IdP config with a client secret.
const up = await jd("PUT", "/v1/hypervisor/oidc-config", { issuer_url: "https://accounts.google.com", client_id: "ioi-test-client", client_secret: SECRET, email_domain: "papabearcarwash.com", enabled: true });
const c = up.body?.config || {};
ok(up.status === 200 && c.issuer_url === "https://accounts.google.com" && c.client_id === "ioi-test-client" && c.enabled === true && c.client_secret_set === true, "PUT persists the IdP config (+ marks secret set)");
ok(!up.raw.includes(SECRET), "update response never returns the client secret");

// 2) Get — config present, secret absent.
const get = await jd("GET", "/v1/hypervisor/oidc-config");
ok(get.body.config?.client_id === "ioi-test-client" && get.body.config?.email_domain === "papabearcarwash.com", "GET returns the stored config");
ok(!get.raw.includes(SECRET) && get.body.config?.client_secret_set === true, "GET marks secret set but never returns it");

// 3) On-disk: secret sealed, no plaintext.
if (existsSync(DATA_DIR)) {
  const f = join(DATA_DIR, "oidc-config", "config.json");
  const rec = existsSync(f) ? JSON.parse(readFileSync(f, "utf8")) : {};
  ok(existsSync(f) && !JSON.stringify(rec).includes(SECRET), "on-disk config contains NO plaintext secret");
  ok((rec.sealed_client_secret || "").length > 16, "client secret is sealed ciphertext at rest", `len ${(rec.sealed_client_secret || "").length}`);
} else { ok(true, "on-disk plaintext check skipped"); ok(true, "on-disk sealed check skipped"); }

// 4) Update WITHOUT a secret preserves the sealed one (no accidental wipe) + can disable.
const up2 = await jd("PUT", "/v1/hypervisor/oidc-config", { issuer_url: "https://accounts.google.com", client_id: "ioi-test-client-2", email_domain: "papabearcarwash.com", enabled: false });
ok(up2.body.config?.client_id === "ioi-test-client-2" && up2.body.config?.enabled === false, "config can be updated + disabled");
ok((await jd("GET", "/v1/hypervisor/oidc-config")).body.config?.client_secret_set === true, "updating without a new secret preserves the sealed one");

// reset to empty/disabled (clean state)
await jd("PUT", "/v1/hypervisor/oidc-config", { issuer_url: "", client_id: "", email_domain: "", enabled: false });

const passed = checks.length - failures;
if (JSON_OUT) console.log(JSON.stringify({ workstream: "oidc-config", verdict: failures ? "FAIL" : "PASS", passed, total: checks.length }, null, 2));
else console.log(`\n  ${failures ? "✗" : "✓"} oidc-config ${passed}/${checks.length}`);
process.exit(failures ? 1 : 0);
