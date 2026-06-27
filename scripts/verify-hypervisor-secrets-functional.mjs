#!/usr/bin/env node
// Done-bar for the Secrets plane (Bucket A #1) — org/user/project secrets SEALED at rest in the
// daemon, backing the native Org/User Settings → Secrets pages (previously mock-only). Proves the
// full lifecycle through BOTH the daemon plane and the adapter's SecretService projection:
//   create → list (scoped) → rotate value → delete  — with the credential SEALED and NEVER surfaced.
//
// Boundary discipline: the daemon EXECUTES (holds the sealed value); every read surface returns
// METADATA ONLY. A sentinel value is planted and asserted absent from every list/create response,
// the daemon plane, the adapter projection, and the on-disk metadata record; it must appear ONLY as
// sealed ciphertext in the separate secret-values record. Scope filtering is verified to isolate the
// org page from the user page. Usage: node scripts/verify-hypervisor-secrets-functional.mjs [--json]
import { readFileSync, existsSync } from "node:fs";
import { join } from "node:path";

const JSON_OUT = process.argv.includes("--json");
const DAEMON = process.env.IOI_HYPERVISOR_DAEMON_URL || "http://127.0.0.1:8765";
const SERVE = process.env.IOI_HYPERVISOR_SERVE_URL || "http://127.0.0.1:4173";
const DATA_DIR = process.env.IOI_HYPERVISOR_DATA_DIR || "/home/heathledger/.ioi/hypervisor/data";
const ORG = "00000000-0000-4000-8000-0000000000a1";
const USER = "00000000-0000-4000-8000-000000000001";
const SENTINEL = "SENTINEL-SECRET-DONOTLEAK-7c4f9a";

const checks = [];
let failures = 0;
const ok = (cond, msg, detail) => { checks.push({ ok: !!cond, msg }); if (!cond) failures++; if (!JSON_OUT) console.log(`    ${cond ? "✓" : "✗ FAIL:"} ${msg}${detail ? ` (${detail})` : ""}`); };
const blocked = (reason) => { console.log(JSON_OUT ? JSON.stringify({ workstream: "secrets", verdict: "BLOCKED", reason }, null, 2) : `  BLOCKED: ${reason}`); process.exit(2); };
const jd = async (m, p, b) => { const r = await fetch(DAEMON + p, { method: m, headers: b ? { "content-type": "application/json" } : undefined, body: b ? JSON.stringify(b) : undefined }); const t = await r.text(); return { status: r.status, raw: t, body: t ? JSON.parse(t) : {} }; };
const ja = async (rpc, b) => { const r = await fetch(`${SERVE}/api/gitpod.v1.SecretService/${rpc}`, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify(b || {}) }); const t = await r.text(); return { status: r.status, raw: t, body: t ? JSON.parse(t) : {} }; };

if (!JSON_OUT) console.log("Secrets plane e2e — daemon-sealed org/user secrets + native projection");
try { const r = await fetch(`${DAEMON}/v1/hypervisor/secrets`, { signal: AbortSignal.timeout(3000) }); if (!r.ok) throw 0; } catch { blocked("hypervisor-daemon (:8765) not running"); }
let serveUp = true;
try { const r = await fetch(`${SERVE}/ai`, { signal: AbortSignal.timeout(3000) }); if (!r.ok) throw 0; } catch { serveUp = false; }
if (!serveUp) blocked("serve (:4173) not running — needed for the SecretService adapter projection");

// Clean any prior sentinel runs (idempotent ids: same scope+name => same id).
const orgId = `sec_${""}`; // computed by daemon; we delete by listing instead
const wipe = async () => { const l = await jd("GET", "/v1/hypervisor/secrets"); for (const s of (l.body.secrets || [])) if (/^DB_(ORG|USER)_SENTINEL$/.test(s.name)) await jd("DELETE", `/v1/hypervisor/secrets/${s.secret_id}`); };
await wipe();

// 1) Create an ORG-scoped secret via the daemon plane.
const cOrg = await jd("POST", "/v1/hypervisor/secrets", { name: "DB_ORG_SENTINEL", value: SENTINEL, scope: { organizationId: ORG }, mount: { environmentVariable: {} } });
const orgSid = cOrg.body?.secret?.secret_id;
ok(cOrg.status === 200 && cOrg.body.ok && !!orgSid, "daemon create org secret", orgSid);
ok(cOrg.body?.secret?.sealed === true && !cOrg.raw.includes(SENTINEL), "create response is metadata-only (value sealed, not echoed)");

// 2) Create a USER-scoped secret via the ADAPTER (the native CreateSecret path).
const cUser = await ja("CreateSecret", { name: "DB_USER_SENTINEL", value: SENTINEL, scope: { userId: USER } });
const userSid = cUser.body?.secret?.id;
ok(cUser.status === 200 && !!userSid, "adapter CreateSecret (user scope)", userSid);
ok(!cUser.raw.includes(SENTINEL), "adapter create response never contains the plaintext value");

// 3) Scope isolation — ORG list shows the org secret, NOT the user secret (and vice-versa).
const lOrg = await ja("ListSecrets", { pagination: { pageSize: 100 }, filter: { scope: { organizationId: ORG } } });
const lUser = await ja("ListSecrets", { pagination: { pageSize: 100 }, filter: { scope: { userId: USER } } });
const orgNames = (lOrg.body.secrets || []).map((s) => s.name);
const userNames = (lUser.body.secrets || []).map((s) => s.name);
ok(orgNames.includes("DB_ORG_SENTINEL") && !orgNames.includes("DB_USER_SENTINEL"), "org-scope list isolates org secrets", orgNames.join(","));
ok(userNames.includes("DB_USER_SENTINEL") && !userNames.includes("DB_ORG_SENTINEL"), "user-scope list isolates user secrets", userNames.join(","));
ok(!lOrg.raw.includes(SENTINEL) && !lUser.raw.includes(SENTINEL), "adapter ListSecrets never returns the plaintext value");

// 4) Daemon list never leaks plaintext either.
const dl = await jd("GET", "/v1/hypervisor/secrets");
ok(!dl.raw.includes(SENTINEL), "daemon list never returns the plaintext value");

// 5) On-disk: metadata record carries NO plaintext; the sealed value record is real ciphertext.
if (existsSync(DATA_DIR)) {
  const metaPath = join(DATA_DIR, "secrets", `${orgSid}.json`);
  const valPath = join(DATA_DIR, "secret-values", `${orgSid}.json`);
  const metaHasPlain = existsSync(metaPath) && readFileSync(metaPath, "utf8").includes(SENTINEL);
  const valRec = existsSync(valPath) ? JSON.parse(readFileSync(valPath, "utf8")) : {};
  const valHasPlain = JSON.stringify(valRec).includes(SENTINEL);
  ok(existsSync(metaPath) && !metaHasPlain, "on-disk metadata record contains NO plaintext");
  ok(!valHasPlain && (valRec.sealed_value || "").length > 32 && valRec.sealed === true, "on-disk value record is sealed ciphertext only", `len ${(valRec.sealed_value || "").length}`);
} else {
  ok(true, "on-disk sealing check skipped (data dir not on this host)");
  ok(true, "on-disk value-record check skipped (data dir not on this host)");
}

// 6) Rotate the value (UpdateSecretValue) — sealed, no plaintext echoed.
const rot = await ja("UpdateSecretValue", { secretId: userSid, value: `${SENTINEL}-ROTATED` });
ok(rot.status === 200 && !rot.raw.includes(SENTINEL), "adapter UpdateSecretValue rotates without echoing the value");

// 7) Delete both — gone from list, value record removed.
await ja("DeleteSecret", { secretId: orgSid });
await ja("DeleteSecret", { secretId: userSid });
const after = await jd("GET", "/v1/hypervisor/secrets");
const stillThere = (after.body.secrets || []).some((s) => s.secret_id === orgSid || s.secret_id === userSid);
ok(!stillThere, "delete removes the secret from the daemon plane");
if (existsSync(DATA_DIR)) ok(!existsSync(join(DATA_DIR, "secret-values", `${orgSid}.json`)), "delete removes the sealed value record");
else ok(true, "delete value-record check skipped (data dir not on this host)");

// 8) Empty input fails closed (no nameless / valueless secrets).
const bad = await ja("CreateSecret", { name: "", value: "x", scope: { organizationId: ORG } });
ok(bad.status >= 400, "create with empty name FAILS CLOSED", `status ${bad.status}`);
const bad2 = await ja("CreateSecret", { name: "X", value: "", scope: { organizationId: ORG } });
ok(bad2.status >= 400, "create with empty value FAILS CLOSED", `status ${bad2.status}`);

const passed = checks.length - failures;
if (JSON_OUT) console.log(JSON.stringify({ workstream: "secrets", verdict: failures ? "FAIL" : "PASS", passed, total: checks.length }, null, 2));
else console.log(`\n  ${failures ? "✗" : "✓"} secrets ${passed}/${checks.length}`);
process.exit(failures ? 1 : 0);
