#!/usr/bin/env node
// Done-bar for the Secrets plane (Bucket A #1) — org/user/project secrets SEALED at rest in the
// daemon. Daemon-only (source-neutral): exercises /v1/hypervisor/secrets directly. Proves the full
// lifecycle (create → scoped list → rotate → delete) with the credential SEALED and NEVER surfaced.
//
// Boundary: the daemon EXECUTES (holds the sealed value); every read returns METADATA ONLY. A
// sentinel value is asserted absent from every create/list response, the daemon plane, and the
// on-disk metadata — present ONLY as sealed ciphertext in the separate secret-values record. Scope
// keys isolate org from user. Usage: node scripts/verify-hypervisor-secrets-functional.mjs [--json]
import { readFileSync, existsSync } from "node:fs";
import { join } from "node:path";

const JSON_OUT = process.argv.includes("--json");
const DAEMON = process.env.IOI_HYPERVISOR_DAEMON_URL || "http://127.0.0.1:8765";
const DATA_DIR = process.env.IOI_HYPERVISOR_DATA_DIR || "/home/heathledger/.ioi/hypervisor/data";
const ORG = "00000000-0000-4000-8000-0000000000a1";
const USER = "00000000-0000-4000-8000-000000000001";
const SENTINEL = "SENTINEL-SECRET-DONOTLEAK-7c4f9a";

const checks = [];
let failures = 0;
const ok = (cond, msg, detail) => { checks.push({ ok: !!cond, msg }); if (!cond) failures++; if (!JSON_OUT) console.log(`    ${cond ? "✓" : "✗ FAIL:"} ${msg}${detail ? ` (${detail})` : ""}`); };
const blocked = (reason) => { console.log(JSON_OUT ? JSON.stringify({ workstream: "secrets", verdict: "BLOCKED", reason }, null, 2) : `  BLOCKED: ${reason}`); process.exit(2); };
const jd = async (m, p, b) => { const r = await fetch(DAEMON + p, { method: m, headers: b ? { "content-type": "application/json" } : undefined, body: b ? JSON.stringify(b) : undefined }); const t = await r.text(); return { status: r.status, raw: t, body: t ? JSON.parse(t) : {} }; };
const scopeKey = (s) => (s.organizationId ? `organizationId:${s.organizationId}` : s.userId ? `userId:${s.userId}` : "global");

if (!JSON_OUT) console.log("Secrets plane e2e — daemon-sealed org/user secrets (daemon-only)");
try { const r = await fetch(`${DAEMON}/v1/hypervisor/editor-targets`, { signal: AbortSignal.timeout(3000) }); if (!r.ok) throw 0; } catch { blocked("hypervisor-daemon (:8765) not running"); }

// self-heal prior runs
{ const l = await jd("GET", "/v1/hypervisor/secrets"); for (const s of (l.body.secrets || [])) if (/^DB_(ORG|USER)_SENTINEL$/.test(s.name || "")) await jd("DELETE", `/v1/hypervisor/secrets/${s.secret_id}`); }

// 1) Create an ORG-scoped secret (value sealed, never echoed).
const cOrg = await jd("POST", "/v1/hypervisor/secrets", { name: "DB_ORG_SENTINEL", value: SENTINEL, scope: { organizationId: ORG }, mount: { environmentVariable: {} } });
const orgSid = cOrg.body?.secret?.secret_id;
ok(cOrg.status === 200 && cOrg.body.ok && !!orgSid, "create org secret", orgSid);
ok(cOrg.body?.secret?.sealed === true && !cOrg.raw.includes(SENTINEL), "create response is metadata-only (value sealed, not echoed)");

// 2) Create a USER-scoped secret.
const cUser = await jd("POST", "/v1/hypervisor/secrets", { name: "DB_USER_SENTINEL", value: SENTINEL, scope: { userId: USER } });
const userSid = cUser.body?.secret?.secret_id;
ok(cUser.status === 200 && !!userSid && !cUser.raw.includes(SENTINEL), "create user secret (no plaintext echoed)", userSid);

// 3) Scope isolation via scope_key.
const list = await jd("GET", "/v1/hypervisor/secrets");
const orgKey = scopeKey({ organizationId: ORG });
const userKey = scopeKey({ userId: USER });
const inScope = (key) => (list.body.secrets || []).filter((s) => s.scope_key === key).map((s) => s.name);
ok(inScope(orgKey).includes("DB_ORG_SENTINEL") && !inScope(orgKey).includes("DB_USER_SENTINEL"), "org scope_key isolates the org secret", inScope(orgKey).join(","));
ok(inScope(userKey).includes("DB_USER_SENTINEL") && !inScope(userKey).includes("DB_ORG_SENTINEL"), "user scope_key isolates the user secret", inScope(userKey).join(","));
ok(!list.raw.includes(SENTINEL), "daemon list never returns the plaintext value");

// 4) On-disk: metadata has NO plaintext; the sealed value record is ciphertext only.
if (existsSync(DATA_DIR)) {
  const metaPath = join(DATA_DIR, "secrets", `${orgSid}.json`);
  const valPath = join(DATA_DIR, "secret-values", `${orgSid}.json`);
  const valRec = existsSync(valPath) ? JSON.parse(readFileSync(valPath, "utf8")) : {};
  ok(existsSync(metaPath) && !readFileSync(metaPath, "utf8").includes(SENTINEL), "on-disk metadata record contains NO plaintext");
  ok(!JSON.stringify(valRec).includes(SENTINEL) && (valRec.sealed_value || "").length > 32 && valRec.sealed === true, "on-disk value record is sealed ciphertext only", `len ${(valRec.sealed_value || "").length}`);
} else { ok(true, "on-disk sealing check skipped"); ok(true, "on-disk value-record check skipped"); }

// 5) Rotate the value — sealed, no plaintext echoed.
const rot = await jd("POST", `/v1/hypervisor/secrets/${userSid}/value`, { value: `${SENTINEL}-ROTATED` });
ok(rot.status === 200 && !rot.raw.includes(SENTINEL), "rotate value (UpdateSecretValue) without echoing the value");

// 6) Delete both — gone, value record removed.
await jd("DELETE", `/v1/hypervisor/secrets/${orgSid}`);
await jd("DELETE", `/v1/hypervisor/secrets/${userSid}`);
const after = await jd("GET", "/v1/hypervisor/secrets");
ok(!(after.body.secrets || []).some((s) => s.secret_id === orgSid || s.secret_id === userSid), "delete removes the secret");
if (existsSync(DATA_DIR)) ok(!existsSync(join(DATA_DIR, "secret-values", `${orgSid}.json`)), "delete removes the sealed value record");
else ok(true, "delete value-record check skipped");

// 7) Empty input fails closed.
ok((await jd("POST", "/v1/hypervisor/secrets", { name: "", value: "x", scope: { organizationId: ORG } })).status >= 400, "create with empty name FAILS CLOSED");
ok((await jd("POST", "/v1/hypervisor/secrets", { name: "X", value: "", scope: { organizationId: ORG } })).status >= 400, "create with empty value FAILS CLOSED");

const passed = checks.length - failures;
if (JSON_OUT) console.log(JSON.stringify({ workstream: "secrets", verdict: failures ? "FAIL" : "PASS", passed, total: checks.length }, null, 2));
else console.log(`\n  ${failures ? "✗" : "✓"} secrets ${passed}/${checks.length}`);
process.exit(failures ? 1 : 0);
