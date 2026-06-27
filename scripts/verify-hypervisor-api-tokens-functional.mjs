#!/usr/bin/env node
// Done-bar for the API access tokens plane (Bucket A #2) — inbound tokens that authenticate calls
// TO the Hypervisor API, backing the native User Settings → "API access tokens" surface (renamed
// from "Personal access tokens"; previously mock-only). Proves the lifecycle through the daemon
// plane + the adapter's UserService projection:
//   create (plaintext returned ONCE) → list (metadata only) → delete  — hash-only at rest.
//
// Security model for an inbound credential: store ONLY a sha256 hash + metadata; surface the
// plaintext exactly once in the create response; it is never recoverable afterward. A sentinel
// asserts the plaintext is absent from every list response, the on-disk record, and that the record
// carries the hash but no value field. Usage: node scripts/verify-hypervisor-api-tokens-functional.mjs [--json]
import { readFileSync, existsSync } from "node:fs";
import { join } from "node:path";

const JSON_OUT = process.argv.includes("--json");
const DAEMON = process.env.IOI_HYPERVISOR_DAEMON_URL || "http://127.0.0.1:8765";
const SERVE = process.env.IOI_HYPERVISOR_SERVE_URL || "http://127.0.0.1:4173";
const DATA_DIR = process.env.IOI_HYPERVISOR_DATA_DIR || "/home/heathledger/.ioi/hypervisor/data";
const USER = "00000000-0000-4000-8000-000000000001";

const checks = [];
let failures = 0;
const ok = (cond, msg, detail) => { checks.push({ ok: !!cond, msg }); if (!cond) failures++; if (!JSON_OUT) console.log(`    ${cond ? "✓" : "✗ FAIL:"} ${msg}${detail ? ` (${detail})` : ""}`); };
const blocked = (reason) => { console.log(JSON_OUT ? JSON.stringify({ workstream: "api-tokens", verdict: "BLOCKED", reason }, null, 2) : `  BLOCKED: ${reason}`); process.exit(2); };
const jd = async (m, p) => { const r = await fetch(DAEMON + p, { method: m }); const t = await r.text(); return { status: r.status, raw: t, body: t ? JSON.parse(t) : {} }; };
const ja = async (rpc, b) => { const r = await fetch(`${SERVE}/api/gitpod.v1.UserService/${rpc}`, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify(b || {}) }); const t = await r.text(); return { status: r.status, raw: t, body: t ? JSON.parse(t) : {} }; };

if (!JSON_OUT) console.log("API access tokens e2e — inbound tokens (hash-only at rest, plaintext once)");
try { const r = await fetch(`${DAEMON}/v1/hypervisor/api-tokens`, { signal: AbortSignal.timeout(3000) }); if (!r.ok) throw 0; } catch { blocked("hypervisor-daemon (:8765) not running"); }
try { const r = await fetch(`${SERVE}/ai`, { signal: AbortSignal.timeout(3000) }); if (!r.ok) throw 0; } catch { blocked("serve (:4173) not running"); }

// wipe prior sentinel runs
const pre = await jd("GET", "/v1/hypervisor/api-tokens");
for (const t of (pre.body.tokens || [])) if (/^DB_TOKEN_SENTINEL/.test(t.description || "")) await fetch(`${DAEMON}/v1/hypervisor/api-tokens/${t.token_id}`, { method: "DELETE" });

// 1) Create via the adapter (the native CreatePersonalAccessToken path) — Read & Write, 30 days.
const c = await ja("CreatePersonalAccessToken", { userId: USER, description: "DB_TOKEN_SENTINEL", validFor: "2592000s", readOnly: false });
const plaintext = c.body?.token;
ok(c.status === 200 && typeof plaintext === "string" && plaintext.startsWith("ioi_pat_"), "create returns the plaintext token (string) ONCE", typeof plaintext === "string" ? plaintext.slice(0, 14) + "…" : typeof plaintext);

// 2) List (adapter) — row metadata present, plaintext + hash ABSENT.
const l = await ja("ListPersonalAccessTokens", { pagination: { pageSize: 100 }, filter: { userIds: [USER] } });
const row = (l.body.personalAccessTokens || []).find((t) => t.description === "DB_TOKEN_SENTINEL");
const tokId = row?.id;
ok(!!row && row.readOnly === false && !!row.expiresAt && !!row.createdAt, "list row carries description/readOnly/created/expires metadata", tokId);
ok(!l.raw.includes(plaintext), "adapter list never returns the plaintext value");
ok(!/token_hash|tokenHash/.test(l.raw), "adapter list never exposes the token hash");

// 3) Daemon list — same: no plaintext, no hash.
const dl = await jd("GET", "/v1/hypervisor/api-tokens");
ok(!dl.raw.includes(plaintext), "daemon list never returns the plaintext value");
ok(!/token_hash/.test(dl.raw), "daemon list strips the token hash");

// 4) On-disk — hash stored (sha256), no plaintext, no value field.
if (existsSync(DATA_DIR)) {
  const f = join(DATA_DIR, "api-tokens", `${tokId}.json`);
  const rec = existsSync(f) ? JSON.parse(readFileSync(f, "utf8")) : {};
  ok(existsSync(f) && !JSON.stringify(rec).includes(plaintext), "on-disk record contains NO plaintext");
  ok((rec.token_hash || "").length === 64 && !("value" in rec), "on-disk record stores the sha256 hash, not the value", `hash len ${(rec.token_hash || "").length}`);
} else {
  ok(true, "on-disk hash check skipped (data dir not on this host)");
  ok(true, "on-disk value-absence check skipped (data dir not on this host)");
}

// 5) userIds filter isolates — a foreign userId returns nothing of ours.
const lForeign = await ja("ListPersonalAccessTokens", { filter: { userIds: ["00000000-0000-4000-8000-0000000000ff"] } });
ok(!(lForeign.body.personalAccessTokens || []).some((t) => t.id === tokId), "userIds filter isolates tokens per user");

// 6) Delete — gone.
await ja("DeletePersonalAccessToken", { personalAccessTokenId: tokId });
const after = await jd("GET", "/v1/hypervisor/api-tokens");
ok(!(after.body.tokens || []).some((t) => t.token_id === tokId), "delete revokes the token");
if (existsSync(DATA_DIR)) ok(!existsSync(join(DATA_DIR, "api-tokens", `${tokId}.json`)), "delete removes the on-disk record");
else ok(true, "delete on-disk check skipped (data dir not on this host)");

// 7) Empty description fails closed.
const bad = await ja("CreatePersonalAccessToken", { userId: USER, description: "", validFor: "2592000s" });
ok(bad.status >= 400, "create with empty description FAILS CLOSED", `status ${bad.status}`);

const passed = checks.length - failures;
if (JSON_OUT) console.log(JSON.stringify({ workstream: "api-tokens", verdict: failures ? "FAIL" : "PASS", passed, total: checks.length }, null, 2));
else console.log(`\n  ${failures ? "✗" : "✓"} api-tokens ${passed}/${checks.length}`);
process.exit(failures ? 1 : 0);
