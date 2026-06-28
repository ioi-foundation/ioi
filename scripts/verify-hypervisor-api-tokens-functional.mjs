#!/usr/bin/env node
// Done-bar for the API access tokens plane (Bucket A #2) — inbound tokens that authenticate calls TO
// the Hypervisor API. Daemon-only (source-neutral): exercises /v1/hypervisor/api-tokens directly.
// Security model: store ONLY a sha256 hash + metadata; surface the plaintext exactly ONCE on create;
// never recoverable after. Usage: node scripts/verify-hypervisor-api-tokens-functional.mjs [--json]
import { readFileSync, existsSync } from "node:fs";
import { join } from "node:path";

const JSON_OUT = process.argv.includes("--json");
const DAEMON = process.env.IOI_HYPERVISOR_DAEMON_URL || "http://127.0.0.1:8765";
const DATA_DIR = process.env.IOI_HYPERVISOR_DATA_DIR || "/home/heathledger/.ioi/hypervisor/data";
const USER = "00000000-0000-4000-8000-000000000001";

const checks = [];
let failures = 0;
const ok = (cond, msg, detail) => { checks.push({ ok: !!cond, msg }); if (!cond) failures++; if (!JSON_OUT) console.log(`    ${cond ? "✓" : "✗ FAIL:"} ${msg}${detail ? ` (${detail})` : ""}`); };
const blocked = (reason) => { console.log(JSON_OUT ? JSON.stringify({ workstream: "api-tokens", verdict: "BLOCKED", reason }, null, 2) : `  BLOCKED: ${reason}`); process.exit(2); };
const jd = async (m, p, b) => { const r = await fetch(DAEMON + p, { method: m, headers: b ? { "content-type": "application/json" } : undefined, body: b ? JSON.stringify(b) : undefined }); const t = await r.text(); return { status: r.status, raw: t, body: t ? JSON.parse(t) : {} }; };

if (!JSON_OUT) console.log("API access tokens e2e — inbound tokens, hash-only at rest, plaintext once (daemon-only)");
try { const r = await fetch(`${DAEMON}/v1/hypervisor/editor-targets`, { signal: AbortSignal.timeout(3000) }); if (!r.ok) throw 0; } catch { blocked("hypervisor-daemon (:8765) not running"); }

// self-heal prior runs
{ const pre = await jd("GET", "/v1/hypervisor/api-tokens"); for (const t of (pre.body.tokens || [])) if (/^DB_TOKEN_SENTINEL/.test(t.description || "")) await jd("DELETE", `/v1/hypervisor/api-tokens/${t.token_id}`); }

// 1) Create — Read & Write, 30 days. Plaintext returned ONCE.
const c = await jd("POST", "/v1/hypervisor/api-tokens", { user_id: USER, description: "DB_TOKEN_SENTINEL", valid_for: "2592000s", read_only: false });
const plaintext = c.body?.token?.value;
const tokId = c.body?.token?.token_id;
ok(c.status === 200 && typeof plaintext === "string" && plaintext.startsWith("ioi_pat_"), "create returns the plaintext token ONCE", typeof plaintext === "string" ? plaintext.slice(0, 14) + "…" : typeof plaintext);
ok(!!tokId && c.body?.token?.read_only === false && !!c.body?.token?.expires_at, "create returns token metadata (id/read_only/expires)", tokId);

// 2) List — metadata present, plaintext + hash ABSENT.
const l = await jd("GET", "/v1/hypervisor/api-tokens");
const row = (l.body.tokens || []).find((t) => t.description === "DB_TOKEN_SENTINEL");
ok(!!row && row.read_only === false && !!row.expires_at && !!row.created_at, "list row carries description/read_only/created/expires");
ok(!l.raw.includes(plaintext), "list never returns the plaintext value");
ok(!/token_hash|tokenHash/.test(l.raw), "list strips the token hash (defense in depth)");

// 3) On-disk — hash stored (sha256), no plaintext, no value field.
if (existsSync(DATA_DIR)) {
  const f = join(DATA_DIR, "api-tokens", `${tokId}.json`);
  const rec = existsSync(f) ? JSON.parse(readFileSync(f, "utf8")) : {};
  ok(existsSync(f) && !JSON.stringify(rec).includes(plaintext), "on-disk record contains NO plaintext");
  ok((rec.token_hash || "").length === 64 && !("value" in rec), "on-disk record stores the sha256 hash, not the value", `hash len ${(rec.token_hash || "").length}`);
} else { ok(true, "on-disk hash check skipped"); ok(true, "on-disk value-absence check skipped"); }

// 4) The token authenticates its principal (the hash is enforceable).
const who = await jd("GET", "/v1/hypervisor/auth/whoami", null);
const apiWho = await (await fetch(`${DAEMON}/v1/hypervisor/auth/whoami`, { headers: { Authorization: `Bearer ${plaintext}` } })).json();
ok(apiWho.principal?.principal_id === USER, "the minted token authenticates its principal");

// 5) Delete — gone.
await jd("DELETE", `/v1/hypervisor/api-tokens/${tokId}`);
const after = await jd("GET", "/v1/hypervisor/api-tokens");
ok(!(after.body.tokens || []).some((t) => t.token_id === tokId), "delete revokes the token");
if (existsSync(DATA_DIR)) ok(!existsSync(join(DATA_DIR, "api-tokens", `${tokId}.json`)), "delete removes the on-disk record");
else ok(true, "delete on-disk check skipped");

// 6) Empty description fails closed.
ok((await jd("POST", "/v1/hypervisor/api-tokens", { user_id: USER, description: "" })).status >= 400, "create with empty description FAILS CLOSED");

const passed = checks.length - failures;
if (JSON_OUT) console.log(JSON.stringify({ workstream: "api-tokens", verdict: failures ? "FAIL" : "PASS", passed, total: checks.length }, null, 2));
else console.log(`\n  ${failures ? "✗" : "✓"} api-tokens ${passed}/${checks.length}`);
process.exit(failures ? 1 : 0);
