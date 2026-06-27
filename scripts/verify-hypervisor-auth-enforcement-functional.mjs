#!/usr/bin/env node
// Done-bar for context-aware auth enforcement (hardening #1). Verifies the fail-safe enforcement
// model on the shared daemon (mode auto/always/never + exposure detection + the gate exempting only
// login-flow paths), then spins up an ISOLATED daemon on a temp data dir to drive the full lockout
// bootstrap: exposed + no-login → enforced + needs_bootstrap → set first operator password with the
// one-time token → login works. Usage: node scripts/verify-hypervisor-auth-enforcement-functional.mjs [--json]
import { spawn } from "node:child_process";
import { mkdtempSync, existsSync, readFileSync, rmSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import net from "node:net";

const JSON_OUT = process.argv.includes("--json");
const DAEMON = process.env.IOI_HYPERVISOR_DAEMON_URL || "http://127.0.0.1:8765";
const BIN = "./target/debug/hypervisor-daemon";
const checks = [];
let failures = 0;
const ok = (cond, msg, detail) => { checks.push({ ok: !!cond, msg }); if (!cond) failures++; if (!JSON_OUT) console.log(`    ${cond ? "✓" : "✗ FAIL:"} ${msg}${detail ? ` (${detail})` : ""}`); };
const blocked = (reason) => { console.log(JSON_OUT ? JSON.stringify({ workstream: "auth-enforcement", verdict: "BLOCKED", reason }, null, 2) : `  BLOCKED: ${reason}`); process.exit(2); };
const code = async (url, opts) => (await fetch(url, opts)).status;
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const freePort = () => new Promise((res) => { const s = net.createServer(); s.listen(0, "127.0.0.1", () => { const p = s.address().port; s.close(() => res(p)); }); });

if (!JSON_OUT) console.log("Auth enforcement e2e — context-aware fail-safe + lockout bootstrap");
try { const r = await fetch(`${DAEMON}/v1/hypervisor/editor-targets`, { signal: AbortSignal.timeout(3000) }); if (!r.ok) throw 0; } catch { blocked("hypervisor-daemon (:8765) not running"); }

// ensure the shared operator has a password (login possible), get a session, force mode=auto.
// All policy changes are AUTHENTICATED — /auth/policy is gated once enforcement is on, so toggles
// must carry the operator session (this also self-heals a leftover "always" from a prior run).
await fetch(`${DAEMON}/v1/hypervisor/principals/00000000-0000-4000-8000-000000000001/password`, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ password: "operator-pass-123" }) });
const tok = await (await fetch(`${DAEMON}/v1/hypervisor/auth/login`, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ email: "johndoe@ioi.local", password: "operator-pass-123" }) })).json().then((d) => d.session_token);
const setMode = (m) => fetch(`${DAEMON}/v1/hypervisor/auth/policy`, { method: "PUT", headers: { "content-type": "application/json", Authorization: `Bearer ${tok}` }, body: JSON.stringify({ mode: m }) });
await setMode("auto");

// --- shared daemon: context-aware enforcement (mode auto) ---
ok(await code(`${DAEMON}/v1/hypervisor/secrets`) === 200, "auto + loopback (not exposed) → NOT enforced");
ok(await code(`${DAEMON}/v1/hypervisor/secrets`, { headers: { "X-Forwarded-Host": "hv.example.com" } }) === 401, "auto + EXPOSED (forwarded-host) → enforced (401)");
ok(await code(`${DAEMON}/v1/hypervisor/secrets`, { headers: { "X-Forwarded-Host": "hv.example.com", Authorization: `Bearer ${tok}` } }) === 200, "exposed + valid session → 200");
// the gate exempts only login-flow paths: /auth/policy must require auth when enforced
ok(await code(`${DAEMON}/v1/hypervisor/auth/policy`, { method: "PUT", headers: { "content-type": "application/json", "X-Forwarded-Host": "hv.example.com" }, body: JSON.stringify({ mode: "never" }) }) === 401, "exposed + unauth → /auth/policy is GATED (can't disable enforcement)");
ok(await code(`${DAEMON}/v1/hypervisor/auth/login`, { method: "POST", headers: { "content-type": "application/json", "X-Forwarded-Host": "hv.example.com" }, body: "{}" }) !== 404, "login endpoint stays reachable under enforcement");
// modes (authenticated toggles)
await setMode("never");
ok(await code(`${DAEMON}/v1/hypervisor/secrets`, { headers: { "X-Forwarded-Host": "hv.example.com" } }) === 200, "mode never + exposed → NOT enforced");
await setMode("always");
ok(await code(`${DAEMON}/v1/hypervisor/secrets`) === 401, "mode always + loopback → enforced (401)");
await setMode("auto"); // restore (authenticated, so it succeeds even though 'always' was enforcing)

// --- isolated daemon: lockout bootstrap (no login configured) ---
if (!existsSync(BIN)) { ok(true, "bootstrap test skipped (daemon binary not built here)"); }
else {
  const dir = mkdtempSync(join(tmpdir(), "ioi-auth-"));
  const port = await freePort();
  const base = `http://127.0.0.1:${port}`;
  const child = spawn(BIN, [], { env: { ...process.env, IOI_HYPERVISOR_DATA_DIR: dir, IOI_HYPERVISOR_DAEMON_ADDR: `127.0.0.1:${port}` }, stdio: "ignore", detached: true });
  try {
    let up = false;
    for (let i = 0; i < 40; i++) { try { if ((await fetch(`${base}/v1/hypervisor/editor-targets`)).ok) { up = true; break; } } catch {} await sleep(250); }
    if (!up) { ok(false, "isolated daemon failed to start"); }
    else {
      await fetch(`${base}/v1/hypervisor/auth/whoami`); // bootstrap the operator principal (no password)
      await fetch(`${base}/v1/hypervisor/auth/policy`, { method: "PUT", headers: { "content-type": "application/json" }, body: JSON.stringify({ mode: "always" }) });
      const status = await (await fetch(`${base}/v1/hypervisor/auth/bootstrap-status`)).json();
      ok(status.needs_bootstrap === true && status.login_possible === false, "fresh enforced instance reports needs_bootstrap");
      const gated = await (await fetch(`${base}/v1/hypervisor/secrets`)).json().catch(() => ({}));
      ok(gated.needs_bootstrap === true, "data plane is gated with needs_bootstrap (401)");
      const tokFile = join(dir, "auth-bootstrap", "bootstrap.json");
      const bootToken = existsSync(tokFile) ? JSON.parse(readFileSync(tokFile, "utf8")).token : "";
      ok(bootToken.startsWith("ioi_bootstrap"), "one-time bootstrap token materialized (log/disk only)");
      const badTok = await (await fetch(`${base}/v1/hypervisor/auth/bootstrap`, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ token: "wrong", password: "longenough1" }) })).status;
      ok(badTok === 403, "bootstrap with a wrong token → 403");
      const boot = await fetch(`${base}/v1/hypervisor/auth/bootstrap`, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ token: bootToken, password: "first-operator-pw" }) });
      const bootBody = await boot.json();
      ok(boot.status === 200 && typeof bootBody.session_token === "string", "bootstrap sets the first operator password + issues a session");
      const login = await (await fetch(`${base}/v1/hypervisor/auth/login`, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ email: "johndoe@ioi.local", password: "first-operator-pw" }) })).status;
      ok(login === 200, "operator can now log in with the bootstrapped password");
      const again = await (await fetch(`${base}/v1/hypervisor/auth/bootstrap`, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ token: bootToken, password: "another-pw-1" }) })).status;
      ok(again === 409, "bootstrap is one-time (409 once a login exists)");
    }
  } finally {
    try { process.kill(-child.pid); } catch {}
    try { rmSync(dir, { recursive: true, force: true }); } catch {}
  }
}

const passed = checks.length - failures;
if (JSON_OUT) console.log(JSON.stringify({ workstream: "auth-enforcement", verdict: failures ? "FAIL" : "PASS", passed, total: checks.length }, null, 2));
else console.log(`\n  ${failures ? "✗" : "✓"} auth-enforcement ${passed}/${checks.length}`);
process.exit(failures ? 1 : 0);
