#!/usr/bin/env node
// Done-bar for the BYOA GitHub App (manifest) connector (master-guide #4) — the STRUCTURAL spine.
//
// Hypervisor ships NO OAuth App: the user creates one in their OWN account via GitHub's App-Manifest
// flow, the daemon seals the App private key, and to act it mints short-lived installation tokens
// fed into the SAME CapabilityLease gateway. The live click-through + publish-via-App-token (PR
// authored by the App bot) is proven manually; this guards the deterministic structure:
//   - the manifest is VALID for a localhost/BYOA callback (NO webhook — GitHub rejects localhost hooks)
//   - least-privilege permissions (contents+pull_requests write, metadata read)
//   - conversion fails closed on a bad code
//   - github-app credentials never leak the sealed pem in any listing
// Model-free. Usage: node scripts/verify-hypervisor-github-app-byoa-functional.mjs [--json]
const JSON_OUT = process.argv.includes("--json");
const DAEMON = process.env.IOI_HYPERVISOR_DAEMON_URL || "http://127.0.0.1:8765";
const checks = [];
let failures = 0;
const ok = (cond, msg, detail) => { checks.push({ ok: !!cond, msg }); if (!cond) failures++; if (!JSON_OUT) console.log(`    ${cond ? "✓" : "✗ FAIL:"} ${msg}${detail ? ` (${detail})` : ""}`); };
const blocked = (reason) => { console.log(JSON_OUT ? JSON.stringify({ workstream: "github-app-byoa", verdict: "BLOCKED", reason }, null, 2) : `  BLOCKED: ${reason}`); process.exit(2); };
const j = async (m, p, b) => { const r = await fetch(DAEMON + p, { method: m, headers: b ? { "content-type": "application/json" } : undefined, body: b ? JSON.stringify(b) : undefined }); return { status: r.status, body: await r.json().catch(() => ({})) }; };

if (!JSON_OUT) console.log("BYOA GitHub App (manifest) connector — structural spine");
try { const r = await fetch(`${DAEMON}/v1/hypervisor/providers`, { signal: AbortSignal.timeout(3000) }); if (!r.ok) throw 0; } catch { blocked("hypervisor-daemon (:8765) not running"); }

// 1) manifest for a USER account (no owner)
const userM = await j("POST", "/v1/hypervisor/scm-connect/github-app/manifest", { callback_base: "http://127.0.0.1:4173" });
const m = userM.body?.manifest || {};
ok(userM.body?.create_url === "https://github.com/settings/apps/new?state=" + userM.body?.state, "user manifest → personal create_url (settings/apps/new)", userM.body?.create_url);
ok(!("hook_attributes" in m), "manifest has NO webhook (GitHub rejects localhost hooks — the bug that failed live)");
ok(m.public === false, "App is private (public:false)");
ok(m.default_permissions?.contents === "write", "least-privilege: contents=write (push)");
ok(m.default_permissions?.pull_requests === "write", "least-privilege: pull_requests=write (open/close PR)");
ok(m.default_permissions?.metadata === "read", "least-privilege: metadata=read (mandatory)");
ok(Object.keys(m.default_permissions || {}).length === 3, "no extra permissions beyond contents/pull_requests/metadata", JSON.stringify(m.default_permissions));
ok(typeof m.redirect_url === "string" && m.redirect_url.endsWith("/__ioi/github-app/callback"), "manifest carries the create redirect_url");
ok(typeof m.setup_url === "string" && m.setup_url.endsWith("/__ioi/github-app/installed"), "manifest carries the install setup_url");

// 2) manifest for an ORG → org create_url
const orgM = await j("POST", "/v1/hypervisor/scm-connect/github-app/manifest", { owner: "some-org", callback_base: "http://127.0.0.1:4173" });
ok((orgM.body?.create_url || "").startsWith("https://github.com/organizations/some-org/settings/apps/new"), "org manifest → org create_url");

// 3) conversion fails closed on a bogus code (no app fabricated)
const conv = await j("POST", "/v1/hypervisor/scm-connect/github-app/conversion", { code: "definitely-not-a-real-manifest-code" });
ok(conv.status !== 200 || conv.body?.ok === false, "conversion FAILS CLOSED on an invalid code", `status ${conv.status}`);
const convEmpty = await j("POST", "/v1/hypervisor/scm-connect/github-app/conversion", {});
ok(convEmpty.status === 400, "conversion requires a code (400)", `status ${convEmpty.status}`);

// 4) installation requires an id
const inst = await j("POST", "/v1/hypervisor/scm-connect/github-app/installation", {});
ok(inst.status === 400, "installation requires an installation_id (400)", `status ${inst.status}`);

// 5) credential hygiene: NO github-app connector listing or capability-lease ever leaks the sealed pem
const connectors = JSON.stringify((await j("GET", "/v1/hypervisor/scm-connectors")).body?.connectors || []);
ok(!/sealed_pem|"pem"|BEGIN (RSA )?PRIVATE KEY/.test(connectors), "connector listings never expose the App private key");
const leases = JSON.stringify((await j("GET", "/v1/hypervisor/capability-leases")).body?.leases || []);
ok(!/sealed_pem|"pem"|BEGIN (RSA )?PRIVATE KEY|ghs_/.test(leases), "capability leases never expose the App key or installation token");

const verdict = failures > 0 ? "FAIL" : "PASS";
if (JSON_OUT) console.log(JSON.stringify({ workstream: "github-app-byoa", verdict, failures, checks: checks.length }, null, 2));
else console.log(`  VERDICT: ${verdict} (${checks.length - failures}/${checks.length} checks)`);
process.exit(verdict === "FAIL" ? 1 : 0);
