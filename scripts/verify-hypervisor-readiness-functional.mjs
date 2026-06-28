#!/usr/bin/env node
// Cut C done-bar — readiness primitives as daemon truth: devcontainer build/rebuild, tasks/services
// readiness, and (the new substrate) ports + preview behind a capability-lease gateway.
//   1. REBUILD: a started env validates its devcontainer config, then rebuild re-detects the recipe
//      and recomputes the readiness gate (a real lifecycle op, not a no-op).
//   2. TASKS/SERVICES: a started env carries real task results (exit codes) + typed services.
//   3. PORTS + PREVIEW: a port a server actually opened is OBSERVED (TCP liveness), EXPOSED behind a
//      capability lease + loopback preview gateway (the preview URL really forwards to the server),
//      and the preview FAILS CLOSED the instant the lease is revoked; unexpose closes it.
// For the local provider the env's server binds a HOST loopback port, so the gateway forwards to
// 127.0.0.1:<port> — this verifier opens that port itself (identical to an env service binding the
// host loopback; the gateway forwards regardless of which process opened it). microVM guest-forward
// is the provider-ladder follow-up (expose fails closed on a microVM env — a NAMED gap, not a fake).
// Requires daemon :8765. Missing ⇒ BLOCKED (named host gap), never a fake pass.
const JSON_OUT = process.argv.includes("--json");
const DAEMON = process.env.IOI_HYPERVISOR_DAEMON_URL || "http://127.0.0.1:8765";
import http from "node:http";

const checks = [];
let failures = 0;
const ok = (c, m, d) => { checks.push({ ok: !!c, m }); if (!c) failures++; if (!JSON_OUT) console.log(`    ${c ? "✓" : "✗ FAIL:"} ${m}${d ? ` (${d})` : ""}`); };
const blocked = (r) => { console.log(JSON_OUT ? JSON.stringify({ workstream: "readiness-functional", verdict: "BLOCKED", reason: r }) : `  BLOCKED: ${r}`); process.exit(2); };
const dj = async (m, p, b) => { const r = await fetch(DAEMON + p, { method: m, headers: { "content-type": "application/json" }, body: b !== undefined ? JSON.stringify(b) : undefined }); const t = await r.text(); let j = {}; try { j = t ? JSON.parse(t) : {}; } catch { j = { _raw: t }; } return { status: r.status, body: j }; };
const getStatus = async (url) => { try { const r = await fetch(url, { signal: AbortSignal.timeout(4000) }); const body = await r.text(); return { status: r.status, body }; } catch (e) { return { status: 0, body: "", err: String(e?.message || e) }; } };

if (!JSON_OUT) console.log("Readiness primitives e2e — rebuild · tasks/services · ports+preview (lease-gated)");
try { const r = await fetch(`${DAEMON}/v1/hypervisor/providers`, { signal: AbortSignal.timeout(3000) }); if (!r.ok) blocked("daemon not running"); } catch { blocked("hypervisor-daemon (:8765) not running"); }

// ---- a started local env ----
const created = await dj("POST", "/v1/hypervisor/environments", { spec: { environment_class_id: "local-workspace-v0", project_id: "readiness-verify" } });
const envId = created.body?.environment?.id;
ok(!!envId, "environment created + started", envId);
const started = await dj("POST", `/v1/hypervisor/environments/${envId}/start`);
const st = started.body?.environment?.status || {};
ok(st.phase === "running", "environment running", st.phase);

// 1) REBUILD lifecycle — validate the devcontainer config, then rebuild re-detects + re-gates.
const validate = await dj("POST", "/v1/hypervisor/env-config", { environment_id: envId, op: "validate" });
ok(validate.body?.valid === true, "devcontainer config validates (scaffolded JSON parses)", validate.body?.reason);
const rebuild = await dj("POST", "/v1/hypervisor/env-config", { environment_id: envId, op: "rebuild" });
ok(rebuild.body?.ok === true && rebuild.body?.state === "succeeded", "rebuild re-detects recipe + recomputes readiness", rebuild.body?.readiness_mode);

// 2) TASKS / SERVICES — real results carried on status.
const post = (await dj("GET", `/v1/hypervisor/environments/${envId}`)).body?.environment?.status || st;
const tasks = post.tasks || [];
ok(Array.isArray(tasks) && tasks.length > 0, "env carries task results", tasks.map((t) => `${t.name}:${t.phase}`).join(","));
const services = post.services || [];
ok(Array.isArray(services) && services.length > 0, "env carries typed services", services.map((s) => `${s.name}:${s.phase}`).join(","));

// 3) PORTS + PREVIEW — open a real server, expose behind a lease, prove the preview forwards, then
//    prove it fails closed on revoke. (Local provider: host loopback port — see header.)
const MARKER = "PREVIEW_OK_C3PO";
// Connection: close so each preview hit is a FRESH TCP connection through the gateway (re-auth every
// time) — otherwise undici keep-alive would reuse the already-authed tunnel and mask the revoke gate.
const server = http.createServer((_req, res) => { res.writeHead(200, { "content-type": "text/plain", "connection": "close" }); res.end(MARKER); });
const livePort = await new Promise((resolve) => server.listen(0, "127.0.0.1", () => resolve(server.address().port)));

const exposed = await dj("POST", `/v1/hypervisor/environments/${envId}/ports/${livePort}/expose`);
ok(exposed.body?.ok === true && exposed.body?.listening === true, "expose: live port observed + gateway bound", `port ${livePort}, listening ${exposed.body?.listening}`);
const previewUrl = exposed.body?.url;
const accessToken = exposed.body?.accessToken;
ok(!!previewUrl && /127\.0\.0\.1:\d+/.test(previewUrl), "expose returns a real preview URL", previewUrl);

const fwd = await getStatus(previewUrl);
ok(fwd.status === 200 && fwd.body.includes(MARKER), "preview URL really forwards to the env's server", `status ${fwd.status}`);

const obs = await dj("GET", `/v1/hypervisor/environments/${envId}/ports`);
const op = (obs.body?.ports || []).find((p) => p.port === livePort);
ok(op?.exposure_state === "open" && op?.listening === true, "observe: port shows open + listening", op ? `${op.exposure_state}/${op.listening}` : "missing");

// revoke the lease (gateway still bound) → preview must fail closed.
const revoke = await dj("POST", "/v1/hypervisor/authority/revoke", { grant_id: accessToken, grant_ref: accessToken });
const afterRevoke = await getStatus(previewUrl);
ok(revoke.body?.ok === true && afterRevoke.status !== 200 && !afterRevoke.body.includes(MARKER), "preview FAILS CLOSED on lease revoke", `revoke ${revoke.body?.ok}, preview ${afterRevoke.status || afterRevoke.err}`);

// unexpose → the port entry closes + URL clears.
await dj("POST", `/v1/hypervisor/environments/${envId}/ports/${livePort}/unexpose`);
const obs2 = await dj("GET", `/v1/hypervisor/environments/${envId}/ports`);
const cp = (obs2.body?.ports || []).find((p) => p.port === livePort);
ok(cp?.exposure_state === "closed" && (cp?.url === null || cp?.url === undefined), "unexpose closes the port + clears the URL", cp ? cp.exposure_state : "missing");

// honest dead-port path: exposing a port with no server is allowed but observed not-listening, and
// the preview honestly 502s (no fake "ready").
const deadPort = livePort + 1;
const deadExpose = await dj("POST", `/v1/hypervisor/environments/${envId}/ports/${deadPort}/expose`);
ok(deadExpose.body?.ok === true && deadExpose.body?.listening === false, "expose a dead port: allowed but observed not-listening (honest)", `listening ${deadExpose.body?.listening}`);
const deadFwd = await getStatus(deadExpose.body?.url);
ok(deadFwd.status === 502 || deadFwd.status === 0, "dead-port preview honestly 502s (no fake ready)", `status ${deadFwd.status || deadFwd.err}`);
await dj("POST", `/v1/hypervisor/environments/${envId}/ports/${deadPort}/unexpose`);

server.close();
const verdict = failures > 0 ? "FAIL" : "PASS";
if (JSON_OUT) console.log(JSON.stringify({ workstream: "readiness-functional", verdict, failures, checks: checks.length }, null, 2));
else console.log(`  VERDICT: ${verdict} (${checks.length - failures}/${checks.length} checks)`);
process.exit(verdict === "FAIL" ? 1 : 0);
