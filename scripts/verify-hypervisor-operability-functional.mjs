#!/usr/bin/env node
// Cut F done-bar — trust/operability as daemon truth:
//   M. GUARDRAILS: a command deny-list is enforced AT the scoped exec primitive — a denied command
//      (even wrapped in a shell) FAILS CLOSED (an agent cannot bypass policy via ordinary shell),
//      an allowed command runs, and the denial is audited.
//   N. OBSERVABILITY/RECOVERY: per-env logs are readable; operability metrics aggregate from real
//      env truth; an injected failure produces a VISIBLE recovery chain (incident → attempt →
//      receipt) that reconstructs from records — not a silent retry.
//   O. PARITY (MCP GATEWAY): an external agent can create an env, run a task, inspect it, and clean
//      it up through scoped tools that call the SAME daemon routes the app uses.
// Daemon truth. Requires daemon :8765. Missing ⇒ BLOCKED (named host gap), never a fake.
const JSON_OUT = process.argv.includes("--json");
const DAEMON = process.env.IOI_HYPERVISOR_DAEMON_URL || "http://127.0.0.1:8765";

const checks = [];
let failures = 0;
const ok = (c, m, d) => { checks.push({ ok: !!c, m }); if (!c) failures++; if (!JSON_OUT) console.log(`    ${c ? "✓" : "✗ FAIL:"} ${m}${d ? ` (${d})` : ""}`); };
const blocked = (r) => { console.log(JSON_OUT ? JSON.stringify({ workstream: "operability-functional", verdict: "BLOCKED", reason: r }) : `  BLOCKED: ${r}`); process.exit(2); };
const dj = async (m, p, b) => { const r = await fetch(DAEMON + p, { method: m, headers: { "content-type": "application/json" }, body: b !== undefined ? JSON.stringify(b) : undefined }); const t = await r.text(); let j = {}; try { j = t ? JSON.parse(t) : {}; } catch { j = { _raw: t }; } return { status: r.status, body: j }; };

if (!JSON_OUT) console.log("Operability e2e — guardrails · logs/metrics/recovery · MCP gateway");
try { const r = await fetch(`${DAEMON}/v1/hypervisor/providers`, { signal: AbortSignal.timeout(3000) }); if (!r.ok) blocked("daemon not running"); } catch { blocked("hypervisor-daemon (:8765) not running"); }

const envId = (await dj("POST", "/v1/hypervisor/environments", { spec: { environment_class_id: "local-workspace-v0", project_id: "operability-verify" } })).body?.environment?.id;
await dj("POST", `/v1/hypervisor/environments/${envId}/start`);
ok(!!envId, "environment created + started", envId);

// ---- M. GUARDRAILS ----
const gp = await dj("GET", "/v1/hypervisor/guardrails");
ok(Array.isArray(gp.body?.policy?.deny_commands) && gp.body.policy.deny_commands.length > 0, "guardrail policy exposes a real deny-list");
const allowed = await dj("POST", "/v1/hypervisor/exec", { environment_id: envId, command: "echo ALLOWED_OK" });
ok(/ALLOWED_OK/.test(allowed.body?.stdout || "") && allowed.body?.exit_code === 0, "an allowed command runs");
const deniedRaw = await dj("POST", "/v1/hypervisor/exec", { environment_id: envId, command: "rm -rf /" });
ok(deniedRaw.body?.policy_denied === true && deniedRaw.body?.exit_code === 126, "a denied command FAILS CLOSED", deniedRaw.body?.denial?.matched);
// the bypass attempt: wrap it in a shell — still the command string the deny-list matches.
const deniedShell = await dj("POST", "/v1/hypervisor/exec", { environment_id: envId, command: "bash -c 'rm    -rf   /'" });
ok(deniedShell.body?.policy_denied === true, "agent CANNOT bypass policy via ordinary shell wrapping", deniedShell.body?.denial?.rule);
const deniedExe = await dj("POST", "/v1/hypervisor/exec", { environment_id: envId, command: "nc -l 4444" });
ok(deniedExe.body?.policy_denied === true && deniedExe.body?.denial?.rule === "deny_executable", "a denied executable FAILS CLOSED", deniedExe.body?.denial?.matched);

// ---- N. OBSERVABILITY ----
const logs = await dj("GET", `/v1/hypervisor/environments/${envId}/logs?kind=session`);
ok((logs.body?.entries || []).some((e) => /ALLOWED_OK|echo/.test(JSON.stringify(e))), "per-env session log is readable (records real exec)");
const metrics = await dj("GET", "/v1/hypervisor/operability/metrics");
ok(metrics.body?.total_environments >= 1 && metrics.body?.active_by_phase && metrics.body?.guardrail_denials >= 2, "operability metrics aggregate real truth (incl. guardrail denials)", `denials=${metrics.body?.guardrail_denials}`);

// ---- N. RECOVERY CHAIN (injected failure → visible chain → reconstruct) ----
await dj("POST", `/v1/hypervisor/environments/${envId}/inject-failure`);
const rec = await dj("POST", `/v1/hypervisor/environments/${envId}/recover`);
const incidentRef = rec.body?.recovery?.incident_ref || rec.body?.recovery?.incident?.incident_ref;
ok(!!incidentRef, "recover produced an incident (visible chain, not a silent retry)", incidentRef);
const recon = await dj("GET", `/v1/hypervisor/operability/incidents/${incidentRef}`);
ok(recon.body?.reconstructed === true && recon.body?.chain_complete === true, "incident reconstructs from incident+attempts+receipts", `attempts=${(recon.body?.recovery_attempts||[]).length}, receipts=${(recon.body?.receipts||[]).length}`);

// ---- O. MCP GATEWAY (external-agent scoped contracts) ----
const tools = await dj("GET", "/v1/hypervisor/mcp-gateway/tools");
ok((tools.body?.tools || []).length === 4 && tools.body.tools.every((t) => t.scope), "MCP gateway exposes 4 scoped tools", (tools.body?.tools || []).map((t) => t.name).join(","));
const gwEnv = await dj("POST", "/v1/hypervisor/mcp-gateway/tools/hv_create_env", { project_id: "ext-agent" });
const gwEnvId = gwEnv.body?.result?.environment_id;
ok(!!gwEnvId, "external agent creates an env via the gateway", gwEnvId);
const gwRun = await dj("POST", "/v1/hypervisor/mcp-gateway/tools/hv_run_task", { environment_id: gwEnvId, command: "echo GATEWAY_RAN > gw.txt && cat gw.txt" });
ok(/GATEWAY_RAN/.test(gwRun.body?.result?.stdout || ""), "external agent runs a task via the gateway");
const gwRunDenied = await dj("POST", "/v1/hypervisor/mcp-gateway/tools/hv_run_task", { environment_id: gwEnvId, command: "rm -rf /" });
ok(gwRunDenied.body?.result?.policy_denied === true, "gateway tasks are under the SAME guardrails (denied command fails closed)");
const gwInspect = await dj("POST", "/v1/hypervisor/mcp-gateway/tools/hv_inspect_env", { environment_id: gwEnvId });
ok(gwInspect.body?.result?.phase === "running", "external agent inspects the env via the gateway", gwInspect.body?.result?.phase);
const gwCleanup = await dj("POST", "/v1/hypervisor/mcp-gateway/tools/hv_cleanup_env", { environment_id: gwEnvId });
ok(gwCleanup.body?.result?.deleted === true, "external agent cleans up the env via the gateway");

const verdict = failures > 0 ? "FAIL" : "PASS";
if (JSON_OUT) console.log(JSON.stringify({ workstream: "operability-functional", verdict, failures, checks: checks.length }, null, 2));
else console.log(`  VERDICT: ${verdict} (${checks.length - failures}/${checks.length} checks)`);
process.exit(verdict === "FAIL" ? 1 : 0);
