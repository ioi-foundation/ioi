#!/usr/bin/env node
// P1 capability-story readiness verifier — four grafts, each cross-checked against the projection
// it claims to render:
//   A. Model Catalog inside Foundry (49-model-catalog; 47-ml-library folds here) — route cards
//      carry the registry's own availability/custody/credential/admission truth + usage from
//      admitted session bindings; admin deliberately links to Agent Studio (single owner).
//   B. Run Replay index (native primitive first slice) — the replay list over live session runs,
//      durable transcripts, and IOI Agent runs; every row opens an owned timeline.
//   C. Proof Explorer facets on Work Ledger — the state-root timeline on demand; rooted-vs-total
//      counts must be exact.
//   D. Authority Clients roster on Connections (57-oauth2-clients, renamed) — lease classes with
//      active/expired/receipted/revocable math matching the lease records; origin honestly
//      unrecorded.
//
// Usage: node apps/hypervisor/scripts/verify-hypervisor-p1-capability.mjs

const DAEMON = (process.env.IOI_HYPERVISOR_DAEMON_URL || "http://127.0.0.1:8765").replace(/\/$/, "");
const SERVE = (process.env.IOI_HYPERVISOR_SERVE_URL || "http://127.0.0.1:4173").replace(/\/$/, "");

const results = [];
const ok = (name, cond, detail) => { results.push({ name, pass: !!cond, detail: detail || "" }); };
const jget = (p) => fetch(`${DAEMON}${p}`).then((r) => r.json()).catch(() => null);
const sGet = (p) => fetch(`${SERVE}${p}`).then(async (r) => ({ status: r.status, text: await r.text() }));

async function run() {
  // A. Model Catalog.
  const [foundry, mr, mb] = await Promise.all([sGet("/__ioi/foundry"), jget("/v1/hypervisor/model-routes"), jget("/v1/hypervisor/model-route-session-bindings")]);
  const routes = (mr || {}).routes || [];
  ok("Foundry renders 200 with Model Catalog", foundry.status === 200 && foundry.text.includes('id="foundry-model-catalog"'));
  if (routes.length) {
    const r0 = routes[0];
    ok("catalog cites route registry truth", foundry.text.includes(r0.route_ref || "@") && foundry.text.includes((r0.availability || {}).state || "@"));
    ok("custody posture verbatim", foundry.text.includes((r0.custody || {}).weight_class || "@") && foundry.text.includes((r0.custody || {}).mount_target || "@"));
    ok("admin links to its single owner (Agent Studio)", foundry.text.includes("Manage in Agent Studio"));
    const binds = ((mb || {}).bindings || []).filter((b) => (b.route_ref || b.model_route_ref) === r0.route_ref).length;
    ok("usage honest vs session bindings", binds === 0 ? foundry.text.includes("no session bindings yet") : foundry.text.includes(`${binds} admitted session binding`), `${binds} bindings`);
  } else {
    ok("catalog empty state honest", foundry.text.includes("No model routes registered yet"));
  }

  // B. Run Replay index.
  const [replay, tr, gr] = await Promise.all([sGet("/__ioi/run-replay"), jget("/v1/hypervisor/agent-run-transcripts"), jget("/v1/hypervisor/goal-runs")]);
  ok("Run Replay index renders 200", replay.status === 200 && replay.text.includes("<h1>Run Replay</h1>"));
  const trRuns = (tr || {}).runs || [];
  const goals = (gr || {}).goal_runs || [];
  if (trRuns.length || goals.length) {
    const newestTr = trRuns.slice().sort((a, b) => String(b.started_at || b.recorded_at || "").localeCompare(String(a.started_at || a.recorded_at || "")))[0];
    ok("replay rows cite recorded runs (newest transcript)", !newestTr || replay.text.includes(newestTr.run_id || "@"), `${trRuns.length} transcripts · ${goals.length} goal runs`);
    ok("replay links open owned timelines", replay.text.includes("/__ioi/run-timeline/"));
    const bare = await sGet("/__ioi/run-timeline");
    ok("bare run-timeline path is the same index", bare.status === 200 && bare.text.includes("<h1>Run Replay</h1>"));
    const deep = await sGet(`/__ioi/run-timeline/${encodeURIComponent(trRuns[0].run_id)}`);
    ok("deep timeline path still serves the timeline page", deep.status === 200 && deep.text.includes("rt-root"));
  } else {
    ok("replay empty state honest", replay.text.includes("No recorded runs yet"));
  }

  // C. Proof Explorer facets.
  const [wl, led] = await Promise.all([sGet("/__ioi/work-ledger"), jget("/v1/hypervisor/work-ledger")]);
  const entries = (led || {}).entries || [];
  const rooted = entries.filter((e) => e.state_root);
  ok("Work Ledger renders Proof Explorer facets", wl.status === 200 && wl.text.includes('id="wl-proof-explorer"'));
  ok("rooted-vs-total counts exact", wl.text.includes(`${rooted.length} of ${entries.length} entries carry a state root`), `${rooted.length}/${entries.length}`);
  if (rooted.length) ok("state-root chips cite real roots", wl.text.includes(String(rooted[0].state_root).slice(0, 18)));
  else ok("no-roots state honest", wl.text.includes("No state-rooted entries yet"));

  // E. Sessions root (rail root — the guide §9 P1 gap).
  const [sessPage, sess] = await Promise.all([sGet("/__ioi/sessions"), jget("/v1/hypervisor/sessions")]);
  const sessList = (sess || {}).sessions || [];
  ok("Sessions root renders 200", sessPage.status === 200 && sessPage.text.includes("<h1>Sessions</h1>"));
  if (sessList.length) {
    ok("sessions cited with lifecycle chips", sessList.slice(0, 5).every((s) => sessPage.text.includes(s.session_ref || "@")) && sessPage.text.includes('id="sess-chips"'), `${sessList.length} sessions`);
    ok("admitted binding shown as session truth", sessPage.text.includes("execute-time default") || sessPage.text.includes("admitted"), "binding column present");
  } else {
    ok("sessions empty state honest", sessPage.text.includes("No sessions yet"));
  }

  // F. Evals lane inside Foundry (sub-surface, never a card).
  const [foundry2, specsRes] = await Promise.all([sGet("/__ioi/foundry"), jget("/v1/hypervisor/foundry/specs")]);
  const evalSpecs = ((specsRes || {}).specs || []).filter((s) => s.kind === "model_eval");
  ok("Evals lane renders inside Foundry", foundry2.text.includes('id="foundry-evals"') && foundry2.text.includes("no eval executes in this plane"));
  ok("scorecard handoff links Release Controls", foundry2.text.includes("/__ioi/governance?tab=releases"));
  if (evalSpecs.length) ok("eval specs cited", evalSpecs.every((s) => foundry2.text.includes(s.id || "@")), `${evalSpecs.length} eval specs`);
  else ok("evals empty state honest", foundry2.text.includes("No eval specs yet"));

  // G. Developer Console on Connections (25-developer-tools folds here).
  const [conn2, mcp] = await Promise.all([sGet("/__ioi/connections"), jget("/v1/hypervisor/mcp-gateway/tools")]);
  const tools = (mcp || {}).tools || [];
  ok("Developer Console renders on Connections", conn2.text.includes('id="conn-developer-console"'));
  ok("MCP tool contracts counted from the gateway", tools.length === 0 || conn2.text.includes(`${tools.length} declared tool contract`), `${tools.length} tools`);
  const scimSt = await fetch(`${DAEMON}/scim/v2/ServiceProviderConfig`).then((r) => r.status).catch(() => 0);
  ok("SCIM posture pill matches live probe", scimSt === 401 ? conn2.text.includes("reachable · auth required") : scimSt === 200 ? conn2.text.includes(">reachable<") : conn2.text.includes("unreachable"), `scim ${scimSt}`);
  ok("API spine posture cited", conn2.text.includes("proxied at") && conn2.text.includes("/v1/*"));

  // D. Authority Clients roster.
  const [conn, ls] = await Promise.all([sGet("/__ioi/connections"), jget("/v1/hypervisor/capability-leases")]);
  const leases = (ls || {}).leases || [];
  ok("Connections renders Authority Clients roster", conn.status === 200 && conn.text.includes('id="conn-authority-clients"'));
  ok("origin honestly unrecorded", conn.text.includes("origin binding is not recorded on leases"));
  if (leases.length) {
    const now = Date.now();
    const active = leases.filter((l) => !l.expires_at || Number(l.expires_at) > now).length;
    const roster = (conn.text.split('id="conn-authority-clients"')[1] || "").split('class="cnwrap"')[0] || "";
    const shown = [...(roster.matchAll(/(\d+) active</g))].reduce((n, m) => n + Number(m[1]), 0);
    ok("active-lease math matches records (sum over client classes)", shown === active, `${shown} shown vs ${active}/${leases.length} active`);
    const receipted = leases.filter((l) => l.receipt_required).length;
    ok("receipt obligation surfaced when present", receipted === 0 || conn.text.includes("receipted"), `${receipted} receipted`);
  } else {
    ok("roster empty state honest", conn.text.includes("No capability leases issued yet"));
  }
}

run().then(() => {
  const fails = results.filter((r) => !r.pass);
  for (const r of results) console.log(`${r.pass ? "PASS" : "FAIL"}  ${r.name}${r.detail ? ` — ${r.detail}` : ""}`);
  console.log(`\n${results.length - fails.length}/${results.length} passed`);
  if (fails.length) process.exit(1);
  console.log("p1-capability readiness: OK");
}).catch((e) => { console.error("verifier crashed:", e); process.exit(1); });
