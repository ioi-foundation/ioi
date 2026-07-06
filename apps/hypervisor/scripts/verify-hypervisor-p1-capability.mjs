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
    ok("replay rows cite recorded runs", trRuns.slice(0, 5).every((t) => replay.text.includes(t.run_id || "@")), `${trRuns.length} transcripts · ${goals.length} goal runs`);
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
