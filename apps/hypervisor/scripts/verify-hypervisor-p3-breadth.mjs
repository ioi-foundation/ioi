#!/usr/bin/env node
// P3 breadth readiness verifier — three grafts, each bound to its owning projections:
//   K. Code Repositories (/__ioi/code — folds into Workbench): repos over project truth, SCM host
//      posture, governed-publish trail; exercised with a created-then-cleaned project.
//   L. Search (/__ioi/search): typed cross-estate discovery — a created object must be findable
//      with an open handoff to its owning surface; the no-index honesty is on the surface.
//   M. Work Analytics (Operations) + Tool Analytics (Connections) facets: funnel/histogram math
//      cross-checked against the projections; missing telemetry NAMED, never charted.
//
// Usage: node apps/hypervisor/scripts/verify-hypervisor-p3-breadth.mjs

const DAEMON = (process.env.IOI_HYPERVISOR_DAEMON_URL || "http://127.0.0.1:8765").replace(/\/$/, "");
const SERVE = (process.env.IOI_HYPERVISOR_SERVE_URL || "http://127.0.0.1:4173").replace(/\/$/, "");

const results = [];
const ok = (name, cond, detail) => { results.push({ name, pass: !!cond, detail: detail || "" }); };
async function jd(method, path, body) {
  const r = await fetch(`${DAEMON}${path}`, { method, headers: { "content-type": "application/json" }, body: body ? JSON.stringify(body) : undefined });
  return { status: r.status, j: await r.json().catch(() => null) };
}
const sGet = (p) => fetch(`${SERVE}${p}`).then(async (r) => ({ status: r.status, text: await r.text() }));

const PROJ = "verify-p3-repo";
async function cleanup() { await jd("DELETE", `/v1/hypervisor/projects/${encodeURIComponent("project:" + PROJ)}`); }

async function run() {
  const pj = await jd("POST", "/v1/hypervisor/projects", { project_name: PROJ, repository_url: `https://example.local/verify/${PROJ}.git` });
  ok("repository-backed project created", pj.status === 200 || pj.status === 201, PROJ);

  // K. Code Repositories.
  const code = await sGet("/__ioi/code");
  ok("Code Repositories renders 200", code.status === 200 && code.text.includes("<h1>Code Repositories</h1>"));
  ok("repo card cites the project's own repository_url", code.text.includes(`${PROJ}.git`));
  const scm = await jd("GET", "/v1/hypervisor/scm-connectors");
  const scmList = (scm.j || {}).connectors || [];
  if (scmList.length) ok("SCM hosts cited with posture", scmList.every((c) => code.text.includes(c.auth_posture || "@")), `${scmList.length} hosts`);
  else ok("SCM empty state honest (bind lane linked)", code.text.includes("No SCM hosts bound") && code.text.includes("git-authentications"));
  const led = await jd("GET", "/v1/hypervisor/work-ledger");
  const pubs = ((led.j || {}).entries || []).filter((e) => String(e.kind || "").includes("publish") || String(e.op || "").includes("publish"));
  if (pubs.length) ok("governed publishes cited from the proof stream", code.text.includes(pubs[0].kind || "@"), `${pubs.length} publishes`);
  else ok("publish trail honest when empty", code.text.includes("No governed publishes recorded yet"));
  ok("no mutation lanes on the repo surface", !/<form[^>]*method="post"/i.test(code.text), "publishing stays a wallet-authorized crossing elsewhere");

  // L. Search.
  const empty = await sGet("/__ioi/search");
  ok("Search renders with honest coverage list", empty.status === 200 && empty.text.includes("exact-substring") && empty.text.includes("no stale search truth"));
  const hits = await sGet(`/__ioi/search?q=${encodeURIComponent(PROJ)}`);
  ok("created object is findable", hits.text.includes(PROJ) && hits.text.includes("Projects (1)"), "typed group with count");
  ok("hit hands off to the owning surface", hits.text.includes(`/projects/project%3A${PROJ}`) || hits.text.includes(`/projects/project:${PROJ}`));
  const none = await sGet("/__ioi/search?q=zzz-no-such-thing-xyz");
  ok("no-match state honest", none.text.includes("No matches for"));

  // M. Work Analytics on Operations.
  const [opsPage, opsProj] = await Promise.all([sGet("/__ioi/operations"), jd("GET", "/v1/hypervisor/operations")]);
  const runsStat = ((opsProj.j || {}).runs) || {};
  ok("Work Analytics facet renders", opsPage.text.includes('id="ops-work-analytics"'));
  ok("run funnel math matches the projection", opsPage.text.includes(`total ${runsStat.total || 0}`) && opsPage.text.includes(`failed ${runsStat.failed || 0}`));
  ok("latency gap NAMED not charted", opsPage.text.includes("not recorded yet (named gap)"));
  ok("improvement handoff honest", (runsStat.failed || 0) > 0 ? opsPage.text.includes("improvement candidate") : opsPage.text.includes("nothing to mine right now") || opsPage.text.includes("No failed runs"));

  // M. Tool Analytics on Connections.
  const [connPage, ls, mcp] = await Promise.all([sGet("/__ioi/connections"), jd("GET", "/v1/hypervisor/capability-leases"), jd("GET", "/v1/hypervisor/mcp-gateway/tools")]);
  ok("Tool Analytics facet renders", connPage.text.includes('id="conn-tool-analytics"'));
  const leased = {};
  (((ls.j || {}).leases) || []).forEach((l) => (l.allowed_tools || []).forEach((t) => { leased[t] = (leased[t] || 0) + 1; }));
  const top = Object.entries(leased).sort((a, b) => b[1] - a[1])[0];
  if (top) ok("top leased tool volume matches lease records", connPage.text.includes(`${top[0]} ×${top[1]}`), `${top[0]} ×${top[1]}`);
  else ok("no-lease state honest", connPage.text.includes("no tool leases yet"));
  const mcpNames = (((mcp.j || {}).tools) || []).map((t) => t.name).filter(Boolean);
  const neverLeased = mcpNames.filter((n) => !leased[n]);
  if (neverLeased.length) ok("declared-but-never-leased is the real gap list", connPage.text.includes(neverLeased[0]), `${neverLeased.length} unused`);
  else ok("all declared tools leased (said plainly)", connPage.text.includes("every declared tool has been leased"));
  ok("per-call telemetry gap NAMED", connPage.text.includes("latency/error is not recorded yet"));
}

run().then(async () => {
  await cleanup();
  const fails = results.filter((r) => !r.pass);
  for (const r of results) console.log(`${r.pass ? "PASS" : "FAIL"}  ${r.name}${r.detail ? ` — ${r.detail}` : ""}`);
  console.log(`\n${results.length - fails.length}/${results.length} passed`);
  if (fails.length) process.exit(1);
  console.log("p3-breadth readiness: OK");
}).catch(async (e) => { await cleanup(); console.error("verifier crashed:", e); process.exit(1); });
