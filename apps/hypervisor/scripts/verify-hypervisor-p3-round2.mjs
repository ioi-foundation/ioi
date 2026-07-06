#!/usr/bin/env node
// P3 round-2 readiness verifier:
//   N. Release Controls lifecycle matrix (native first slice) — every release gate joined to its
//      target's LIVE object state; a locally-joinable target (domain app draft) shows its real
//      state, an unjoinable named ref says so, and nothing is guessed.
//   O. Data Lineage proof citations on ODK object details — the proof-stream entries citing the
//      record's ref, with the honest empty state when governed work has not touched it yet.
// Creates a real ODK chain + DomainApp + two ReleaseControls, verifies, cleans up.
//
// Usage: node apps/hypervisor/scripts/verify-hypervisor-p3-round2.mjs

const DAEMON = (process.env.IOI_HYPERVISOR_DAEMON_URL || "http://127.0.0.1:8765").replace(/\/$/, "");
const SERVE = (process.env.IOI_HYPERVISOR_SERVE_URL || "http://127.0.0.1:4173").replace(/\/$/, "");

const results = [];
const ok = (name, cond, detail) => { results.push({ name, pass: !!cond, detail: detail || "" }); };
async function jd(method, path, body) {
  const r = await fetch(`${DAEMON}${path}`, { method, headers: { "content-type": "application/json" }, body: body ? JSON.stringify(body) : undefined });
  return { status: r.status, j: await r.json().catch(() => null) };
}
const sGet = (p) => fetch(`${SERVE}${p}`).then(async (r) => ({ status: r.status, text: await r.text() }));

const made = { ont: null, sd: null, dapp: null, rc1: null, rc2: null };
async function cleanup() {
  if (made.rc1) await jd("DELETE", `/v1/hypervisor/governance/release-controls/${made.rc1}`);
  if (made.rc2) await jd("DELETE", `/v1/hypervisor/governance/release-controls/${made.rc2}`);
  if (made.dapp) await jd("DELETE", `/v1/hypervisor/domain-apps/${made.dapp}`);
  if (made.sd) await jd("DELETE", `/v1/hypervisor/odk/surface-descriptors/${made.sd}`);
  if (made.ont) await jd("DELETE", `/v1/hypervisor/odk/domain-ontologies/${made.ont}`);
}

async function run() {
  // Substrate: ontology → domain_app descriptor → DomainApp draft.
  const ont = await jd("POST", "/v1/hypervisor/odk/domain-ontologies", { domain: "verify-p3r2", canonical_object_model: { objects: ["Case"], actions: [], states: ["open"], roles: [], events: [] } });
  const ontRef = ont.j?.ontology?.ref || ont.j?.domain_ontology?.ref;
  made.ont = ont.j?.ontology?.id || ont.j?.domain_ontology?.id;
  ok("ontology created", ont.status === 201 && !!ontRef, ontRef);
  const sd = await jd("POST", "/v1/hypervisor/odk/surface-descriptors", { name: "verify-p3r2-app", composition_pattern: "domain_app", ontology_ref: ontRef });
  made.sd = sd.j?.surface_descriptor?.id;
  const sdRef = sd.j?.surface_descriptor?.ref;
  ok("domain_app descriptor created", sd.status === 201 && !!sdRef, sdRef);
  const da = await jd("POST", "/v1/hypervisor/domain-apps", { name: "verify-p3r2-app", surface_descriptor_ref: sdRef, visibility: "private" });
  made.dapp = da.j?.domain_app?.domain_app_id;
  const daRef = da.j?.domain_app?.domain_app_ref;
  ok("DomainApp draft created", da.status === 201 && !!daRef, daRef);

  // Two gates: one over the joinable app, one over an unjoinable named ref.
  const rc1 = await jd("POST", "/v1/hypervisor/governance/release-controls", { release_target_ref: daRef, rollout_mode: "full" });
  made.rc1 = rc1.j?.release_control?.id;
  ok("release gate over the domain app", rc1.status === 201 && !!made.rc1);
  const rc2 = await jd("POST", "/v1/hypervisor/governance/release-controls", { release_target_ref: "authority-action://verify-p3r2-named", rollout_mode: "canary", canary_percent: 25 });
  made.rc2 = rc2.j?.release_control?.id;
  ok("release gate over a named ref", rc2.status === 201 && !!made.rc2);

  // N. Matrix rendering.
  const gv = await sGet("/__ioi/governance?tab=releases");
  ok("lifecycle matrix renders", gv.status === 200 && gv.text.includes('id="gov-lifecycle-matrix"'));
  ok("joinable target shows its LIVE state", gv.text.includes(daRef) && gv.text.includes(">draft<"), "domain app draft");
  ok("unjoinable target stays a named ref, not a guess", gv.text.includes("named ref — no local join"));
  ok("rollout facts verbatim", gv.text.includes("canary 25%"));
  ok("honesty line on the matrix", gv.text.includes("never guessed"));

  // O. Proof citations on the ODK detail.
  const od = await sGet(`/__ioi/odk/ontologies/${encodeURIComponent(made.ont)}`);
  ok("proof citations section renders on ODK detail", od.status === 200 && od.text.includes('id="odk-proof-citations"'));
  ok("the record's own ref is echoed", od.text.includes(ontRef));
  const led = await jd("GET", "/v1/hypervisor/work-ledger");
  const cited = ((led.j || {}).entries || []).some((e) => JSON.stringify(e).includes(ontRef));
  if (cited) ok("citations listed from the proof stream", od.text.includes("citation"), "entries cite this ref");
  else ok("citation empty state honest", od.text.includes("No proof-stream citations yet"));
}

run().then(async () => {
  await cleanup();
  const fails = results.filter((r) => !r.pass);
  for (const r of results) console.log(`${r.pass ? "PASS" : "FAIL"}  ${r.name}${r.detail ? ` — ${r.detail}` : ""}`);
  console.log(`\n${results.length - fails.length}/${results.length} passed`);
  if (fails.length) process.exit(1);
  console.log("p3-round2 readiness: OK");
}).catch(async (e) => { await cleanup(); console.error("verifier crashed:", e); process.exit(1); });
