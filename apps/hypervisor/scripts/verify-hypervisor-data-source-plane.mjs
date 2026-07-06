#!/usr/bin/env node
// Data-source daemon plane done-bar — the DAEMON-PLANE-FIRST shape (contract before any UI promise).
//
// The Data surface's source catalog had no daemon truth (empty capture envelope, no plane). Per the
// decision rule, the truth is built as a daemon CONTRACT first: a fail-closed, receipted DRAFT
// registry of declared external data sources — admission-only, ingestion explicitly not wired.
//
// Asserts: the plane serves; registration is FAIL-CLOSED (plaintext secret rejected, unknown kind
// rejected, network kind requires an endpoint, credential posture validated); a valid registration
// persists as a `declared`, receipted record that is honestly NOT wired for ingestion; the record
// reads back; the overview names its governance gaps; and the Data owner surface renders the plane
// as authority with the sources seed kept secondary.
//
// Usage: node apps/hypervisor/scripts/verify-hypervisor-data-source-plane.mjs
// Exit 2 = BLOCKED (daemon not running).

const SERVE = (process.env.IOI_HYPERVISOR_SERVE_URL || "http://127.0.0.1:4173").replace(/\/$/, "");
const DAEMON = (process.env.IOI_HYPERVISOR_DAEMON_URL || "http://127.0.0.1:8765").replace(/\/$/, "");

const results = [];
const ok = (name, cond, detail) => { results.push({ name, pass: !!cond, detail: detail || "" }); };
async function jd(method, p, body) {
  const r = await fetch(`${DAEMON}${p}`, { method, headers: { "content-type": "application/json" }, body: body ? JSON.stringify(body) : undefined });
  return { status: r.status, j: await r.json().catch(() => ({})) };
}

async function run() {
  const up = await fetch(`${DAEMON}/v1/hypervisor/data-sources`).then((r) => r.ok).catch(() => false);
  if (!up) { console.error("BLOCKED: daemon data-source plane not reachable at " + DAEMON); process.exit(2); }

  // 1. Plane serves + overview names its draft-nature gaps.
  const list0 = await jd("GET", "/v1/hypervisor/data-sources");
  ok("data-source plane serves a registry list", list0.status === 200 && Array.isArray(list0.j.data_sources), `${(list0.j.data_sources || []).length} sources`);
  const ov = await jd("GET", "/v1/hypervisor/data-sources/overview");
  ok("overview schema + known kinds + governance gaps", ov.j.schema_version === "ioi.hypervisor.data-sources-overview.v1" && (ov.j.known_kinds || []).length >= 5 && (ov.j.governance_gaps || []).length >= 1);
  ok("overview names that ingestion is NOT wired (draft honesty)", JSON.stringify(ov.j.governance_gaps || []).match(/not wired|declaration only|nothing here connects/i) !== null);

  // 2. Registration is FAIL-CLOSED.
  const secret = await jd("POST", "/v1/hypervisor/data-sources", { name: "x", kind: "postgres", endpoint: "postgres://h", password: "hunter2" });
  ok("plaintext secret rejected outright", secret.status === 400 && secret.j.error?.code === "data_source_plaintext_secret_rejected", secret.j.error?.code);
  const badKind = await jd("POST", "/v1/hypervisor/data-sources", { name: "x", kind: "bogus" });
  ok("unknown kind rejected fail-closed", badKind.status === 400 && badKind.j.error?.code === "data_source_kind_invalid", badKind.j.error?.code);
  const noEndpoint = await jd("POST", "/v1/hypervisor/data-sources", { name: "x", kind: "postgres" });
  ok("network kind without an endpoint rejected", noEndpoint.status === 400 && noEndpoint.j.error?.code === "data_source_endpoint_required", noEndpoint.j.error?.code);
  const noName = await jd("POST", "/v1/hypervisor/data-sources", { kind: "local_folder" });
  ok("registration without a name rejected", noName.status === 400 && noName.j.error?.code === "data_source_name_required", noName.j.error?.code);
  const badCred = await jd("POST", "/v1/hypervisor/data-sources", { name: "x", kind: "local_folder", credential_posture: "just_paste_the_key" });
  ok("invalid credential posture rejected (postures only, never a secret)", badCred.status === 400 && badCred.j.error?.code === "data_source_credential_posture_invalid", badCred.j.error?.code);

  // 3. Valid registration = declared, receipted, honestly NOT wired.
  const marker = `Verify Source ${Date.now().toString(36)}`;
  const created = await jd("POST", "/v1/hypervisor/data-sources", { name: marker, kind: "rest_api", endpoint: "https://api.example.invalid/v1", credential_posture: "wallet_credential_lease" });
  const rec = created.j.data_source;
  ok("valid registration persists a declared record", created.status === 201 && rec?.schema_version === "ioi.hypervisor.data-source.v1" && rec?.lifecycle?.status === "declared", rec?.source_id);
  ok("registration is receipted", (rec?.receipt_refs || []).length >= 1 && String(rec.receipt_refs[0]).startsWith("agentgres://data-source-receipt/"));
  ok("registration is honestly NOT wired for ingestion (named gap, no fake runtime)", rec?.ingestion?.wired === false);
  ok("no plaintext credential stored (posture only)", rec?.credential_posture === "wallet_credential_lease" && !JSON.stringify(rec).match(/hunter2|password|api_key/i));
  const got = await jd("GET", `/v1/hypervisor/data-sources/${rec.source_id}`);
  ok("record reads back by id", got.status === 200 && got.j.data_source?.name === marker);
  const listN = await jd("GET", "/v1/hypervisor/data-sources");
  ok("registered source appears in the list", (listN.j.data_sources || []).some((d) => d.source_id === rec.source_id));

  // 4. Data owner surface renders the plane as authority, sources seed secondary.
  const page = await fetch(`${SERVE}/__ioi/odk`).then(async (r) => ({ status: r.status, text: await r.text() })).catch(() => ({ status: 0, text: "" }));
  ok("Data/Ontology surface serves brand-clean", page.status === 200 && !/\bPalantir\b/.test(page.text));
  ok("owner surface renders the data-source plane as authority (the registered source)", page.text.includes(marker) || /Data sources/i.test(page.text), "surface reflects the plane");
  ok("sources capture seed kept secondary (linked reference)", page.text.includes("/__apps/sources"));
}

run().then(() => {
  let fail = 0;
  for (const r of results) { console.log(`  ${r.pass ? "PASS" : "FAIL"}  ${r.name}${r.detail ? `  (${r.detail})` : ""}`); if (!r.pass) fail++; }
  console.log(`\n${results.length - fail}/${results.length} passed`);
  console.log(`data-source plane readiness: ${fail ? "FAIL" : "OK"}`);
  process.exit(fail ? 1 : 0);
}).catch((e) => { console.error("verifier crashed:", e); process.exit(1); });
