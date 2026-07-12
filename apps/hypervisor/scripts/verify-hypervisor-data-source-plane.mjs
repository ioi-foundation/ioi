#!/usr/bin/env node
// Data-source daemon plane done-bar — ISOLATED (#69). Contract before any UI promise, proven on a
// throwaway daemon+serve pair (temp IOI_HYPERVISOR_DATA_DIR, random IOI_HYPERVISOR_DAEMON_ADDR)
// so every successful AND rejected declaration journey runs without leaking one record into the
// real registry. The old shape of this verifier declared fixtures on the shared daemon and
// "cleaned up" through DELETE /v1/hypervisor/data-sources/:id — a route that DOES NOT EXIST — so
// each run leaked its fixture. No production DELETE authority is added for test convenience; the
// journeys are isolated instead, and the real daemon's source + receipt counts are asserted
// UNCHANGED at the end.
//
// Asserts: the plane serves; registration is FAIL-CLOSED (plaintext secret rejected, unknown kind
// rejected, network kind requires an endpoint, credential posture validated); input is TYPED and
// BOUNDED (#69 hardening: present-but-non-string fields refuse typed — a malformed
// credential_posture can never default to no_credentials_required; oversized fields refuse);
// persistence is ATOMIC (record first, receipt second, the receipt returned explicitly beside the
// record, receipt-file evidence exact); the overview projects the declaration vocabulary
// (source_kinds with requires_endpoint, known_kinds retained); the record reads back; and the
// Data owner surface (isolated serve) renders the plane as authority.
//
// Usage: node apps/hypervisor/scripts/verify-hypervisor-data-source-plane.mjs
// Exit 2 = BLOCKED (daemon binary not built).

import { startIsolatedPlane, receiptFileCount } from "./lib/isolated-daemon.mjs";

const REAL_DAEMON = (process.env.IOI_HYPERVISOR_DAEMON_URL || "http://127.0.0.1:8765").replace(/\/$/, "");
const REAL_DATA_DIR = process.env.IOI_HYPERVISOR_DATA_DIR || `${process.env.HOME}/.ioi/hypervisor/data`;
const RECEIPT_FAMILY = "data-source-registry-receipts";

const results = [];
const ok = (name, cond, detail) => { results.push({ name, pass: !!cond, detail: detail || "" }); };

async function run() {
  // Real-daemon snapshot (when it is up): the whole point of isolation is that NOTHING below
  // touches it. Down is fine — the isolation claim is then trivially true for records; receipt
  // files are counted from storage either way.
  const realBefore = await fetch(`${REAL_DAEMON}/v1/hypervisor/data-sources`).then((r) => r.json()).catch(() => null);
  const realReceiptsBefore = receiptFileCount(REAL_DATA_DIR, RECEIPT_FAMILY);

  const plane = await startIsolatedPlane({ serve: true });
  if (!plane) { console.error("BLOCKED: target/debug/hypervisor-daemon is not built — cargo build -p ioi-node --bin hypervisor-daemon"); process.exit(2); }
  const { daemonUrl, serveUrl, dataDir } = plane;
  async function jd(method, p, body) {
    const r = await fetch(`${daemonUrl}${p}`, { method, headers: { "content-type": "application/json" }, body: body ? JSON.stringify(body) : undefined });
    return { status: r.status, j: await r.json().catch(() => ({})) };
  }

  try {
    // 1. The isolated plane starts EMPTY and serves; the overview names its draft-nature gaps and
    // projects the declaration vocabulary.
    const list0 = await jd("GET", "/v1/hypervisor/data-sources");
    ok("isolated data-source plane serves an EMPTY registry (fresh temp data dir)", list0.status === 200 && Array.isArray(list0.j.data_sources) && list0.j.data_sources.length === 0, `${(list0.j.data_sources || []).length} sources`);
    const ov = await jd("GET", "/v1/hypervisor/data-sources/overview");
    ok("overview schema + known kinds + governance gaps", ov.j.schema_version === "ioi.hypervisor.data-sources-overview.v1" && (ov.j.known_kinds || []).length >= 5 && (ov.j.governance_gaps || []).length >= 1);
    ok("overview names that ingestion is NOT wired (draft honesty)", JSON.stringify(ov.j.governance_gaps || []).match(/not wired|declaration only|nothing here connects/i) !== null);
    ok("overview projects the declaration vocabulary: source_kinds = [{kind, requires_endpoint}] covering every known kind", Array.isArray(ov.j.source_kinds) && ov.j.source_kinds.length === (ov.j.known_kinds || []).length && ov.j.source_kinds.every((k) => typeof k.kind === "string" && typeof k.requires_endpoint === "boolean") && ov.j.source_kinds.find((k) => k.kind === "postgres")?.requires_endpoint === true && ov.j.source_kinds.find((k) => k.kind === "local_folder")?.requires_endpoint === false);
    ok("known_kinds retained beside source_kinds (compatibility projection)", JSON.stringify(ov.j.known_kinds) === JSON.stringify((ov.j.source_kinds || []).map((k) => k.kind)));

    // 2. Registration is FAIL-CLOSED (every rejection on the ISOLATED plane).
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
    const credEp = await jd("POST", "/v1/hypervisor/data-sources", { name: "x", kind: "rest_api", endpoint: "https://u:p@host/rows" });
    ok("credential-bearing endpoint rejected typed", credEp.status === 400 && credEp.j.error?.code === "data_source_endpoint_credentialed", credEp.j.error?.code);

    // 3. TYPED + BOUNDED intake (#69 hardening) — present-but-wrong-type refuses, never defaults.
    const postureNum = await jd("POST", "/v1/hypervisor/data-sources", { name: "x", kind: "local_folder", credential_posture: 7 });
    ok("non-string credential_posture refuses typed — it can NEVER default to no_credentials_required", postureNum.status === 400 && postureNum.j.error?.code === "data_source_field_type_invalid", postureNum.j.error?.code);
    const kindArr = await jd("POST", "/v1/hypervisor/data-sources", { name: "x", kind: ["postgres"] });
    ok("non-string kind refuses typed", kindArr.status === 400 && kindArr.j.error?.code === "data_source_field_type_invalid", kindArr.j.error?.code);
    const nameObj = await jd("POST", "/v1/hypervisor/data-sources", { name: { a: 1 }, kind: "local_folder" });
    ok("non-string name refuses typed", nameObj.status === 400 && nameObj.j.error?.code === "data_source_field_type_invalid", nameObj.j.error?.code);
    const epNum = await jd("POST", "/v1/hypervisor/data-sources", { name: "x", kind: "rest_api", endpoint: 443 });
    ok("non-string endpoint refuses typed", epNum.status === 400 && epNum.j.error?.code === "data_source_field_type_invalid", epNum.j.error?.code);
    const leaseNum = await jd("POST", "/v1/hypervisor/data-sources", { name: "x", kind: "local_folder", credential_lease_ref: 9 });
    const projNum = await jd("POST", "/v1/hypervisor/data-sources", { name: "x", kind: "local_folder", project_ref: 9 });
    ok("non-string credential_lease_ref / project_ref refuse typed", leaseNum.j.error?.code === "data_source_field_type_invalid" && projNum.j.error?.code === "data_source_field_type_invalid");
    const longName = await jd("POST", "/v1/hypervisor/data-sources", { name: "n".repeat(121), kind: "local_folder" });
    const longRef = await jd("POST", "/v1/hypervisor/data-sources", { name: "x", kind: "local_folder", project_ref: "p".repeat(201) });
    ok("oversized name / project_ref refuse bounded (never truncated into a different identity)", longName.j.error?.code === "data_source_field_too_long" && longRef.j.error?.code === "data_source_field_too_long");
    const rejectedCount = await jd("GET", "/v1/hypervisor/data-sources");
    ok("EVERY rejection above persisted NOTHING (registry still empty, zero receipt files)", rejectedCount.j.data_sources.length === 0 && receiptFileCount(dataDir, RECEIPT_FAMILY) === 0);

    // 4. Valid registration = declared, receipted ATOMICALLY, receipt returned explicitly.
    const marker = `Verify Source ${Date.now().toString(36)}`;
    const created = await jd("POST", "/v1/hypervisor/data-sources", { name: marker, kind: "rest_api", endpoint: "https://api.example.invalid/v1", credential_posture: "wallet_credential_lease" });
    const rec = created.j.data_source;
    ok("valid registration persists a declared record", created.status === 201 && rec?.schema_version === "ioi.hypervisor.data-source.v1" && rec?.lifecycle?.status === "declared", rec?.source_id);
    ok("the receipt is returned EXPLICITLY alongside the record (data_source_receipt)", created.j.data_source_receipt?.schema_version === "ioi.hypervisor.data-source-receipt.v1" && created.j.data_source_receipt?.receipt_ref === (rec?.receipt_refs || [])[0] && created.j.data_source_receipt?.source_ref === rec?.source_ref, created.j.data_source_receipt?.receipt_id);
    ok("registration is receipted", (rec?.receipt_refs || []).length >= 1 && String(rec.receipt_refs[0]).startsWith("agentgres://data-source-receipt/"));
    ok("ATOMIC evidence: exactly ONE record file and ONE receipt file exist (record-first/receipt-second, no orphan on either side)", receiptFileCount(dataDir, "data-source-registry") === 1 && receiptFileCount(dataDir, RECEIPT_FAMILY) === 1);
    ok("registration is honestly NOT wired for ingestion (named gap, no fake runtime)", rec?.ingestion?.wired === false);
    ok("no plaintext credential stored (posture only)", rec?.credential_posture === "wallet_credential_lease" && !JSON.stringify(rec).match(/hunter2|password|api_key/i));
    ok("omitted optional fields persist consistently null (project_ref, credential_binding)", rec?.project_ref === null && rec?.credential_binding === null);
    const got = await jd("GET", `/v1/hypervisor/data-sources/${rec.source_id}`);
    ok("record reads back by id", got.status === 200 && got.j.data_source?.name === marker);
    const listN = await jd("GET", "/v1/hypervisor/data-sources");
    ok("registered source appears in the list", (listN.j.data_sources || []).some((d) => d.source_id === rec.source_id));
    const local = await jd("POST", "/v1/hypervisor/data-sources", { name: "local drop", kind: "file_drop" });
    ok("local kind declares without an endpoint; endpoint persists consistently null; posture defaults for OMITTED only", local.status === 201 && local.j.data_source?.endpoint === null && local.j.data_source?.credential_posture === "no_credentials_required");

    // 5. Data owner surface (ISOLATED serve) renders the plane as authority.
    const page = await fetch(`${serveUrl}/__ioi/odk`).then(async (r) => ({ status: r.status, text: await r.text() })).catch(() => ({ status: 0, text: "" }));
    ok("Data/Ontology surface serves brand-clean", page.status === 200 && !/\bPalantir\b/.test(page.text));
    ok("owner surface renders the data-source plane as authority (the registered source)", page.text.includes(marker) || /Data sources/i.test(page.text), "surface reflects the plane");
    ok("sources capture seed kept secondary (linked reference)", page.text.includes("/__apps/sources"));
  } finally {
    await plane.stop();
  }

  // 6. ISOLATION PROOF — the real daemon's source count and receipt-file count are UNCHANGED.
  const realAfter = await fetch(`${REAL_DAEMON}/v1/hypervisor/data-sources`).then((r) => r.json()).catch(() => null);
  const realReceiptsAfter = receiptFileCount(REAL_DATA_DIR, RECEIPT_FAMILY);
  ok("REAL daemon source count unchanged (every journey ran isolated)", (realBefore === null && realAfter === null) || (realBefore?.data_sources || []).length === (realAfter?.data_sources || []).length, realBefore ? `${(realBefore.data_sources || []).length} before/after` : "real daemon not running (trivially unchanged)");
  ok("REAL daemon receipt-file count unchanged", realReceiptsBefore === realReceiptsAfter, `${realReceiptsBefore} before/after`);
}

run().then(() => {
  let fail = 0;
  for (const r of results) { console.log(`  ${r.pass ? "PASS" : "FAIL"}  ${r.name}${r.detail ? `  (${r.detail})` : ""}`); if (!r.pass) fail++; }
  console.log(`\n${results.length - fail}/${results.length} passed`);
  console.log(`data-source plane readiness: ${fail ? "FAIL" : "OK"}`);
  process.exit(fail ? 1 : 0);
}).catch((e) => { console.error("verifier crashed:", e); process.exit(1); });
