#!/usr/bin/env node
// Filecoin/CAS archive custody done-bar — the STORAGE leg after the compute trio. Storage
// backends hold payload bytes; they do not own operational truth (canon:
// docs/architecture/components/storage-backends/{doctrine,filecoin-cas}.md). Byte availability
// behind daemon-owned refs: not compute, not authority, not restore truth, not a peer control
// plane.
//
// Proves: bounded backend kinds validate; preflight really probes the store; storage candidates
// ride the candidate plane saying availability≠restore-truth; export seals bytes (Argon2id+AEAD)
// BEFORE write so no plaintext private material ever reaches a backend; the wallet challenge
// binds material+state_root+backend+encryption; the archive object records address/hash/size/
// media-type/backend metadata; corrupt bytes fail closed; missing bytes open an
// ArtifactAvailabilityIncident; a stale/wrong repair source emits repair_failed; a verified
// replacement commitment emits an ArtifactRepairReceipt and is admitted; restore succeeds ONLY
// after fetch + commitment hash + decrypt + admitted state_root all verify; ipfs/filecoin live
// modes block NAMED without credentials/config; Work Ledger + Operations + Environments surface
// it; no fee objects, no RoutingDecisionReceipt.
// Usage: node apps/hypervisor/scripts/verify-hypervisor-filecoin-cas-archive-custody.mjs
//
// ITS OWN STACK (R-240, verifier hazard sweep 2, 2026-09-29). This verifier created storage backends, provider
// accounts and archives in the owner's daemon (:8765) and then APPENDED TO, DELETED and OVERWROTE the files the daemon
// named — the archive commitment and the custody material, inside the owner's ~/.ioi/hypervisor/data. It now runs on
// a FRESH isolated daemon + serve (lib/verifier-stack.mjs), every daemon-given path it corrupts or restores is
// refused if it lies under the owner's Hypervisor home (refuseOwnerPath), and a provider-ops write names its owner and
// idempotency key (the owned-mutation contract every provider write now requires).
//
// A REAL AUTHORITY, NOT A TEST SIGNER. A grant-gated provider or storage crossing now needs a configured authority
// principal — a test-signer grant is no authority (501 provider_operation_authority_required). The plane's daemon is
// pointed at a sealed deployment-local wallet.network authority node of this verifier's own (a temp state dir, a
// passphrase unique to the run), and each crossing is the product's own ask: the ungranted call parks a challenge
// (403), the operator approves it with the passphrase on the daemon's decision route, and the retry names the
// decision's approval_ref (the one-use grant the authority minted for exactly that request). The authority starts a
// chain, so a run takes several minutes; IOI_WALLET_AUTHORITY_BINARY overrides the node binary.
// This verifier carried the first copy of that code; since 2026-09-29 it uses the shared one the provider-adapter
// verifiers use (lib/verifier-authority-stack.mjs), which also stops the node on a SIGTERM/SIGINT (R-240, failover
// teardown identity). No assertion changed.
// Exit 2 (BLOCKED): no daemon or authority binary, or the authority node never became ready.

import path from "node:path";
import { readFileSync, writeFileSync, rmSync, appendFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { refuseOwnerPath } from "./lib/verifier-stack.mjs";
import { authorityVerifierStack } from "./lib/verifier-authority-stack.mjs";

const HERE = path.dirname(fileURLToPath(import.meta.url));
const { ensureSshFixture } = await import(path.join(HERE, "ensure-ssh-fixture.mjs"));

// ── the sealed authority this verifier's daemon takes its grants from, and the stack on it ──
const A = await authorityVerifierStack({ label: "filecoin-cas-archive-custody" });
const STACK = A.stack;
const DAEMON = STACK.daemonUrl;
const SHELL = STACK.serveUrl;
// A daemon-given file this verifier corrupts, deletes or restores: always inside its own plane's data dir.
const ownPath = (p, what) => refuseOwnerPath(p, what);
const LIVE_MODE = process.env.IOI_FILECOIN_LIVE === "1" || process.env.IOI_IPFS_LIVE === "1";
const LIVE_TOKEN = process.env.IOI_FILECOIN_TOKEN || process.env.IOI_IPFS_TOKEN || "";

const results = [];
const ok = (name, cond, detail) => { results.push({ name, pass: !!cond, detail: detail || "" }); };
async function jd(method, url, body) {
  const r = await fetch(url.startsWith("http") ? url : `${DAEMON}${url}`, {
    method, headers: { "content-type": "application/json" },
    body: body ? JSON.stringify(body) : undefined,
  });
  return { status: r.status, j: await r.json().catch(() => ({})) };
}
// The operator's approval of a parked crossing: the daemon's decision route runs the authority's `approve` with the
// passphrase and answers the approval_ref the retry names (null when the refusal parked no challenge).
const REASON = "filecoin/CAS custody verifier";
const operatorGrant = (refused) => A.approve(refused, REASON);
const archiveOp = (body) => A.crossing("/v1/hypervisor/storage-archive-ops", body, REASON);

let sshAccountId = null;
let env = null;
const backendIds = [];
let opSeq = 0;
function providerOp(o, extra = {}) {
  // One logical op, one idempotency key: the challenged call and its granted retry are the same request.
  return A.crossing("/v1/hypervisor/provider-ops", A.owned({ provider_id: sshAccountId, op: o, environment_ref: env, ...extra }, `fc-${env}-${o}-${++opSeq}`), REASON);
}

async function run() {
  const tag = Date.now().toString(16);
  env = `env-fc-${tag}`;
  const fixture = await ensureSshFixture();

  // ── 1. Backend object plane: bounded kinds, honest capabilities, REAL preflight probe ──
  const badKind = await jd("POST", "/v1/hypervisor/storage-backends", { kind: "s3", display_name: "nope" });
  const cas = (await jd("POST", "/v1/hypervisor/storage-backends", { kind: "cas", display_name: `CAS ${tag}` })).j.backend || {};
  backendIds.push(cas.account_id);
  ok("bounded backend kinds — unknown kind 422; `cas` creates with availability≠restore-truth capabilities",
    badKind.status === 422 && /local_disk/.test(badKind.j.reason || "")
    && cas.account_ref?.startsWith("storage-backend://")
    && cas.capabilities?.encryption_required === true
    && /NOT restore truth/.test(cas.capabilities?.authority || "")
    && /content-addressed/.test(cas.capabilities?.addressing || ""));
  const pf = await jd("POST", `/v1/hypervisor/storage-backends/${cas.account_id}/preflight`);
  ok("preflight really probes the store (write/read/delete round-trip) → verified with evidence",
    pf.j.ok === true && pf.j.status === "verified"
    && /write\/read\/delete/.test(pf.j.preflight?.evidence?.probe || "")
    && pf.j.preflight?.evidence?.mode === "real_local");

  // ── 2. Candidate plane: storage options alongside compute, availability≠restore truth ──
  const intent = (await jd("POST", "/v1/hypervisor/cloud-candidates/intents", {
    runtime_class: "runtime.workbench", resource_classes: ["storage.archive", "storage.cas"],
  })).j.intent || {};
  const batch = (await jd("POST", "/v1/hypervisor/cloud-candidates/candidates/refresh", { intent_ref: intent.intent_ref })).j;
  const sc = (batch.candidates || []).find((c) => c.provider_account_ref === cas.account_ref) || {};
  ok("storage candidate rides the plane: adapter:storage-backend, archive/cas classes, custody honesty, evidence-bound",
    sc.adapter_ref === "adapter:storage-backend" && sc.runtime_class === "storage.archive"
    && (sc.resource_classes || []).includes("storage.cas")
    && (sc.evidence?.claims || []).some((c) => /NOT restore truth/.test(c))
    && /sealed_wallet_secret/.test(sc.custody_plan?.detail || "")
    && /is not authority|not spend authority/.test(sc.spend_estimate?.authority || "")
    && /cannot provision/.test(sc.authority || ""));
  const sources = (await jd("GET", "/v1/hypervisor/cloud-candidates/candidate-sources")).j.sources || [];
  const stSource = sources.find((s) => s.source === "storage_network") || {};
  ok("storage_network candidate source reflects real backend records (engaged with evidence)",
    stSource.state === "storage_backends_engaged"
    && (stSource.evidence?.verified_backends || 0) >= 1
    && /NOT restore truth/.test(stSource.rule || ""));

  // ── 3. Daemon-custody material via the REAL BYO SSH lane ──
  const acc = (await jd("POST", "/v1/hypervisor/provider-accounts", {
    kind: "baremetal_ssh", display_name: `FC node ${tag}`,
    endpoint: { host: fixture.host, port: fixture.port, user: fixture.user },
  })).j.account || {};
  sshAccountId = acc.account_id;
  await jd("POST", `/v1/hypervisor/provider-accounts/${acc.account_id}/credential`, { private_key: fixture.client_key });
  await jd("POST", `/v1/hypervisor/provider-accounts/${acc.account_id}/preflight`);
  await providerOp("create");
  const marker = `filecoin-cas-${tag}`;
  await providerOp("workrun", { command: `echo ${marker} > archive-me.txt && cat archive-me.txt` });
  const snap = await providerOp("snapshot");
  const materialRef = snap.j.evidence?.restore_material_ref || "";
  const stateRoot = snap.j.evidence?.state_root || "";
  ok("BYO SSH snapshot admits daemon-custody material (sha256 state_root)",
    materialRef.startsWith("provider-material://") && stateRoot.startsWith("sha256:"));
  const materials = (await jd("GET", "/v1/hypervisor/provider-materials")).j.materials || [];
  const material = materials.find((m) => m.material_ref === materialRef) || {};
  const custodyBytes = readFileSync(ownPath(material.path, "custody material"));

  // ── 4. Export: wallet-bound, sealed BEFORE write, commitment recorded ──
  const challenge = await jd("POST", "/v1/hypervisor/storage-archive-ops", { op: "export", backend_id: cas.account_id, material_ref: materialRef });
  const facets = challenge.j.lease_request_facets || {};
  ok("export wallet challenge binds material + state_root + backend + encryption posture",
    challenge.status === 403
    && facets.material_ref === materialRef && facets.state_root === stateRoot
    && facets.backend_ref === cas.account_ref && facets.encryption === "sealed_wallet_secret");
  const grant = await operatorGrant(challenge);
  const exported = await jd("POST", "/v1/hypervisor/storage-archive-ops", { op: "export", backend_id: cas.account_id, material_ref: materialRef, wallet_approval_grant: grant });
  const archive = exported.j.archive || {};
  const commitment = archive.commitment || {};
  ok("exported archive records CID-style address + hash + size + media type + backend metadata",
    exported.j.ok === true
    && String(commitment.address || "").startsWith("cas://sha256/")
    && String(commitment.stored_sha256 || "").startsWith("sha256:")
    && (commitment.size_bytes || 0) > 0 && commitment.read_back_verified === true
    && archive.media_type === "application/x-tar+gzip"
    && archive.backend_kind === "cas" && archive.state_root === stateRoot
    && /NOT restore truth/.test(archive.availability_note || ""));
  const storedBytes = readFileSync(ownPath(commitment.path, "archive commitment"));
  ok("public/decentralized backend NEVER receives plaintext (sealed bytes differ; no gzip magic; state_root ≠ stored hash)",
    archive.encryption?.plaintext_at_backend === false
    && !storedBytes.equals(custodyBytes)
    && !(storedBytes[0] === 0x1f && storedBytes[1] === 0x8b)
    && custodyBytes[0] === 0x1f && custodyBytes[1] === 0x8b
    && commitment.stored_sha256 !== stateRoot);
  const ledger1 = ((await jd("GET", "/v1/hypervisor/work-ledger")).j.entries || [])
    .filter((e) => e.kind === "storage_custody" && e.archive_ref === archive.archive_ref);
  ok("Work Ledger shows the archive export receipt (state_root + commitment + custody rule)",
    ledger1.some((e) => e.op === "export" && e.status === "ok"
      && e.state_root === stateRoot && e.commitment?.address === commitment.address
      && /not restore truth/.test(e.custody_rule || "")));

  // ── 5. Verify / corrupt / incident / restore-refusal / repair ──
  const v1 = await archiveOp({ op: "verify", archive_ref: archive.archive_ref });
  ok("verify re-fetches and re-hashes the stored commitment (availability evidence only)",
    v1.j.ok === true && v1.j.stored_sha256 === commitment.stored_sha256 && /not restore truth/.test(v1.j.note || ""));
  appendFileSync(ownPath(commitment.path, "archive commitment"), Buffer.from("CORRUPTION"));
  const v2 = await archiveOp({ op: "verify", archive_ref: archive.archive_ref });
  ok("corrupt stored bytes → hash_mismatch ArtifactAvailabilityIncident opens; archive impaired",
    v2.status === 409 && String(v2.j.incident_ref || "").startsWith("artifact-availability-incident://")
    && v2.j.archive_status === "impaired" && /stale or corrupt/.test(v2.j.reason || ""));
  const r1 = await archiveOp({ op: "restore", archive_ref: archive.archive_ref });
  ok("restore of corrupt bytes fails CLOSED — a fetchable object is NOT restore validity",
    r1.status === 409 && /storage_commitment_mismatch/.test(r1.j.reason || "")
    && /NOT restore validity/.test(r1.j.reason || ""));
  const rep1 = await archiveOp({ op: "repair", archive_ref: archive.archive_ref });
  const repair = rep1.j.repair || {};
  ok("repair from verified daemon custody → ArtifactRepairReceipt admits a REPLACEMENT commitment bound to the same state_root",
    rep1.j.ok === true && rep1.j.outcome === "repaired"
    && String(rep1.j.repair_ref || "").startsWith("artifact-repair-receipt://")
    && repair.new_commitment?.address !== repair.old_commitment?.address
    && repair.state_root === stateRoot
    && /a new CID alone repairs nothing/.test(repair.admission_note || ""));
  const incAfter = ((await jd("GET", "/v1/hypervisor/storage-incidents")).j.incidents || [])
    .filter((i) => i.archive_ref === archive.archive_ref);
  ok("repair closes the open incident (status repaired, repair backlink)",
    incAfter.length >= 1 && incAfter.every((i) => i.status === "repaired" && i.repair_ref === rep1.j.repair_ref));
  const archNow = ((await jd("GET", "/v1/hypervisor/storage-archives")).j.archives || [])
    .find((a) => a.archive_ref === archive.archive_ref) || {};
  const r2 = await archiveOp({ op: "restore", archive_ref: archive.archive_ref });
  ok("restore succeeds ONLY after hash + decrypt + admitted state_root validation (custody re-materialized)",
    archNow.status === "available"
    && r2.j.ok === true && r2.j.state_root_verified === stateRoot && r2.j.custody_rematerialized === true);
  const envRestore = await providerOp("restore", { material_ref: materialRef });
  ok("environment restore through provider-ops re-verifies the SAME admitted state_root (storage never bypasses daemon truth)",
    envRestore.j.ok === true && envRestore.j.evidence?.state_root_verified === stateRoot);

  // ── 6. Missing bytes + stale/wrong repair source ──
  const archNow2 = ((await jd("GET", "/v1/hypervisor/storage-archives")).j.archives || [])
    .find((a) => a.archive_ref === archive.archive_ref) || {};
  rmSync(ownPath(archNow2.commitment.path, "archive commitment"), { force: true });
  const v3 = await archiveOp({ op: "verify", archive_ref: archive.archive_ref });
  ok("missing stored bytes → missing_bytes availability incident, fail closed",
    v3.status === 409 && String(v3.j.incident_ref || "").startsWith("artifact-availability-incident://"));
  // stale/wrong repair source: corrupt the DAEMON custody bytes — repair must refuse.
  writeFileSync(ownPath(material.path, "custody material"), Buffer.concat([custodyBytes, Buffer.from("STALE")]));
  const rep2 = await archiveOp({ op: "repair", archive_ref: archive.archive_ref });
  ok("stale/wrong repair source → repair_failed ArtifactRepairReceipt (never a silent overwrite)",
    rep2.status === 409 && rep2.j.outcome === "repair_failed"
    && /custody_hash_mismatch/.test(rep2.j.reason || "")
    && String(rep2.j.repair_ref || "").startsWith("artifact-repair-receipt://"));
  writeFileSync(ownPath(material.path, "custody material"), custodyBytes);
  const rep3 = await archiveOp({ op: "repair", archive_ref: archive.archive_ref });
  ok("restored custody source → repair succeeds and the archive is admitted available again",
    rep3.j.ok === true && rep3.j.outcome === "repaired");

  // ── 7. Filecoin fixture semantics + ipfs/filecoin live honesty ──
  const fc = (await jd("POST", "/v1/hypervisor/storage-backends", { kind: "filecoin", display_name: `Filecoin ${tag}`, endpoint: { mode: "fixture" } })).j.backend || {};
  backendIds.push(fc.account_id);
  const fcPf = await jd("POST", `/v1/hypervisor/storage-backends/${fc.account_id}/preflight`);
  const fcExport = await archiveOp({ op: "export", backend_id: fc.account_id, material_ref: materialRef });
  const fcArch = fcExport.j.archive || {};
  ok("filecoin FIXTURE is unmistakably fixture: local-cas addressing, labelled warning, never network availability",
    fcPf.j.ok === true && /FIXTURE/.test(fcPf.j.preflight?.evidence?.warning || "")
    && fcExport.j.ok === true
    && String(fcArch.commitment?.address || "").startsWith("local-cas://sha256/")
    && fcArch.commitment?.mode === "fixture_evidence"
    && /NOT network availability/.test(fcArch.commitment?.warning || ""));
  const fcStored = readFileSync(ownPath(fcArch.commitment.path, "fixture archive commitment"));
  ok("fixture filecoin backend also NEVER sees plaintext (sealed, differs from custody bytes)",
    !fcStored.equals(custodyBytes) && !(fcStored[0] === 0x1f && fcStored[1] === 0x8b));
  const ipfs = (await jd("POST", "/v1/hypervisor/storage-backends", { kind: "ipfs", display_name: `IPFS ${tag}`, endpoint: { mode: "live", endpoint: "http://127.0.0.1:9" } })).j.backend || {};
  backendIds.push(ipfs.account_id);
  const ipfsPf = await jd("POST", `/v1/hypervisor/storage-backends/${ipfs.account_id}/preflight`);
  await jd("POST", `/v1/hypervisor/storage-backends/${ipfs.account_id}/credential`, { api_key: `IPFS-${tag}` });
  const ipfsPf2 = await jd("POST", `/v1/hypervisor/storage-backends/${ipfs.account_id}/preflight`);
  const ipfsExport = await jd("POST", "/v1/hypervisor/storage-archive-ops", { op: "export", backend_id: ipfs.account_id, material_ref: materialRef });
  ok("ipfs/filecoin LIVE blocks NAMED: no credential → credentials_absent; unreachable API → unreachable; export refuses unverified",
    ipfsPf.status === 409 && /ipfs_live_credentials_absent/.test(ipfsPf.j.reason || "")
    && ipfsPf2.status === 409 && /ipfs_live_unreachable/.test(ipfsPf2.j.reason || "")
    && ipfsExport.status === 409 && /storage_backend_unverified/.test(ipfsExport.j.reason || ""));

  // ── 8. Surfaces + invariants ──
  const opsHtml = await fetch(`${SHELL}/__ioi/operations`).then((r) => r.text());
  ok("Operations shows storage backend health + incidents (#ops-storage-backends)",
    opsHtml.includes('id="ops-storage-backends"') && /Storage backend health/.test(opsHtml)
    && opsHtml.includes(cas.account_ref));
  const envHtml = await fetch(`${SHELL}/__ioi/environments`).then((r) => r.text());
  ok("Environments shows archive custody posture for environment materials (#env-archive-custody)",
    envHtml.includes('id="env-archive-custody"') && envHtml.includes(env)
    && /storage availability is NOT restore truth/.test(envHtml));
  if (LIVE_MODE && !LIVE_TOKEN) {
    ok("storage_live_credentials_absent — IOI_FILECOIN_LIVE/IOI_IPFS_LIVE=1 requires a token; live execution BLOCKED (not faked)", false);
  } else if (!LIVE_MODE) {
    ok("live_storage_not_run — fixture/local CAS validated the custody ladder; live Filecoin/IPFS availability is NOT claimed", true);
  }
  const audit = JSON.stringify({
    archives: (await jd("GET", "/v1/hypervisor/storage-archives")).j,
    incidents: (await jd("GET", "/v1/hypervisor/storage-incidents")).j,
    batch,
  }).toLowerCase();
  ok("no fee objects, no RoutingDecisionReceipt, no markup; no storage id ever becomes authority",
    !audit.includes("routingdecisionreceipt") && !audit.includes("fee_amount") && !audit.includes("markup\":")
    && /no cid, deal, pin, or backend id ever becomes authority/i.test(archive.authority || ""));
  const ft = await fetch(`${SHELL}/__ioi/fallthrough`).then((r) => r.json()).catch(() => ({}));
  ok("fallthrough stays empty", Array.isArray(ft.proxied) && ft.proxied.length === 0);
}

async function cleanup() {
  try { if (sshAccountId && env) await providerOp("delete"); } catch { /* best effort */ }
  if (sshAccountId) await jd("DELETE", `/v1/hypervisor/provider-accounts/${sshAccountId}`);
  for (const id of backendIds) { if (id) await jd("DELETE", `/v1/hypervisor/storage-backends/${id}`); }
}

run()
  .then(cleanup, async (e) => { await cleanup(); throw e; })
  .then(async () => {
    await A.stop();
    let fail = 0;
    for (const r of results) { console.log(`  ${r.pass ? "PASS" : "FAIL"}  ${r.name}${r.detail ? `  (${r.detail})` : ""}`); if (!r.pass) fail++; }
    console.log(`\n${results.length - fail}/${results.length} passed`);
    console.log(`filecoin/cas archive custody readiness: ${fail ? "FAIL" : "OK"}${LIVE_MODE ? "" : " (live_storage_not_run)"}`);
    if (A.decisionRefusals.length) console.log(`authority decisions refused: ${A.decisionRefusals.map((d) => `${d.op || "?"}: ${d.status} ${d.code}`).join(", ")}`);
    process.exit(fail ? 1 : 0);
  })
  .catch(async (e) => {
    console.error("verifier crashed:", e);
    await A.stop().catch(() => {});
    process.exit(1);
  });
