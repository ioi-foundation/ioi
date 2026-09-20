#!/usr/bin/env node
// extract-retained-c7-bounded-live-effect-run — M12.9 (register R-211): ONE retained owner-authorized
// LIVE Akash run that reached bid, lease, live provider readback, endpoint evidence, teardown and a
// provider-confirmed final debit, lifted from the live driver's artifact directory and the shared
// daemon's durable record families into ONE tracked, redacted, hash-committed evidence set. The set is
// the durable-record input the generation gate (check:c8-bounded-live-effect-certificate) assembles a
// C8 v2 certificate from at run time; it is not a certificate itself and claims nothing on its own.
//
// WHICH RUN, AND WHICH IT IS NOT. The run is dseq 1787324505416 (`env-c7-capstone-4`, 2026-08-21):
// the only positive run on this host whose eleven driver artifacts AND seven durable family records
// all exist. It is NOT the T7 integrated capstone M01.7 closed on (dseq 1787578174606, 2026-08-24),
// whose artifacts and certificate bytes do not exist on this host; that capstone stays re-qualified
// by check:t7-retained-capstone-applicability as an attested hash. The set says so in its own words.
//
// What is extracted: the eleven artifact projections the assembler reads, each scoped to the
// certified environment (receipts, operations and reconciliation rows for that environment only;
// whoami projected to its principal), the deployment, provider-lease, endpoint and capability-lease
// records and every provider-operation of the environment, the historical source basis and the
// substrate anchor as the run's own evidence attested them (the live substrate log has grown since
// and cannot be tracked). Any member whose name matches a secret pattern is REMOVED and recorded by
// name; the run is committed by sha256 over its redacted bytes.
//
//   node scripts/extract-retained-c7-bounded-live-effect-run.mjs [--artifacts <dir>] [--data-dir <dir>]
//        [--environment <env>] [--attested <run-evidence.json>] [--output <file>]
import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";

const arg = (name) => { const i = process.argv.indexOf(name); return i >= 0 ? process.argv[i + 1] : null; };
const artifacts = path.resolve(arg("--artifacts") || ".artifacts/implementation/c7-c8-development-1787324505416");
const dataDir = path.resolve(arg("--data-dir") || path.join(process.env.HOME || "", ".ioi", "hypervisor", "data"));
const environment = arg("--environment") || "env-c7-capstone-4";
const attestedPath = path.resolve(arg("--attested") || ".artifacts/implementation/c7-c8-development-1787324505416-v2-successor/run-evidence.json");
const output = path.resolve(arg("--output") || "docs/architecture/_meta/evidence/m12-9-c7-retained-bounded-live-effect-run-2026-09-20.v1.json");
const T7_CAPSTONE_DSEQ = "1787578174606";
const SECRET = /(password|session_token|sealed_token|api[_-]?key|secret|private[_-]?key|mnemonic|bearer|authorization)/iu;
const stable = (v) => JSON.stringify(v, (k, x) => (x && typeof x === "object" && !Array.isArray(x) ? Object.fromEntries(Object.keys(x).sort().map((key) => [key, x[key]])) : x));
const sha = (v) => `sha256:${crypto.createHash("sha256").update(stable(v)).digest("hex")}`;
function redact(value, redacted, at = "$") {
  if (Array.isArray(value)) return value.map((x, i) => redact(x, redacted, `${at}[${i}]`));
  if (value && typeof value === "object") {
    const out = {};
    for (const [k, v] of Object.entries(value)) {
      if (SECRET.test(k)) { redacted.push(`${at}.${k}`); continue; }
      out[k] = redact(v, redacted, `${at}.${k}`);
    }
    return out;
  }
  if (typeof value === "string" && /ioi_(sess|bootstrap)_[A-Za-z0-9_-]+|(?:^|[^A-Za-z0-9])sk-[A-Za-z0-9_-]{12,}/u.test(value)) { redacted.push(at); return "<redacted>"; }
  return value;
}
const readArtifact = (name) => JSON.parse(fs.readFileSync(path.join(artifacts, name), "utf8"));
const readFamily = (family) => { const dir = path.join(dataDir, family); return fs.existsSync(dir) ? fs.readdirSync(dir).filter((f) => f.endsWith(".json")).map((f) => JSON.parse(fs.readFileSync(path.join(dir, f), "utf8"))) : []; };

const attested = JSON.parse(fs.readFileSync(attestedPath, "utf8"));
if (attested?.durable?.environment_ref !== environment) { console.error(`attested run evidence is for ${attested?.durable?.environment_ref}, not ${environment}`); process.exit(2); }
const deployment = readFamily("akash-deployments").find((r) => r.environment_ref === environment);
if (!deployment) { console.error(`no akash-deployments record for ${environment} under ${dataDir}`); process.exit(2); }
if (deployment.execution_mode !== "live_console_api" || !deployment.lease_ref || deployment.state !== "final_debit_settled") { console.error("the run is not a live, leased, final-debit-settled deployment"); process.exit(2); }
const dseq = String(deployment.dseq);
const providerLease = readFamily("akash-leases").find((r) => r.environment_ref === environment && r.lease_ref === deployment.lease_ref);
const endpoint = readFamily("akash-endpoints").find((r) => r.environment_ref === environment && r.endpoint_ref === deployment.endpoint_ref);
const cast = readArtifact("c7-cast.json");
const capabilityLease = readFamily("capability-leases").find((r) => r.lease_id === cast.capability_lease?.lease_id);
const providerOperations = readFamily("provider-operations").filter((r) => r.environment_ref === environment).sort((a, b) => String(a.at).localeCompare(String(b.at)));
const whoamiRaw = readArtifact("c7-whoami.json");
const whoami = { ok: whoamiRaw.ok, authenticated: whoamiRaw.authenticated, principal: { principal_ref: whoamiRaw.principal?.principal_ref, role: whoamiRaw.principal?.role, source: whoamiRaw.principal?.source, schema_version: whoamiRaw.principal?.schema_version } };
const reconciliationRaw = readArtifact("c7-reconciliation.json");
const redacted = [];
const run = {
  dseq,
  environment_ref: environment,
  subject: {
    campaign: path.basename(artifacts),
    run_at: deployment.created_at ?? deployment.events?.[0]?.at ?? null,
    execution_mode: deployment.execution_mode,
    settlement_state: deployment.state,
    is_t7_capstone: false,
    t7_capstone_dseq: T7_CAPSTONE_DSEQ,
    statement: `this is the retained 2026-08-21 positive live run dseq ${dseq} (${environment}); it is NOT the T7 integrated capstone M01.7 closed on (dseq ${T7_CAPSTONE_DSEQ}, 2026-08-24), whose artifacts and certificate bytes do not exist on the extracting host and whose certificate remains re-qualified as an attested hash by check:t7-retained-capstone-applicability`,
  },
  source_basis: {
    commit: attested.source.commit,
    daemon_binary_sha256: attested.source.daemon_binary_sha256,
    dirty_state_declaration: attested.source.dirty_state_declaration,
    publication_eligible: false,
    basis: "the run's own evidence, as attested on 2026-08-21: the tree was declared dirty and the certificate is never publication-eligible",
  },
  substrate_anchor: {
    bytes: attested.durable.substrate_muxlog_bytes,
    prefix_sha256: attested.durable.substrate_muxlog_prefix_sha256,
    basis: "attested by the run's own evidence against the live substrate log on 2026-08-21, not recomputed here: the log has grown since and is not tracked",
  },
  artifacts: redact({
    challenge: readArtifact("c7-challenge.json"),
    proposal_admission: readArtifact("c7-proposal-admission.json"),
    cast,
    start: readArtifact("c7-start.json"),
    logs: readArtifact("c7-logs.json"),
    delete: readArtifact("c7-delete.json"),
    reconcile: fs.existsSync(path.join(artifacts, "c7-reconcile.json")) ? readArtifact("c7-reconcile.json") : null,
    whoami,
    receipts: { receipts: (readArtifact("c7-receipts.json").receipts || []).filter((r) => r.environment_ref === environment) },
    reconciliation: { ...reconciliationRaw, rows: (reconciliationRaw.rows || []).filter((r) => r.environment_ref === environment) },
    operations: { operations: (readArtifact("c7-operations.json").operations || []).filter((r) => r.environment_ref === environment) },
  }, redacted, "$.artifacts"),
  records: redact({
    deployment,
    provider_lease: providerLease,
    endpoint,
    capability_lease: capabilityLease,
    provider_operations: providerOperations,
  }, redacted, "$.records"),
  redacted_members: redacted,
};
run.run_sha256 = sha({ dseq: run.dseq, environment_ref: run.environment_ref, subject: run.subject, source_basis: run.source_basis, substrate_anchor: run.substrate_anchor, artifacts: run.artifacts, records: run.records });
const set = {
  schema_version: "ioi.evidence.retained-c7-bounded-live-effect-run.v1",
  extracted_at: new Date().toISOString(),
  basis: "the live driver's artifact directory for the run and the shared daemon's durable akash-deployments, akash-leases, akash-endpoints, capability-leases and provider-operations families (execution_mode live_console_api); one owner-authorized run of 2026-08-21 that reached bid, lease, live provider readback, endpoint evidence, teardown and a provider-confirmed final debit",
  what_this_is_not: `not a certificate and not a new crossing: the durable records one C8 v2 certificate is GENERATED from at run time; it is NOT the T7 integrated capstone (dseq ${T7_CAPSTONE_DSEQ}) and claims nothing about it; a certificate regenerated from these records is evidence about the 2026-08-21 crossing and never a fresh one`,
  attested_certificate_sha256: attested.certificate_hash ?? null,
  attested_certificate_basis: "the certificate_hash sealed from these same records on 2026-08-21 (the run's -v2-successor certificate, not tracked); the generation gate regenerates the certificate from this set and requires the regenerated hash to EQUAL it",
  extension_owed: { settled_positive_runs_without_artifact_sets: 13, note: "thirteen further live final_debit_settled runs (2026-08-22..24, including the T7 capstone) exist only as durable records without the driver's artifact set; they cannot answer the assembler's challenge, proposal and receipt members and are not extracted (R-211)" },
  runs: [run],
  set_sha256: sha([run.run_sha256]),
};
if (!set.attested_certificate_sha256) {
  // The -v2-successor run-evidence carries no hash; seal it the way the generator does so the set carries the attested hash.
  const { sealCertificate } = await import("../apps/hypervisor/scripts/lib/c7-c8-certificate.mjs");
  set.attested_certificate_sha256 = sealCertificate(attested).certificate_hash;
}
fs.mkdirSync(path.dirname(output), { recursive: true });
fs.writeFileSync(output, `${JSON.stringify(set, null, 2)}\n`);
console.log(JSON.stringify({ output: path.relative(process.cwd(), output), bytes: fs.statSync(output).size, dseq, redacted: redacted.length, receipts: run.artifacts.receipts.receipts.length, operations: run.artifacts.operations.operations.length, provider_operations: providerOperations.length, run_sha256: run.run_sha256, set_sha256: set.set_sha256, attested_certificate_sha256: set.attested_certificate_sha256 }));
