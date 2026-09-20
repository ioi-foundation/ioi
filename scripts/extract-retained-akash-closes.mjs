#!/usr/bin/env node
// extract-retained-akash-closes — M09.6 (register R-210): the nine owner-authorized LIVE Akash runs that
// reached no qualified bid, closed, and settled to a provider-confirmed refund, lifted from the shared
// daemon's durable record families into ONE tracked, redacted, hash-committed evidence set. The set is the
// durable-record input the generation gate (check:provider-neutral-live-transaction) assembles a typed
// terminal certificate from at run time; it is not a certificate itself and claims nothing on its own.
//
// What is extracted per run: the akash-deployments record (provider-native settlement readback, close
// HTTP, teardown state, the typed no-bid reason, the challenge request hash, the events) and every
// provider-operations record that names the run's dseq (reconcile readbacks, logs) — with any member whose
// name matches a secret pattern REMOVED and recorded by name, and every row committed by sha256 over its
// redacted bytes. What is NOT here, because the records never held it, is listed per row as
// `unrecorded_members` so the certificate can name it rather than silently omit it.
//
//   node scripts/extract-retained-akash-closes.mjs --data-dir <daemon data dir> --output <file>
import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";

const arg = (name) => { const i = process.argv.indexOf(name); return i >= 0 ? process.argv[i + 1] : null; };
const dataDir = path.resolve(arg("--data-dir") || path.join(process.env.HOME || "", ".ioi", "hypervisor", "data"));
const output = path.resolve(arg("--output") || "docs/architecture/_meta/evidence/m09-6-akash-retained-no-qualified-bid-closes-2026-09-20.v1.json");
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
const readFamily = (family) => { const dir = path.join(dataDir, family); return fs.existsSync(dir) ? fs.readdirSync(dir).filter((f) => f.endsWith(".json")).map((f) => ({ file: f, record: JSON.parse(fs.readFileSync(path.join(dir, f), "utf8")) })) : []; };
const deployments = readFamily("akash-deployments").map((x) => x.record).filter((r) => r.execution_mode === "live_console_api" && r.bid_ref == null && r.lease_ref == null && r.state === "refund_settled");
if (deployments.length === 0) { console.error(`no live no-qualified-bid closes under ${dataDir}`); process.exit(2); }
const operations = readFamily("provider-operations").map((x) => x.record);
const rows = deployments.sort((a, b) => String(a.at).localeCompare(String(b.at))).map((deployment) => {
  const dseq = String(deployment.dseq);
  const ops = operations.filter((op) => JSON.stringify(op).includes(dseq)).sort((a, b) => String(a.at).localeCompare(String(b.at)));
  const redacted = [];
  const row = {
    dseq,
    deployment: redact(deployment, redacted, "$.deployment"),
    operations: ops.map((op) => redact(op, redacted, `$.operations[${op.operation_id}]`)),
    unrecorded_members: [
      ...(ops.some((op) => op.op === "create" && op.proposal_consumption) ? [] : ["proposal_consumption"]),
      ...(ops.some((op) => Array.isArray(op.journal_state_roots) && op.journal_state_roots.length >= 2) ? [] : ["journal_state_roots"]),
      "capability_lease",
      "source_commit",
      "operator_principal_ref",
    ],
    redacted_members: redacted,
  };
  row.row_sha256 = sha({ dseq: row.dseq, deployment: row.deployment, operations: row.operations, unrecorded_members: row.unrecorded_members });
  return row;
});
const set = {
  schema_version: "ioi.evidence.retained-akash-no-qualified-bid-closes.v1",
  extracted_at: new Date().toISOString(),
  basis: "the shared daemon's durable akash-deployments and provider-operations families (execution_mode live_console_api); owner-authorized runs of 2026-08-21 that reached no qualified bid within the polling window, closed, and settled to a provider-confirmed refund",
  what_this_is_not: "not a certificate and not a success: nine safe refusals that were closed and refunded; each row names the canonical members the records never held (unrecorded_members) so a certificate generated from it can name them too",
  rows,
  set_sha256: sha(rows.map((r) => r.row_sha256)),
};
fs.mkdirSync(path.dirname(output), { recursive: true });
fs.writeFileSync(output, `${JSON.stringify(set, null, 2)}\n`);
console.log(JSON.stringify({ output: path.relative(process.cwd(), output), rows: rows.length, redacted: rows.reduce((n, r) => n + r.redacted_members.length, 0), set_sha256: set.set_sha256, ops_per_row: rows.map((r) => r.operations.length) }));
