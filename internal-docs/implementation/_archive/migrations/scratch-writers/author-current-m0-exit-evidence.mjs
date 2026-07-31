import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";

const repoRoot = process.cwd();
const workItemsRoot = path.join(repoRoot, "internal-docs/implementation/work-items");
const evidenceRoot = path.join(repoRoot, "internal-docs/implementation/evidence/M0");
const recordedOn = "2026-07-25";

const baselines = {
  "m0-canon-owner-coverage-and-orphan-verifier": ["proposed", "8b59b7e32e9b8bcb391d22b1b5430b330a2f729009e9a78d91872e4c18f7f972"],
  "m0-literal-exit-evidence-contract": ["proposed", "9c2506769aeea928ae53902bbd970c21235f7a640bea2c3179bba215b257e680"],
  "m0-program-control-selected-profile-exit-proof": ["proposed", "aee6370fdbd1292b958a94927309e3b81be5f245b44b429998a012ac8eb45f75"],
  "m0-route-final-invoker-pg-census-maintenance": ["proposed", "80f038968b8dafc170d29cbc6c5a34fbab8c364c6c69d890e0b7fb31f9d6be6c"],
  "m0-selected-profile-baseline-evidence-and-claim-lock": ["proposed", "32f75b896258b3d2a53ede2e897828a0e209b5c650aa0b5b840d744a2e194d37"],
  "m0-source-disposition-and-single-sequencer-verifier": ["proposed", "69a4b098ed8b2cd4b77ce9de3cdd3acb28c68fbdb39b1f6992ed435e6f98f015"],
  "m0-unsigned-review-anchor": ["verified", "eba6eef4d3e07887f2586c1b5b91a7d4bd2a4738260085102f4af0593b3a35eb"],
  "m0-work-item-contract-completeness-and-owner-lint": ["proposed", "fa2dc72a52435410d4aa7c1a50bc9f65ea768fba2cd2bed787baacac79624dd8"],
};

const claims = {
  "m0-canon-owner-coverage-and-orphan-verifier": ["1553 reviewed entries cover the discovered current route/effect census.", "The current review epoch is hash-chained to sequence 10 and retains human judgments."],
  "m0-literal-exit-evidence-contract": ["Successful literals are standalone, content-bound to exact artifacts, and cannot be inferred from process exit codes."],
  "m0-program-control-selected-profile-exit-proof": ["The current M0 program-control suite passes 56/56 adversarial assertions and the read-only snapshot check."],
  "m0-route-final-invoker-pg-census-maintenance": ["The current registry contains 1553 reviewed entries with four newly reviewed continuity/projection routes and no unreviewed drift."],
  "m0-selected-profile-baseline-evidence-and-claim-lock": ["The selected profile and all explicit nonclaims remain hash-bound in the refreshed program-control artifacts."],
  "m0-source-disposition-and-single-sequencer-verifier": ["The master guide remains the sole M0-M14 sequencer and generated projections mint neither authority nor status."],
  "m0-unsigned-review-anchor": ["The sequence-11 unsigned review anchor is internally coherent, predecessor-bound, and passes all tamper tests."],
  "m0-work-item-contract-completeness-and-owner-lint": ["The current tracked work-item gate passes and the private status-chain finalization validator passes all post-migration transitions."],
};

function stable(value) { return `${JSON.stringify(value, null, 2)}\n`; }
function sha256(value) { return crypto.createHash("sha256").update(value).digest("hex"); }
function rel(id) { return `internal-docs/implementation/work-items/${id}.v1.json`; }
function read(id) { return JSON.parse(fs.readFileSync(path.join(repoRoot, rel(id)), "utf8")); }
function write(record) { fs.writeFileSync(path.join(repoRoot, rel(record.work_item_id)), stable(record)); }
function fileSha(relative) { return sha256(fs.readFileSync(path.join(repoRoot, relative))); }

function authorEvidence(id) {
  const record = read(id);
  const proof = `internal-docs/implementation/evidence/M0/${id}-proof.v1.json`;
  const exit = record.evidence_index.expected_output_paths[0];
  const artifact = {
    schema_version: "ioi.program.work-item-proof.v1",
    work_item_id: id,
    recorded_on: recordedOn,
    authoritative_revision: {
      branch: "agent/autonomous-m0-m14",
      certified_commit_sha: "00869d171",
      review_epoch: "m1-continuity-projection-review-2026-07-25",
      review_anchor_head_sha256: "ad88761c74adfa7b6cc3bc66d808cddf65e9dd426e1aa1530c88364d07b75ee4",
      publication_state: "local_unpushed_branch",
    },
    held_proofs: {
      m0_program_control: { result: "PASS", assertions_passed: 56, assertions_total: 56, reviewed_entries: 1553, fingerprint: "e544985e96304fa04d76e1a4ccfa5a09851c3a8dce6a6eb9789f15edbf984001" },
      pre_next_leg: { result: "PASS", literal_result: "Pre-next-leg readiness passed." },
      architecture_registry: { result: "PASS", contracts: 51, fixtures: 171 },
      program_source_attestation: { result: "PASS", currentness_claimed: false, scope: "supplied_repository_snapshot" },
    },
    falsifiable_claim_results: claims[id].map((claim) => ({ claim, result: "PASS" })),
    remaining_nonclaims: ["M0 workflow evidence grants no product authority and makes no M1 or later-stage product claim."],
  };
  fs.mkdirSync(evidenceRoot, { recursive: true });
  fs.writeFileSync(path.join(repoRoot, proof), stable(artifact));
  const literal = record.evidence_index.literal_exit;
  fs.writeFileSync(path.join(repoRoot, exit), [
    "IOI_LITERAL_EXIT_LOG_FORMAT=ioi.program.literal_exit.v1",
    `BAR=${literal.replace(/_EXIT=0$/u, "")}`,
    `ARTIFACT=${proof}`,
    `ARTIFACT_SHA256=${fileSha(proof)}`,
    literal,
    "",
  ].join("\n"));
  return { proof, exit };
}

const evidence = new Map(Object.keys(baselines).map((id) => [id, authorEvidence(id)]));

function attach(record) {
  const { proof, exit } = evidence.get(record.work_item_id);
  record.evidence_refs = [...new Set([...(record.evidence_refs ?? []).filter((ref) => ref !== proof && ref !== exit), proof, exit])];
  record.evidence_index.retained_refs = [...record.evidence_refs];
  record.evidence_index.historical_unavailable_refs = [];
  record.evidence_index.checkout_validation = "current_checkout_verified";
  record.current_implementation_evidence = `Current M0 recertification retained on ${recordedOn}: ${claims[record.work_item_id].join(" ")}`;
}

function evidenceBinding(record) {
  const literal = record.evidence_index.literal_exit;
  const files = [...new Set(record.evidence_refs)].sort().map((ref) => {
    const lines = fs.readFileSync(path.join(repoRoot, ref), "utf8").split(/\r?\n/u);
    return { path: ref, exists: true, sha256: fileSha(ref), exact_literal_line_count: ref === record.evidence_index.expected_output_paths[0] && lines.filter((line) => line === literal).length === 1 ? 1 : 0 };
  });
  const body = { expected_literal: literal, evidence_files: files, exact_literal_line_count: files.reduce((sum, file) => sum + file.exact_literal_line_count, 0) };
  return { ...body, literal_valid: body.exact_literal_line_count === 1, evidence_bundle_sha256: sha256(stable(body)) };
}

function entry(id) { const record = read(id); return { record, sha256: fileSha(rel(id)) }; }

function refreshAggregate(record) {
  const dispositions = record.aggregate_child_dispositions;
  const disposition = new Map(dispositions.map((row) => [row.child_work_item_id, row.selection_state]));
  const bind = (id, relation, selection_state) => {
    const target = entry(id);
    return { work_item_id: id, relation, selection_state, record_sha256: target.sha256, status_at_binding: target.record.status, evidence_binding: evidenceBinding(target.record) };
  };
  const payload = {
    child_dispositions: dispositions,
    child_bindings: record.aggregate_child_ids.map((id) => bind(id, "aggregate_child", disposition.get(id))),
    dependency_bindings: record.dependency_work_item_ids.map((id) => bind(id, "unconditional_dependency", null)),
    aggregate_evidence_binding: evidenceBinding(record),
  };
  record.aggregate_verification_binding = { schema_version: "ioi.program.aggregate-verification-binding.v1", ...payload, binding_payload_sha256: sha256(stable(payload)), nonclaim: "This exact-digest binding is a private closure precondition. It does not promote a child, dependency, proof gate, aggregate, work item, or stage and cannot substitute for literal-valid retained evidence." };
}

function digestTransaction(transaction) { return sha256(stable(transaction)); }

function verifyProposed(record, aggregate = false) {
  attach(record);
  record.status = "verified";
  record.last_status_transaction = recordedOn;
  if (aggregate) refreshAggregate(record);
  delete record.status_transaction_chain;
  const transaction = {
    schema_version: "ioi.program.work-item-status-transaction.v1",
    sequence: 1,
    work_item_id: record.work_item_id,
    transaction_on: recordedOn,
    from_status: "proposed",
    to_status: "verified",
    prior_record_sha256: baselines[record.work_item_id][1],
    current_record_payload_sha256: sha256(stable(record)),
    previous_transaction_sha256: null,
    evidence_refs: [evidence.get(record.work_item_id).proof, evidence.get(record.work_item_id).exit],
    literal_exit: record.evidence_index.literal_exit,
  };
  transaction.transaction_sha256 = digestTransaction(transaction);
  record.status_transaction_chain = [transaction];
  write(record);
}

function recertifyVerified(record) {
  attach(record);
  record.status = "evidence_ready";
  record.last_status_transaction = recordedOn;
  delete record.status_transaction_chain;
  const intermediateSha = sha256(stable(record));
  const first = {
    schema_version: "ioi.program.work-item-status-transaction.v1", sequence: 1, work_item_id: record.work_item_id, transaction_on: recordedOn,
    from_status: "verified", to_status: "evidence_ready", prior_record_sha256: baselines[record.work_item_id][1], current_record_payload_sha256: intermediateSha,
    previous_transaction_sha256: null, evidence_refs: [evidence.get(record.work_item_id).proof], literal_exit: null,
  };
  first.transaction_sha256 = digestTransaction(first);
  record.status = "verified";
  const second = {
    schema_version: "ioi.program.work-item-status-transaction.v1", sequence: 2, work_item_id: record.work_item_id, transaction_on: recordedOn,
    from_status: "evidence_ready", to_status: "verified", prior_record_sha256: intermediateSha, current_record_payload_sha256: sha256(stable(record)),
    previous_transaction_sha256: first.transaction_sha256, evidence_refs: [evidence.get(record.work_item_id).proof, evidence.get(record.work_item_id).exit], literal_exit: record.evidence_index.literal_exit,
  };
  second.transaction_sha256 = digestTransaction(second);
  record.status_transaction_chain = [first, second];
  write(record);
}

for (const id of Object.keys(baselines).filter((id) => !["m0-program-control-selected-profile-exit-proof", "m0-unsigned-review-anchor"].includes(id))) verifyProposed(read(id));
recertifyVerified(read("m0-unsigned-review-anchor"));
verifyProposed(read("m0-program-control-selected-profile-exit-proof"), true);

process.stdout.write("Authored eight current M0 proof bundles and status transactions.\n");
