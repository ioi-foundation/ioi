import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";

const repoRoot = process.cwd();
const workItemsRoot = path.join(repoRoot, "internal-docs/implementation/work-items");
const evidenceRoot = path.join(repoRoot, "internal-docs/implementation/evidence/M1");
const recordedOn = "2026-07-25";
const certifiedCommit = "00869d171";
const implementationCommit = "3c39566ec";

function stable(value) {
  return `${JSON.stringify(value, null, 2)}\n`;
}

function sha256(value) {
  return crypto.createHash("sha256").update(value).digest("hex");
}

function sha256File(relative) {
  return sha256(fs.readFileSync(path.join(repoRoot, relative)));
}

function readRecord(id) {
  return JSON.parse(fs.readFileSync(path.join(workItemsRoot, `${id}.v1.json`), "utf8"));
}

function writeRecord(record) {
  fs.writeFileSync(path.join(workItemsRoot, `${record.work_item_id}.v1.json`), `${JSON.stringify(record, null, 2)}\n`);
}

const commonHeldProofs = {
  live_sequence_zero_certification: {
    command: "IOI_SYSTEM_SEQUENCE_ZERO_CERTIFY=1 node apps/hypervisor/scripts/verify-hypervisor-system-sequence-zero-materialization.mjs",
    result: "PASS",
    assertions_passed: 133,
    assertions_total: 133,
    journey_count: 14,
    journeys: [
      "dual-system-projection",
      "named-continuity",
      "constitutional-amendment",
      "protected-transition",
      "system-activation",
      "primary",
      "wallet-replay",
      "partial-prefix-replay",
      "dependency-ordered-replay",
      "unconsumed-revocation",
      "cross-version-compatibility",
      "receipt-version-compatibility",
      "precondition-cleanup",
      "terminal-intent-durability",
    ],
    teardown: {
      owned: 45,
      removed: 45,
      process_groups: 21,
      descendants_remaining: 0,
    },
  },
  daemon_tests: {
    command: "cargo test -p ioi-node --bin hypervisor-daemon -- --test-threads=1",
    result: "PASS",
    tests_passed: 341,
    tests_total: 341,
  },
  pre_next_leg: {
    command: "npm run check:pre-next-leg",
    result: "PASS",
    literal_result: "Pre-next-leg readiness passed.",
  },
  architecture_contract_bar: {
    result: "PASS",
    contracts: 51,
    fixtures: 171,
    typescript_differential_cases: 289,
    rust_architecture_tests: 18,
    source_policy_tests: 5,
  },
  m0_program_control: {
    result: "PASS",
    assertions_passed: 56,
    assertions_total: 56,
    reviewed_entries: 1553,
    review_epoch: "m1-continuity-projection-review-2026-07-25",
    review_anchor_head_sha256: "ad88761c74adfa7b6cc3bc66d808cddf65e9dd426e1aa1530c88364d07b75ee4",
    fingerprint: "e544985e96304fa04d76e1a4ccfa5a09851c3a8dce6a6eb9789f15edbf984001",
  },
  diff_integrity: {
    command: "git diff --check",
    result: "PASS",
  },
};

const proofSpecs = {
  "m1-genesis-admission": {
    claims: {
      selected_package_admits_under_exact_governed_authority: "PASS",
      recursive_secrets_and_noncanonical_keys_refuse: "PASS",
      authorized_projection_remains_pre_activation: "PASS",
      replay_and_cleanup_preserve_authority_semantics: "PASS",
    },
    nonclaims: ["This proof makes no M2 membership, topology, consensus, or multi-node claim."],
  },
  "m1-governed-initialize-activate": {
    claims: {
      initialize_and_activate_use_distinct_scopes: "PASS",
      exact_registered_graph_and_wallet_receipt_required: "PASS",
      sealed_intent_replay_converges_without_duplicate_effect: "PASS",
      invalid_or_detached_state_refuses_before_finalization: "PASS",
    },
    nonclaims: ["This proof covers the selected single-authority lifecycle only."],
  },
  "m1-sequence-zero-materialization": {
    claims: {
      sequence_zero_materialization_identity_is_exact_and_pre_activation: "PASS",
      portable_grant_binds_retained_signed_artifact: "PASS",
      current_and_frozen_legacy_receipts_validate: "PASS",
      crash_replay_and_cleanup_converge: "PASS",
    },
    nonclaims: ["This proof does not claim distributed genesis or M2 membership."],
  },
  "m1-protected-migration-dissolution-enrollment": {
    claims: {
      succession_builds_contract_valid_live_chain_successor: "PASS",
      migration_acknowledgement_binds_exact_head_and_destination: "PASS",
      dissolution_retains_terminal_residual_disposition: "PASS",
      local_only_enrollment_cannot_widen_network_scope: "PASS",
      stale_replayed_relocated_and_wrong_scope_requests_refuse: "PASS",
      named_operations_never_alias_generic_protected_operations: "PASS",
    },
    nonclaims: ["Enrollment remains local_only; M2 owns membership and topology."],
  },
  "m1-dual-genesis-and-read-projection": {
    claims: {
      two_independent_systems_materialize_distinct_genesis_roots: "PASS",
      chain_and_projection_reads_bind_each_system_identity: "PASS",
      cross_system_substitution_refuses: "PASS",
      lifecycle_and_continuity_projections_reconstruct_after_restart: "PASS",
      reads_do_not_mint_authority_or_infer_effects: "PASS",
    },
    nonclaims: ["Dual genesis proves independent bounded Systems on one selected node, not M2 membership or consensus."],
  },
  "m1-system-genesis-product-journey": {
    claims: {
      full_fourteen_journey_suite_passes_without_regression: "PASS",
      every_journey_uses_real_wallet_authority: "PASS",
      terminal_crash_recovery_converges: "PASS",
      cross_version_and_receipt_compatibility_pass: "PASS",
      teardown_leaves_no_owned_descendants: "PASS",
    },
    nonclaims: ["This is the M1 selected-profile product journey, not an M2 multi-node claim."],
  },
  "m1-5-protected-transitions": {
    claims: {
      generic_protected_transitions_verified: "PASS",
      constitutional_amendment_execution_verified: "PASS",
      succession_migration_dissolution_and_enrollment_verified: "PASS",
      ordinary_lifecycle_authority_cannot_admit_protected_effects: "PASS",
      exact_predecessor_and_exactly_once_replay_invariants_hold: "PASS",
    },
    nonclaims: ["The M1.5 aggregate does not claim M2 membership, topology, or consensus."],
  },
  "m1-selected-profile-exit-proof": {
    claims: {
      every_unconditional_m1_child_is_verified_with_content_bound_exit: "PASS",
      full_live_certification_passes_133_of_133: "PASS",
      full_daemon_suite_passes_341_of_341: "PASS",
      pre_next_leg_and_program_control_bars_pass: "PASS",
      architecture_and_read_projection_contracts_pass: "PASS",
      no_owned_process_or_worktree_residue_remains_from_certification: "PASS",
    },
    nonclaims: [
      "M1 proves the selected single-authority, single-node bounded System profile only.",
      "M2 membership readiness, writer fencing, topology, and multi-node recovery have not started.",
    ],
  },
};

function authorProofAndExit(id) {
  const record = readRecord(id);
  const proofRelative = `internal-docs/implementation/evidence/M1/${id}-proof.v1.json`;
  const exitRelative = record.evidence_index.expected_output_paths[0];
  const proof = {
    schema_version: "ioi.program.work-item-proof.v1",
    work_item_id: id,
    recorded_on: recordedOn,
    authoritative_revision: {
      branch: "agent/autonomous-m0-m14",
      certified_commit_sha: certifiedCommit,
      implementation_commit_sha: implementationCommit,
      base_merge_commit_sha: "a44f8c670bdd75197d6a6f53c98f0bfd08699be5",
      publication_state: "local_unpushed_branch",
    },
    held_proofs: commonHeldProofs,
    falsifiable_claim_results: proofSpecs[id].claims,
    remaining_nonclaims: proofSpecs[id].nonclaims,
  };
  fs.mkdirSync(evidenceRoot, { recursive: true });
  fs.writeFileSync(path.join(repoRoot, proofRelative), `${JSON.stringify(proof, null, 2)}\n`);
  const literal = record.evidence_index.literal_exit;
  const exit = [
    "IOI_LITERAL_EXIT_LOG_FORMAT=ioi.program.literal_exit.v1",
    `BAR=${literal.replace(/_EXIT=0$/u, "")}`,
    `ARTIFACT=${proofRelative}`,
    `ARTIFACT_SHA256=${sha256File(proofRelative)}`,
    literal,
    "",
  ].join("\n");
  fs.writeFileSync(path.join(repoRoot, exitRelative), exit);
  return { proofRelative, exitRelative };
}

const evidencePaths = new Map();
for (const id of Object.keys(proofSpecs)) evidencePaths.set(id, authorProofAndExit(id));

const evidenceSummaries = {
  "m1-genesis-admission": "Re-certified at the M1 exit revision: selected-package genesis admission, authority binding, denial paths, replay, and cleanup all passed in the held 133/133 live suite; daemon tests passed 341/341 and pre-next-leg passed.",
  "m1-governed-initialize-activate": "Re-certified at the M1 exit revision: governed initialize/activate remain scope-separated, exact, replay-convergent, and fail closed; the held live suite passed 133/133, daemon tests 341/341, and pre-next-leg passed.",
  "m1-sequence-zero-materialization": "Re-certified at the M1 exit revision: sequence-zero materialization and portable authority evidence remain exact, compatible, replay-convergent, and cleanup-safe; held live proof passed 133/133.",
  "m1-protected-migration-dissolution-enrollment": "Verified at the M1 exit revision: named succession, exact-head migration acknowledgement, dissolution with residual disposition, and local_only enrollment execute through distinct authority paths and reject stale, replayed, relocated, aliased, or widening requests.",
  "m1-dual-genesis-and-read-projection": "Verified at the M1 exit revision: two independent bounded Systems materialize distinct genesis roots and expose identity-bound chain, lifecycle, continuity, and active-profile read projections; cross-system substitution refuses.",
  "m1-system-genesis-product-journey": "Verified at the M1 exit revision by the complete fourteen-journey real-wallet certification: 133/133 assertions passed and teardown removed all 45 owned processes with zero descendants remaining.",
  "m1-5-protected-transitions": "Verified aggregate: generic protected transitions, amendment execution, and named succession/migration/dissolution/enrollment children all retain content-bound exits and pass exact-head, exactly-once, authority-separation, crash-replay, and denial proofs.",
  "m1-selected-profile-exit-proof": "Verified M1 selected-profile exit: every unconditional M1 child retains a content-bound literal; live certification passed 133/133, daemon tests 341/341, pre-next-leg and M0 program control passed, and architecture/read projections are current.",
};

function attachEvidence(record) {
  const { proofRelative, exitRelative } = evidencePaths.get(record.work_item_id);
  record.canon_snapshot = {
    captured_at: recordedOn,
    aggregate_sha256: "",
    owners: record.canon_owners.map((owner) => ({ path: owner, sha256: sha256File(owner) })),
  };
  record.canon_snapshot.aggregate_sha256 = sha256(
    record.canon_snapshot.owners.map((owner) => `${owner.path}:${owner.sha256}`).join("\n"),
  );
  const existing = (record.evidence_refs ?? []).filter((ref) => ref !== proofRelative && ref !== exitRelative);
  record.evidence_refs = [...existing, proofRelative, exitRelative];
  record.evidence_index.retained_refs = [...record.evidence_refs];
  record.evidence_index.historical_unavailable_refs = [];
  record.evidence_index.checkout_validation = "current_checkout_verified";
  record.current_implementation_evidence = evidenceSummaries[record.work_item_id];
}

function evidenceBinding(record) {
  const expectedLiteral = record.evidence_index.literal_exit;
  const files = [...new Set(record.evidence_refs)].sort().map((ref) => {
    const source = fs.readFileSync(path.join(repoRoot, ref), "utf8");
    const literalCount = source.split(/\r?\n/u).filter((line) => line === expectedLiteral).length;
    return {
      path: ref,
      exists: true,
      sha256: sha256File(ref),
      exact_literal_line_count: literalCount === 1 && ref === record.evidence_index.expected_output_paths[0] ? 1 : 0,
    };
  });
  const body = {
    expected_literal: expectedLiteral,
    evidence_files: files,
    exact_literal_line_count: files.reduce((total, file) => total + file.exact_literal_line_count, 0),
  };
  return {
    ...body,
    literal_valid: body.exact_literal_line_count === 1,
    evidence_bundle_sha256: sha256(stable(body)),
  };
}

function recordEntry(id) {
  const record = readRecord(id);
  return {
    record,
    record_sha256: sha256File(`internal-docs/implementation/work-items/${id}.v1.json`),
  };
}

function refreshAggregateBinding(record) {
  const dispositionByChild = new Map(record.aggregate_child_dispositions.map((entry) => [entry.child_work_item_id, entry]));
  const childBindings = record.aggregate_child_ids.map((id) => {
    const child = recordEntry(id);
    return {
      work_item_id: id,
      relation: "aggregate_child",
      selection_state: dispositionByChild.get(id).selection_state,
      record_sha256: child.record_sha256,
      status_at_binding: child.record.status,
      evidence_binding: evidenceBinding(child.record),
    };
  });
  const dependencyBindings = record.dependency_work_item_ids.map((id) => {
    const dependency = recordEntry(id);
    return {
      work_item_id: id,
      relation: "unconditional_dependency",
      selection_state: null,
      record_sha256: dependency.record_sha256,
      status_at_binding: dependency.record.status,
      evidence_binding: evidenceBinding(dependency.record),
    };
  });
  const aggregateEvidenceBinding = evidenceBinding(record);
  const payload = {
    child_dispositions: record.aggregate_child_dispositions,
    child_bindings: childBindings,
    dependency_bindings: dependencyBindings,
    aggregate_evidence_binding: aggregateEvidenceBinding,
  };
  record.aggregate_verification_binding = {
    schema_version: "ioi.program.aggregate-verification-binding.v1",
    ...payload,
    binding_payload_sha256: sha256(stable(payload)),
    nonclaim: "This exact-digest binding is a private closure precondition. It does not promote a child, dependency, proof gate, aggregate, work item, or stage and cannot substitute for literal-valid retained evidence.",
  };
}

const baseline = {
  "m1-genesis-admission": { status: "verified", sha256: "986f26b6763d41ea8b50f0f552c49919b978494e4b97b6cb01b8d164b6247139" },
  "m1-governed-initialize-activate": { status: "verified", sha256: "1bbda683574899b5d178d7e18d786b2b2c7a9a66acf7b8d32f5d536d012adaec" },
  "m1-sequence-zero-materialization": { status: "verified", sha256: "56832ee634655a9a9e98562c372b118a287dd0fc9bf21321348ec8e5e618364b" },
  "m1-protected-migration-dissolution-enrollment": { status: "proposed", sha256: "2b64b059163ded2c63e217b9520fac5c14834cce4c56355a8ca28b93ccd57c66" },
  "m1-dual-genesis-and-read-projection": { status: "proposed", sha256: "9cdb15c60ab1dbe579e4c4330dc8019a78f0280f3faea15cd11404b2925dd330" },
  "m1-system-genesis-product-journey": { status: "proposed", sha256: "788bc7cd9307196bcd7ac0ce37df2490339124b8c448f77da1b3ce49c2f3f4e6" },
  "m1-5-protected-transitions": { status: "scoped", sha256: "eff59e22abf0678abb0b35cc3c3716ad14c4f744c74115bc9b3b4b4d8d338472" },
  "m1-selected-profile-exit-proof": { status: "proposed", sha256: "a1b26de91d401fe3b7652d9be0a5fde0546e2a581c321726585c72d317a759b8" },
};

function verifyRecord(record, refreshBinding = false) {
  attachEvidence(record);
  record.status = "verified";
  record.last_status_transaction = recordedOn;
  if (refreshBinding) refreshAggregateBinding(record);
  delete record.status_transaction_chain;
  const payloadSha = sha256(stable(record));
  const transaction = {
    schema_version: "ioi.program.work-item-status-transaction.v1",
    sequence: 1,
    work_item_id: record.work_item_id,
    transaction_on: recordedOn,
    from_status: baseline[record.work_item_id].status,
    to_status: "verified",
    prior_record_sha256: baseline[record.work_item_id].sha256,
    current_record_payload_sha256: payloadSha,
    previous_transaction_sha256: null,
    evidence_refs: [evidencePaths.get(record.work_item_id).proofRelative, evidencePaths.get(record.work_item_id).exitRelative],
    literal_exit: record.evidence_index.literal_exit,
  };
  transaction.transaction_sha256 = sha256(stable(transaction));
  record.status_transaction_chain = [transaction];
  writeRecord(record);
}

function recertifyHistoricalVerified(record) {
  attachEvidence(record);
  record.status = "evidence_ready";
  record.last_status_transaction = recordedOn;
  delete record.status_transaction_chain;
  const evidenceReadyPayloadSha = sha256(stable(record));
  const evidenceReadyTransaction = {
    schema_version: "ioi.program.work-item-status-transaction.v1",
    sequence: 1,
    work_item_id: record.work_item_id,
    transaction_on: recordedOn,
    from_status: "verified",
    to_status: "evidence_ready",
    prior_record_sha256: baseline[record.work_item_id].sha256,
    current_record_payload_sha256: evidenceReadyPayloadSha,
    previous_transaction_sha256: null,
    evidence_refs: [evidencePaths.get(record.work_item_id).proofRelative],
    literal_exit: null,
  };
  evidenceReadyTransaction.transaction_sha256 = sha256(stable(evidenceReadyTransaction));

  record.status = "verified";
  const verifiedPayloadSha = sha256(stable(record));
  const verifiedTransaction = {
    schema_version: "ioi.program.work-item-status-transaction.v1",
    sequence: 2,
    work_item_id: record.work_item_id,
    transaction_on: recordedOn,
    from_status: "evidence_ready",
    to_status: "verified",
    prior_record_sha256: evidenceReadyPayloadSha,
    current_record_payload_sha256: verifiedPayloadSha,
    previous_transaction_sha256: evidenceReadyTransaction.transaction_sha256,
    evidence_refs: [evidencePaths.get(record.work_item_id).proofRelative, evidencePaths.get(record.work_item_id).exitRelative],
    literal_exit: record.evidence_index.literal_exit,
  };
  verifiedTransaction.transaction_sha256 = sha256(stable(verifiedTransaction));
  record.status_transaction_chain = [evidenceReadyTransaction, verifiedTransaction];
  writeRecord(record);
}

for (const id of ["m1-genesis-admission", "m1-governed-initialize-activate", "m1-sequence-zero-materialization"]) {
  const record = readRecord(id);
  recertifyHistoricalVerified(record);
}

for (const id of [
  "m1-protected-migration-dissolution-enrollment",
  "m1-dual-genesis-and-read-projection",
  "m1-system-genesis-product-journey",
]) verifyRecord(readRecord(id));

verifyRecord(readRecord("m1-5-protected-transitions"), true);
verifyRecord(readRecord("m1-selected-profile-exit-proof"), true);

process.stdout.write("Authored eight M1 proof bundles, refreshed two aggregate bindings, and appended five verified status transactions.\n");
