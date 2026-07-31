#!/usr/bin/env node
// Focused fail-closed tests for the current aggregate binding projector/gate.
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import process from "node:process";
import {
  blockingAggregateBindingRefreshRefusals,
  deriveAggregateVerificationBinding,
  validateAggregateVerificationBinding,
} from "./lib/aggregate-verification-binding.mjs";

let failures = 0;
function check(name, condition, detail = "") {
  if (condition) process.stdout.write(`  ok   ${name}\n`);
  else {
    failures += 1;
    process.stdout.write(`  FAIL ${name}${detail ? ` — ${detail}` : ""}\n`);
  }
}

function clone(value) {
  return JSON.parse(JSON.stringify(value));
}

function main() {
  process.stdout.write("aggregate verification binding fixture test\n");
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), "ioi-aggregate-binding-"));
  try {
    const childLiteral = "M3_WORK_SESSION_AUTOMATION_PRODUCT_EXIT=0";
    const childExit =
      "internal-docs/implementation/evidence/M3/m3-work-session-automation-product-journey.exit.v1.txt";
    const aggregateLiteral = "M3_DIRECT_PATH_AND_EXIT_PROOF_EXIT=0";
    const aggregateExit =
      "internal-docs/implementation/evidence/M3/m3-direct-path-and-exit-proof.exit.v1.txt";
    const child = {
      work_item_id: "fixture-child",
      status: "verified",
      evidence_refs: [childExit],
      evidence_index: {
        literal_exit: childLiteral,
        retained_refs: [childExit],
        expected_output_paths: [childExit],
      },
      file: "child.json",
    };
    const aggregate = {
      work_item_id: "fixture-aggregate",
      record_role: "aggregate_exit",
      status: "active",
      aggregate_child_ids: [child.work_item_id],
      aggregate_child_dispositions: [{
        child_work_item_id: child.work_item_id,
        selection_state: "unconditional_active",
        activation_gate_id: null,
        selection_authority: "sole-sequencer stage membership",
        selection_evidence_refs: [],
        disposition_basis:
          "This fixture child is an unconditional aggregate member for exact binding tests.",
      }],
      dependency_work_item_ids: [child.work_item_id],
      evidence_refs: [aggregateExit],
      evidence_index: {
        literal_exit: aggregateLiteral,
        retained_refs: [aggregateExit],
        expected_output_paths: [aggregateExit],
      },
      file: "aggregate.json",
    };
    const records = [child, aggregate];
    const recordPath = (record) => path.join(tmp, record.file);
    fs.writeFileSync(recordPath(child), `${JSON.stringify(child, null, 2)}\n`);
    fs.writeFileSync(recordPath(aggregate), `${JSON.stringify(aggregate, null, 2)}\n`);

    aggregate.aggregate_verification_binding = deriveAggregateVerificationBinding(
      aggregate,
      { records, recordPath },
    );
    let refusals = validateAggregateVerificationBinding(aggregate, {
      records,
      recordPath,
    });
    check(
      "an exact verified child/dependency and both conforming literals validate",
      refusals.length === 0,
      JSON.stringify(refusals),
    );

    child.changed_after_binding = true;
    fs.writeFileSync(recordPath(child), `${JSON.stringify(child, null, 2)}\n`);
    refusals = validateAggregateVerificationBinding(aggregate, {
      records,
      recordPath,
    });
    check(
      "changed child record bytes stale both child and dependency bindings",
      refusals.some((entry) => entry.check === "aggregate-binding-child-stale") &&
        refusals.some((entry) => entry.check === "aggregate-binding-dependency-stale"),
      JSON.stringify(refusals),
    );

    aggregate.aggregate_verification_binding = deriveAggregateVerificationBinding(
      aggregate,
      { records, recordPath },
    );
    aggregate.aggregate_verification_binding.child_bindings[0]
      .evidence_binding.literal_valid = false;
    refusals = validateAggregateVerificationBinding(aggregate, {
      records,
      recordPath,
    });
    check(
      "a caller-mutated child evidence binding is stale",
      refusals.some((entry) => entry.check === "aggregate-binding-child-stale"),
      JSON.stringify(refusals),
    );

    child.pg_gate_states = [{
      pg_id: "PG-FIXTURE",
      applicability: "required_now",
      closure_status: "open",
      evidence_refs: [],
      literal_exit: null,
    }];
    fs.writeFileSync(recordPath(child), `${JSON.stringify(child, null, 2)}\n`);
    aggregate.aggregate_verification_binding = deriveAggregateVerificationBinding(
      aggregate,
      { records, recordPath },
    );
    refusals = validateAggregateVerificationBinding(aggregate, {
      records,
      recordPath,
    });
    check(
      "a required-now child PG gate remains a hard aggregate refusal",
      refusals.some((entry) => entry.check === "required-pg-gate-open"),
      JSON.stringify(refusals),
    );
    child.pg_gate_states = [];
    fs.writeFileSync(recordPath(child), `${JSON.stringify(child, null, 2)}\n`);

    delete aggregate.aggregate_verification_binding;
    refusals = validateAggregateVerificationBinding(aggregate, {
      records,
      recordPath,
    });
    check(
      "a missing aggregate binding refuses",
      refusals.some((entry) => entry.check === "aggregate-binding-missing"),
      JSON.stringify(refusals),
    );

    child.evidence_refs = [];
    child.evidence_index.retained_refs = [];
    child.evidence_index.expected_output_paths = [
      "internal-docs/implementation/evidence/M4/fixture-missing-child.exit.v1.txt",
    ];
    fs.writeFileSync(recordPath(child), `${JSON.stringify(child, null, 2)}\n`);
    aggregate.aggregate_verification_binding = deriveAggregateVerificationBinding(
      aggregate,
      { records, recordPath },
    );
    refusals = validateAggregateVerificationBinding(aggregate, {
      records,
      recordPath,
    });
    check(
      "a missing child literal refuses even when the stored projection is current",
      refusals.some((entry) =>
        entry.check === "aggregate-binding-child-literal-invalid"
      ),
      JSON.stringify(refusals),
    );

    // Restore the child and make only the aggregate literal absent.
    child.evidence_refs = [childExit];
    child.evidence_index.retained_refs = [childExit];
    child.evidence_index.expected_output_paths = [childExit];
    fs.writeFileSync(recordPath(child), `${JSON.stringify(child, null, 2)}\n`);
    aggregate.evidence_refs = [];
    aggregate.evidence_index.retained_refs = [];
    aggregate.evidence_index.expected_output_paths = [
      "internal-docs/implementation/evidence/M4/fixture-missing-aggregate.exit.v1.txt",
    ];
    aggregate.aggregate_verification_binding = deriveAggregateVerificationBinding(
      aggregate,
      { records, recordPath },
    );
    refusals = validateAggregateVerificationBinding(aggregate, {
      records,
      recordPath,
    });
    check(
      "a missing aggregate literal refuses even when the stored projection is current",
      refusals.some((entry) =>
        entry.check === "aggregate-binding-own-literal-invalid"
      ),
      JSON.stringify(refusals),
    );
    check(
      "an unverified aggregate may refresh when only its own proof is absent",
      blockingAggregateBindingRefreshRefusals("active", refusals).length === 0,
      JSON.stringify(blockingAggregateBindingRefreshRefusals("active", refusals)),
    );

    child.status = "active";
    fs.writeFileSync(recordPath(child), `${JSON.stringify(child, null, 2)}\n`);
    aggregate.aggregate_verification_binding = deriveAggregateVerificationBinding(
      aggregate,
      { records, recordPath },
    );
    refusals = validateAggregateVerificationBinding(aggregate, {
      records,
      recordPath,
    });
    check(
      "an active child remains a hard pre-proof refresh refusal",
      blockingAggregateBindingRefreshRefusals("active", refusals).some((entry) =>
        entry.check === "aggregate-binding-child-status"
      ),
      JSON.stringify(blockingAggregateBindingRefreshRefusals("active", refusals)),
    );

    child.status = "verified";
    child.evidence_refs = [];
    child.evidence_index.retained_refs = [];
    child.evidence_index.expected_output_paths = [
      "internal-docs/implementation/evidence/M4/fixture-missing-child.exit.v1.txt",
    ];
    fs.writeFileSync(recordPath(child), `${JSON.stringify(child, null, 2)}\n`);
    aggregate.aggregate_verification_binding = deriveAggregateVerificationBinding(
      aggregate,
      { records, recordPath },
    );
    refusals = validateAggregateVerificationBinding(aggregate, {
      records,
      recordPath,
    });
    check(
      "missing child evidence and its invalid literal remain hard refresh refusals",
      blockingAggregateBindingRefreshRefusals("active", refusals).some((entry) =>
        entry.check === "aggregate-binding-child-literal-invalid" ||
          entry.check === "aggregate-binding-child-evidence-missing"
      ),
      JSON.stringify(blockingAggregateBindingRefreshRefusals("active", refusals)),
    );
    check(
      "a verified aggregate cannot use the pre-proof own-evidence exception",
      blockingAggregateBindingRefreshRefusals("verified", refusals).some((entry) =>
        entry.check === "aggregate-binding-own-literal-invalid" ||
          entry.check === "aggregate-binding-own-evidence-missing"
      ),
      JSON.stringify(blockingAggregateBindingRefreshRefusals("verified", refusals)),
    );

    // Verify the projector itself never mutates its inputs.
    const before = JSON.stringify(records);
    deriveAggregateVerificationBinding(clone(aggregate), {
      records,
      recordPath,
    });
    check("derivation does not mutate current records", JSON.stringify(records) === before);
  } finally {
    fs.rmSync(tmp, { recursive: true, force: true });
  }
  process.stdout.write(
    `aggregate verification binding fixtures: ${failures === 0 ? "PASS" : "FAIL"}\n`,
  );
  process.exit(failures === 0 ? 0 : 1);
}

main();
