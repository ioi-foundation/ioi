#!/usr/bin/env node
// Regression for the cache path that once admitted focused_checks: [] after a
// successful dry run. This test exercises the exact exported cache validator;
// it does not execute or certify a stage.
import process from "node:process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { spawnSync } from "node:child_process";
import {
  applyVerifiedAggregateRecertification,
  certificationPrivateAuthorityFingerprint,
  certificationToolchainFingerprint,
  dispatchStageCertificationTransaction,
  FOCUSED_CHECK_TIMEOUT_MS,
  STAGE_CERTIFICATION_FORMAT,
  validateCachedFocusedChecks,
  validateStageCertificationEnvelope,
  validateStageCertificationInputStability,
} from "./certify-stage.mjs";
import {
  deriveAggregateVerificationBinding,
  validateAggregateVerificationBinding,
} from "./lib/aggregate-verification-binding.mjs";
import {
  sha256File,
  sha256Text,
  writeJsonDeterministic,
} from "./lib/estate.mjs";

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
  process.stdout.write("stage certification cache fixture test\n");
  check(
    "focused-check timeout exceeds the room-plane wrapper's 45-minute child ceiling",
    FOCUSED_CHECK_TIMEOUT_MS >= 60 * 60 * 1000 &&
      FOCUSED_CHECK_TIMEOUT_MS > 45 * 60 * 1000,
    `${FOCUSED_CHECK_TIMEOUT_MS}`,
  );
  const expected = {
    stageId: "MX",
    aggregateWorkItemId: "mx-exit",
    inputDigest: "a".repeat(64),
    commands: ["node first.mjs", "npm run second"],
  };
  const valid = {
    evidence_format: "ioi.program.stage_certification.v1",
    stage_id: expected.stageId,
    aggregate_work_item_id: expected.aggregateWorkItemId,
    input_digest: expected.inputDigest,
    focused_checks: [
      { command: expected.commands[0], exit: 0, seconds: 1.25 },
      { command: expected.commands[1], exit: 0, seconds: 2.5 },
    ],
    result: "PASS",
  };

  let defects = validateCachedFocusedChecks(valid, expected);
  check("a complete exact green cache is reusable", defects.length === 0, defects.join(" | "));

  const empty = clone(valid);
  empty.focused_checks = [];
  defects = validateCachedFocusedChecks(empty, expected);
  check(
    "an empty focused-check cache refuses",
    defects.some((defect) => defect.includes("carries 0 focused checks")),
    defects.join(" | "),
  );

  const red = clone(valid);
  red.focused_checks[1].exit = 1;
  defects = validateCachedFocusedChecks(red, expected);
  check(
    "a cached red command refuses",
    defects.some((defect) => defect.includes("cached check is red")),
    defects.join(" | "),
  );

  const reordered = clone(valid);
  reordered.focused_checks.reverse();
  defects = validateCachedFocusedChecks(reordered, expected);
  check(
    "a changed command order refuses",
    defects.some((defect) => defect.includes("command set/order is stale")),
    defects.join(" | "),
  );

  const stale = clone(valid);
  stale.input_digest = "b".repeat(64);
  defects = validateCachedFocusedChecks(stale, expected);
  check(
    "a stale input digest refuses",
    defects.some((defect) => defect.includes("input_digest is stale")),
    defects.join(" | "),
  );

  const retained = [...valid.focused_checks];
  check(
    "a reusable cache retains every original check in order",
    JSON.stringify(retained.map((entry) => entry.command)) ===
      JSON.stringify(expected.commands) && retained.every((entry) => entry.exit === 0),
  );

  const currentEnvelopeInput = {
    inputDigest: expected.inputDigest,
    commands: expected.commands,
    children: [{ id: "mx-child", status: "verified" }],
    literals: [
      {
        work_item_id: "mx-child",
        expected: "MX_CHILD_EXIT=0",
        artifact_path: "evidence/mx-child.exit.txt",
        artifact_sha256: "c".repeat(64),
      },
      {
        work_item_id: expected.aggregateWorkItemId,
        expected: "MX_AGGREGATE_EXIT=0",
        artifact_path: "evidence/mx-aggregate.exit.txt",
        artifact_sha256: "d".repeat(64),
      },
    ],
    adversarialOrFaultProof: ["declared adversarial proof"],
  };
  const validStageEnvelope = {
    ...valid,
    evidence_format: STAGE_CERTIFICATION_FORMAT,
    children: currentEnvelopeInput.children,
    literal_exits: currentEnvelopeInput.literals,
    literal_exit: currentEnvelopeInput.literals[1],
    adversarial_or_fault_proof: currentEnvelopeInput.adversarialOrFaultProof,
  };
  let envelopeDefects = validateStageCertificationEnvelope(validStageEnvelope, {
    stageId: expected.stageId,
    aggregateWorkItemId: expected.aggregateWorkItemId,
    currentInput: currentEnvelopeInput,
  });
  check(
    "a complete current green stage-certification envelope validates",
    envelopeDefects.length === 0,
    envelopeDefects.join(" | "),
  );
  for (const [name, candidate] of [
    ["handcrafted untyped aggregate result", { literal_exit: currentEnvelopeInput.literals[1] }],
    ["wrong-stage aggregate result", { ...validStageEnvelope, stage_id: "M-WRONG" }],
    ["wrong-aggregate result", { ...validStageEnvelope, aggregate_work_item_id: "wrong-exit" }],
    ["red aggregate result", { ...validStageEnvelope, result: "FAIL" }],
    ["empty aggregate focused checks", { ...validStageEnvelope, focused_checks: [] }],
    ["red aggregate focused check", {
      ...validStageEnvelope,
      focused_checks: validStageEnvelope.focused_checks.map((entry, index) =>
        index === 0 ? { ...entry, exit: 1 } : entry
      ),
    }],
    ["stale aggregate input digest", { ...validStageEnvelope, input_digest: "e".repeat(64) }],
    ["incomplete aggregate literal bindings", { ...validStageEnvelope, literal_exits: [] }],
    ["forged aggregate adversarial proof substitution", {
      ...validStageEnvelope,
      adversarial_or_fault_proof: ["forged adversarial proof"],
    }],
  ]) {
    envelopeDefects = validateStageCertificationEnvelope(candidate, {
      stageId: expected.stageId,
      aggregateWorkItemId: expected.aggregateWorkItemId,
      currentInput: currentEnvelopeInput,
    });
    check(`${name} is refused`, envelopeDefects.length > 0, envelopeDefects.join(" | "));
  }

  const inputPayload = {
    checkout: { tracked_diff_sha256: "1".repeat(64) },
    private_authority: { aggregate_sha256: "2".repeat(64) },
    certification_toolchain: { aggregate_sha256: "3".repeat(64) },
    literals: [{ artifact_sha256: "4".repeat(64) }],
    aggregate_binding_payload_sha256: "5".repeat(64),
  };
  const inputState = (payload) => ({
    payload,
    inputDigest: sha256Text(JSON.stringify(payload)),
  });
  const stableInput = inputState(inputPayload);
  check(
    "an exact post-check input payload remains stable",
    validateStageCertificationInputStability(stableInput, inputState(clone(inputPayload))).length === 0,
  );
  for (const [phase, mutate] of [
    ["post-fresh-check", (payload) => {
      payload.checkout.tracked_diff_sha256 = "6".repeat(64);
    }],
    ["post-cached-check", (payload) => {
      payload.private_authority.aggregate_sha256 = "7".repeat(64);
    }],
    ["verified-recertification", (payload) => {
      payload.certification_toolchain.aggregate_sha256 = "8".repeat(64);
    }],
    ["post-evidence-check", (payload) => {
      payload.literals[0].artifact_sha256 = "9".repeat(64);
    }],
    ["pre-dispatch", (payload) => {
      payload.aggregate_binding_payload_sha256 = "a".repeat(64);
    }],
  ]) {
    const changed = clone(inputPayload);
    mutate(changed);
    const drift = validateStageCertificationInputStability(
      stableInput,
      inputState(changed),
      { phase },
    );
    check(`${phase} refuses complete-input drift`, drift.length > 0, drift.join(" | "));
  }

  const forbiddenApply = spawnSync(process.execPath, [
    "internal-docs/implementation/tools/certify-stage.mjs",
    "M-STATIC-FIXTURE",
    "--apply",
    "--no-run",
  ], {
    cwd: process.cwd(),
    encoding: "utf8",
  });
  check(
    "--apply --no-run refuses before a static or cached PASS can transition",
    forbiddenApply.status === 2 &&
      forbiddenApply.stderr.includes("--apply --no-run is forbidden") &&
      !forbiddenApply.stdout.includes("transition"),
    `status=${forbiddenApply.status} stdout=${forbiddenApply.stdout} stderr=${forbiddenApply.stderr}`,
  );

  const toolchain = certificationToolchainFingerprint();
  const toolPaths = new Set(toolchain.files.map((entry) => entry.path));
  for (const required of [
    "internal-docs/implementation/tools/certify-stage.mjs",
    "internal-docs/implementation/tools/transition.mjs",
    "internal-docs/implementation/tools/refresh-aggregate-verification-binding.mjs",
    "internal-docs/implementation/tools/lib/aggregate-verification-binding.mjs",
    "internal-docs/implementation/tools/lib/literal-exit.mjs",
    "internal-docs/implementation/tools/test-aggregate-verification-binding.mjs",
    "internal-docs/implementation/tools/test-certify-stage-cache.mjs",
  ]) {
    check(
      `toolchain fingerprint binds ${required}`,
      toolPaths.has(required),
    );
  }
  check(
    "toolchain fingerprint has one aggregate digest over exact tool bytes",
    /^[a-f0-9]{64}$/u.test(toolchain.aggregate_sha256),
    toolchain.aggregate_sha256,
  );

  const latestTmp = fs.mkdtempSync(path.join(os.tmpdir(), "ioi-latest-rollback-"));
  try {
    for (const failureKind of ["transition", "verified-recertification"]) {
      for (const preexisting of [true, false]) {
        const latestPath = path.join(
          latestTmp,
          `${failureKind}.${preexisting ? "existing" : "new"}.latest.json`,
        );
        if (preexisting) {
          fs.writeFileSync(latestPath, "{\"generation\":\"before\"}\n");
          fs.chmodSync(latestPath, 0o640);
        }
        let failed = false;
        try {
          dispatchStageCertificationTransaction({
            latestPath,
            retainedResult: { generation: "candidate" },
            dispatch: () => {
              throw new Error(`injected ${failureKind} failure`);
            },
          });
        } catch {
          failed = true;
        }
        check(`${failureKind} latest rollback observes injected failure`, failed);
        if (preexisting) {
          check(
            `${failureKind} failure restores pre-existing latest bytes and mode`,
            fs.readFileSync(latestPath, "utf8") ===
                "{\"generation\":\"before\"}\n" &&
              (fs.lstatSync(latestPath).mode & 0o7777) === 0o640,
          );
        } else {
          check(
            `${failureKind} failure removes a newly-created latest artifact`,
            !fs.existsSync(latestPath),
          );
        }
      }
    }
  } finally {
    fs.rmSync(latestTmp, { recursive: true, force: true });
  }

  // A private record/map/hold/evidence mutation is an input mutation even
  // though git cannot see it. The cache directory alone is excluded to break
  // the dry-run/apply cycle.
  const privateDigests = new Map([
    ["program/sequence.v1.json", "1".repeat(64)],
    ["work-items/active/mx.v1.json", "2".repeat(64)],
    ["generated/.certify/MX.old.json", "3".repeat(64)],
  ]);
  const privateFingerprint = (files, overrides = new Map()) =>
    certificationPrivateAuthorityFingerprint({
      files,
      digestOf: (relative) => overrides.get(relative) ?? privateDigests.get(relative),
    });
  const privateBase = privateFingerprint([...privateDigests.keys()]);
  const privateMutation = privateFingerprint([...privateDigests.keys()], new Map([
    ["work-items/active/mx.v1.json", "4".repeat(64)],
  ]));
  check(
    "mutating one private-authority file invalidates the certification input",
    privateMutation.aggregate_sha256 !== privateBase.aggregate_sha256,
  );
  const privateAddition = privateFingerprint([
    ...privateDigests.keys(),
    "_archive/holds/new-hold.v1.json",
  ], new Map([["_archive/holds/new-hold.v1.json", "5".repeat(64)]]));
  check(
    "adding one private-authority file invalidates the certification input",
    privateAddition.aggregate_sha256 !== privateBase.aggregate_sha256,
  );
  const privateRemoval = privateFingerprint([
    "program/sequence.v1.json",
    "generated/.certify/MX.old.json",
  ]);
  check(
    "removing one private-authority file invalidates the certification input",
    privateRemoval.aggregate_sha256 !== privateBase.aggregate_sha256,
  );
  const cacheOnlyChange = privateFingerprint([
    ...privateDigests.keys(),
    "generated/.certify/MX.new.json",
  ], new Map([["generated/.certify/MX.new.json", "6".repeat(64)]]));
  check(
    "certification-cache-only additions do not self-invalidate an immediate apply",
    cacheOnlyChange.aggregate_sha256 === privateBase.aggregate_sha256,
  );

  // Verified re-certification must atomically replace its cited result and the
  // aggregate binding over those exact bytes. Drive the live pure projector in
  // a temporary repository so no implementation status or evidence is touched.
  const tmpRepo = fs.mkdtempSync(path.join(os.tmpdir(), "ioi-cert-rebound-"));
  try {
    const tmpEstate = path.join(tmpRepo, "internal-docs", "implementation");
    const childRecordPath = path.join(tmpEstate, "work-items", "active", "child.json");
    const aggregateRecordPath = path.join(tmpEstate, "work-items", "active", "aggregate.json");
    const certificationRel =
      "internal-docs/implementation/evidence/fixture-aggregate.certification.v1.json";
    const certificationPath = path.join(tmpRepo, certificationRel);
    const artifactRel = "proof/fixture-artifact.json";
    const artifactPath = path.join(tmpRepo, artifactRel);
    fs.mkdirSync(path.dirname(artifactPath), { recursive: true });
    fs.writeFileSync(artifactPath, "{\"proof\":true}\n");
    const writeExit = (relative, literal, bar) => {
      const absolute = path.join(tmpRepo, relative);
      fs.mkdirSync(path.dirname(absolute), { recursive: true });
      fs.writeFileSync(absolute, [
        "IOI_LITERAL_EXIT_LOG_FORMAT=ioi.program.literal_exit.v1",
        `BAR=${bar}`,
        `ARTIFACT=${artifactRel}`,
        `ARTIFACT_SHA256=${sha256File(artifactPath)}`,
        literal,
        "NONCLAIM=Fixture proof only; closes no live record or stage.",
        "",
      ].join("\n"));
    };
    const childExit = "proof/child.exit.v1.txt";
    const aggregateExit = "proof/aggregate.exit.v1.txt";
    writeExit(childExit, "FIXTURE_CHILD_EXIT=0", "fixture-child");
    writeExit(aggregateExit, "FIXTURE_AGGREGATE_EXIT=0", "fixture-aggregate");
    const child = {
      work_item_id: "fixture-child",
      record_role: "implementation_cut",
      status: "verified",
      file: "work-items/active/child.json",
      evidence_refs: [childExit],
      evidence_index: {
        literal_exit: "FIXTURE_CHILD_EXIT=0",
        retained_refs: [childExit],
        expected_output_paths: [childExit],
      },
    };
    const aggregate = {
      work_item_id: "fixture-aggregate",
      record_role: "aggregate_exit",
      status: "verified",
      file: "work-items/active/aggregate.json",
      aggregate_child_ids: [child.work_item_id],
      aggregate_child_dispositions: [{
        child_work_item_id: child.work_item_id,
        selection_state: "unconditional_active",
      }],
      dependency_work_item_ids: [],
      evidence_refs: [aggregateExit, certificationRel],
      evidence_index: {
        literal_exit: "FIXTURE_AGGREGATE_EXIT=0",
        retained_refs: [aggregateExit, certificationRel],
        expected_output_paths: [aggregateExit],
      },
      last_status_transaction: { fixture: "must-remain-unchanged" },
    };
    const recordPath = (record) => path.join(tmpEstate, record.file);
    writeJsonDeterministic(childRecordPath, child);
    writeJsonDeterministic(certificationPath, { generation: 1 });
    aggregate.aggregate_verification_binding = deriveAggregateVerificationBinding(
      aggregate,
      { records: [child, aggregate], recordPath, repoRoot: tmpRepo },
    );
    writeJsonDeterministic(aggregateRecordPath, aggregate);
    const loadRecords = () => [
      JSON.parse(fs.readFileSync(childRecordPath, "utf8")),
      JSON.parse(fs.readFileSync(aggregateRecordPath, "utf8")),
    ];
    const oldBinding = aggregate.aggregate_verification_binding.binding_payload_sha256;
    applyVerifiedAggregateRecertification({
      aggregateWorkItemId: aggregate.work_item_id,
      aggregatePath: aggregateRecordPath,
      certificationPath,
      retainedResult: { generation: 2, result: "PASS" },
      loadRecords,
      recordPath,
      repoRoot: tmpRepo,
    });
    const reboundRecords = loadRecords();
    const rebound = reboundRecords[1];
    check(
      "verified re-certification replaces the cited certification bytes",
      JSON.parse(fs.readFileSync(certificationPath, "utf8")).generation === 2,
    );
    check(
      "verified re-certification refreshes the aggregate binding over those bytes",
      rebound.aggregate_verification_binding.binding_payload_sha256 !== oldBinding &&
        validateAggregateVerificationBinding(rebound, {
          records: reboundRecords,
          recordPath,
          repoRoot: tmpRepo,
        }).length === 0,
    );
    check(
      "verified re-certification changes neither status nor historical transition",
      rebound.status === "verified" &&
        rebound.last_status_transaction.fixture === "must-remain-unchanged",
    );

    const certificationBeforeFailure = fs.readFileSync(certificationPath);
    const aggregateBeforeFailure = fs.readFileSync(aggregateRecordPath);
    let recertDriftRefused = false;
    try {
      applyVerifiedAggregateRecertification({
        aggregateWorkItemId: aggregate.work_item_id,
        aggregatePath: aggregateRecordPath,
        certificationPath,
        retainedResult: { generation: 3, result: "PASS" },
        loadRecords,
        recordPath,
        repoRoot: tmpRepo,
        validateInput: () => {
          throw new Error("injected verified-recertification input drift");
        },
      });
    } catch {
      recertDriftRefused = true;
    }
    check("verified re-certification refuses a final input-drift check", recertDriftRefused);
    check(
      "verified re-certification input drift writes neither certification nor aggregate",
      fs.readFileSync(certificationPath).equals(certificationBeforeFailure) &&
        fs.readFileSync(aggregateRecordPath).equals(aggregateBeforeFailure),
    );
    let injectedFailure = false;
    try {
      applyVerifiedAggregateRecertification({
        aggregateWorkItemId: aggregate.work_item_id,
        aggregatePath: aggregateRecordPath,
        certificationPath,
        retainedResult: { generation: 3, result: "PASS" },
        loadRecords,
        recordPath,
        repoRoot: tmpRepo,
        writeJson: (absolute, value) => {
          if (absolute === aggregateRecordPath) {
            throw new Error("injected aggregate write failure");
          }
          writeJsonDeterministic(absolute, value);
        },
      });
    } catch {
      injectedFailure = true;
    }
    check("the injected aggregate write failure is observed", injectedFailure);
    check(
      "a failed verified re-certification restores certification and aggregate bytes atomically",
      fs.readFileSync(certificationPath).equals(certificationBeforeFailure) &&
        fs.readFileSync(aggregateRecordPath).equals(aggregateBeforeFailure),
    );
  } finally {
    fs.rmSync(tmpRepo, { recursive: true, force: true });
  }

  process.stdout.write(
    `stage certification cache fixtures: ${failures === 0 ? "PASS" : "FAIL"}\n`,
  );
  process.exit(failures === 0 ? 0 : 1);
}

main();
