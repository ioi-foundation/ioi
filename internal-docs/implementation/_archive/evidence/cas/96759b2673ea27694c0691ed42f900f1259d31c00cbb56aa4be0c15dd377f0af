#!/usr/bin/env node
// ATOMIC status/evidence transition.
//
//   node tools/transition.mjs <work-item-id> <status> --result <certification.json> [--apply]
//   node tools/transition.mjs <work-item-id> --reattest --reason "<why>" [--apply]
//
// Replaces the ten-step hand-edited transaction. One command derives every
// downstream artifact from ONE retained certification result:
//
//   1. work-item status + last_status_transaction        (from the result)
//   2. evidence registration under evidence/             (from the result)
//   3. canon snapshot provenance                          (from the checkout)
//   4. generated/canon-impact.v1.json                     (regenerated)
//   5. NOW.md + generated/program-state.v1.json           (regenerated)
//
// It is a transaction: every file is staged in memory, the whole set is
// validated, and nothing is written unless all of it holds. A failed validation
// leaves the estate byte-identical.
//
// It refuses to move a record to `verified` without a content-bound literal
// exit whose digest matches a retained artifact. A process exit code, an HTTP
// status, or a screenshot is never accepted as that literal.
//
// It also refuses to move a record to `verified` when:
//   * the retained artifact is not a conforming ioi.program.literal_exit.v1
//     log — checked by the SHARED validator in tools/lib/literal-exit.mjs, the
//     same one check-literal-exit-contract uses, so the gate and the bar can
//     never disagree about what an exit artifact is; or
//   * an open successor hold names the record as a predecessor closure. See
//     tools/lib/holds.mjs; the repair for a held closure is its successor.
//
// --- Same-status re-attestation -------------------------------------------
//
// A record legitimately changes after it was attested: a canon owner is
// repointed, a doc it cites is split, a path is corrected. The historical
// attestation then no longer resolves, and `check-attestations` fails — correctly,
// because an attestation nobody can re-derive is worse than none.
//
// The wrong repair is to recompute the digest inside the historical record. That
// edits a claim about a moment that has already passed, and it had already been
// done once here before an independent review caught it.
//
// `--reattest` is the right repair. It appends to an append-only ledger that
// lives OUTSIDE the record it hashes — writing it therefore cannot invalidate the
// digest it just recorded — and each entry names the digest it supersedes, so the
// historical claim stays verifiable as a chain link rather than being rewritten.
//
// A re-attestation binds the record's CURRENT BYTES AND NOTHING ELSE. It does not
// advance status, does not register evidence, does not touch the record, and
// asserts no new implementation proof.
import fs from "node:fs";
import path from "node:path";
import process from "node:process";
import { execFileSync } from "node:child_process";
import {
  ESTATE_ROOT,
  finding,
  readJson,
  REPO_ROOT,
  report,
  sha256File,
  sha256Text,
  withFileRollback,
  writeJsonDeterministic,
} from "./lib/estate.mjs";
import { refuseUnlessConformingLiteralExitLog } from "./lib/literal-exit.mjs";
import {
  deriveAggregateVerificationBinding,
  validateAggregateVerificationBinding,
} from "./lib/aggregate-verification-binding.mjs";
import {
  appendStateTransition,
  LEDGER_ABS as HOLD_LEDGER_ABS,
  openHoldsAwaitingSuccessor,
  openHoldsForRecord,
  QUALIFIED_STATUS,
  readHoldLedger,
} from "./lib/holds.mjs";
import { loadWorkItems, statusAuthority } from "./generate-now.mjs";
import {
  currentStageCertificationInput,
  validateStageCertificationEnvelope,
} from "./certify-stage.mjs";

const REQUIRES_LITERAL = new Set(["verified"]);
export const WORK_ITEM_CERTIFICATION_FORMAT =
  "ioi.program.work_item_certification.v1";

// A non-aggregate cut has no authority to claim the stage-wide command set or
// aggregate join. It still needs a typed, content-bound envelope of its own:
// exact current record bytes, exact identity/role/stage/from-status, and PASS.
// Literal and adversarial proof are validated separately by the shared gate
// below so both envelope types use the same evidence contract.
export function validateWorkItemCertificationEnvelope(
  result,
  { record, recordSha256 },
) {
  const defects = [];
  if (!result || typeof result !== "object") {
    return ["work-item certification is not an object"];
  }
  if (result.evidence_format !== WORK_ITEM_CERTIFICATION_FORMAT) {
    defects.push(
      `work-item certification evidence_format must be ${WORK_ITEM_CERTIFICATION_FORMAT}`,
    );
  }
  if (result.certification_scope !== "single_work_item") {
    defects.push("work-item certification_scope must be single_work_item");
  }
  if (result.result !== "PASS") defects.push("work-item certification result is not PASS");
  if (result.work_item_id !== record.work_item_id) {
    defects.push("work-item certification work_item_id is wrong");
  }
  if (result.stage_id !== record.stage_id) {
    defects.push("work-item certification stage_id is wrong");
  }
  if (result.record_role !== record.record_role) {
    defects.push("work-item certification record_role is wrong");
  }
  if (result.status_from !== record.status) {
    defects.push("work-item certification status_from is stale");
  }
  if (!/^[a-f0-9]{64}$/u.test(result.record_sha256 ?? "")) {
    defects.push("work-item certification record_sha256 is not a sha256 digest");
  } else if (result.record_sha256 !== recordSha256) {
    defects.push("work-item certification record_sha256 is stale");
  }
  if (
    JSON.stringify(result.adversarial_or_fault_proof) !==
      JSON.stringify(record.adversarial_or_fault_proof ?? [])
  ) {
    defects.push(
      "work-item certification adversarial_or_fault_proof does not exactly match the current record declaration",
    );
  }
  return defects;
}

function arg(name) {
  const i = process.argv.indexOf(name);
  return i === -1 ? null : process.argv[i + 1];
}

function run(command, args) {
  return execFileSync(command, args, {
    cwd: REPO_ROOT,
    encoding: "utf8",
    stdio: ["ignore", "pipe", "pipe"],
  });
}

// A status transaction may re-anchor only the record it is advancing, and only
// while that record remains unverified. Canon snapshots are provenance, not a
// fleet-wide synchronisation surface: restamping unrelated records would erase
// the review boundary that canon-impact owns.
export function canonSnapshotRefreshArgs(workItemId) {
  return [
    "internal-docs/implementation/tools/refresh-canon-snapshots.mjs",
    "--write-unverified",
    "--work-item",
    workItemId,
  ];
}

export function sortWorkItemArgs(workItemId) {
  return [
    "internal-docs/implementation/tools/sort-work-items.mjs",
    "--write",
    "--work-item",
    workItemId,
  ];
}

const REATTESTATION_LEDGER = path.join(
  ESTATE_ROOT,
  "_archive",
  "attestations",
  "record-reattestations.v1.json",
);

function readReattestationLedger() {
  if (!fs.existsSync(REATTESTATION_LEDGER)) {
    return {
      evidence_format: "ioi.estate.record_reattestation_ledger.v1",
      rule:
        "Append-only. Each entry binds a work-item record's bytes at a moment and names the digest it supersedes, so a superseded attestation stays verifiable as a chain link instead of being rewritten. The ledger lives outside every record it hashes.",
      claim_boundary:
        "A re-attestation asserts record integrity ONLY. It is not a status transition, not evidence registration, and not implementation proof.",
      entries: [],
    };
  }
  return readJson(REATTESTATION_LEDGER);
}

/// The digest a record is currently expected to carry: the newest re-attestation
/// if one exists, otherwise the historical migration attestation.
function effectiveDigest(ledger, workItemId, recordRel) {
  const chain = ledger.entries.filter((e) => e.work_item_id === workItemId);
  if (chain.length > 0) return chain[chain.length - 1].private_record_sha256;
  const dir = path.join(ESTATE_ROOT, "_archive", "migrations");
  if (!fs.existsSync(dir)) return null;
  for (const file of fs.readdirSync(dir).filter((f) => f.endsWith(".json"))) {
    for (const entry of readJson(path.join(dir, file)).entries ?? []) {
      if (entry.private_record === recordRel && entry.private_record_sha256_after) {
        return entry.private_record_sha256_after;
      }
    }
  }
  return null;
}

function reattest(record, findings) {
  const reason = arg("--reason");
  const apply = process.argv.includes("--apply");
  const workItemId = record.work_item_id;
  const absolute = path.join(ESTATE_ROOT, record.file);
  const recordRel = `internal-docs/implementation/${record.file}`;

  // A reason is required and must be a cause, not a ceremony. Without it the
  // ledger records that something changed but never why, which is the same
  // unverifiable claim re-attestation exists to remove.
  if (!reason || reason.trim().length < 20) {
    findings.push(
      finding(
        "error",
        "reattest-reason",
        "--reason is required and must state what changed the record (at least 20 characters); a re-attestation without a cause records that bytes moved but not why",
      ),
    );
    process.exit(report("transition", findings));
  }

  const ledger = readReattestationLedger();
  const actual = sha256File(absolute);
  const expected = effectiveDigest(ledger, workItemId, recordRel);

  if (!expected) {
    findings.push(
      finding(
        "error",
        "reattest-unattested",
        `${workItemId} has no prior attestation to supersede; there is nothing to re-attest`,
      ),
    );
    process.exit(report("transition", findings));
  }
  if (expected === actual) {
    findings.push(
      finding(
        "error",
        "reattest-unchanged",
        `${workItemId} already digests to its effective attestation (${actual}); re-attesting an unchanged record would add a ledger entry that proves nothing`,
      ),
    );
    process.exit(report("transition", findings));
  }

  const entry = {
    sequence: ledger.entries.length + 1,
    work_item_id: workItemId,
    private_record: recordRel,
    status_at_reattestation: record.status,
    supersedes_sha256: expected,
    private_record_sha256: actual,
    reason: reason.trim(),
    at_commit: run("git", ["rev-parse", "HEAD"]).trim(),
    claim: "record_integrity_only",
    not_claimed:
      "This re-attestation binds the record's current bytes. It asserts no new implementation proof, no status advance, and no additional verification. The status shown is the status the record already held.",
  };

  if (!apply) {
    process.stdout.write(
      `re-attestation would append: ${workItemId} ${expected.slice(0, 12)} -> ${actual.slice(0, 12)} (status unchanged: ${record.status})\n`,
    );
    process.exit(report("transition", findings));
  }

  fs.mkdirSync(path.dirname(REATTESTATION_LEDGER), { recursive: true });
  writeJsonDeterministic(REATTESTATION_LEDGER, {
    ...ledger,
    entries: [...ledger.entries, entry],
  });

  // The ledger is outside the record, so the record's digest is unchanged by
  // this write. Prove it rather than assuming it.
  const after = sha256File(absolute);
  if (after !== actual) {
    findings.push(
      finding(
        "error",
        "reattest-self-invalidating",
        `writing the ledger changed ${recordRel} from ${actual} to ${after}; an attestation that invalidates itself is not an attestation`,
      ),
    );
    process.exit(report("transition", findings));
  }

  process.stdout.write(
    `${workItemId}: re-attested at ${actual} (supersedes ${expected}); status unchanged (${record.status}); no implementation proof claimed\n`,
  );
  process.exit(report("transition", findings));
}

function main() {
  const reattesting = process.argv.includes("--reattest");
  const positional = process.argv.slice(2).filter((a) => !a.startsWith("-"));
  // `--reason "text"` and `--result path` consume the token after the flag; a
  // re-attestation takes only the work-item id positionally.
  const flagValues = new Set(
    ["--reason", "--result"].map((f) => arg(f)).filter(Boolean),
  );
  const [workItemId, status] = positional.filter((a) => !flagValues.has(a));
  const resultPath = arg("--result");
  const apply = process.argv.includes("--apply");
  const findings = [];

  if (reattesting && status) {
    process.stderr.write(
      "--reattest is same-status by construction; it takes no target status. To change status, run a transition.\n",
    );
    process.exit(2);
  }
  if (!workItemId || (!status && !reattesting)) {
    process.stderr.write(
      "usage: transition.mjs <work-item-id> <status> --result <certification.json> [--apply]\n" +
        "       transition.mjs <work-item-id> --reattest --reason \"<why the record changed>\" [--apply]\n",
    );
    process.exit(2);
  }

  const records = loadWorkItems();
  const record = records.find((r) => r.work_item_id === workItemId);
  if (!record) {
    process.stderr.write(`unknown work item: ${workItemId}\n`);
    process.exit(2);
  }

  if (reattesting) reattest(record, findings);

  // --- the status authority must be this private record
  const authority = statusAuthority(record);
  if (authority.owner !== "private_record") {
    findings.push(
      finding(
        "error",
        "status-authority",
        `${workItemId}'s status authority is ${authority.ref}; a private transition cannot advance a cut whose authority is a merged tracked record. Land the change and run tools/reconcile-status.mjs instead.`,
      ),
    );
    process.exit(report("transition", findings));
  }

  // --- proof gate
  //
  // Hardened after an independent review demonstrated that the earlier gate
  // accepted a caller-authored JSON whose literal could be the string "exit 0",
  // whose artifact could live outside the repository, and whose digest binding
  // was optional and then self-filled. Every one of those holes is closed here.
  //
  // The literal is NOT chosen by the caller: it must equal the literal the
  // record itself declares in evidence_index.literal_exit, and the artifact must
  // be one of the record's own declared expected_output_paths.
  let result = null;
  if (REQUIRES_LITERAL.has(status)) {
    if (!resultPath) {
      findings.push(
        finding(
          "error",
          "proof-required",
          `advancing ${workItemId} to ${status} requires --result <certification.json> carrying a content-bound literal exit`,
        ),
      );
      process.exit(report("transition", findings));
    }
    result = readJson(path.resolve(resultPath));
    const literal = result.literal_exit ?? {};

    // The result envelope itself is authority-bearing. Aggregate admission is
    // accepted only from certify-stage's exact, current, complete stage proof;
    // a caller-authored {literal_exit, adversarial_or_fault_proof} object is not
    // a stage certification. Non-aggregate children use a separate typed
    // single-work-item envelope and never manufacture stage-wide proof fields.
    if (record.record_role === "aggregate_exit") {
      try {
        const currentInput = currentStageCertificationInput(record.stage_id);
        if (currentInput.aggregate.work_item_id !== workItemId) {
          findings.push(finding(
            "error",
            "stage-certification-envelope",
            `${workItemId} is not the aggregate exit currently declared by stage ${record.stage_id}`,
          ));
        }
        for (const defect of validateStageCertificationEnvelope(result, {
          stageId: record.stage_id,
          aggregateWorkItemId: workItemId,
          currentInput,
        })) {
          findings.push(finding(
            "error",
            "stage-certification-envelope",
            defect,
          ));
        }
      } catch (error) {
        findings.push(finding(
          "error",
          "stage-certification-envelope",
          `cannot recompute current stage-certification authority: ${error.message}`,
        ));
      }
    } else {
      const recordSha256 = sha256File(path.join(ESTATE_ROOT, record.file));
      for (const defect of validateWorkItemCertificationEnvelope(result, {
        record,
        recordSha256,
      })) {
        findings.push(finding(
          "error",
          "work-item-certification-envelope",
          defect,
        ));
      }
    }

    // The record's own declaration is the authority for what the literal is.
    const index = record.evidence_index;
    const declaredLiteral = index && !Array.isArray(index)
      ? index.literal_exit
      : null;
    const declaredPaths = index && !Array.isArray(index)
      ? (index.expected_output_paths ?? [])
      : [];

    if (!declaredLiteral) {
      findings.push(
        finding(
          "error",
          "proof-undeclared",
          `${workItemId} declares no evidence_index.literal_exit; a record cannot be verified against a literal it never declared`,
        ),
      );
    } else if (literal.expected !== declaredLiteral) {
      findings.push(
        finding(
          "error",
          "proof-literal-mismatch",
          `certification names "${literal.expected}" but ${workItemId} declares "${declaredLiteral}"; the caller does not choose the literal`,
        ),
      );
    }

    // A literal that is a process exit code, an HTTP status, or a screenshot is
    // not proof — program/rules.md section 6.
    if (
      typeof literal.expected === "string" &&
      /^(?:exit\s*\d+|\d{3}|ok|pass(?:ed)?|success|true|screenshot.*)$/iu.test(
        literal.expected.trim(),
      )
    ) {
      findings.push(
        finding(
          "error",
          "proof-not-proof",
          `"${literal.expected}" is a process/HTTP/status token, not an expected-path literal bound to artifact bytes`,
        ),
      );
    }

    if (!literal.artifact_path) {
      findings.push(
        finding("error", "proof-required", "certification names no artifact_path"),
      );
    } else {
      // The artifact must be inside the repository AND declared by the record.
      const artifact = path.resolve(REPO_ROOT, literal.artifact_path);
      const inside = artifact === REPO_ROOT ||
        artifact.startsWith(`${REPO_ROOT}${path.sep}`);
      if (!inside) {
        findings.push(
          finding(
            "error",
            "proof-artifact-outside-repo",
            `artifact resolves outside the repository: ${literal.artifact_path}`,
          ),
        );
      } else if (
        declaredPaths.length > 0 &&
        !declaredPaths.includes(literal.artifact_path)
      ) {
        findings.push(
          finding(
            "error",
            "proof-artifact-undeclared",
            `${literal.artifact_path} is not among ${workItemId}'s declared expected_output_paths`,
          ),
        );
      } else if (!fs.existsSync(artifact)) {
        findings.push(
          finding(
            "error",
            "proof-artifact",
            `retained artifact does not exist: ${literal.artifact_path}`,
          ),
        );
      } else {
        const text = fs.readFileSync(artifact, "utf8");
        const occurrences = text.split(literal.expected).length - 1;
        if (occurrences !== 1) {
          findings.push(
            finding(
              "error",
              "proof-literal",
              `expected exactly one "${literal.expected}" in ${literal.artifact_path}, found ${occurrences}`,
            ),
          );
        }

        // --- the artifact must BE a retained literal-exit log
        //
        // Counting occurrences of a string inside a file is not the contract.
        // On 2026-07-29 a `verified` transition was admitted against an exit
        // artifact that was free-form prose with the literal on line 1: the
        // literal-log contract already refused it, and this gate never asked.
        // It asks now, through the same validator
        // (tools/lib/literal-exit.mjs) that check-literal-exit-contract uses,
        // so the two can never again disagree about what an exit artifact is.
        for (const refusal of refuseUnlessConformingLiteralExitLog(
          literal.artifact_path,
          { expectLiteral: literal.expected },
        )) {
          findings.push(finding("error", refusal.check, refusal.message));
        }
        // The digest is REQUIRED and never derived. Deriving it would make the
        // binding vacuous: any bytes would match themselves.
        const digest = sha256File(artifact);
        if (!literal.artifact_sha256) {
          findings.push(
            finding(
              "error",
              "proof-binding-absent",
              `certification carries no artifact_sha256; the digest is required and is never derived (actual: ${digest})`,
            ),
          );
        } else if (literal.artifact_sha256 !== digest) {
          findings.push(
            finding(
              "error",
              "proof-binding",
              `artifact digest ${digest} does not match the certified ${literal.artifact_sha256}`,
            ),
          );
        }
      }
    }

    if ((result.adversarial_or_fault_proof ?? []).length === 0) {
      findings.push(
        finding(
          "error",
          "proof-adversarial",
          `advancing to ${status} requires retained adversarial, denial, recovery, replay, or fault evidence in the certification result`,
        ),
      );
    }

    // A record cannot leap from proposed straight to verified.
    if (record.status === "proposed") {
      findings.push(
        finding(
          "error",
          "proof-status-leap",
          `${workItemId} is proposed; a cut is scoped and worked before it is verified`,
        ),
      );
    }

    // --- open-successor holds
    //
    // A closure this record is a predecessor of has an owed, unwritten
    // successor. Re-verifying the predecessor would clear the qualification by
    // ceremony instead of by proof, which is precisely what
    // `successor_required` was supposed to prevent and, for eight months, did
    // not. The repair is the named successor, not another pass over this record.
    for (const hold of openHoldsForRecord(workItemId)) {
      findings.push(
        finding(
          "error",
          "open-successor-hold",
          `${workItemId} is held by ${hold.hold_id} (${hold.subject}); it projects as ${QUALIFIED_STATUS} until the successor named by that hold is admitted. Author the successor; do not re-verify the predecessor.`,
        ),
      );
    }

    // An aggregate exit must never use the generic transition entry point to
    // bypass stage certification's exact child/dependency/evidence join. The
    // explicit refresher authors the current binding; both admitting callers
    // enforce the same projection.
    if (record.record_role === "aggregate_exit") {
      for (const refusal of validateAggregateVerificationBinding(record, {
        records,
      })) {
        findings.push(finding("error", refusal.check, refusal.message));
      }
    }
  }

  if (findings.some((f) => f.level === "error")) {
    process.exit(report("transition", findings));
  }

  if (!apply) {
    process.stdout.write(
      `transition would apply: ${workItemId} ${record.status} -> ${status}\n`,
    );
    process.exit(report("transition", findings));
  }

  // --- stage every write in memory, then commit them together
  const writes = [];
  const absolute = path.join(ESTATE_ROOT, record.file);
  const full = readJson(absolute);
  const before = full.status;
  full.status = status;
  // sort-work-items moves the record after this transaction. Keep the record's
  // self-describing private artifact locator aligned with that governed target;
  // otherwise every legitimate proposed -> active/verified transition leaves a
  // dangling path and the work-item contract fails after the atomic command.
  // The estate has two physical buckets, not one bucket per logical status:
  // proposed records live in work-items/proposed; scoped, active, and verified
  // records all live in work-items/active. Keep self-locators aligned with the
  // same rule used by sort-work-items.
  const targetBucket = status === "proposed" ? "proposed" : "active";
  for (const artifact of full.private_artifacts ?? []) {
    if (artifact?.artifact_id === `work-item-record:${workItemId}`) {
      artifact.path = `internal-docs/implementation/work-items/${targetBucket}/${path.basename(record.file)}`;
    }
  }
  full.last_status_transaction = {
    from: before,
    to: status,
    at_commit: run("git", ["rev-parse", "HEAD"]).trim(),
    certification_result_sha256: result
      ? sha256Text(JSON.stringify(result))
      : null,
    rule:
      "Derived by tools/transition.mjs from one retained certification result. No downstream artifact was hand-edited.",
  };
  if (result) {
    const evidenceRel = `evidence/${workItemId}.certification.v1.json`;
    const ref = `internal-docs/implementation/${evidenceRel}`;
    writes.push([path.join(ESTATE_ROOT, evidenceRel), result]);
    // evidence_index is an OBJECT in 122 of 126 records ({literal_exit,
    // retained_refs, expected_output_paths, ...}) and a bare array in 4.
    // Both shapes must round-trip, or the atomic command is dead on the
    // overwhelming majority of the estate.
    const index = full.evidence_index;
    if (Array.isArray(index)) {
      full.evidence_index = [...new Set([...index, ref])];
    } else if (index && typeof index === "object") {
      full.evidence_index = {
        ...index,
        retained_refs: [...new Set([...(index.retained_refs ?? []), ref])],
      };
    } else {
      full.evidence_index = { retained_refs: [ref] };
    }
  }
  writes.push([absolute, full]);

  // --- discharge every open hold this record was the named successor for.
  // The discharge rides inside the same transaction as the status change, so a
  // failed regeneration rolls the hold back open with everything else. A hold
  // is never closed by a record that did not reach `verified`.
  const discharged = [];
  if (status === "verified") {
    const ledger = readHoldLedger();
    const awaiting = openHoldsAwaitingSuccessor(workItemId, ledger);
    for (const hold of awaiting) {
      appendStateTransition(ledger, hold.hold_id, {
        from: "open",
        to: "successor_admitted",
        successor_work_item_id: workItemId,
        at_commit: run("git", ["rev-parse", "HEAD"]).trim(),
        recorded_by: "tools/transition.mjs",
        claim:
          "A successor was admitted at `verified` under its own status authority and proof gate. This discharges the hold and asserts nothing further about the predecessor's original closure.",
      });
      discharged.push(hold.hold_id);
    }
    if (discharged.length > 0) writes.push([HOLD_LEDGER_ABS, ledger]);
  }

  // Snapshot EVERY file the direct writes, filing move, and derived generators
  // can touch. The former transaction captured only `writes`, so a failure
  // after sort-work-items or generate-now restored the record/evidence while
  // leaving a duplicate filing or a projection from the failed future state.
  const targetAbsolute = path.join(
    ESTATE_ROOT,
    "work-items",
    targetBucket,
    path.basename(record.file),
  );
  const transactionPaths = [
    ...writes.map(([target]) => target),
    absolute,
    targetAbsolute,
    path.join(ESTATE_ROOT, "generated", "canon-impact.v1.json"),
    path.join(ESTATE_ROOT, "NOW.md"),
    path.join(ESTATE_ROOT, "generated", "program-state.v1.json"),
  ];

  try {
    withFileRollback(transactionPaths, () => {
      for (const [target, value] of writes) writeJsonDeterministic(target, value);

      // --- regenerate every derived artifact from the new state
      // This is deliberately target-bound. On a transition to `verified`, the
      // status write above means --write-unverified performs no re-anchoring;
      // certification therefore requires the target snapshot to have been
      // refreshed and reviewed while the record was still unverified. Never
      // substitute bare --write here: that would restamp the entire estate.
      run("node", canonSnapshotRefreshArgs(workItemId));
      run("node", ["internal-docs/implementation/tools/canon-impact.mjs", "--write"]);

      // Registering the aggregate's certification result adds retained evidence,
      // and snapshot refresh may update child/dependency record bytes. Refresh
      // the exact join only after both have settled, still inside the transaction,
      // so admission cannot make the binding stale in the act of admitting it.
      // Child transitions intentionally do not rewrite parent aggregates; the
      // explicit aggregate-binding refresher owns that reviewed pre-certification
      // step.
      if (full.record_role === "aggregate_exit") {
        const currentRecords = loadWorkItems();
        const currentAggregate = currentRecords.find((candidate) =>
          candidate.work_item_id === workItemId
        );
        if (!currentAggregate) {
          throw new Error(`cannot reload aggregate ${workItemId} after evidence registration`);
        }
        const rebound = readJson(absolute);
        rebound.aggregate_verification_binding = deriveAggregateVerificationBinding(
          currentAggregate,
          { records: currentRecords },
        );
        writeJsonDeterministic(absolute, rebound);
      }

      run("node", sortWorkItemArgs(workItemId));
      run("node", ["internal-docs/implementation/tools/generate-now.mjs", "--write"]);
    });
  } catch (error) {
    findings.push(
      finding(
        "error",
        "transition-rolled-back",
        `regeneration failed (${error.message}); every file this transaction wrote was restored`,
      ),
    );
    process.exit(report("transition", findings));
  }

  process.stdout.write(
    `${workItemId}: ${before} -> ${status}; evidence registered; canon impact, NOW, and program state regenerated${
      discharged.length > 0
        ? `; discharged open-successor hold(s) ${discharged.join(", ")}`
        : ""
    }\n`,
  );
  process.exit(report("transition", findings));
}

if (import.meta.url === `file://${process.argv[1]}`) main();
