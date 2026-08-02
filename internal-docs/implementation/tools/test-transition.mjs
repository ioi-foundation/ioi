#!/usr/bin/env node
// Fixture test for the atomic transition and its proof gate.
//
//   node tools/test-transition.mjs
//
// Exists because an independent review found that `transition.mjs --apply` threw
// a TypeError on 122 of 126 real records — it assumed `evidence_index` was an
// array when almost every record carries an object — and that its proof gate
// accepted a caller-authored literal, an artifact outside the repository, and an
// optional-then-self-filled digest.
//
// Every case below is run against the REAL record shapes in the estate, in a
// throwaway copy, so the test cannot pass on a shape the estate does not use.
//
// Extended 2026-07-29 after a `verified` transition was admitted against an
// exit artifact that was FREE-FORM PROSE. The gate counted occurrences of the
// literal string inside the file and never asked whether the file was a
// retained ioi.program.literal_exit.v1 log — a contract the estate already
// implemented, in a validator the gate did not call. The regression case below
// replays that exact record against that exact artifact.
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import process from "node:process";
import { execFileSync, spawnSync } from "node:child_process";
import {
  ESTATE_ROOT,
  readJson,
  REPO_ROOT,
  sha256File,
  sha256Text,
  withFileRollback,
} from "./lib/estate.mjs";
import {
  REFUSAL_NAMES,
  refuseUnlessConformingLiteralExitLog,
} from "./lib/literal-exit.mjs";
import {
  openHolds,
  openHoldsForRecord,
  readHoldLedger,
} from "./lib/holds.mjs";
import {
  canonSnapshotRefreshArgs,
  sortWorkItemArgs,
  validateWorkItemCertificationEnvelope,
  WORK_ITEM_CERTIFICATION_FORMAT,
} from "./transition.mjs";
import { canonSnapshotWritePermitted } from "./refresh-canon-snapshots.mjs";

let failures = 0;
function check(name, condition, detail = "") {
  if (condition) process.stdout.write(`  ok   ${name}\n`);
  else {
    failures += 1;
    process.stdout.write(`  FAIL ${name}${detail ? ` — ${detail}` : ""}\n`);
  }
}

function runTransition(args) {
  try {
    return {
      exit: 0,
      out: execFileSync("node", [
        path.join("internal-docs/implementation/tools/transition.mjs"),
        ...args,
      ], { cwd: REPO_ROOT, encoding: "utf8", stdio: ["ignore", "pipe", "pipe"] }),
    };
  } catch (error) {
    return {
      exit: error.status ?? 1,
      out: `${error.stdout ?? ""}${error.stderr ?? ""}`,
    };
  }
}

function runTool(relative, args) {
  return spawnSync(process.execPath, [relative, ...args], {
    cwd: REPO_ROOT,
    encoding: "utf8",
  });
}

function workItemBytesDigest() {
  const entries = [];
  for (const bucket of ["active", "proposed"]) {
    const root = path.join(ESTATE_ROOT, "work-items", bucket);
    for (const file of fs.readdirSync(root).filter((entry) => entry.endsWith(".json")).sort()) {
      const absolute = path.join(root, file);
      entries.push([`${bucket}/${file}`, sha256File(absolute)]);
    }
  }
  return sha256Text(JSON.stringify(entries));
}

function main() {
  process.stdout.write("transition fixture test\n");

  // --- shape coverage: the estate's real evidence_index shapes
  const shapes = { object: 0, array: 0, other: 0 };
  const records = [];
  for (const sub of ["active", "proposed"]) {
    const dir = path.join(ESTATE_ROOT, "work-items", sub);
    if (!fs.existsSync(dir)) continue;
    for (const f of fs.readdirSync(dir)) {
      if (!f.endsWith(".v1.json")) continue;
      const r = JSON.parse(fs.readFileSync(path.join(dir, f), "utf8"));
      records.push(r);
      const i = r.evidence_index;
      if (Array.isArray(i)) shapes.array += 1;
      else if (i && typeof i === "object") shapes.object += 1;
      else shapes.other += 1;
    }
  }
  check(
    "the estate carries both evidence_index shapes, so both must round-trip",
    shapes.object > 0 && shapes.array > 0,
    JSON.stringify(shapes),
  );

  // The transition's evidence-index merge must not throw on either shape. This
  // mirrors transition.mjs exactly; a divergence here is the bug the review found.
  const merge = (index, ref) => {
    if (Array.isArray(index)) return [...new Set([...index, ref])];
    if (index && typeof index === "object") {
      return {
        ...index,
        retained_refs: [...new Set([...(index.retained_refs ?? []), ref])],
      };
    }
    return { retained_refs: [ref] };
  };
  let threw = null;
  for (const r of records) {
    try {
      merge(r.evidence_index, "internal-docs/implementation/evidence/probe.json");
    } catch (error) {
      threw = `${r.work_item_id}: ${error.message}`;
      break;
    }
  }
  check(
    "the evidence-index merge round-trips every real record without throwing",
    threw === null,
    threw ?? "",
  );
  const objectRecord = records.find((r) =>
    r.evidence_index && !Array.isArray(r.evidence_index)
  );
  const merged = merge(objectRecord.evidence_index, "ref://probe");
  check(
    "merging into the object shape preserves its declared literal_exit",
    merged.literal_exit === objectRecord.evidence_index.literal_exit,
  );
  check(
    "merging into the object shape appends to retained_refs",
    (merged.retained_refs ?? []).includes("ref://probe"),
  );

  // --- canon-snapshot transaction boundary ------------------------------
  // A former implementation invoked the refresher with bare --write, which
  // restamped every verified and unverified work item as a side effect of one
  // record's transition. Pin both halves of the repair: the transition's exact
  // command and the refresher's exact record-write predicate.
  const refreshTarget = "fixture-target";
  const refreshArgs = canonSnapshotRefreshArgs(refreshTarget);
  check(
    "a transition scopes canon-snapshot refresh to its target unverified record",
    JSON.stringify(refreshArgs) === JSON.stringify([
      "internal-docs/implementation/tools/refresh-canon-snapshots.mjs",
      "--write-unverified",
      "--work-item",
      refreshTarget,
    ]),
    JSON.stringify(refreshArgs),
  );
  check(
    "a transition never invokes the fleet-wide canon-snapshot --write mode",
    !refreshArgs.includes("--write"),
    JSON.stringify(refreshArgs),
  );
  check(
    "a transition scopes filing to the same one target record",
    JSON.stringify(sortWorkItemArgs(refreshTarget)) === JSON.stringify([
      "internal-docs/implementation/tools/sort-work-items.mjs",
      "--write",
      "--work-item",
      refreshTarget,
    ]),
    JSON.stringify(sortWorkItemArgs(refreshTarget)),
  );

  const snapshotPolicy = {
    selectedWorkItem: refreshTarget,
    write: true,
    writeUnverified: true,
  };
  const fixtureRecords = [
    { work_item_id: refreshTarget, status: "active", bytes: "target-before" },
    { work_item_id: "unrelated-unverified", status: "active", bytes: "unverified-before" },
    { work_item_id: "unrelated-verified", status: "verified", bytes: "verified-before" },
  ];
  const afterSnapshotRefresh = new Map(
    fixtureRecords.map((fixture) => [fixture.work_item_id, fixture.bytes]),
  );
  for (const fixture of fixtureRecords) {
    if (canonSnapshotWritePermitted(fixture, snapshotPolicy)) {
      afterSnapshotRefresh.set(fixture.work_item_id, `${fixture.bytes}:refreshed`);
    }
  }
  check(
    "the selected unverified target is the only writable snapshot record",
    afterSnapshotRefresh.get(refreshTarget) === "target-before:refreshed",
  );
  check(
    "an unrelated unverified record remains byte-identical during target refresh",
    afterSnapshotRefresh.get("unrelated-unverified") === "unverified-before",
  );
  check(
    "an unrelated verified record remains byte-identical during target refresh",
    afterSnapshotRefresh.get("unrelated-verified") === "verified-before",
  );
  check(
    "a verified target cannot be silently re-anchored by transition refresh",
    !canonSnapshotWritePermitted(
      { work_item_id: refreshTarget, status: "verified" },
      snapshotPolicy,
    ),
  );

  // A malformed or unknown selector must refuse before touching even one
  // work-item byte. The old parser treated a missing value as fleet-wide and an
  // unknown value as an empty successful selection.
  const selectorBytesBefore = workItemBytesDigest();
  for (const probe of [
    {
      name: "missing selector value",
      args: ["--write-unverified", "--work-item"],
      expected: "requires one non-flag value",
    },
    {
      name: "flag used as selector value",
      args: ["--work-item", "--write-unverified"],
      expected: "requires one non-flag value",
    },
    {
      name: "duplicate selector",
      args: ["--work-item", refreshTarget, "--work-item", refreshTarget],
      expected: "at most once",
    },
    {
      name: "unknown selector",
      args: ["--write-unverified", "--work-item", "fixture-no-such-work-item"],
      expected: "unknown work item",
    },
  ]) {
    const selected = runTool(
      "internal-docs/implementation/tools/refresh-canon-snapshots.mjs",
      probe.args,
    );
    check(
      `${probe.name} refuses with exit 2 before snapshot writes`,
      selected.status === 2 && selected.stderr.includes(probe.expected),
      `status=${selected.status} stdout=${selected.stdout} stderr=${selected.stderr}`,
    );
  }
  check(
    "all refused snapshot selectors leave the work-item estate byte-identical",
    workItemBytesDigest() === selectorBytesBefore,
  );
  for (const probe of [
    {
      name: "missing filing selector value",
      args: ["--write", "--work-item"],
      expected: "requires one non-flag value",
    },
    {
      name: "unknown filing selector",
      args: ["--write", "--work-item", "fixture-no-such-work-item"],
      expected: "unknown work item",
    },
  ]) {
    const selected = runTool(
      "internal-docs/implementation/tools/sort-work-items.mjs",
      probe.args,
    );
    check(
      `${probe.name} refuses with exit 2 before filing writes`,
      selected.status === 2 && selected.stderr.includes(probe.expected),
      `status=${selected.status} stdout=${selected.stdout} stderr=${selected.stderr}`,
    );
  }
  check(
    "all refused filing selectors leave the work-item estate byte-identical",
    workItemBytesDigest() === selectorBytesBefore,
  );

  // --- proof gate refusals, exercised against the live tool
  // The target must DECLARE a literal, or the declared-literal refusals below
  // silently do not run — which is exactly the kind of vacuous assertion this
  // test exists to prevent.
  // Any private-authority, non-verified record with a declared literal drives
  // the gate: every refusal below is a dry-run probe of the verified
  // transition, which is gated identically from proposed, scoped, active, and
  // evidence_ready. (An M0-and-proposed-only selector starved once the M0
  // records advanced.)
  const driveable = (r) =>
    r.status !== "verified" &&
    r.record_role !== "aggregate_exit" &&
    r.evidence_index && !Array.isArray(r.evidence_index) &&
    r.evidence_index.literal_exit &&
    (r.evidence_index.expected_output_paths ?? []).length > 0 &&
    !fs.existsSync(path.join(
      REPO_ROOT,
      "docs/architecture/_meta/work-items",
      `${r.work_item_id}.v1.json`,
    ));
  const target = records.find((r) => r.stage_id === "M0" && driveable(r)) ??
    records.find(driveable);
  check(
    "a private-authority record that DECLARES a literal is available to drive the gate",
    Boolean(target),
  );
  if (!target) {
    process.exit(1);
  }

  const targetRecordSha = sha256File(path.join(
    ESTATE_ROOT,
    "work-items",
    target.status === "proposed" ? "proposed" : "active",
    `${target.work_item_id}.v1.json`,
  ));
  const validChildEnvelope = {
    evidence_format: WORK_ITEM_CERTIFICATION_FORMAT,
    certification_scope: "single_work_item",
    result: "PASS",
    work_item_id: target.work_item_id,
    stage_id: target.stage_id,
    record_role: target.record_role,
    status_from: target.status,
    record_sha256: targetRecordSha,
    adversarial_or_fault_proof: target.adversarial_or_fault_proof ?? [],
  };
  check(
    "a complete content-bound single-work-item certification envelope validates",
    validateWorkItemCertificationEnvelope(validChildEnvelope, {
      record: target,
      recordSha256: targetRecordSha,
    }).length === 0,
  );
  for (const [name, mutation] of [
    ["handcrafted untyped child result", { evidence_format: null }],
    ["red child result", { result: "FAIL" }],
    ["wrong child identity", { work_item_id: "wrong-child" }],
    ["stale child record binding", { record_sha256: "0".repeat(64) }],
    ["wrong child stage", { stage_id: "M-WRONG" }],
    ["forged child adversarial proof substitution", {
      adversarial_or_fault_proof: Array.isArray(target.adversarial_or_fault_proof)
        ? [...target.adversarial_or_fault_proof, "forged"]
        : `${target.adversarial_or_fault_proof ?? ""} forged`,
    }],
  ]) {
    const defects = validateWorkItemCertificationEnvelope(
      { ...validChildEnvelope, ...mutation },
      { record: target, recordSha256: targetRecordSha },
    );
    check(`${name} is refused by the child envelope contract`, defects.length > 0);
  }

  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), "ioi-transition-"));
  const outsideArtifact = path.join(tmp, "outside.txt");
  fs.writeFileSync(outsideArtifact, "M0_SOMETHING_EXIT=0\n");

  const writeResult = (body) => {
    const p = path.join(tmp, "result.json");
    fs.writeFileSync(p, JSON.stringify(body, null, 2));
    return p;
  };

  const aggregateProbe = records.find((candidate) =>
    candidate.record_role === "aggregate_exit" &&
    candidate.status !== "verified" &&
    !fs.existsSync(path.join(
      REPO_ROOT,
      "docs/architecture/_meta/work-items",
      `${candidate.work_item_id}.v1.json`,
    ))
  );
  check(
    "a private unverified aggregate is available to exercise live envelope admission",
    Boolean(aggregateProbe),
  );
  if (aggregateProbe) {
    const aggregateRefusal = runTransition([
      aggregateProbe.work_item_id,
      "verified",
      "--result",
      writeResult({
        literal_exit: {},
        adversarial_or_fault_proof: aggregateProbe.adversarial_or_fault_proof ?? [],
      }),
    ]);
    check(
      "the live aggregate transition refuses a handcrafted non-stage envelope",
      aggregateRefusal.exit !== 0 &&
        aggregateRefusal.out.includes("stage-certification-envelope"),
      aggregateRefusal.out.slice(0, 260),
    );
  }

  // The same bounded rollback primitive used by transition must restore both
  // sides of a filing move plus all derived orientation outputs. Exercise an
  // injected failure immediately after filing and again after orientation.
  const atomicRoot = path.join(tmp, "atomic");
  const sourceRecord = path.join(atomicRoot, "proposed", "fixture.json");
  const targetRecord = path.join(atomicRoot, "active", "fixture.json");
  const nowProjection = path.join(atomicRoot, "NOW.md");
  const stateProjection = path.join(atomicRoot, "program-state.v1.json");
  fs.mkdirSync(path.dirname(sourceRecord), { recursive: true });
  fs.writeFileSync(sourceRecord, "source-before\n");
  fs.writeFileSync(nowProjection, "now-before\n");
  fs.writeFileSync(stateProjection, "state-before\n");
  const atomicPaths = [sourceRecord, targetRecord, nowProjection, stateProjection];
  for (const failurePoint of ["after filing", "after orientation"]) {
    let injected = false;
    try {
      withFileRollback(atomicPaths, () => {
        fs.writeFileSync(sourceRecord, "source-mutated\n");
        fs.mkdirSync(path.dirname(targetRecord), { recursive: true });
        fs.renameSync(sourceRecord, targetRecord);
        if (failurePoint === "after filing") throw new Error("injected-after-filing");
        fs.writeFileSync(nowProjection, "now-future\n");
        fs.writeFileSync(stateProjection, "state-future\n");
        throw new Error("injected-after-orientation");
      });
    } catch {
      injected = true;
    }
    check(`${failurePoint} injection actually throws`, injected);
    check(
      `${failurePoint} rollback restores the source and removes the duplicate target`,
      fs.readFileSync(sourceRecord, "utf8") === "source-before\n" &&
        !fs.existsSync(targetRecord),
    );
    check(
      `${failurePoint} rollback restores both orientation projections`,
      fs.readFileSync(nowProjection, "utf8") === "now-before\n" &&
      fs.readFileSync(stateProjection, "utf8") === "state-before\n",
    );
  }

  const modeOf = (absolute) => fs.lstatSync(absolute).mode & 0o7777;
  const chmodTarget = path.join(atomicRoot, "chmod-target.json");
  fs.writeFileSync(chmodTarget, "chmod-before\n");
  fs.chmodSync(chmodTarget, 0o640);
  try {
    withFileRollback([chmodTarget], () => {
      fs.chmodSync(chmodTarget, 0o777);
      fs.writeFileSync(chmodTarget, "chmod-after\n");
      throw new Error("injected-after-chmod");
    });
  } catch {
    // Expected injected failure.
  }
  check(
    "chmod-in-place rollback restores exact bytes and regular-file mode",
    fs.readFileSync(chmodTarget, "utf8") === "chmod-before\n" &&
      modeOf(chmodTarget) === 0o640,
    `mode=${modeOf(chmodTarget).toString(8)}`,
  );

  const recreateSource = path.join(atomicRoot, "recreate", "source.json");
  const recreateTarget = path.join(atomicRoot, "recreate", "target.json");
  fs.mkdirSync(path.dirname(recreateSource), { recursive: true });
  fs.writeFileSync(recreateSource, "original-source\n");
  fs.chmodSync(recreateSource, 0o620);
  try {
    withFileRollback([recreateSource, recreateTarget], () => {
      fs.renameSync(recreateSource, recreateTarget);
      fs.chmodSync(recreateTarget, 0o755);
      fs.writeFileSync(recreateSource, "replacement-source\n");
      fs.chmodSync(recreateSource, 0o600);
      throw new Error("injected-after-rename-recreate");
    });
  } catch {
    // Expected injected failure.
  }
  check(
    "rename/recreate rollback removes replacement/destination and restores original regular-file bytes/mode",
    fs.readFileSync(recreateSource, "utf8") === "original-source\n" &&
      modeOf(recreateSource) === 0o620 &&
      !fs.existsSync(recreateTarget),
    `source_mode=${modeOf(recreateSource).toString(8)} target_exists=${fs.existsSync(recreateTarget)}`,
  );

  let r = runTransition([target.work_item_id, "verified"]);
  check(
    "verified without a certification result is refused",
    r.exit !== 0 && r.out.includes("proof-required"),
    r.out.slice(0, 160),
  );

  r = runTransition([target.work_item_id, "verified", "--result", writeResult({
    literal_exit: { expected: "exit 0", artifact_path: "package.json", artifact_sha256: "x" },
    adversarial_or_fault_proof: ["something"],
  })]);
  check(
    'a literal of "exit 0" is refused as not-proof',
    r.exit !== 0 && (r.out.includes("proof-not-proof") || r.out.includes("proof-literal-mismatch")),
    r.out.slice(0, 200),
  );

  r = runTransition([target.work_item_id, "verified", "--result", writeResult({
    literal_exit: {
      expected: "M0_SOMETHING_EXIT=0",
      artifact_path: outsideArtifact,
      artifact_sha256: sha256File(outsideArtifact),
    },
    adversarial_or_fault_proof: ["something"],
  })]);
  check(
    "an artifact outside the repository is refused",
    r.exit !== 0 &&
      (r.out.includes("outside-repo") || r.out.includes("proof-literal-mismatch")),
    r.out.slice(0, 200),
  );

  const declared = target.evidence_index && !Array.isArray(target.evidence_index)
    ? target.evidence_index.literal_exit
    : null;
  check("the target declares a literal, so the refusals below actually run", Boolean(declared));
  if (declared) {
    r = runTransition([target.work_item_id, "verified", "--result", writeResult({
      literal_exit: {
        expected: declared,
        artifact_path: "package.json",
        artifact_sha256: sha256File(path.join(REPO_ROOT, "package.json")),
      },
      adversarial_or_fault_proof: ["something"],
    })]);
    check(
      "an artifact the record never declared is refused",
      r.exit !== 0 && r.out.includes("undeclared"),
      r.out.slice(0, 200),
    );

    r = runTransition([target.work_item_id, "verified", "--result", writeResult({
      literal_exit: { expected: declared, artifact_path: "package.json" },
      adversarial_or_fault_proof: [],
    })]);
    check(
      "a missing artifact digest is refused, never derived",
      r.exit !== 0 &&
        (r.out.includes("proof-binding-absent") || r.out.includes("undeclared")),
      r.out.slice(0, 200),
    );

    r = runTransition([target.work_item_id, "verified", "--result", writeResult({
      literal_exit: { expected: declared, artifact_path: "package.json" },
      adversarial_or_fault_proof: [],
    })]);
    check(
      "adversarial evidence is required",
      r.exit !== 0,
      r.out.slice(0, 160),
    );
  }

  // A record whose status authority is a merged tracked record can never be
  // advanced privately.
  const merged_authority = records.find((r) =>
    fs.existsSync(path.join(
      REPO_ROOT,
      "docs/architecture/_meta/work-items",
      `${r.work_item_id}.v1.json`,
    ))
  );
  if (merged_authority) {
    r = runTransition([merged_authority.work_item_id, "scoped"]);
    check(
      "a cut whose authority is a merged tracked record cannot be advanced privately",
      r.exit !== 0 && r.out.includes("status-authority"),
      r.out.slice(0, 160),
    );
  }

  // --- the shared literal-log validator, and the gate that now calls it ----
  //
  // 1. The frozen fixture classes must every one refuse, and refuse under a
  //    NAME from the closed refusal set. A refusal a caller cannot name is a
  //    refusal a caller cannot assert on.
  const fixtureDir = path.join(ESTATE_ROOT, "fixtures", "literal-exit");
  const fixtureManifest = readJson(path.join(fixtureDir, "manifest.v1.json"));
  const namesSeen = new Set();
  let unrefused = [];
  let unnamed = [];
  for (const fixture of fixtureManifest.fixtures) {
    const rel = path.relative(
      REPO_ROOT,
      path.join(fixtureDir, fixture.file),
    );
    const refusals = refuseUnlessConformingLiteralExitLog(rel);
    if (refusals.length === 0) unrefused.push(fixture.class);
    for (const r of refusals) {
      namesSeen.add(r.check);
      if (!REFUSAL_NAMES.includes(r.check)) unnamed.push(`${fixture.class}:${r.check}`);
    }
  }
  check(
    "every predeclared malformed-log fixture class is refused",
    unrefused.length === 0,
    unrefused.join(", "),
  );
  check(
    "every refusal carries a name from the closed refusal set",
    unnamed.length === 0,
    unnamed.join(", "),
  );
  check(
    "the fixture set exercises more than one distinct refusal name",
    namesSeen.size > 1,
    [...namesSeen].join(", "),
  );

  // 2. The validator is not a blanket refusal: a CONFORMING retained log
  //    passes it clean. Without this, "refuses everything" would score as a
  //    passing gate.
  const conforming = [];
  const evidenceRoot = path.join(ESTATE_ROOT, "evidence");
  for (const dir of fs.readdirSync(evidenceRoot).filter((d) => /^M\d{1,2}$/u.test(d))) {
    for (const entry of fs.readdirSync(path.join(evidenceRoot, dir))) {
      if (!entry.endsWith(".exit.v1.txt")) continue;
      const rel = path.relative(
        REPO_ROOT,
        path.join(evidenceRoot, dir, entry),
      );
      if (refuseUnlessConformingLiteralExitLog(rel).length === 0) {
        conforming.push(rel);
      }
    }
  }
  check(
    "a conforming retained log passes the shared validator with zero refusals",
    conforming.length > 0,
    "no retained stage log validates clean; the positive case cannot be asserted",
  );

  // 3. A conforming log that certifies a DIFFERENT bar is refused when the
  //    caller pins the literal it requires.
  if (conforming.length > 0) {
    const mismatched = refuseUnlessConformingLiteralExitLog(conforming[0], {
      expectLiteral: "SOME_OTHER_BAR_EXIT=0",
    });
    check(
      "a conforming log presented for a literal it does not carry is refused by name",
      mismatched.some((r) => r.check === "proof-literal-log-literal-mismatch"),
      JSON.stringify(mismatched.map((r) => r.check)),
    );
  }

  // 4. THE REGRESSION. The record whose verification was withdrawn, its own
  //    declared literal, its own retained artifact, its own digest — the exact
  //    certification the old gate admitted. It must now refuse, by name.
  const withdrawn = records.find((r) =>
    r.verification_correction?.state === "WITHDRAWN" &&
    r.evidence_index && !Array.isArray(r.evidence_index) &&
    (r.evidence_index.expected_output_paths ?? []).length > 0
  );
  check(
    "the withdrawn record is available to replay the exact admitted certification",
    Boolean(withdrawn),
  );
  if (withdrawn) {
    const artifactRel = withdrawn.evidence_index.expected_output_paths[0];
    const artifactAbs = path.join(REPO_ROOT, artifactRel);
    r = runTransition([withdrawn.work_item_id, "verified", "--result", writeResult({
      literal_exit: {
        expected: withdrawn.evidence_index.literal_exit,
        artifact_path: artifactRel,
        artifact_sha256: sha256File(artifactAbs),
      },
      adversarial_or_fault_proof: ["the predeclared refusals of the withdrawn record"],
    })]);
    check(
      "a free-form-prose exit artifact is refused as a non-conforming literal log",
      r.exit !== 0 && r.out.includes("proof-literal-log-malformed"),
      r.out.slice(0, 200),
    );
    check(
      "the refusal names the missing contract keys, not just the malformed lines",
      r.out.includes("proof-literal-log-missing-key"),
      r.out.slice(0, 200),
    );
    check(
      "the literal string being present exactly once no longer admits the artifact",
      fs.readFileSync(artifactAbs, "utf8").split(
        withdrawn.evidence_index.literal_exit,
      ).length - 1 === 1 && r.exit !== 0,
    );
  }

  // 5. A record held by an open successor hold cannot be re-verified. Before
  // closure, exercise the live CLI refusal. After every hold is correctly
  // discharged, reopen one historical hold only in memory and exercise the
  // shared predicate used by transition.mjs. A closure-successful estate must
  // not make its own regression fixture impossible to drive.
  const ledger = readHoldLedger();
  const driveableHeldRecord = (holds) => holds
    .flatMap((h) => h.predecessor_records ?? [])
    .find((id) => {
      const record = records.find((rec) => rec.work_item_id === id);
      return record && record.evidence_index && !Array.isArray(record.evidence_index) &&
        record.evidence_index.literal_exit &&
        !fs.existsSync(path.join(
          REPO_ROOT,
          "docs/architecture/_meta/work-items",
          `${id}.v1.json`,
        ));
    });
  let held = driveableHeldRecord(openHolds(ledger));
  let syntheticLedger = null;
  if (!held) {
    const historical = (ledger.holds ?? []).find((hold) =>
      driveableHeldRecord([hold])
    );
    if (historical) {
      const reopened = structuredClone(historical);
      reopened.state = "open";
      reopened.state_transitions = [];
      syntheticLedger = { ...ledger, holds: [reopened] };
      held = driveableHeldRecord([reopened]);
    }
  }
  check(
    "a live or in-memory historical hold is available to drive the hold refusal",
    Boolean(held),
    "no hold names a privately-authoritative predecessor",
  );
  if (held) {
    if (syntheticLedger) {
      check(
        "a predecessor under an open successor hold cannot be re-verified",
        openHoldsForRecord(held, syntheticLedger).length === 1,
        "the shared transition hold predicate did not qualify the synthetic predecessor",
      );
    } else {
      const record = records.find((rec) => rec.work_item_id === held);
      const artifactRel = (record.evidence_index.expected_output_paths ?? [])[0];
      r = runTransition([held, "verified", "--result", writeResult({
        literal_exit: {
          expected: record.evidence_index.literal_exit,
          artifact_path: artifactRel ?? "package.json",
          artifact_sha256: artifactRel && fs.existsSync(path.join(REPO_ROOT, artifactRel))
            ? sha256File(path.join(REPO_ROOT, artifactRel))
            : sha256File(path.join(REPO_ROOT, "package.json")),
        },
        adversarial_or_fault_proof: ["hold probe"],
      })]);
      check(
        "a predecessor under an open successor hold cannot be re-verified",
        r.exit !== 0 && r.out.includes("open-successor-hold"),
        r.out.slice(0, 240),
      );
    }
  }

  // A dry run must not mutate anything. The record lives in whichever status
  // directory its current status files it under.
  const targetDir = target.status === "proposed" ? "proposed" : "active";
  const targetPath = path.join(
    ESTATE_ROOT,
    "work-items",
    targetDir,
    `${target.work_item_id}.v1.json`,
  );
  const before = sha256File(targetPath);
  runTransition([
    target.work_item_id,
    target.status === "proposed" ? "scoped" : "evidence_ready",
  ]);
  const after = sha256File(targetPath);
  check("a dry run leaves the record byte-identical", before === after);

  fs.rmSync(tmp, { recursive: true, force: true });
  process.stdout.write(
    failures === 0
      ? "transition fixture test: PASS\n"
      : `transition fixture test: FAIL (${failures})\n`,
  );
  process.exit(failures === 0 ? 0 : 1);
}

main();
