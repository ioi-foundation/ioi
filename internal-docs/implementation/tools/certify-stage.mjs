#!/usr/bin/env node
// LANE 2 — stage certification.
//
//   node tools/certify-stage.mjs <STAGE> [--apply]
//
// One content-bound stage proof. It:
//   * resolves the stage's aggregate exit record and every child from
//     program/sequence.v1.json and the work-item estate;
//   * checks every child has reached `verified` under its own status authority;
//   * checks every child's retained literal exit — declared in the record's
//     evidence_index — is present exactly once in a retained artifact, AND that
//     the artifact is a conforming ioi.program.literal_exit.v1 log under the
//     shared validator. A child that declares no literal is reported, not
//     silently skipped, when it is verified;
//   * refuses to certify on any child or aggregate held by an open successor
//     hold: a closure that projects as verified_historical_with_open_successor
//     is not a satisfied closure;
//   * runs the stage module's declared focused checks;
//   * with --apply, hands the retained result to tools/transition.mjs so the
//     status change, evidence registration, and every regeneration happen in one
//     atomic step.
//
// Certification results are cached by input digest under generated/.certify/, so
// re-running with unchanged inputs is free. The cache keys on content, never on
// time, so a stale cache cannot certify a changed stage.
import fs from "node:fs";
import path from "node:path";
import process from "node:process";
import { execFileSync } from "node:child_process";
import {
  ESTATE_ROOT,
  finding,
  listEstateFiles,
  parseFrontMatter,
  readJson,
  REPO_ROOT,
  report,
  restoreFileSet,
  sha256File,
  sha256Text,
  snapshotFileSet,
  withFileRollback,
  writeJsonDeterministic,
} from "./lib/estate.mjs";
import { refuseUnlessConformingLiteralExitLog } from "./lib/literal-exit.mjs";
import {
  reboundAggregateVerificationRecord,
  validateAggregateVerificationBinding,
} from "./lib/aggregate-verification-binding.mjs";
import { openHoldsForRecord, QUALIFIED_STATUS } from "./lib/holds.mjs";
import { loadWorkItems, statusAuthority } from "./generate-now.mjs";

export const STAGE_CERTIFICATION_FORMAT =
  "ioi.program.stage_certification.v1";
export const FOCUSED_CHECK_TIMEOUT_MS = 60 * 60 * 1000;

export function focusedChecks(stageModuleRel) {
  const absolute = path.join(ESTATE_ROOT, stageModuleRel);
  if (!fs.existsSync(absolute)) return [];
  const parsed = parseFrontMatter(fs.readFileSync(absolute, "utf8"));
  if (!parsed) return [];
  const section = /## Focused checks during development\n([\s\S]*?)(\n## |$)/u
    .exec(parsed.body);
  if (!section) return [];
  return [...section[1].matchAll(/`([^`]+)`/gu)]
    .map((m) => m[1])
    .filter((c) => c.startsWith("npm run ") || c.startsWith("node ") || c.startsWith("cargo "));
}

// A cache hit is proof-bearing only when it carries the complete exact command
// set and every retained exit is zero. The old cache branch printed "reusing"
// but never loaded the cached checks, then overwrote the cache and admitted a
// result with focused_checks: []. Keep this validator exported so the refusal
// is covered without running a real stage.
export function validateCachedFocusedChecks(cached, {
  stageId,
  aggregateWorkItemId,
  inputDigest,
  commands,
}) {
  const defects = [];
  if (!cached || typeof cached !== "object") return ["cache is not an object"];
  if (cached.evidence_format !== "ioi.program.stage_certification.v1") {
    defects.push("cache evidence_format is not ioi.program.stage_certification.v1");
  }
  if (cached.stage_id !== stageId) defects.push("cache stage_id is stale");
  if (cached.aggregate_work_item_id !== aggregateWorkItemId) {
    defects.push("cache aggregate_work_item_id is stale");
  }
  if (cached.input_digest !== inputDigest) defects.push("cache input_digest is stale");
  if (cached.result !== "PASS") defects.push("cache result is not PASS");
  const checks = Array.isArray(cached.focused_checks)
    ? cached.focused_checks
    : [];
  if (checks.length !== commands.length) {
    defects.push(
      `cache carries ${checks.length} focused checks, expected ${commands.length}`,
    );
  }
  if (JSON.stringify(checks.map((check) => check.command)) !== JSON.stringify(commands)) {
    defects.push("cache focused-check command set/order is stale");
  }
  for (const check of checks) {
    if (check.exit !== 0) defects.push(`cached check is red: ${check.command}`);
    if (typeof check.seconds !== "number" || check.seconds < 0) {
      defects.push(`cached check lacks a valid duration: ${check.command}`);
    }
  }
  return defects;
}

export function checkoutFingerprint() {
  const head = execFileSync("git", ["rev-parse", "HEAD"], {
    cwd: REPO_ROOT,
    encoding: "utf8",
  }).trim();
  const trackedDiff = execFileSync(
    "git",
    ["diff", "--binary", "--no-ext-diff", "HEAD", "--"],
    {
      cwd: REPO_ROOT,
      encoding: "utf8",
      maxBuffer: 256 * 1024 * 1024,
    },
  );
  const untracked = execFileSync(
    "git",
    ["ls-files", "--others", "--exclude-standard", "-z"],
    { cwd: REPO_ROOT, encoding: "utf8", maxBuffer: 64 * 1024 * 1024 },
  ).split("\0").filter(Boolean).sort().map((relative) => {
    const absolute = path.join(REPO_ROOT, relative);
    const stat = fs.lstatSync(absolute);
    return stat.isSymbolicLink()
      ? [relative, "symlink", fs.readlinkSync(absolute)]
      : [relative, "file", sha256File(absolute)];
  });
  return {
    head,
    tracked_diff_sha256: sha256Text(trackedDiff),
    untracked,
  };
}

export function certificationToolchainFingerprint() {
  const toolsRoot = path.join(ESTATE_ROOT, "tools");
  const files = [];
  const stack = [toolsRoot];
  while (stack.length > 0) {
    const directory = stack.pop();
    for (const entry of fs.readdirSync(directory, { withFileTypes: true })) {
      const absolute = path.join(directory, entry.name);
      if (entry.isDirectory()) {
        stack.push(absolute);
      } else if (entry.isFile() && entry.name.endsWith(".mjs")) {
        files.push({
          path: path.relative(REPO_ROOT, absolute),
          sha256: sha256File(absolute),
        });
      }
    }
  }
  files.sort((left, right) => left.path.localeCompare(right.path));
  return {
    files,
    aggregate_sha256: sha256Text(JSON.stringify(files)),
  };
}

// The private implementation estate is gitignored, so checkoutFingerprint()
// cannot see its program/map/record/evidence/hold/attestation authority. Bind
// every estate file except the certification cache itself. The cache directory
// is the only excluded cycle: a dry certification writes there, and an
// immediate --apply must be able to reuse that exact result. Promotion/CAS
// writes are intentionally included and therefore must settle before the dry
// run; an intervening promotion correctly invalidates and reruns certification.
export function certificationPrivateAuthorityFingerprint({
  files = listEstateFiles(),
  digestOf = (relative) => sha256File(path.join(ESTATE_ROOT, relative)),
} = {}) {
  const entries = [...new Set(files)]
    .filter((relative) =>
      relative !== "generated/.certify" &&
      !relative.startsWith("generated/.certify/")
    )
    .sort()
    .map((relative) => ({
      path: relative,
      sha256: digestOf(relative),
    }));
  return {
    excluded_cycle_prefix: "generated/.certify/",
    files: entries,
    aggregate_sha256: sha256Text(JSON.stringify(entries)),
  };
}

export function stageCertificationInputPayload({
  stage,
  records,
  aggregate,
  literals,
  commands,
}) {
  const mine = records.filter((record) => record.stage_id === stage.id);
  return {
    stage,
    records: mine.map((record) => ({
      id: record.work_item_id,
      status: statusAuthority(record).status,
      sha256: sha256File(path.join(ESTATE_ROOT, record.file)),
    })),
    module: fs.existsSync(path.join(ESTATE_ROOT, stage.module))
      ? sha256File(path.join(ESTATE_ROOT, stage.module))
      : null,
    // A focused check certifies the implementation checkout, not only the
    // private record text.
    checkout: checkoutFingerprint(),
    certification_toolchain: certificationToolchainFingerprint(),
    private_authority: certificationPrivateAuthorityFingerprint(),
    literals,
    aggregate_binding_payload_sha256:
      aggregate?.aggregate_verification_binding?.binding_payload_sha256 ?? null,
    commands,
  };
}

export function stageCertificationInputState(options) {
  const payload = stageCertificationInputPayload(options);
  return {
    payload,
    inputDigest: sha256Text(JSON.stringify(payload)),
  };
}

export function collectStageLiteralBindings(
  aggregate,
  records,
  { repoRoot = REPO_ROOT } = {},
) {
  if (!aggregate) throw new Error("stage has no aggregate exit record");
  const byId = new Map(records.map((record) => [record.work_item_id, record]));
  const selected = (aggregate.aggregate_child_ids ?? []).map((id) => {
    const record = byId.get(id);
    if (!record) throw new Error(`aggregate names missing child ${id}`);
    return record;
  });
  selected.push(aggregate);
  return selected.map((record) => {
    const index = record.evidence_index;
    const expected = index && !Array.isArray(index)
      ? index.literal_exit
      : null;
    const paths = index && !Array.isArray(index)
      ? (index.expected_output_paths ?? [])
      : [];
    if (!expected || paths.length !== 1) {
      throw new Error(
        `${record.work_item_id} must declare one literal_exit and exactly one expected output path`,
      );
    }
    const artifact = path.resolve(repoRoot, paths[0]);
    const inside = artifact === repoRoot || artifact.startsWith(`${repoRoot}${path.sep}`);
    if (!inside || !fs.existsSync(artifact)) {
      throw new Error(
        `${record.work_item_id} literal artifact is absent or outside the repository: ${paths[0]}`,
      );
    }
    return {
      work_item_id: record.work_item_id,
      expected,
      artifact_path: paths[0],
      artifact_sha256: sha256File(artifact),
    };
  });
}

// Re-read every stage-certification input from current bytes. This is used
// after checks (fresh OR cached), immediately before dispatch, and by the
// aggregate transition admission gate. No caller is allowed to validate a
// result against the objects it loaded before a potentially mutating check.
export function currentStageCertificationInput(stageId) {
  const sequence = readJson(path.join(ESTATE_ROOT, "program", "sequence.v1.json"));
  const stage = sequence.stages.find((candidate) => candidate.id === stageId);
  if (!stage) throw new Error(`unknown stage: ${stageId}`);
  const records = loadWorkItems();
  const aggregateId = stage.exit_gate?.aggregate_work_item_id ?? null;
  const aggregate = records.find((record) =>
    record.work_item_id === aggregateId
  );
  if (!aggregate) {
    throw new Error(`stage ${stageId} has no current aggregate ${aggregateId ?? "(undeclared)"}`);
  }
  const literals = collectStageLiteralBindings(aggregate, records);
  const commands = focusedChecks(stage.module);
  const state = stageCertificationInputState({
    stage,
    records,
    aggregate,
    literals,
    commands,
  });
  return {
    ...state,
    stage,
    records,
    aggregate,
    literals,
    commands,
    children: (aggregate.aggregate_child_ids ?? []).map((id) => {
      const child = records.find((record) => record.work_item_id === id);
      return {
        id,
        status: child ? statusAuthority(child).status : "absent",
      };
    }),
    adversarialOrFaultProof: aggregate.adversarial_or_fault_proof ?? [],
  };
}

export function validateStageCertificationInputStability(
  before,
  current,
  { phase = "post-check" } = {},
) {
  const defects = [];
  if (!before || !current) {
    return [`${phase}: stage-certification input state is absent`];
  }
  if (before.inputDigest !== current.inputDigest) {
    defects.push(
      `${phase}: input digest moved from ${before.inputDigest} to ${current.inputDigest}`,
    );
  }
  if (JSON.stringify(before.payload) !== JSON.stringify(current.payload)) {
    defects.push(`${phase}: complete stage-certification input payload moved`);
  }
  return defects;
}

export function validateStageCertificationEnvelope(
  result,
  { stageId, aggregateWorkItemId, currentInput },
) {
  const defects = validateCachedFocusedChecks(result, {
    stageId,
    aggregateWorkItemId,
    inputDigest: currentInput.inputDigest,
    commands: currentInput.commands,
  });
  if (!/^[a-f0-9]{64}$/u.test(result?.input_digest ?? "")) {
    defects.push("stage certification input_digest is not a sha256 digest");
  }
  if (currentInput.commands.length === 0) {
    defects.push("stage aggregate declares no focused checks; an empty proof set cannot admit it");
  }
  if (JSON.stringify(result?.children) !== JSON.stringify(currentInput.children)) {
    defects.push("stage certification child set/statuses are incomplete or stale");
  }
  if (JSON.stringify(result?.literal_exits) !== JSON.stringify(currentInput.literals)) {
    defects.push("stage certification literal-exit bindings are incomplete or stale");
  }
  const aggregateLiteral = currentInput.literals.find((literal) =>
    literal.work_item_id === aggregateWorkItemId
  ) ?? null;
  if (JSON.stringify(result?.literal_exit) !== JSON.stringify(aggregateLiteral)) {
    defects.push("stage certification aggregate literal binding is absent or stale");
  }
  if (
    JSON.stringify(result?.adversarial_or_fault_proof) !==
      JSON.stringify(currentInput.adversarialOrFaultProof)
  ) {
    defects.push(
      "stage certification adversarial_or_fault_proof does not exactly match the current aggregate declaration",
    );
  }
  return defects;
}

// Re-certifying an already-verified aggregate changes the retained
// certification bytes that its exact join binds. Replace the certification and
// rebound aggregate as one bounded transaction; either both current bodies are
// admitted or both original bodies are restored.
export function applyVerifiedAggregateRecertification({
  aggregateWorkItemId,
  aggregatePath,
  certificationPath,
  retainedResult,
  loadRecords = loadWorkItems,
  recordPath,
  repoRoot = REPO_ROOT,
  writeJson = writeJsonDeterministic,
  afterCertificationWrite = null,
  validateInput = null,
}) {
  const snapshot = snapshotFileSet([aggregatePath, certificationPath]);
  try {
    if (validateInput) validateInput();
    writeJson(certificationPath, retainedResult);
    if (afterCertificationWrite) afterCertificationWrite();

    const records = loadRecords();
    const aggregate = records.find((record) =>
      record.work_item_id === aggregateWorkItemId
    );
    if (!aggregate) {
      throw new Error(`cannot reload verified aggregate ${aggregateWorkItemId}`);
    }
    if (aggregate.status !== "verified" || aggregate.record_role !== "aggregate_exit") {
      throw new Error(
        `${aggregateWorkItemId} is not a verified aggregate_exit during re-certification`,
      );
    }
    const rebound = reboundAggregateVerificationRecord(aggregate, {
      records,
      recordPath,
      repoRoot,
    });
    writeJson(aggregatePath, rebound);

    const refreshedRecords = loadRecords();
    const refreshed = refreshedRecords.find((record) =>
      record.work_item_id === aggregateWorkItemId
    );
    if (!refreshed) {
      throw new Error(`cannot reload rebound aggregate ${aggregateWorkItemId}`);
    }
    const refusals = validateAggregateVerificationBinding(refreshed, {
      records: refreshedRecords,
      recordPath,
      repoRoot,
    });
    if (refusals.length > 0) {
      throw new Error(
        `rebound aggregate is invalid: ${refusals.map((entry) => entry.check).join(", ")}`,
      );
    }
    return refreshed.aggregate_verification_binding;
  } catch (error) {
    restoreFileSet(snapshot);
    throw error;
  }
}

// `*.latest.json` is a dispatch artifact, not a scratch write outside the
// transaction. It is written before transition/recertification because the
// downstream gate reads it, so that write and the downstream action must share
// one rollback boundary. A failed first dispatch removes a newly-created
// latest; a failed later dispatch restores the exact prior bytes and mode.
export function dispatchStageCertificationTransaction({
  latestPath,
  retainedResult,
  dispatch,
  writeJson = writeJsonDeterministic,
}) {
  return withFileRollback([latestPath], () => {
    writeJson(latestPath, retainedResult);
    return dispatch();
  });
}

function main() {
  const stageId = process.argv[2];
  const apply = process.argv.includes("--apply");
  const runChecks = !process.argv.includes("--no-run");
  // --no-run is a read-only structural preflight. Letting it combine with
  // --apply admitted a static PASS with focused_checks: [], bypassing every
  // executable stage proof. Refuse the invocation before stage lookup, cache
  // access, evidence writes, or transition dispatch.
  if (apply && !runChecks) {
    process.stderr.write(
      "--apply --no-run is forbidden: a stage cannot be certified or transitioned without its focused checks\n",
    );
    process.exit(2);
  }
  if (!stageId) {
    process.stderr.write("usage: certify-stage.mjs <STAGE> [--apply] [--no-run]\n");
    process.exit(2);
  }

  const sequence = readJson(
    path.join(ESTATE_ROOT, "program", "sequence.v1.json"),
  );
  const stage = sequence.stages.find((s) => s.id === stageId);
  if (!stage) {
    process.stderr.write(`unknown stage: ${stageId}\n`);
    process.exit(2);
  }

  const findings = [];
  const records = loadWorkItems();
  const aggregate = stage.exit_gate
    ? records.find((r) =>
      r.work_item_id === stage.exit_gate.aggregate_work_item_id
    )
    : null;

  if (stage.exit_gate && !aggregate) {
    findings.push(
      finding(
        "error",
        "aggregate-missing",
        `stage ${stageId} names exit gate ${stage.exit_gate.aggregate_work_item_id}, which has no record`,
      ),
    );
  }

  // --- dependency edges
  for (const dep of stage.depends_on ?? []) {
    const depStage = sequence.stages.find((s) => s.id === dep);
    const depAggregate = depStage?.exit_gate
      ? records.find((r) =>
        r.work_item_id === depStage.exit_gate.aggregate_work_item_id
      )
      : null;
    const depStatus = depAggregate ? statusAuthority(depAggregate).status : null;
    if (depStatus !== "verified") {
      findings.push(
        finding(
          "error",
          "dependency",
          `stage ${stageId} depends on ${dep}, whose exit gate is ${
            depStatus ?? "absent"
          }`,
        ),
      );
    }
  }

  // --- children
  const childIds = aggregate?.aggregate_child_ids ?? [];
  const children = childIds.map((id) => ({
    id,
    record: records.find((r) => r.work_item_id === id) ?? null,
  }));
  for (const child of children) {
    if (!child.record) {
      findings.push(
        finding("error", "child-missing", `aggregate names unknown child ${child.id}`),
      );
      continue;
    }
    const authority = statusAuthority(child.record);
    if (authority.status !== "verified") {
      findings.push(
        finding(
          "error",
          "child-status",
          `child ${child.id} is ${authority.status} under ${authority.ref}; the aggregate manufactures no child status`,
        ),
      );
    }
    // A verified child under an open successor hold is not a satisfied
    // closure: it projects as verified_historical_with_open_successor, and a
    // stage cannot be certified on top of a qualification.
    for (const hold of openHoldsForRecord(child.id)) {
      findings.push(
        finding(
          "error",
          "child-open-successor-hold",
          `child ${child.id} is held by ${hold.hold_id} (${hold.subject}) and projects as ${QUALIFIED_STATUS}; the stage cannot certify on a closure whose successor is owed and unwritten`,
        ),
      );
    }
  }
  if (aggregate) {
    for (const hold of openHoldsForRecord(aggregate.work_item_id)) {
      findings.push(
        finding(
          "error",
          "aggregate-open-successor-hold",
          `aggregate ${aggregate.work_item_id} is held by ${hold.hold_id} (${hold.subject}) and projects as ${QUALIFIED_STATUS}`,
        ),
      );
    }

    // The aggregate must bind the current bytes, statuses, and retained literal
    // evidence of every selected child/dependency plus its own exit. The stage
    // module may name this as a stop rule, but prose is not the gate.
    for (const refusal of validateAggregateVerificationBinding(aggregate, {
      records,
    })) {
      findings.push(finding("error", refusal.check, refusal.message));
    }
  }
  // --- content-bound literal exits
  // Records declare their literal inside evidence_index, not at the top level.
  // Reading a top-level `literal_exit` made this bar dead code on 100% of the
  // estate, so every stage certified its literal dimension unconditionally.
  const literals = [];
  for (const child of children.filter((c) => c.record)) {
    const index = child.record.evidence_index;
    const declared = index && !Array.isArray(index) ? index.literal_exit : null;
    const paths = index && !Array.isArray(index)
      ? (index.expected_output_paths ?? [])
      : [];
    const childStatus = statusAuthority(child.record).status;
    if (!declared) {
      if (childStatus === "verified") {
        findings.push(
          finding(
            "error",
            "literal-undeclared",
            `child ${child.id} is verified but declares no evidence_index.literal_exit`,
          ),
        );
      }
      continue;
    }
    const literal = { expected: declared, artifact_path: paths[0] ?? null };
    const artifact = literal.artifact_path
      ? path.join(REPO_ROOT, literal.artifact_path)
      : null;
    if (!artifact || !fs.existsSync(artifact)) {
      findings.push(
        finding(
          childStatus === "verified" ? "error" : "warn",
          "literal-artifact",
          `child ${child.id} (${childStatus}) declares "${declared}" but its artifact is not retained: ${
            literal.artifact_path ?? "(no expected_output_paths)"
          }`,
        ),
      );
      continue;
    }
    const text = fs.readFileSync(artifact, "utf8");
    const count = text.split(literal.expected).length - 1;
    if (count !== 1) {
      findings.push(
        finding(
          "error",
          "literal-exit",
          `child ${child.id}: expected exactly one "${literal.expected}", found ${count}`,
        ),
      );
    }
    // The artifact must be a conforming retained log, not merely a file with
    // the literal somewhere inside it. Same shared validator as the transition
    // gate and the literal-exit bar.
    for (const refusal of refuseUnlessConformingLiteralExitLog(
      literal.artifact_path,
      { expectLiteral: literal.expected },
    )) {
      findings.push(
        finding(
          childStatus === "verified" ? "error" : "warn",
          refusal.check,
          `child ${child.id}: ${refusal.message}`,
        ),
      );
    }
    literals.push({
      work_item_id: child.id,
      expected: literal.expected,
      artifact_path: literal.artifact_path,
      artifact_sha256: sha256File(artifact),
    });
  }

  // The aggregate owns a distinct retained literal. It is not one of its own
  // children, so validate and bind it explicitly; otherwise --apply can never
  // locate the aggregate proof and stage certification is permanently dead.
  if (aggregate) {
    const index = aggregate.evidence_index;
    const declared = index && !Array.isArray(index) ? index.literal_exit : null;
    const paths = index && !Array.isArray(index)
      ? (index.expected_output_paths ?? [])
      : [];
    const artifactPath = paths[0] ?? null;
    const artifact = artifactPath ? path.join(REPO_ROOT, artifactPath) : null;
    if (!declared) {
      findings.push(finding(
        "error",
        "aggregate-literal-undeclared",
        `aggregate ${aggregate.work_item_id} declares no evidence_index.literal_exit`,
      ));
    } else if (!artifact || !fs.existsSync(artifact)) {
      findings.push(finding(
        "error",
        "aggregate-literal-artifact",
        `aggregate ${aggregate.work_item_id} declares "${declared}" but its artifact is not retained: ${artifactPath ?? "(no expected_output_paths)"}`,
      ));
    } else {
      const artifactText = fs.readFileSync(artifact, "utf8");
      const count = artifactText.split(declared).length - 1;
      if (count !== 1) {
        findings.push(finding(
          "error",
          "aggregate-literal-exit",
          `aggregate ${aggregate.work_item_id}: expected exactly one "${declared}", found ${count}`,
        ));
      }
      for (const refusal of refuseUnlessConformingLiteralExitLog(
        artifactPath,
        { expectLiteral: declared },
      )) {
        findings.push(finding(
          "error",
          refusal.check,
          `aggregate ${aggregate.work_item_id}: ${refusal.message}`,
        ));
      }
      literals.push({
        work_item_id: aggregate.work_item_id,
        expected: declared,
        artifact_path: artifactPath,
        artifact_sha256: sha256File(artifact),
      });
    }
  }

  // --- input digest for the cache
  const commands = focusedChecks(stage.module);
  const initialInput = stageCertificationInputState({
    stage,
    records,
    aggregate,
    literals,
    commands,
  });
  const inputDigest = initialInput.inputDigest;
  const cachePath = path.join(
    ESTATE_ROOT,
    "generated",
    ".certify",
    `${stageId}.${inputDigest.slice(0, 16)}.json`,
  );

  // --- focused checks, only when inputs changed
  const checks = [];
  let reuseCache = false;
  if (runChecks && fs.existsSync(cachePath)) {
    let cached = null;
    let cacheDefects = [];
    try {
      cached = readJson(cachePath);
      cacheDefects = validateCachedFocusedChecks(cached, {
        stageId,
        aggregateWorkItemId: aggregate?.work_item_id ?? null,
        inputDigest,
        commands,
      });
    } catch (error) {
      cacheDefects = [`cache cannot be read: ${error.message}`];
    }
    if (cacheDefects.length === 0) {
      checks.push(...cached.focused_checks);
      reuseCache = true;
      process.stdout.write(
        `inputs unchanged; reusing ${checks.length} content-bound focused check(s) from ${path.basename(cachePath)}\n`,
      );
    } else {
      process.stdout.write(
        `cached certification ${path.basename(cachePath)} is not reusable (${cacheDefects.join(" | ")}); rerunning focused checks\n`,
      );
    }
  }
  if (runChecks && !reuseCache) {
    for (const command of commands) {
      const started = Date.now();
      let exit = 0;
      try {
        execFileSync("bash", ["-lc", command], {
          cwd: REPO_ROOT,
          encoding: "utf8",
          stdio: ["ignore", "pipe", "pipe"],
          timeout: FOCUSED_CHECK_TIMEOUT_MS,
        });
      } catch (error) {
        exit = error.status ?? 1;
      }
      checks.push({
        command,
        exit,
        seconds: (Date.now() - started) / 1000,
      });
      if (exit !== 0) {
        findings.push(
          finding(
            "error",
            "focused-check",
            `${command} exited ${exit}`,
          ),
        );
      }
    }
  }

  // Focused checks are allowed to discover drift, never to mutate their own
  // proof inputs and then certify the pre-check snapshot. Re-read the complete
  // tracked checkout, private estate, toolchain, records, literals, aggregate
  // binding, module, and commands after both the fresh and cached paths.
  let postCheckInput = null;
  try {
    postCheckInput = currentStageCertificationInput(stageId);
    const phase = reuseCache ? "post-cached-check" : "post-fresh-check";
    for (const defect of validateStageCertificationInputStability(
      initialInput,
      postCheckInput,
      { phase },
    )) {
      findings.push(finding("error", "certification-input-drift", defect));
    }
  } catch (error) {
    findings.push(finding(
      "error",
      "certification-input-recompute",
      `could not re-read complete stage input after focused checks: ${error.message}`,
    ));
  }

  if (runChecks && commands.length === 0) {
    findings.push(finding(
      "error",
      "focused-checks-empty",
      `stage ${stageId} declares no focused checks; an empty executable proof set cannot certify its aggregate`,
    ));
  }

  let result = {
    evidence_format: STAGE_CERTIFICATION_FORMAT,
    stage_id: stageId,
    aggregate_work_item_id: aggregate?.work_item_id ?? null,
    input_digest: inputDigest,
    children: children.map((c) => ({
      id: c.id,
      status: c.record ? statusAuthority(c.record).status : "absent",
    })),
    literal_exits: literals,
    focused_checks: checks,
    result: findings.some((f) => f.level === "error") ? "FAIL" : "PASS",
    nonclaims: [
      "A passing focused check proves only its own scope.",
      "This certification closes the stage exit gate only when every child is verified under its own status authority and every retained literal is content-bound.",
    ],
  };

  // An apply path gets one final re-read immediately before any PASS cache is
  // recorded or any transition/re-certification is dispatched. This covers
  // both a fresh run and a reused cache, and the transition independently
  // repeats the envelope/input check at admission.
  if (apply && result.result === "PASS") {
    try {
      const dispatchInput = currentStageCertificationInput(stageId);
      for (const defect of validateStageCertificationInputStability(
        initialInput,
        dispatchInput,
        { phase: "pre-dispatch" },
      )) {
        findings.push(finding("error", "certification-input-drift", defect));
      }
    } catch (error) {
      findings.push(finding(
        "error",
        "certification-input-recompute",
        `could not re-read complete stage input before dispatch: ${error.message}`,
      ));
    }
    if (findings.some((entry) => entry.level === "error")) {
      result = { ...result, result: "FAIL" };
    }
  }

  // A --no-run pass must NEVER populate the cache: it executed zero focused
  // checks, so caching it would make every later full run reuse a certification
  // that proved nothing. The cache is also keyed on the set of commands, so
  // editing a stage's focused checks invalidates it.
  if (result.result === "PASS" && runChecks) {
    writeJsonDeterministic(cachePath, result);
  }

  if (apply && result.result === "PASS" && aggregate) {
    // The aggregate's OWN literal binding drives the transition — never a
    // child's. (literals[0] was the alphabetically-first child, a latent bug
    // that could not fire before the first stage certification.)
    const aggregateLiteral = literals.find(
      (l) => l.work_item_id === aggregate.work_item_id,
    ) ?? null;
    if (!aggregateLiteral) {
      throw new Error(
        `cannot apply: no content-bound literal for the aggregate ${aggregate.work_item_id}`,
      );
    }
    const resultPath = path.join(
      ESTATE_ROOT,
      "generated",
      ".certify",
      `${stageId}.latest.json`,
    );
    const retainedResult = {
      ...result,
      literal_exit: aggregateLiteral,
      adversarial_or_fault_proof: aggregate.adversarial_or_fault_proof ?? [],
    };
    dispatchStageCertificationTransaction({
      latestPath: resultPath,
      retainedResult,
      dispatch: () => {
        if (statusAuthority(aggregate).status === "verified") {
          // Re-certification after the aggregate's declared child/evidence set
          // changes does not manufacture a second status transition. Replace
          // the stable retained certification result and exact binding together.
          applyVerifiedAggregateRecertification({
            aggregateWorkItemId: aggregate.work_item_id,
            aggregatePath: path.join(ESTATE_ROOT, aggregate.file),
            certificationPath: path.join(
              ESTATE_ROOT,
              "evidence",
              `${aggregate.work_item_id}.certification.v1.json`,
            ),
            retainedResult,
            validateInput: () => {
              const current = currentStageCertificationInput(stageId);
              const defects = validateStageCertificationInputStability(
                initialInput,
                current,
                { phase: "verified-recertification" },
              );
              if (defects.length > 0) throw new Error(defects.join(" | "));
            },
          });
          process.stdout.write(
            `${aggregate.work_item_id} is already verified; refreshed content-bound certification recorded with no status transition\n`,
          );
        } else {
          execFileSync("node", [
            "internal-docs/implementation/tools/transition.mjs",
            aggregate.work_item_id,
            "verified",
            "--result",
            resultPath,
            "--apply",
          ], { cwd: REPO_ROOT, stdio: "inherit" });
        }
      },
    });
  }

  process.stdout.write(
    `certify ${stageId}: ${children.length} child(ren), ${literals.length} content-bound literal(s), ${checks.length} focused check(s)\n`,
  );
  process.exit(report(`certify-stage:${stageId}`, findings));
}

if (import.meta.url === `file://${process.argv[1]}`) main();
