#!/usr/bin/env node
// Regenerate the machine-local implementation-program projection.
//
// The output is intentionally gitignored. The master guide owns sequencing,
// work-item records own cut status, and committed stage-exit artifacts own
// stage verification. This script only projects those owners into one local
// session-orientation file; it grants nothing and closes no stage.
import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { execFileSync } from "node:child_process";
import { fileURLToPath } from "node:url";

export const REPO_ROOT = path.resolve(
  path.dirname(fileURLToPath(import.meta.url)),
  "..",
);
export const STATE_FILE = "internal-docs/implementation/program-state.json";
export const GUIDE_FILE =
  "internal-docs/implementation/ioi-target-end-state-master-implementation-guide.md";
export const WORK_ITEM_DIR = "docs/architecture/_meta/work-items";
export const M0_EXIT_FILE =
  "docs/evidence/m0-program-control/m0-exit-report.json";
export const M0_LITERAL_EXIT_FILE =
  "docs/evidence/implementation-plan-reconciliation/m0-exit.v1.txt";
export const M0_EVIDENCE_FILES = [
  M0_EXIT_FILE,
  M0_LITERAL_EXIT_FILE,
  "docs/evidence/m0-program-control/program-evidence-index.json",
  "docs/evidence/m0-program-control/blocker-ledger.json",
];
export const P0_OWNER_WORK_ITEM_ID = "m5-p0-readiness-verifier";

const WORK_ITEM_FORMAT = "ioi.program.work_item.v1";
const ONGOING_WORK_ITEM_STATUSES = new Set(["active", "evidence_ready"]);
const WORK_ITEM_STATUSES = new Set([
  "proposed",
  "scoped",
  ...ONGOING_WORK_ITEM_STATUSES,
  "verified",
  "blocked",
  "superseded",
  "rejected",
]);
const ISO_DATE = /^\d{4}-\d{2}-\d{2}$/u;

const fail = (message) => {
  throw new Error(message);
};

const readJson = (repoRoot, relativePath) =>
  JSON.parse(fs.readFileSync(path.join(repoRoot, relativePath), "utf8"));

const runGit = (repoRoot, args) =>
  execFileSync("git", args, {
    cwd: repoRoot,
    encoding: "utf8",
    stdio: ["ignore", "pipe", "pipe"],
  }).trim();

const stableValue = (value) => {
  if (Array.isArray(value)) {
    return value.map(stableValue);
  }
  if (value !== null && typeof value === "object") {
    return Object.fromEntries(
      Object.keys(value)
        .sort()
        .map((key) => [key, stableValue(value[key])]),
    );
  }
  return value;
};

export const stableJson = (value) => JSON.stringify(stableValue(value));

const sha256 = (value) =>
  crypto.createHash("sha256").update(value).digest("hex");

export const readM0LiteralExit = (repoRoot = REPO_ROOT) => {
  const log = fs.readFileSync(
    path.join(repoRoot, M0_LITERAL_EXIT_FILE),
    "utf8",
  );
  const literalValues = [...log.matchAll(/^M0_EXIT=(.*)$/gmu)].map(
    (match) => match[1],
  );
  if (literalValues.length !== 1 || literalValues[0] !== "0") {
    fail(`${M0_LITERAL_EXIT_FILE} must contain exactly one literal M0_EXIT=0`);
  }
  const artifactRefs = [...log.matchAll(/^ARTIFACT=(.*)$/gmu)].map(
    (match) => match[1],
  );
  if (artifactRefs.length !== 1 || artifactRefs[0] !== M0_EXIT_FILE) {
    fail(`${M0_LITERAL_EXIT_FILE} must bind ${M0_EXIT_FILE}`);
  }
  const declaredHashes = [
    ...log.matchAll(/^ARTIFACT_SHA256=([0-9a-f]{64})$/gmu),
  ].map((match) => match[1]);
  const artifactSha256 = sha256(
    fs.readFileSync(path.join(repoRoot, M0_EXIT_FILE)),
  );
  if (declaredHashes.length !== 1 || declaredHashes[0] !== artifactSha256) {
    fail(
      `${M0_LITERAL_EXIT_FILE} does not bind the current M0 exit-report bytes`,
    );
  }
  return {
    ref: M0_LITERAL_EXIT_FILE,
    literal: "M0_EXIT=0",
    artifact_ref: M0_EXIT_FILE,
    artifact_sha256: artifactSha256,
  };
};

const compareText = (left, right) => {
  if (left === right) {
    return 0;
  }
  return left < right ? -1 : 1;
};

const validateWorkItem = (record, source) => {
  if (record?.evidence_format !== WORK_ITEM_FORMAT) {
    fail(`${source} is not an ${WORK_ITEM_FORMAT} record`);
  }
  if (
    typeof record.work_item_id !== "string" ||
    record.work_item_id.length === 0
  ) {
    fail(`${source} has no work_item_id`);
  }
  if (!/^M(?:[0-9]|1[0-4])$/u.test(record.stage_id ?? "")) {
    fail(`${source} has invalid stage_id ${record.stage_id}`);
  }
  if (!WORK_ITEM_STATUSES.has(record.status)) {
    fail(`${source} has invalid status ${record.status}`);
  }
};

export const readGuideStages = (repoRoot = REPO_ROOT) => {
  const guidePath = path.join(repoRoot, GUIDE_FILE);
  if (!fs.existsSync(guidePath)) {
    fail(
      `${GUIDE_FILE} is required to regenerate program state; restore the machine-local implementation estate first`,
    );
  }
  const guide = fs.readFileSync(guidePath, "utf8");
  const stages = [];
  const headingPattern = /^### (M(?:[0-9]|1[0-4])) — (.+)$/gmu;
  for (const match of guide.matchAll(headingPattern)) {
    stages.push({ stage_id: match[1], title: match[2].trim() });
  }
  const expected = Array.from({ length: 15 }, (_, index) => `M${index}`);
  const actual = stages.map((stage) => stage.stage_id);
  if (JSON.stringify(actual) !== JSON.stringify(expected)) {
    fail(
      `${GUIDE_FILE} must contain exactly one M0-M14 stage heading in order (got ${actual.join(", ") || "none"})`,
    );
  }
  return stages;
};

const readWorkspaceWorkItems = (repoRoot) => {
  const absoluteDir = path.join(repoRoot, WORK_ITEM_DIR);
  if (!fs.existsSync(absoluteDir)) {
    return [];
  }
  const entries = fs
    .readdirSync(absoluteDir, { withFileTypes: true })
    .filter((entry) => entry.isFile() && entry.name.endsWith(".v1.json"))
    .map((entry) => entry.name)
    .sort();
  return entries.map((name) => {
    const relativePath = `${WORK_ITEM_DIR}/${name}`;
    const record = readJson(repoRoot, relativePath);
    validateWorkItem(record, relativePath);
    return {
      kind: "workspace",
      label: "workspace",
      path: relativePath,
      record,
    };
  });
};

const listConcreteRefs = (repoRoot) => {
  const output = runGit(repoRoot, [
    "for-each-ref",
    "--format=%(refname:short)%09%(objectname)%09%(symref)",
    "refs/heads",
    "refs/remotes/origin",
  ]);
  if (output.length === 0) {
    return [];
  }
  return output
    .split("\n")
    .map((line) => {
      const [ref, commit, symbolicTarget = ""] = line.split("\t");
      return { ref, commit, symbolicTarget };
    })
    .filter(({ symbolicTarget }) => symbolicTarget.length === 0)
    .sort((left, right) => compareText(left.ref, right.ref));
};

const readRefWorkItems = (repoRoot, refInfo) => {
  let names = "";
  try {
    names = runGit(repoRoot, [
      "ls-tree",
      "-r",
      "--name-only",
      refInfo.ref,
      "--",
      WORK_ITEM_DIR,
    ]);
  } catch {
    return [];
  }
  return names
    .split("\n")
    .filter((name) => name.endsWith(".v1.json"))
    .sort()
    .map((relativePath) => {
      const source = `${refInfo.ref}:${relativePath}`;
      let record;
      try {
        record = JSON.parse(
          runGit(repoRoot, ["show", `${refInfo.ref}:${relativePath}`]),
        );
      } catch (error) {
        fail(`cannot read ${source}: ${error.message}`);
      }
      validateWorkItem(record, source);
      return {
        kind: "ref",
        label: refInfo.ref,
        commit: refInfo.commit,
        path: relativePath,
        record,
      };
    });
};

const normalizedBranch = (ref) =>
  ref.startsWith("origin/") ? ref.slice("origin/".length) : ref;

const isStrictAncestorCommit = (repoRoot, ancestor, descendant) => {
  if (ancestor === descendant) {
    return false;
  }
  try {
    execFileSync("git", ["merge-base", "--is-ancestor", ancestor, descendant], {
      cwd: repoRoot,
      stdio: "ignore",
    });
    return true;
  } catch {
    return false;
  }
};

export const discoverWorkItems = (repoRoot = REPO_ROOT) => {
  const workspace = readWorkspaceWorkItems(repoRoot);
  const refs = listConcreteRefs(repoRoot);
  const refGroups = refs.map((refInfo) => ({
    kind: "ref",
    label: refInfo.ref,
    entries: readRefWorkItems(repoRoot, refInfo),
  }));
  const refRecords = refGroups.flatMap(({ entries }) => entries);
  const ongoingOccurrences = [...workspace, ...refRecords].filter(
    ({ record }) => ONGOING_WORK_ITEM_STATUSES.has(record.status),
  );
  const ongoingById = new Map();
  for (const occurrence of ongoingOccurrences) {
    const entries = ongoingById.get(occurrence.record.work_item_id) ?? [];
    entries.push(occurrence);
    ongoingById.set(occurrence.record.work_item_id, entries);
  }
  const currentCuts = [...ongoingById.entries()]
    .sort(([leftId], [rightId]) => compareText(leftId, rightId))
    .map(([currentWorkItemId, currentSources]) => {
      const currentVariants = new Set(
        currentSources.map(({ record }) => stableJson(record)),
      );
      if (currentVariants.size !== 1) {
        fail(
          `ongoing work item ${currentWorkItemId} has conflicting record bodies across the workspace and refs`,
        );
      }
      const currentRefSources = currentSources.filter(
        ({ kind }) => kind === "ref",
      );
      if (currentRefSources.length === 0) {
        fail(
          `ongoing work item ${currentWorkItemId} is not discoverable from a local or origin ref`,
        );
      }
      // Keep the nearest ref tips that carry this exact status transaction.
      // Descendant branches inherit unchanged records; they must not reassign
      // an ongoing cut away from the branch where that record first appears.
      const currentOriginRefSources = currentRefSources.filter(
        (source) =>
          !currentRefSources.some((candidate) =>
            isStrictAncestorCommit(repoRoot, candidate.commit, source.commit),
          ),
      );
      const branches = [
        ...new Set(
          currentOriginRefSources.map(({ label }) => normalizedBranch(label)),
        ),
      ].sort();
      if (branches.length !== 1) {
        fail(
          `ongoing work item ${currentWorkItemId} is exposed by ambiguous branch names: ${branches.join(", ")}`,
        );
      }
      const sourceRefs = [
        ...new Set(currentOriginRefSources.map(({ label }) => label)),
      ].sort();
      const sourceCommits = Object.fromEntries(
        sourceRefs.map((ref) => [
          ref,
          currentOriginRefSources.find(({ label }) => label === ref).commit,
        ]),
      );
      const currentRecord = currentSources[0].record;
      return {
        record: currentRecord,
        branch: branches[0],
        source_refs: sourceRefs,
        source_commits: sourceCommits,
        record_sha256: sha256(stableJson(currentRecord)),
      };
    });

  // Prefer the most complete committed status layer visible locally. The
  // workspace wins an equal-count tie so an in-transaction regeneration sees
  // newly authored records; a main checkout that predates the status layer can
  // still orient through the reconciliation branch once that work is
  // committed. Feature-only ongoing records are then added without importing
  // unrelated feature-branch status copies.
  const statusLayerCandidates = [
    { kind: "workspace", label: "workspace", entries: workspace },
    ...refGroups,
  ].filter(({ entries }) => entries.length > 0);
  statusLayerCandidates.sort(
    (left, right) =>
      right.entries.length - left.entries.length ||
      (left.kind === "workspace" ? -1 : right.kind === "workspace" ? 1 : 0) ||
      (left.label.startsWith("origin/")
        ? 1
        : right.label.startsWith("origin/")
          ? -1
          : 0) ||
      left.label.localeCompare(right.label),
  );
  if (statusLayerCandidates.length === 0) {
    fail(
      "no work-item status layer is visible in the workspace or local/origin refs",
    );
  }
  const statusLayer = statusLayerCandidates[0];
  const projectedById = new Map(
    statusLayer.entries.map((entry) => [entry.record.work_item_id, entry]),
  );
  for (const current of currentCuts) {
    if (projectedById.has(current.record.work_item_id)) {
      continue;
    }
    const currentRefSource = ongoingById
      .get(current.record.work_item_id)
      .find(({ kind }) => kind === "ref");
    projectedById.set(current.record.work_item_id, {
      ...currentRefSource,
      path: currentRefSource.path,
    });
  }
  const projected = [...projectedById.values()].sort((left, right) => {
    const leftStage = Number(left.record.stage_id.slice(1));
    const rightStage = Number(right.record.stage_id.slice(1));
    return (
      leftStage - rightStage ||
      compareText(left.record.work_item_id, right.record.work_item_id)
    );
  });

  return {
    current_cuts: currentCuts,
    status_layer: {
      kind: statusLayer.kind,
      label: statusLayer.label,
      record_count: statusLayer.entries.length,
    },
    projected,
    workspace,
  };
};

const parseArgs = (argv) => {
  let asOf = null;
  for (let index = 0; index < argv.length; index += 1) {
    if (argv[index] === "--as-of") {
      asOf = argv[index + 1] ?? null;
      index += 1;
      continue;
    }
    fail(`unknown argument: ${argv[index]}`);
  }
  if (asOf !== null && !ISO_DATE.test(asOf)) {
    fail(`--as-of must be YYYY-MM-DD (got ${asOf})`);
  }
  return { asOf };
};

const deriveAsOfDate = (requestedDate, m0Exit, discovery) => {
  if (requestedDate !== null) {
    return requestedDate;
  }
  const dates = [
    m0Exit.as_of_date,
    ...discovery.projected.map(({ record }) => record.last_status_transaction),
  ].filter((date) => typeof date === "string" && ISO_DATE.test(date));
  if (dates.length === 0) {
    fail("cannot derive an as-of date; pass --as-of YYYY-MM-DD");
  }
  return dates.sort().at(-1);
};

const locateMasterRef = (repoRoot) => {
  for (const ref of ["origin/master", "master"]) {
    try {
      return { ref, commit: runGit(repoRoot, ["rev-parse", ref]) };
    } catch {
      // Try the next conventional master ref.
    }
  }
  fail("cannot resolve origin/master or master");
};

const projectWorkItemRefs = (discovery, stageId) =>
  discovery.projected
    .filter(({ record }) => record.stage_id === stageId)
    .map(({ kind, label, path: recordPath, record }) => ({
      work_item_id: record.work_item_id,
      status: record.status,
      record_ref: kind === "workspace" ? recordPath : `${label}:${recordPath}`,
    }));

export const buildProgramState = ({
  repoRoot = REPO_ROOT,
  asOf = null,
} = {}) => {
  const guideStages = readGuideStages(repoRoot);
  const m0Exit = readJson(repoRoot, M0_EXIT_FILE);
  if (m0Exit.evidence_format !== "ioi.m0.exit_report.v1") {
    fail(`${M0_EXIT_FILE} has an unknown evidence_format`);
  }
  if (m0Exit.m0_exit_state !== "verified") {
    fail(`${M0_EXIT_FILE} does not carry the committed M0 verified exit proof`);
  }
  const m0LiteralExit = readM0LiteralExit(repoRoot);
  for (const evidencePath of M0_EVIDENCE_FILES) {
    if (!fs.existsSync(path.join(repoRoot, evidencePath))) {
      fail(`M0 evidence path does not exist: ${evidencePath}`);
    }
  }

  const discovery = discoverWorkItems(repoRoot);
  const currentRecords = discovery.current_cuts.map(({ record }) => record);
  const p0Owner = discovery.workspace.find(
    ({ record }) => record.work_item_id === P0_OWNER_WORK_ITEM_ID,
  )?.record;
  if (p0Owner === undefined) {
    fail(`P0 owner record ${P0_OWNER_WORK_ITEM_ID} is missing`);
  }
  if (
    p0Owner.stage_id !== "M5" ||
    !["proposed", "scoped"].includes(p0Owner.status)
  ) {
    fail(
      `P0 owner ${P0_OWNER_WORK_ITEM_ID} must be a proposed/scoped M5 work item`,
    );
  }
  const master = locateMasterRef(repoRoot);
  const asOfDate = deriveAsOfDate(asOf, m0Exit, discovery);

  const stages = guideStages.map(({ stage_id: stageId, title }) => {
    const stageCurrentRecords = currentRecords.filter(
      (record) => record.stage_id === stageId,
    );
    let state = "pending";
    let statusBasis = {
      kind: "no_stage_exit_proof",
      note: "Work-item status alone does not verify a stage.",
    };
    const evidence = [];
    if (stageId === "M0") {
      state = "verified";
      statusBasis = {
        kind: "stage_exit_proof",
        ref: M0_EXIT_FILE,
        literal_exit: m0LiteralExit,
      };
      evidence.push(...M0_EVIDENCE_FILES);
    } else if (stageCurrentRecords.length > 0) {
      state = stageCurrentRecords.some((record) => record.status === "active")
        ? "active"
        : "evidence_ready";
      statusBasis = {
        kind: "current_work_items",
        work_items: stageCurrentRecords.map((record) => ({
          work_item_id: record.work_item_id,
          status: record.status,
        })),
      };
    }
    const stage = {
      stage_id: stageId,
      title,
      state,
      status_basis: statusBasis,
      work_item_refs: projectWorkItemRefs(discovery, stageId),
    };
    if (evidence.length > 0) {
      stage.evidence = evidence;
      stage.cross_check = {
        m0_exit_state: m0Exit.m0_exit_state,
        literal_exit: m0LiteralExit.literal,
        literal_exit_artifact_sha256: m0LiteralExit.artifact_sha256,
        as_of: m0Exit.as_of_date,
        architecture_or_production_capability_closure:
          m0Exit.architecture_or_production_capability_closure,
      };
      stage.nonclaims = m0Exit.nonclaims;
    }
    return stage;
  });
  for (const currentRecord of currentRecords) {
    const currentStageIndex = Number(currentRecord.stage_id.slice(1));
    if (
      currentStageIndex > 0 &&
      stages[currentStageIndex - 1]?.state !== "verified"
    ) {
      fail(
        `ongoing work item ${currentRecord.work_item_id} belongs to ${currentRecord.stage_id}, but predecessor M${currentStageIndex - 1} lacks a committed stage-exit proof`,
      );
    }
  }

  return {
    evidence_format: "ioi.program.live_state.v1",
    authority: GUIDE_FILE,
    status_owners: {
      work_items: `${WORK_ITEM_DIR}/*.v1.json`,
      selected_status_layer: discovery.status_layer,
      stage_exit_proofs:
        "committed evidence artifacts named by each verified stage",
      projection: STATE_FILE,
    },
    rule: "This is a derived, read-only machine-local projection, not a second sequencer. It grants nothing and closes nothing. The master guide owns M0-M14 sequence and exit definitions; work-item records own cut status; a stage is verified only by its committed stage-exit proof. Development-workflow review evidence is an unsigned hash chain with honest nonclaims. Product authority remains wallet-network grants, sealed intents, and receipts.",
    as_of: {
      date: asOfDate,
      master_ref: master.ref,
      master_commit: master.commit,
      derived_from: [
        GUIDE_FILE,
        `${WORK_ITEM_DIR}/*.v1.json`,
        M0_EXIT_FILE,
        M0_LITERAL_EXIT_FILE,
        `selected status layer: ${discovery.status_layer.label} (${discovery.status_layer.record_count} records)`,
        "local and origin git refs (current work-item discovery)",
      ],
    },
    stages,
    current_cuts: discovery.current_cuts.map((current) => {
      const currentRecord = current.record;
      return {
        work_item_id: currentRecord.work_item_id,
        stage_id: currentRecord.stage_id,
        status: currentRecord.status,
        objective: currentRecord.objective,
        pr: currentRecord.pr ?? null,
        branch: current.branch,
        record_sha256: current.record_sha256,
        source_refs: current.source_refs,
        source_commits: current.source_commits,
        evidence_refs: currentRecord.evidence_refs ?? [],
        remaining_nonclaims: currentRecord.remaining_nonclaims ?? [],
        last_status_transaction: currentRecord.last_status_transaction,
      };
    }),
    p0_protocol: {
      state: "planned_not_activated",
      owner_work_item_id: P0_OWNER_WORK_ITEM_ID,
      readiness_prerequisite_stages: ["M3", "M4", "M5"],
      direct_path_preservation_required: true,
      claim_gate_stage_id: "M9",
      note: "This projection claims no P0 readiness manifest, cohort evidence, or activation. The named M5 work item owns the future readiness verifier and direct-path preservation proof; claim-bearing qualification remains gated at M9.",
    },
    next_work_item_ids: discovery.projected
      .filter(({ record }) =>
        ["active", "evidence_ready", "proposed", "scoped"].includes(
          record.status,
        ),
      )
      .map(({ record }) => record.work_item_id),
    session_start_ritual: [
      `Regenerate with node scripts/generate-program-state.mjs and validate with node internal-docs/implementation/check-program-state.mjs.`,
      "Read every current work-item record from its named ref, then read each master-guide stage and exit definition.",
      "Treat verified work items as cut evidence only; never infer stage verification without the committed stage-exit proof.",
      "Keep multi-node, federation, and claim-bearing cohort language gated to their M9-M13 owners.",
    ],
  };
};

export const writeProgramState = ({
  repoRoot = REPO_ROOT,
  asOf = null,
} = {}) => {
  const state = buildProgramState({ repoRoot, asOf });
  const outputPath = path.join(repoRoot, STATE_FILE);
  fs.mkdirSync(path.dirname(outputPath), { recursive: true });
  fs.writeFileSync(outputPath, `${JSON.stringify(state, null, 2)}\n`);
  return state;
};

const isMain =
  process.argv[1] !== undefined &&
  path.resolve(process.argv[1]) === fileURLToPath(import.meta.url);

if (isMain) {
  try {
    const { asOf } = parseArgs(process.argv.slice(2));
    const state = writeProgramState({ asOf });
    const currentSummary =
      state.current_cuts.length === 0
        ? "no ongoing work items"
        : `${state.current_cuts.length} current work item(s): ${state.current_cuts
            .map((cut) => `${cut.work_item_id} (${cut.status})`)
            .join(", ")}`;
    process.stdout.write(
      `program-state generated: ${STATE_FILE}; ${state.stages.length} stages; ${currentSummary}; as of ${state.as_of.date}.\n`,
    );
  } catch (error) {
    process.stderr.write(`program-state generation failed: ${error.message}\n`);
    process.exit(1);
  }
}
