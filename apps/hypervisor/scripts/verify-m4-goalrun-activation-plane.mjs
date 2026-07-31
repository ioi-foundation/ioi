#!/usr/bin/env node

// Focused M4 Goal Chat → GoalRun activation crossing.
//
// Runs only against a throwaway daemon registry. It proves that ordinary text is retained as an
// ioi.ai draft first; only an explicit user review over the exact draft commitment creates one
// GoalRun; retries converge; changed idempotency material, stale review, and source substitution
// fail before GoalRun persistence; and restart reconstructs the activation, receipts, root, head,
// and GoalRun binding from daemon-owned storage.

import {
  lstatSync,
  mkdtempSync,
  mkdirSync,
  readFileSync,
  readlinkSync,
  readdirSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { createHash } from "node:crypto";
import { spawnSync } from "node:child_process";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import Ajv2020 from "ajv/dist/2020.js";
import addFormats from "ajv-formats";
import {
  DAEMON_BINARY,
  isIsolatedDaemonLogName,
  sanitizedVerifierBaseEnv,
  startIsolatedPlane,
} from "./lib/isolated-daemon.mjs";
import { startRealWalletNetworkPrincipalAuthorityFixture } from "./lib/wallet-network-principal-authority-fixture.mjs";
import { mintApprovalGrant } from "../../../scripts/lib/mint-approval-grant.mjs";

const DEPLOYMENT_AUTHORITY_REF = "domain://acme-host";
const GOAL_RUN_CREATE_SCOPE = "scope:goal.run.create";

const HERE = dirname(fileURLToPath(import.meta.url));
const REPO = join(HERE, "..", "..", "..");
const activationSchema = JSON.parse(
  readFileSync(
    join(
      REPO,
      "docs",
      "architecture",
      "_meta",
      "schemas",
      "goal-run-activation.v1.schema.json",
    ),
    "utf8",
  ),
);
const activationReceiptSchema = JSON.parse(
  readFileSync(
    join(
      REPO,
      "docs",
      "architecture",
      "_meta",
      "schemas",
      "goal-run-activation-receipt.v1.schema.json",
    ),
    "utf8",
  ),
);
const goalRunSchema = JSON.parse(
  readFileSync(
    join(REPO, "docs", "architecture", "_meta", "schemas", "goal-run.v1.schema.json"),
    "utf8",
  ),
);
const admittedStateSchema = JSON.parse(
  readFileSync(
    join(
      REPO,
      "docs",
      "architecture",
      "_meta",
      "schemas",
      "goal-run-admitted-state.v1.schema.json",
    ),
    "utf8",
  ),
);
const executionCeilingSchema = JSON.parse(
  readFileSync(
    join(
      REPO,
      "docs",
      "architecture",
      "_meta",
      "schemas",
      "goal-run-execution-ceiling.v1.schema.json",
    ),
    "utf8",
  ),
);
const profileResolutionReceiptSchema = JSON.parse(
  readFileSync(
    join(
      REPO,
      "docs",
      "architecture",
      "_meta",
      "schemas",
      "goal-run-profile-resolution-receipt.v1.schema.json",
    ),
    "utf8",
  ),
);
const ajv = new Ajv2020({ allErrors: true, strict: false });
addFormats(ajv);
const validateActivation = ajv.compile(activationSchema);
const validateActivationReceipt = ajv.compile(activationReceiptSchema);
const validateGoalRun = ajv.compile(goalRunSchema);
const validateAdmittedState = ajv.compile(admittedStateSchema);
const validateExecutionCeiling = ajv.compile(executionCeilingSchema);
const validateProfileResolutionReceipt = ajv.compile(profileResolutionReceiptSchema);
const validateReceiptObligation = ajv.compile(
  goalRunSchema.properties.receipt_obligations.items,
);

function canonicalJson(value) {
  if (value === null || typeof value !== "object") return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(",")}]`;
  return `{${Object.keys(value).sort().map((key) => `${JSON.stringify(key)}:${canonicalJson(value[key])}`).join(",")}}`;
}

function receiptRoot(record) {
  const material = structuredClone(record);
  delete material.receipt_root;
  return `sha256:${createHash("sha256").update(canonicalJson(material)).digest("hex")}`;
}

function admittedStateRoot(record) {
  const material = structuredClone(record);
  material.state_root = null;
  material.state_root_ref = null;
  return `sha256:${createHash("sha256").update(canonicalJson(material)).digest("hex")}`;
}

function executionCeilingHash(record) {
  const material = {
    domain: "ioi.goal-run-execution-ceiling-release-jcs-sha256.v1",
    schema_version: record.schema_version,
    goal_run_execution_ceiling_id: record.goal_run_execution_ceiling_id,
    owner_ref: record.owner_ref,
    max_total_invocations: record.max_total_invocations,
    max_parallel_invocations: record.max_parallel_invocations,
  };
  return `sha256:${createHash("sha256").update(canonicalJson(material)).digest("hex")}`;
}

function durableTreeByteSnapshot(root) {
  const metadataFields = (metadata) => ({
    inode: String(metadata.ino),
    mode: Number(metadata.mode),
    nlink: String(metadata.nlink),
    mtime_ns: String(metadata.mtimeNs),
    ctime_ns: String(metadata.ctimeNs),
  });
  const rootMetadata = lstatSync(root, { bigint: true });
  const rows = [["directory", "", metadataFields(rootMetadata)]];
  const walk = (directory, relative = "") => {
    for (const entry of readdirSync(directory, { withFileTypes: true })) {
      if (!relative && isIsolatedDaemonLogName(entry.name)) continue;
      const nextRelative = relative ? `${relative}/${entry.name}` : entry.name;
      const absolute = join(directory, entry.name);
      const metadata = lstatSync(absolute, { bigint: true });
      if (metadata.isSymbolicLink()) {
        rows.push(["symlink", nextRelative, {
          ...metadataFields(metadata),
          target: readlinkSync(absolute),
        }]);
      } else if (metadata.isDirectory()) {
        rows.push(["directory", nextRelative, metadataFields(metadata)]);
        walk(absolute, nextRelative);
      } else if (metadata.isFile()) {
        rows.push(["file", nextRelative, {
          ...metadataFields(metadata),
          size: String(metadata.size),
          bytes: readFileSync(absolute).toString("base64"),
        }]);
      } else rows.push(["non-regular", nextRelative, metadataFields(metadata)]);
    }
  };
  walk(root);
  return canonicalJson(
    rows.sort((left, right) => {
      const pathOrder = left[1].localeCompare(right[1]);
      return pathOrder || left[0].localeCompare(right[0]);
    }),
  );
}

function snapshotRoot(snapshot) {
  return `sha256:${createHash("sha256").update(snapshot).digest("hex")}`;
}

function buildCurrentDaemonBinary() {
  const result = spawnSync(
    "cargo",
    ["build", "--locked", "-p", "ioi-node", "--bin", "hypervisor-daemon"],
    {
      cwd: REPO,
      env: {
        ...CLEAN_BASE_ENV,
        CARGO_TARGET_DIR: join(REPO, "target"),
        CARGO_TERM_COLOR: "never",
        NO_COLOR: "1",
      },
      stdio: "inherit",
      timeout: 45 * 60 * 1000,
    },
  );
  if (result.error) {
    throw new Error(`current daemon build could not start: ${result.error.message}`);
  }
  if (result.status !== 0) {
    throw new Error(
      `current daemon build failed with ${result.signal || `exit ${result.status}`}`,
    );
  }
  const bytes = readFileSync(DAEMON_BINARY);
  return `sha256:${createHash("sha256").update(bytes).digest("hex")}`;
}

const dataDir = mkdtempSync(join(tmpdir(), "ioi-m4-goalrun-activation-"));
const faultDataDir = mkdtempSync(join(tmpdir(), "ioi-m4-goalrun-activation-fault-"));
const unknownReceiptDataDir = mkdtempSync(
  join(tmpdir(), "ioi-m4-goalrun-activation-unknown-receipt-"),
);
const checks = [];
const EXPECTED_CHECKS = 44;
const check = (name, pass, detail = "") => checks.push({ name, pass: Boolean(pass), detail });
const familyCount = (family, root = dataDir) => {
  try {
    return readdirSync(join(root, family)).filter((name) => name.endsWith(".json")).length;
  } catch {
    return 0;
  }
};

async function request(base, method, path, body, headers = {}) {
  const response = await fetch(`${base}${path}`, {
    method,
    headers: { "content-type": "application/json", ...headers },
    body: body === undefined ? undefined : JSON.stringify(body),
  });
  return { status: response.status, body: await response.json().catch(() => ({})) };
}

function activationId(record) {
  return String(record?.activation_id || "").replace("goal-run-activation://", "");
}

function tamperGoalDraft(sourceRef) {
  const dir = join(dataDir, "ioi-ai-goal-drafts");
  const file = readdirSync(dir)
    .filter((name) => name.endsWith(".json"))
    .map((name) => join(dir, name))
    .find((path) => JSON.parse(readFileSync(path, "utf8")).draft_intent_ref === sourceRef);
  if (!file) throw new Error(`source draft ${sourceRef} not found`);
  const record = JSON.parse(readFileSync(file, "utf8"));
  record.goal_text = `${record.goal_text} [substituted after review]`;
  writeFileSync(file, `${JSON.stringify(record, null, 2)}\n`);
}

function tamperAuthorityDecision(activationRef) {
  const dir = join(dataDir, "goal-run-activation-authority-decisions");
  const file = readdirSync(dir)
    .filter((name) => name.endsWith(".json"))
    .map((name) => join(dir, name))
    .find((path) => JSON.parse(readFileSync(path, "utf8")).activation_ref === activationRef);
  if (!file) throw new Error(`authority decision for ${activationRef} not found`);
  const record = JSON.parse(readFileSync(file, "utf8"));
  record.principal_ref = "user://substituted-principal";
  writeFileSync(file, `${JSON.stringify(record, null, 2)}\n`);
}

function recordPath(family, predicate, root = dataDir) {
  const dir = join(root, family);
  return readdirSync(dir)
    .filter((name) => name.endsWith(".json"))
    .map((name) => join(dir, name))
    .find((path) => predicate(JSON.parse(readFileSync(path, "utf8"))));
}

function replaceRecord(path, mutate) {
  const original = readFileSync(path);
  const record = JSON.parse(original.toString("utf8"));
  mutate(record);
  writeFileSync(path, `${JSON.stringify(record, null, 2)}\n`);
  return () => writeFileSync(path, original);
}

let plane = null;
let authorityResolver = null;
const CLEAN_BASE_ENV = sanitizedVerifierBaseEnv();

async function startActivationPlane(options = {}) {
  if (!authorityResolver) throw new Error("wallet.network authority fixture is not started");
  return startIsolatedPlane({
    ...options,
    baseEnv: CLEAN_BASE_ENV,
    env: {
      ...authorityResolver.env,
      IOI_HYPERVISOR_AUTHORITY_PRINCIPAL_REF: DEPLOYMENT_AUTHORITY_REF,
      ...(options.env || {}),
    },
  });
}

async function mintActivationGrant(challenge) {
  const approval = challenge?.body?.error?.approval;
  if (!approval?.policy_hash || !approval?.request_hash) return null;
  return authorityResolver.mintRecorded(
    DEPLOYMENT_AUTHORITY_REF,
    approval.policy_hash,
    approval.request_hash,
    GOAL_RUN_CREATE_SCOPE,
  );
}

try {
  const builtDaemonRoot = buildCurrentDaemonBinary();
  console.log(`M4_GOALRUN_ACTIVATION_DAEMON_BINARY_SHA256=${builtDaemonRoot}`);
  const legacyResult = {
    ...JSON.parse(
      readFileSync(
        join(
          REPO,
          "docs",
          "architecture",
          "_meta",
          "schemas",
          "fixtures",
          "work-result-v1",
          "positive-minimal.json",
        ),
        "utf8",
      ),
    ),
    work_result_id: "work-result://m3/legacy-migration-proof",
    work_subject_ref: "goal://m3/legacy-migration-proof",
    goal_run_ref: "goal://m3/legacy-migration-proof",
  };
  mkdirSync(join(dataDir, "work-results"), { recursive: true });
  writeFileSync(
    join(
      dataDir,
      "work-results",
      `${legacyResult.work_result_id.replace(/[^a-zA-Z0-9_-]/gu, "_")}.json`,
    ),
    `${JSON.stringify(legacyResult, null, 2)}\n`,
    { flag: "wx" },
  );
  authorityResolver = await startRealWalletNetworkPrincipalAuthorityFixture({
    baseEnv: CLEAN_BASE_ENV,
  });
  plane = await startActivationPlane({ dataDir });
  if (!plane) {
    console.error("BLOCKED: build target/debug/hypervisor-daemon first");
    process.exitCode = 2;
  } else {
    const migratedLegacyResults = await request(
      plane.daemonUrl,
      "GET",
      "/v1/hypervisor/work-results",
    );
    check(
      "startup folds M3 legacy WorkResult bytes into the canonical registry without deleting history",
      migratedLegacyResults.body?.work_results?.some(
        (entry) => entry.work_result_id === legacyResult.work_result_id,
      ) &&
        familyCount("work-result-registry") === 1 &&
        familyCount("work-results") === 1,
      `canonical=${familyCount("work-result-registry")} legacy=${familyCount("work-results")}`,
    );
    const draftRequest = {
      schema_version: "ioi.goal-run-activation-draft-request.v1",
      goal_text: "Research the bounded hosted OutcomeRoom admission contract",
      constraints: ["retain negative and inconclusive evidence"],
      project_ref: null,
      result_profile: "research",
      idempotency_key: "m4-goal-chat-positive-activation-v1",
    };

    const drafted = await request(
      plane.daemonUrl,
      "POST",
      "/v1/goal-orchestration/goal-run-activations",
      draftRequest,
    );
    const activation = drafted.body.activation;
    const id = activationId(activation);
    const directOriginMutationBefore = durableTreeByteSnapshot(dataDir);
    const directOriginBypass = await request(
      plane.daemonUrl,
      "POST",
      "/v1/goal-orchestration/goal-runs",
      {
        goal: "Bypass the explicit activation crossing",
        origin_surface: "ioi_goal_chat",
        activation_evidence: { claimed: true },
      },
    );
    const directOriginMutationAfter = durableTreeByteSnapshot(dataDir);
    check(
      "draft persists typed ioi_goal_draft and an origin tag cannot bypass activation",
      drafted.status === 201 &&
        activation?.schema_version === "ioi.goal-run-activation.v1" &&
        activation?.status === "draft" &&
        activation?.source_context?.source_kind === "ioi_goal_draft" &&
        activation?.admitted_goal_ref === null &&
        activation?.review_requirement === "explicit_user" &&
        directOriginBypass.status === 422 &&
        directOriginBypass.body?.error?.code === "goal_run_activation_required_for_origin" &&
        directOriginMutationAfter === directOriginMutationBefore,
      `draft=${drafted.status}/${drafted.body?.error?.code} bypass=${directOriginBypass.status}/${directOriginBypass.body?.error?.code} durable_tree=${snapshotRoot(directOriginMutationBefore)}->${snapshotRoot(directOriginMutationAfter)}`,
    );
    check(
      "draft activation conforms to the registered durable contract",
      validateActivation(activation),
      ajv.errorsText(validateActivation.errors),
    );
    check(
      "daemon resolves owner, source, and an immutable content-addressed profile closure",
      drafted.body.goal_draft?.user_ref === "user://local-operator" &&
        drafted.body.goal_draft?.draft_intent_ref === activation?.source_context?.source_ref &&
        activation?.requesting_principal_ref === "user://local-operator" &&
        /^goal-run-profile:\/\/generic-adaptive\/revision\/sha256:[0-9a-f]{64}$/u.test(
          String(activation?.requested_goal_run_profile_revision_ref || ""),
        ) &&
        /^sha256:[0-9a-f]{64}$/u.test(
          String(activation?.requested_goal_run_profile_content_hash || ""),
        ) &&
        /^orchestration-policy:\/\/bounded-goal-run-admission\/revision\/sha256:[0-9a-f]{64}$/u.test(
          String(drafted.body?.resolved_profile?.policy_ref || ""),
        ) &&
        /^harness-profile:\/\/daemon-resolved\//u.test(
          String(drafted.body?.resolved_profile?.component_ref || ""),
        ),
    );

    const profileInjection = await request(
      plane.daemonUrl,
      "POST",
      "/v1/goal-orchestration/goal-run-activations",
      {
        ...draftRequest,
        idempotency_key: "m4-goal-chat-profile-injection",
        requested_goal_run_profile_revision_ref: "goal-run-profile://caller/revision/9",
      },
    );
    check(
      "caller profile injection refuses before activation persistence",
      profileInjection.status === 400 &&
        profileInjection.body?.error?.code === "goal_run_activation_draft_request_invalid" &&
        familyCount("goal-run-activations") === 1,
      `${profileInjection.status}/${profileInjection.body?.error?.code}`,
    );

    const replayedDraft = await request(
      plane.daemonUrl,
      "POST",
      "/v1/goal-orchestration/goal-run-activations",
      draftRequest,
    );
    check(
      "same draft idempotency key and body converge",
      replayedDraft.status === 200 &&
        replayedDraft.body?.activation?.activation_id === activation?.activation_id &&
        replayedDraft.body?.activation_hash === drafted.body?.activation_hash &&
        familyCount("goal-run-activations") === 1,
      `${replayedDraft.status}/${replayedDraft.body?.error?.code}`,
    );

    const bodySwap = await request(
      plane.daemonUrl,
      "POST",
      "/v1/goal-orchestration/goal-run-activations",
      { ...draftRequest, goal_text: "Changed text under a reused key" },
    );
    check(
      "idempotency-key body substitution refuses before new source or GoalRun",
      bodySwap.status === 409 &&
        bodySwap.body?.error?.code === "goal_run_activation_idempotency_body_conflict" &&
        familyCount("goal-run-activations") === 1 &&
        familyCount("goal-runs") === 0,
      `${bodySwap.status}/${bodySwap.body?.error?.code}`,
    );

    const deniedReview = await request(
      plane.daemonUrl,
      "POST",
      `/v1/goal-orchestration/goal-run-activations/${id}/submit`,
      {
        schema_version: "ioi.goal-run-activation-submit-request.v1",
        expected_activation_hash: drafted.body.activation_hash,
        review_decision: "deny",
      },
    );
    check(
      "missing explicit approval cannot mint goal identity",
      deniedReview.status === 422 &&
        deniedReview.body?.error?.code ===
          "goal_run_activation_explicit_user_review_required" &&
        familyCount("goal-runs") === 0,
      `${deniedReview.status}/${deniedReview.body?.error?.code}`,
    );

    const staleReview = await request(
      plane.daemonUrl,
      "POST",
      `/v1/goal-orchestration/goal-run-activations/${id}/submit`,
      {
        schema_version: "ioi.goal-run-activation-submit-request.v1",
        expected_activation_hash: `sha256:${"f".repeat(64)}`,
        review_decision: "approve",
      },
    );
    check(
      "stale reviewed bytes refuse before GoalRun persistence",
      staleReview.status === 409 &&
        staleReview.body?.error?.code === "goal_run_activation_stale_draft" &&
        familyCount("goal-runs") === 0,
      `${staleReview.status}/${staleReview.body?.error?.code}`,
    );

    // Prove the source is resolved from durable bytes at submit time rather than trusted from the
    // request. This draft is intentionally left refused; a distinct key owns the positive lane.
    tamperGoalDraft(activation.source_context.source_ref);
    const substitutedSource = await request(
      plane.daemonUrl,
      "POST",
      `/v1/goal-orchestration/goal-run-activations/${id}/submit`,
      {
        schema_version: "ioi.goal-run-activation-submit-request.v1",
        expected_activation_hash: drafted.body.activation_hash,
        review_decision: "approve",
      },
    );
    check(
      "durable source substitution refuses before GoalRun persistence",
      substitutedSource.status === 409 &&
        substitutedSource.body?.error?.code ===
          "goal_run_activation_source_integrity_failure" &&
        familyCount("goal-runs") === 0,
      `${substitutedSource.status}/${substitutedSource.body?.error?.code}`,
    );

    const authorityDraft = await request(
      plane.daemonUrl,
      "POST",
      "/v1/goal-orchestration/goal-run-activations",
      { ...draftRequest, idempotency_key: "m4-goal-chat-authority-substitution" },
    );
    const authorityId = activationId(authorityDraft.body.activation);
    tamperAuthorityDecision(authorityDraft.body.activation.activation_id);
    const substitutedAuthority = await request(
      plane.daemonUrl,
      "POST",
      `/v1/goal-orchestration/goal-run-activations/${authorityId}/submit`,
      {
        schema_version: "ioi.goal-run-activation-submit-request.v1",
        expected_activation_hash: authorityDraft.body.activation_hash,
        review_decision: "approve",
      },
    );
    check(
      "daemon-resolved authority substitution refuses before GoalRun persistence",
      substitutedAuthority.status === 409 &&
        substitutedAuthority.body?.error?.code ===
          "goal_run_activation_authority_integrity_failure" &&
        familyCount("goal-runs") === 0,
      `${substitutedAuthority.status}/${substitutedAuthority.body?.error?.code}`,
    );

    const profileDraft = await request(
      plane.daemonUrl,
      "POST",
      "/v1/goal-orchestration/goal-run-activations",
      { ...draftRequest, idempotency_key: "m4-goal-chat-profile-missing" },
    );
    const profileId = activationId(profileDraft.body.activation);
    const profilePath = recordPath(
      "goal-run-profile-revisions",
      (record) => record.revision_ref === profileDraft.body?.resolved_profile?.revision_ref,
    );
    const profileBytes = readFileSync(profilePath);
    rmSync(profilePath);
    const missingProfile = await request(
      plane.daemonUrl,
      "POST",
      `/v1/goal-orchestration/goal-run-activations/${profileId}/submit`,
      {
        schema_version: "ioi.goal-run-activation-submit-request.v1",
        expected_activation_hash: profileDraft.body.activation_hash,
        review_decision: "approve",
      },
    );
    writeFileSync(profilePath, profileBytes);
    check(
      "missing exact GoalRunProfile release refuses before GoalRun admission",
      missingProfile.status === 409 &&
        missingProfile.body?.error?.code === "goal_run_activation_profile_missing" &&
        familyCount("goal-runs") === 0,
      `${missingProfile.status}/${missingProfile.body?.error?.code}`,
    );

    const tamperedProfileDraft = await request(
      plane.daemonUrl,
      "POST",
      "/v1/goal-orchestration/goal-run-activations",
      { ...draftRequest, idempotency_key: "m4-goal-chat-profile-tampered" },
    );
    const restoreProfile = replaceRecord(profilePath, (record) => {
      record.description = `${record.description} [tampered]`;
    });
    const tamperedProfile = await request(
      plane.daemonUrl,
      "POST",
      `/v1/goal-orchestration/goal-run-activations/${activationId(tamperedProfileDraft.body.activation)}/submit`,
      {
        schema_version: "ioi.goal-run-activation-submit-request.v1",
        expected_activation_hash: tamperedProfileDraft.body.activation_hash,
        review_decision: "approve",
      },
    );
    restoreProfile();
    check(
      "tampered GoalRunProfile bytes refuse their stale content address",
      tamperedProfile.status === 409 &&
        tamperedProfile.body?.error?.code ===
          "goal_run_activation_profile_integrity_failure" &&
        familyCount("goal-runs") === 0,
      `${tamperedProfile.status}/${tamperedProfile.body?.error?.code}`,
    );

    const positiveDraft = await request(
      plane.daemonUrl,
      "POST",
      "/v1/goal-orchestration/goal-run-activations",
      { ...draftRequest, idempotency_key: "m4-goal-chat-positive-activation-v2" },
    );
    const positiveId = activationId(positiveDraft.body.activation);
    const authorityChallenge = await request(
      plane.daemonUrl,
      "POST",
      `/v1/goal-orchestration/goal-run-activations/${positiveId}/submit`,
      {
        schema_version: "ioi.goal-run-activation-submit-request.v1",
        expected_activation_hash: positiveDraft.body.activation_hash,
        review_decision: "approve",
      },
    );
    check(
      "explicit review exposes a wallet-owned authority request before GoalRun admission",
      authorityChallenge.status === 403 &&
        authorityChallenge.body?.error?.code === "goal_run_activation_authority_required" &&
        authorityChallenge.body?.error?.required_scope === GOAL_RUN_CREATE_SCOPE &&
        /^sha256:[0-9a-f]{64}$/u.test(
          String(authorityChallenge.body?.error?.approval?.policy_hash || ""),
        ) &&
        /^sha256:[0-9a-f]{64}$/u.test(
          String(authorityChallenge.body?.error?.approval?.request_hash || ""),
        ) &&
        familyCount("goal-runs") === 0,
      `${authorityChallenge.status}/${authorityChallenge.body?.error?.code}`,
    );
    const expiredGrant = mintApprovalGrant({
      seed: "07".repeat(32),
      policyHash: authorityChallenge.body?.error?.approval?.policy_hash,
      requestHash: authorityChallenge.body?.error?.approval?.request_hash,
      audience: authorityResolver.capabilityAccountId,
      expiresAt: 1,
    });
    const expiredAuthority = await request(
      plane.daemonUrl,
      "POST",
      `/v1/goal-orchestration/goal-run-activations/${positiveId}/submit`,
      {
        schema_version: "ioi.goal-run-activation-submit-request.v1",
        expected_activation_hash: positiveDraft.body.activation_hash,
        review_decision: "approve",
        wallet_approval_grant: expiredGrant,
      },
    );
    check(
      "expired activation authority refuses before GoalRun admission",
      expiredAuthority.status === 403 &&
        expiredAuthority.body?.error?.code === "goal_run_activation_authority_required" &&
        familyCount("goal-runs") === 0,
      `${expiredAuthority.status}/${expiredAuthority.body?.error?.code}`,
    );
    const activationGrant = await mintActivationGrant(authorityChallenge);
    const admitted = await request(
      plane.daemonUrl,
      "POST",
      `/v1/goal-orchestration/goal-run-activations/${positiveId}/submit`,
      {
        schema_version: "ioi.goal-run-activation-submit-request.v1",
        expected_activation_hash: positiveDraft.body.activation_hash,
        review_decision: "approve",
        wallet_approval_grant: activationGrant,
      },
    );
    const goalRun = admitted.body.goal_run;
    const goalRunId = String(goalRun?.goal_ref || "").replace("goal://", "");
    check(
      "explicit exact-hash review admits one durable GoalRun",
      admitted.status === 201 &&
        admitted.body.activation?.status === "admitted" &&
        admitted.body.activation?.admitted_goal_ref === goalRun?.goal_ref &&
        goalRun?.origin_surface === "ioi_goal_chat" &&
        goalRun?.activation_ref === admitted.body.activation?.activation_id &&
        goalRun?.user_intent_ref === admitted.body.goal_draft?.draft_intent_ref &&
        goalRun?.owner_ref === "user://local-operator" &&
        admitted.body?.authority_decision?.admission_bearing === true &&
        /^wallet\.network:\/\/grant\/approval\/[0-9a-f]{64}$/u.test(
          String(admitted.body?.authority_decision?.grant_ref || ""),
        ) &&
        String(admitted.body?.authority_decision?.authority_admission_intent_ref || "").startsWith(
          "authority-admission-intents/",
        ) &&
        familyCount("goal-runs") === 1,
      `${admitted.status}/${admitted.body?.error?.code}`,
    );
    if (admitted.status !== 201 || !goalRun?.goal_ref) {
      throw new Error(
        `positive activation did not reach GoalRun admission: status=${admitted.status} code=${admitted.body?.error?.code || "none"} activation_status=${admitted.body?.activation?.status || "absent"} goal_ref_present=${Boolean(goalRun?.goal_ref)} response_keys=${Object.keys(admitted.body || {}).sort().slice(0, 32).map((key) => key.slice(0, 120)).join(",")}`,
      );
    }
    check(
      "admitted activation and GoalRun conform to their registered durable contracts",
      validateActivation(admitted.body.activation) && validateGoalRun(goalRun),
      `${ajv.errorsText(validateActivation.errors)} ${ajv.errorsText(validateGoalRun.errors)}`,
    );
    const executionCeiling = admitted.body?.goal_run_execution_ceiling;
    const profileResolutionReceipt = JSON.parse(
      readFileSync(
        join(dataDir, "goal-run-profile-resolution-receipts", `${goalRunId}.json`),
        "utf8",
      ),
    );
    check(
      "activation retains root, lifecycle head, exact zero-execution profile closure, and three receipt classes",
      /^agentgres:\/\/state-root\/goal-run\/[^/]+\/sha256:[0-9a-f]{64}$/u.test(
        String(goalRun?.admitted_state_root_ref || ""),
      ) &&
        /^sha256:/u.test(String(goalRun?.lifecycle_head || "")) &&
        /^goal-run-profile:\/\//u.test(String(goalRun?.goal_run_profile_revision_ref || "")) &&
        validateExecutionCeiling(executionCeiling) &&
        executionCeilingHash(executionCeiling) === executionCeiling?.content_hash &&
        executionCeiling?.max_total_invocations === 0 &&
        executionCeiling?.max_parallel_invocations === 0 &&
        goalRun?.goal_run_execution_ceiling_revision_ref === executionCeiling?.revision_ref &&
        goalRun?.goal_run_execution_ceiling_content_hash === executionCeiling?.content_hash &&
        goalRun?.declared_invocation_budget?.max_total_invocations === 0 &&
        goalRun?.declared_invocation_budget?.max_parallel_invocations === 0 &&
        goalRun?.admitted_override_set_ref === null &&
        goalRun?.admitted_override_set_hash === null &&
        validateProfileResolutionReceipt(profileResolutionReceipt) &&
        profileResolutionReceipt?.goal_run_execution_ceiling_revision_ref ===
          executionCeiling?.revision_ref &&
        profileResolutionReceipt?.goal_run_execution_ceiling_content_hash ===
          executionCeiling?.content_hash &&
        profileResolutionReceipt?.declared_invocation_budget?.max_total_invocations === 0 &&
        profileResolutionReceipt?.declared_invocation_budget?.max_parallel_invocations === 0 &&
        profileResolutionReceipt?.admitted_override_set_ref === null &&
        profileResolutionReceipt?.admitted_override_set_hash === null &&
        /^receipt:\/\//u.test(String(admitted.body.receipts?.review?.receipt_ref || "")) &&
        /^receipt:\/\//u.test(String(admitted.body.receipts?.admission?.receipt_ref || "")) &&
        /^receipt:\/\//u.test(String(admitted.body.receipts?.activation?.receipt_ref || "")) &&
        [
          admitted.body.receipts?.review,
          admitted.body.receipts?.admission,
          admitted.body.receipts?.activation,
        ].every((receipt) => /^sha256:[0-9a-f]{64}$/u.test(String(receipt?.receipt_root || ""))),
    );
    check(
      "GoalRun retains registered typed receipt obligations with complete discharge",
      Array.isArray(goalRun?.receipt_obligations) &&
        goalRun.receipt_obligations.length === 1 &&
        goalRun.receipt_obligations.every((entry) => validateReceiptObligation(entry)) &&
        admitted.body?.receipt_obligation_discharge?.all_required_discharged === true &&
        admitted.body?.receipt_obligation_discharge?.discharges?.length === 1,
      ajv.errorsText(validateReceiptObligation.errors),
    );
    check(
      "admitted state validates, reproduces a content-addressed local key, and crossed Agentgres",
      validateAdmittedState(admitted.body?.admitted_state) &&
        admitted.body?.admitted_state?.state_root_ref === goalRun?.admitted_state_root_ref &&
        admitted.body?.admitted_state?.goal_run_execution_ceiling_revision_ref ===
          goalRun?.goal_run_execution_ceiling_revision_ref &&
        admitted.body?.admitted_state?.goal_run_execution_ceiling_content_hash ===
          goalRun?.goal_run_execution_ceiling_content_hash &&
        admitted.body?.admitted_state?.declared_invocation_budget?.max_total_invocations === 0 &&
        admitted.body?.admitted_state?.declared_invocation_budget?.max_parallel_invocations === 0 &&
        admitted.body?.admitted_state?.admitted_override_set_ref === null &&
        admitted.body?.admitted_state?.admitted_override_set_hash === null &&
        admittedStateRoot(admitted.body.admitted_state) === admitted.body.admitted_state.state_root &&
        admitted.body.admitted_state.state_root_ref.endsWith(
          `/${admitted.body.admitted_state.state_root}`,
        ) &&
        familyCount("goal-run-activation-admitted-states") === 1 &&
        readFileSync(join(dataDir, "substrate", "muxlog.bin")).length > 0,
      ajv.errorsText(validateAdmittedState.errors),
    );
    const typedActivationReceipt = admitted.body.receipts?.activation;
    check(
      "activation admission receipt validates its registered contract and both portable invariants",
      validateActivationReceipt(typedActivationReceipt) &&
        typedActivationReceipt?.receipt_id === typedActivationReceipt?.receipt_ref &&
        receiptRoot(typedActivationReceipt) === typedActivationReceipt?.receipt_root &&
        goalRun?.receipt_obligations?.every((obligation) =>
          obligation.bound_fact_requirement_refs.every((reference) =>
            typedActivationReceipt?.attested_boundary_fact_refs?.includes(reference),
          ),
        ),
      ajv.errorsText(validateActivationReceipt.errors),
    );

    const replayedSubmit = await request(
      plane.daemonUrl,
      "POST",
      `/v1/goal-orchestration/goal-run-activations/${positiveId}/submit`,
      {
        schema_version: "ioi.goal-run-activation-submit-request.v1",
        expected_activation_hash: positiveDraft.body.activation_hash,
        review_decision: "approve",
      },
    );
    check(
      "authorized submit retry replays instead of minting a second GoalRun",
      replayedSubmit.status === 200 &&
        replayedSubmit.body?.replayed === true &&
        replayedSubmit.body?.goal_run?.goal_ref === goalRun?.goal_ref &&
        familyCount("goal-runs") === 1,
      `${replayedSubmit.status}/${replayedSubmit.body?.error?.code}`,
    );

    const statePath = recordPath(
      "goal-run-activation-admitted-states",
      (record) => record.state_root_ref === goalRun.admitted_state_root_ref,
    );
    const stateBytes = readFileSync(statePath);
    rmSync(statePath);
    const missingState = await request(
      plane.daemonUrl,
      "GET",
      `/v1/goal-orchestration/goal-run-activations/${positiveId}`,
    );
    writeFileSync(statePath, stateBytes);
    check(
      "a prefix-shaped state ref without local owner evidence refuses replay",
      missingState.status === 409 &&
        missingState.body?.error?.code ===
          "goal_run_activation_state_evidence_missing",
      `${missingState.status}/${missingState.body?.error?.code}`,
    );
    const restoreState = replaceRecord(statePath, (record) => {
      record.source_context_hash = `sha256:${"e".repeat(64)}`;
    });
    const tamperedState = await request(
      plane.daemonUrl,
      "GET",
      `/v1/goal-orchestration/goal-run-activations/${positiveId}`,
    );
    restoreState();
    check(
      "tampered admitted-state bytes refuse before projection",
      tamperedState.status === 409 &&
        tamperedState.body?.error?.code ===
          "goal_run_activation_state_integrity_failure",
      `${tamperedState.status}/${tamperedState.body?.error?.code}`,
    );

    const zeroEffectTreeBefore = durableTreeByteSnapshot(dataDir);
    const startAttempt = await request(
      plane.daemonUrl,
      "POST",
      `/v1/goal-orchestration/goal-runs/${goalRunId}/start`,
      {},
    );
    const zeroEffectTreeAfterStart = durableTreeByteSnapshot(dataDir);
    check(
      "zero-execution GoalRun start refuses before reservation, dependency resolution, or receipt effects",
      startAttempt.status === 422 &&
        startAttempt.body?.error?.code === "goal_run_execution_budget_exhausted" &&
        startAttempt.body?.error?.details?.effects_started === false &&
        zeroEffectTreeAfterStart === zeroEffectTreeBefore,
      `${startAttempt.status}/${startAttempt.body?.error?.code} tree=${snapshotRoot(zeroEffectTreeBefore)}->${snapshotRoot(zeroEffectTreeAfterStart)}`,
    );
    const resultAttempt = await request(
      plane.daemonUrl,
      "POST",
      `/v1/goal-orchestration/goal-runs/${goalRunId}/results`,
      {
        work_result_id: "work-result://m4-resultless-refusal",
        result_profile: "research",
        outcome_class: "negative",
        status: "failed",
      },
    );
    const zeroEffectTreeAfterResult = durableTreeByteSnapshot(dataDir);
    check(
      "zero-execution GoalRun refuses WorkResult creation before record, backlink, or receipt effects",
      resultAttempt.status === 422 &&
        resultAttempt.body?.error?.code === "goal_run_execution_budget_exhausted" &&
        zeroEffectTreeAfterResult === zeroEffectTreeBefore,
      `${resultAttempt.status}/${resultAttempt.body?.error?.code} tree=${snapshotRoot(zeroEffectTreeBefore)}->${snapshotRoot(zeroEffectTreeAfterResult)}`,
    );
    const deltaAttempt = await request(
      plane.daemonUrl,
      "POST",
      `/v1/goal-orchestration/goal-runs/${goalRunId}/outcome-deltas`,
      {
        proposed_by_ref: "work-result://m4-resultless-refusal",
        target_ref: "frontier://m4/resultless",
        delta_kind: "update",
      },
    );
    const zeroEffectTreeAfterDelta = durableTreeByteSnapshot(dataDir);
    check(
      "zero-execution GoalRun refuses OutcomeDelta creation before record, backlink, or receipt effects",
      deltaAttempt.status === 422 &&
        deltaAttempt.body?.error?.code === "goal_run_execution_budget_exhausted" &&
        zeroEffectTreeAfterDelta === zeroEffectTreeBefore,
      `${deltaAttempt.status}/${deltaAttempt.body?.error?.code} tree=${snapshotRoot(zeroEffectTreeBefore)}->${snapshotRoot(zeroEffectTreeAfterDelta)}`,
    );

    const ceilingPath = recordPath(
      "goal-run-execution-ceiling-revisions",
      (record) => record.revision_ref === executionCeiling.revision_ref,
    );
    const missingCeilingDraft = await request(
      plane.daemonUrl,
      "POST",
      "/v1/goal-orchestration/goal-run-activations",
      { ...draftRequest, idempotency_key: "m4-goal-chat-ceiling-missing" },
    );
    const ceilingBytes = readFileSync(ceilingPath);
    rmSync(ceilingPath);
    const missingCeiling = await request(
      plane.daemonUrl,
      "POST",
      `/v1/goal-orchestration/goal-run-activations/${activationId(missingCeilingDraft.body.activation)}/submit`,
      {
        schema_version: "ioi.goal-run-activation-submit-request.v1",
        expected_activation_hash: missingCeilingDraft.body.activation_hash,
        review_decision: "approve",
      },
    );
    writeFileSync(ceilingPath, ceilingBytes);
    check(
      "missing exact execution-ceiling release refuses before GoalRun admission",
      missingCeiling.status === 409 &&
        missingCeiling.body?.error?.code === "goal_run_execution_ceiling_missing" &&
        familyCount("goal-runs") === 1,
      `${missingCeiling.status}/${missingCeiling.body?.error?.code}`,
    );

    const tamperedCeilingDraft = await request(
      plane.daemonUrl,
      "POST",
      "/v1/goal-orchestration/goal-run-activations",
      { ...draftRequest, idempotency_key: "m4-goal-chat-ceiling-tampered" },
    );
    const restoreTamperedCeiling = replaceRecord(ceilingPath, (record) => {
      record.max_total_invocations = 1;
    });
    const tamperedCeiling = await request(
      plane.daemonUrl,
      "POST",
      `/v1/goal-orchestration/goal-run-activations/${activationId(tamperedCeilingDraft.body.activation)}/submit`,
      {
        schema_version: "ioi.goal-run-activation-submit-request.v1",
        expected_activation_hash: tamperedCeilingDraft.body.activation_hash,
        review_decision: "approve",
      },
    );
    restoreTamperedCeiling();
    check(
      "tampered execution-ceiling bytes refuse their stale content address",
      tamperedCeiling.status === 409 &&
        tamperedCeiling.body?.error?.code ===
          "goal_run_execution_ceiling_contract_invalid" &&
        familyCount("goal-runs") === 1,
      `${tamperedCeiling.status}/${tamperedCeiling.body?.error?.code}`,
    );

    const invalidCeilingDraft = await request(
      plane.daemonUrl,
      "POST",
      "/v1/goal-orchestration/goal-run-activations",
      { ...draftRequest, idempotency_key: "m4-goal-chat-ceiling-invalid" },
    );
    const restoreWidenedCeiling = replaceRecord(ceilingPath, (record) => {
      record.max_total_invocations = 1;
      record.max_parallel_invocations = 1;
      record.content_hash = executionCeilingHash(record);
      record.revision_ref = `${record.goal_run_execution_ceiling_id}/revision/${record.content_hash}`;
    });
    const widenedCeiling = await request(
      plane.daemonUrl,
      "POST",
      `/v1/goal-orchestration/goal-run-activations/${activationId(invalidCeilingDraft.body.activation)}/submit`,
      {
        schema_version: "ioi.goal-run-activation-submit-request.v1",
        expected_activation_hash: invalidCeilingDraft.body.activation_hash,
        review_decision: "approve",
      },
    );
    restoreWidenedCeiling();
    const restoreDefaultedCeiling = replaceRecord(ceilingPath, (record) => {
      delete record.max_total_invocations;
      delete record.max_parallel_invocations;
    });
    const defaultedCeiling = await request(
      plane.daemonUrl,
      "POST",
      `/v1/goal-orchestration/goal-run-activations/${activationId(invalidCeilingDraft.body.activation)}/submit`,
      {
        schema_version: "ioi.goal-run-activation-submit-request.v1",
        expected_activation_hash: invalidCeilingDraft.body.activation_hash,
        review_decision: "approve",
      },
    );
    restoreDefaultedCeiling();
    check(
      "widened or defaulted execution ceilings refuse instead of inferring invocation capacity",
      widenedCeiling.status === 409 &&
        widenedCeiling.body?.error?.code ===
          "goal_run_execution_ceiling_integrity_failure" &&
        defaultedCeiling.status === 409 &&
        defaultedCeiling.body?.error?.code ===
          "goal_run_execution_ceiling_contract_invalid" &&
        familyCount("goal-runs") === 1,
      `widened=${widenedCeiling.status}/${widenedCeiling.body?.error?.code} defaulted=${defaultedCeiling.status}/${defaultedCeiling.body?.error?.code}`,
    );

    const genericBypassResultsBefore = familyCount("work-result-registry");
    const genericBypassDeltasBefore = familyCount("outcome-delta-registry");
    const genericBypassTreeBefore = durableTreeByteSnapshot(dataDir);
    const genericZeroExecutionResult = await request(
      plane.daemonUrl,
      "POST",
      "/v1/hypervisor/work-results",
      {
        goal_ref: goalRun.goal_ref,
        result_profile: "research",
        outcome_class: "positive",
        status: "completed",
      },
    );
    const genericZeroExecutionDelta = await request(
      plane.daemonUrl,
      "POST",
      "/v1/hypervisor/outcome-deltas",
      {
        goal_ref: goalRun.goal_ref,
        proposed_by_ref: "work-result://m4-zero-execution-bypass",
        target_ref: "goal://m4/zero-execution-bypass",
        delta_kind: "update",
      },
    );
    const genericRoomResult = await request(
      plane.daemonUrl,
      "POST",
      "/v1/hypervisor/work-results",
      {
        goal_ref: goalRun.goal_ref,
        outcome_room_ref: "outcome-room://or_m4_generic_bypass",
        result_profile: "research",
        outcome_class: "positive",
        status: "completed",
      },
    );
    const genericRoomAdmissionResult = await request(
      plane.daemonUrl,
      "POST",
      "/v1/hypervisor/work-results",
      {
        goal_ref: goalRun.goal_ref,
        room_admission: { admitted: true },
        result_profile: "research",
        outcome_class: "positive",
        status: "completed",
      },
    );
    const genericRoomDelta = await request(
      plane.daemonUrl,
      "POST",
      "/v1/hypervisor/outcome-deltas",
      {
        goal_ref: goalRun.goal_ref,
        proposed_by_ref: "work-result://m4-resultless-refusal",
        outcome_room_ref: "outcome-room://or_m4_generic_bypass",
        target_ref: "frontier://m4/generic-bypass",
        delta_kind: "update",
      },
    );
    const genericRoomAdmissionDelta = await request(
      plane.daemonUrl,
      "POST",
      "/v1/hypervisor/outcome-deltas",
      {
        goal_ref: goalRun.goal_ref,
        proposed_by_ref: "work-result://m4-resultless-refusal",
        room_admission: { admitted: true },
        target_ref: "frontier://m4/generic-bypass",
        delta_kind: "update",
      },
    );
    const genericBypassTreeAfter = durableTreeByteSnapshot(dataDir);
    check(
      "generic WorkResult and OutcomeDelta routes cannot bypass room ownership or the zero-execution GoalRun ceiling",
      genericZeroExecutionResult.status === 422 &&
        genericZeroExecutionResult.body?.error?.code ===
          "goal_run_execution_budget_exhausted" &&
        genericZeroExecutionDelta.status === 422 &&
        genericZeroExecutionDelta.body?.error?.code ===
          "goal_run_execution_budget_exhausted" &&
        [genericRoomResult, genericRoomAdmissionResult].every(
        (response) =>
          response.status === 422 &&
          response.body?.error?.code ===
            "generic_work_result_room_binding_refused",
      ) &&
        [genericRoomDelta, genericRoomAdmissionDelta].every(
          (response) =>
            response.status === 422 &&
            response.body?.error?.code ===
              "generic_outcome_delta_room_binding_refused",
        ) &&
        familyCount("work-result-registry") === genericBypassResultsBefore &&
        familyCount("outcome-delta-registry") === genericBypassDeltasBefore &&
        genericBypassTreeAfter === genericBypassTreeBefore,
      `zero=${genericZeroExecutionResult.status}/${genericZeroExecutionResult.body?.error?.code},${genericZeroExecutionDelta.status}/${genericZeroExecutionDelta.body?.error?.code} room=${genericRoomResult.status}/${genericRoomAdmissionResult.status},${genericRoomDelta.status}/${genericRoomAdmissionDelta.status} registryDelta=${familyCount("work-result-registry") - genericBypassResultsBefore}/${familyCount("outcome-delta-registry") - genericBypassDeltasBefore} durable_tree=${snapshotRoot(genericBypassTreeBefore)}->${snapshotRoot(genericBypassTreeAfter)}`,
    );

    const beforeRestart = {
      activationHash: admitted.body.activation_hash,
      goalRef: goalRun.goal_ref,
      root: goalRun.admitted_state_root_ref,
      head: goalRun.lifecycle_head,
      receiptRefs: goalRun.receipt_refs,
      executionCeilingRevisionRef: goalRun.goal_run_execution_ceiling_revision_ref,
      executionCeilingContentHash: goalRun.goal_run_execution_ceiling_content_hash,
      declaredInvocationBudget: goalRun.declared_invocation_budget,
      admittedOverrideSetRef: goalRun.admitted_override_set_ref,
      admittedOverrideSetHash: goalRun.admitted_override_set_hash,
      resultCount: familyCount("work-result-registry"),
      deltaCount: familyCount("outcome-delta-registry"),
    };
    await plane.stop();
    plane = await startActivationPlane({ dataDir });
    const afterRestart = await request(
      plane.daemonUrl,
      "GET",
      `/v1/goal-orchestration/goal-run-activations/${positiveId}`,
    );
    check(
      "restart replays activation, GoalRun root/head, and receipts from durable state",
      afterRestart.status === 200 &&
        afterRestart.body?.activation_hash === beforeRestart.activationHash &&
        afterRestart.body?.goal_run?.goal_ref === beforeRestart.goalRef &&
        afterRestart.body?.goal_run?.admitted_state_root_ref === beforeRestart.root &&
        afterRestart.body?.goal_run?.lifecycle_head === beforeRestart.head &&
        afterRestart.body?.goal_run?.goal_run_execution_ceiling_revision_ref ===
          beforeRestart.executionCeilingRevisionRef &&
        afterRestart.body?.goal_run?.goal_run_execution_ceiling_content_hash ===
          beforeRestart.executionCeilingContentHash &&
        JSON.stringify(afterRestart.body?.goal_run?.declared_invocation_budget) ===
          JSON.stringify(beforeRestart.declaredInvocationBudget) &&
        afterRestart.body?.goal_run?.admitted_override_set_ref ===
          beforeRestart.admittedOverrideSetRef &&
        afterRestart.body?.goal_run?.admitted_override_set_hash ===
          beforeRestart.admittedOverrideSetHash &&
        afterRestart.body?.goal_run_execution_ceiling?.revision_ref ===
          beforeRestart.executionCeilingRevisionRef &&
        JSON.stringify(afterRestart.body?.goal_run?.receipt_refs) ===
          JSON.stringify(beforeRestart.receiptRefs) &&
        afterRestart.body?.receipts?.review?.receipt_ref ===
          admitted.body.receipts?.review?.receipt_ref &&
        afterRestart.body?.receipts?.admission?.receipt_ref ===
          admitted.body.receipts?.admission?.receipt_ref &&
        afterRestart.body?.receipts?.activation?.receipt_ref ===
          admitted.body.receipts?.activation?.receipt_ref,
      `${afterRestart.status}/${afterRestart.body?.error?.code}`,
    );
    const malformedGoalRunPath = join(dataDir, "goal-runs", "malformed.json");
    writeFileSync(malformedGoalRunPath, "{not-json\n");
    const malformedGoalList = await request(
      plane.daemonUrl,
      "GET",
      "/v1/goal-orchestration/goal-runs",
    );
    const malformedGoalGet = await request(
      plane.daemonUrl,
      "GET",
      `/v1/goal-orchestration/goal-runs/${goalRunId}`,
    );
    const malformedActivationReplay = await request(
      plane.daemonUrl,
      "GET",
      `/v1/goal-orchestration/goal-run-activations/${positiveId}`,
    );
    const resultsBeforeMalformedRefusal = familyCount("work-result-registry");
    const malformedGoalMutation = await request(
      plane.daemonUrl,
      "POST",
      `/v1/goal-orchestration/goal-runs/${goalRunId}/results`,
      {},
    );
    rmSync(malformedGoalRunPath);
    check(
      "malformed GoalRun sibling makes reads, activation replay, and mutation fail closed",
      [malformedGoalList, malformedGoalGet, malformedGoalMutation].every(
        (response) =>
          response.status === 500 &&
          response.body?.error?.code === "goal_run_registry_unreadable",
      ) &&
        malformedActivationReplay.status === 409 &&
        malformedActivationReplay.body?.error?.code ===
          "goal_run_activation_goal_registry_unreadable" &&
        familyCount("work-result-registry") === resultsBeforeMalformedRefusal,
      `list=${malformedGoalList.status}/${malformedGoalList.body?.error?.code} get=${malformedGoalGet.status}/${malformedGoalGet.body?.error?.code} activation=${malformedActivationReplay.status}/${malformedActivationReplay.body?.error?.code} mutation=${malformedGoalMutation.status}/${malformedGoalMutation.body?.error?.code}`,
    );

    const duplicateGoalRunPath = join(dataDir, "goal-runs", "gr_m4_duplicate.json");
    writeFileSync(
      duplicateGoalRunPath,
      `${JSON.stringify(
        {
          ...goalRun,
          goal_run_id: "gr_m4_duplicate",
          goal_ref: goalRun.goal_ref,
        },
        null,
        2,
      )}\n`,
    );
    const duplicateGoalList = await request(
      plane.daemonUrl,
      "GET",
      "/v1/goal-orchestration/goal-runs",
    );
    const duplicateActivationReplay = await request(
      plane.daemonUrl,
      "GET",
      `/v1/goal-orchestration/goal-run-activations/${positiveId}`,
    );
    rmSync(duplicateGoalRunPath);
    check(
      "duplicate canonical GoalRun reference refuses complete-census projection",
      duplicateGoalList.status === 500 &&
        duplicateGoalList.body?.error?.code === "goal_run_registry_unreadable" &&
        duplicateActivationReplay.status === 409 &&
        duplicateActivationReplay.body?.error?.code ===
          "goal_run_activation_goal_registry_unreadable",
      `list=${duplicateGoalList.status}/${duplicateGoalList.body?.error?.code} activation=${duplicateActivationReplay.status}/${duplicateActivationReplay.body?.error?.code}`,
    );
    const replayedGoalRun = await request(
      plane.daemonUrl,
      "GET",
      `/v1/goal-orchestration/goal-runs/${goalRunId}`,
    );
    const replayedResults = await request(
      plane.daemonUrl,
      "GET",
      "/v1/hypervisor/work-results",
    );
    const replayedDeltas = await request(
      plane.daemonUrl,
      "GET",
      "/v1/hypervisor/outcome-deltas",
    );
    check(
      "restart preserves the resultless GoalRun and creates no invocation result, delta, backlink, or receipt",
      replayedGoalRun.status === 200 &&
        validateGoalRun(replayedGoalRun.body?.goal_run) &&
        replayedGoalRun.body?.goal_run?.work_result_refs?.length === 0 &&
        JSON.stringify(replayedGoalRun.body?.goal_run?.receipt_refs) ===
          JSON.stringify(beforeRestart.receiptRefs) &&
        replayedResults.body?.work_results?.length === beforeRestart.resultCount &&
        replayedDeltas.body?.outcome_deltas?.length === beforeRestart.deltaCount,
      `${replayedGoalRun.status}/results=${replayedResults.body?.work_results?.length || 0}/deltas=${replayedDeltas.body?.outcome_deltas?.length || 0}`,
    );

    // `/v1/goal-orchestration/*` is intentionally outside the generic Hypervisor auth
    // middleware, so this read boundary must resolve and filter its principal itself. Prove both
    // an authenticated cross-owner denial and an exposed anonymous denial before any bytes are
    // projected.
    const ownerPrincipal = {
      email: "m4-activation-owner@local",
      password: "m4-owner-password",
      principal_id: "usr_m4_activation_owner",
    };
    const outsiderPrincipal = {
      email: "m4-activation-outsider@local",
      password: "m4-outsider-password",
      principal_id: "usr_m4_activation_outsider",
    };
    await request(
      plane.daemonUrl,
      "POST",
      "/v1/hypervisor/principals",
      ownerPrincipal,
    );
    await request(
      plane.daemonUrl,
      "POST",
      "/v1/hypervisor/principals",
      outsiderPrincipal,
    );
    const ownerLogin = await request(
      plane.daemonUrl,
      "POST",
      "/v1/hypervisor/auth/login",
      { email: ownerPrincipal.email, password: ownerPrincipal.password },
    );
    const outsiderLogin = await request(
      plane.daemonUrl,
      "POST",
      "/v1/hypervisor/auth/login",
      { email: outsiderPrincipal.email, password: outsiderPrincipal.password },
    );
    const ownerHeaders = {
      authorization: `Bearer ${ownerLogin.body.session_token}`,
    };
    const outsiderHeaders = {
      authorization: `Bearer ${outsiderLogin.body.session_token}`,
    };
    const managedOutsiderHeaders = {
      ...outsiderHeaders,
      "x-forwarded-host": "hypervisor.example.invalid",
    };
    const managedOwnerHeaders = {
      ...ownerHeaders,
      "x-forwarded-host": "hypervisor.example.invalid",
    };
    const ownerSessionRef = "session:m4-owner-bound-goalrun";
    const ownerSession = await request(
      plane.daemonUrl,
      "POST",
      "/v1/hypervisor/sessions",
      { session_ref: ownerSessionRef },
      managedOwnerHeaders,
    );
    const goalsBeforeCrossOwnerSession = familyCount("goal-runs");
    const crossOwnerSessionGoal = await request(
      plane.daemonUrl,
      "POST",
      "/v1/goal-orchestration/goal-runs",
      {
        goal: "Cross-owner Session binding must fail closed",
        session_ref: ownerSessionRef,
      },
      managedOutsiderHeaders,
    );
    check(
      "authenticated GoalRun creation cannot bind another owner's Session/workspace",
      ownerSession.status === 202 &&
        crossOwnerSessionGoal.status === 403 &&
        crossOwnerSessionGoal.body?.error?.code ===
          "goal_run_target_session_owner_mismatch" &&
        familyCount("goal-runs") === goalsBeforeCrossOwnerSession,
      `${ownerSession.status}/${crossOwnerSessionGoal.status}/${crossOwnerSessionGoal.body?.error?.code}`,
    );
    const ownerDraft = await request(
      plane.daemonUrl,
      "POST",
      "/v1/goal-orchestration/goal-run-activations",
      { ...draftRequest, idempotency_key: "m4-goal-chat-owner-filter" },
      ownerHeaders,
    );
    const ownerDraftId = activationId(ownerDraft.body.activation);
    const ownerRead = await request(
      plane.daemonUrl,
      "GET",
      `/v1/goal-orchestration/goal-run-activations/${ownerDraftId}`,
      undefined,
      ownerHeaders,
    );
    const missingActivationId = "gra_m4_absent_owner_oracle_probe";
    const activationOwnerOracleBefore = durableTreeByteSnapshot(dataDir);
    const outsiderRead = await request(
      plane.daemonUrl,
      "GET",
      `/v1/goal-orchestration/goal-run-activations/${ownerDraftId}`,
      undefined,
      managedOutsiderHeaders,
    );
    const outsiderSubmit = await request(
      plane.daemonUrl,
      "POST",
      `/v1/goal-orchestration/goal-run-activations/${ownerDraftId}/submit`,
      {
        schema_version: "ioi.goal-run-activation-submit-request.v1",
        expected_activation_hash: ownerDraft.body.activation_hash,
        review_decision: "approve",
      },
      managedOutsiderHeaders,
    );
    const outsiderMissingRead = await request(
      plane.daemonUrl,
      "GET",
      `/v1/goal-orchestration/goal-run-activations/${missingActivationId}`,
      undefined,
      managedOutsiderHeaders,
    );
    const outsiderMissingSubmit = await request(
      plane.daemonUrl,
      "POST",
      `/v1/goal-orchestration/goal-run-activations/${missingActivationId}/submit`,
      {
        schema_version: "ioi.goal-run-activation-submit-request.v1",
        expected_activation_hash: ownerDraft.body.activation_hash,
        review_decision: "approve",
      },
      managedOutsiderHeaders,
    );
    const activationOwnerOracleAfter = durableTreeByteSnapshot(dataDir);
    const activationOwnerOracleRefusals = [
      outsiderRead,
      outsiderSubmit,
      outsiderMissingRead,
      outsiderMissingSubmit,
    ];
    check(
      "activation replay and submit authorize before existence and expose one owner-mismatch refusal class",
      ownerDraft.status === 201 &&
        ownerRead.status === 200 &&
        ownerRead.body?.goal_draft?.user_ref === "user://usr_m4_activation_owner" &&
        activationOwnerOracleRefusals.every(
          (response) =>
            response.status === 403 &&
            response.body?.error?.code ===
              "goal_run_activation_projection_owner_mismatch" &&
            canonicalJson(response.body) === canonicalJson(outsiderRead.body),
        ) &&
        activationOwnerOracleAfter === activationOwnerOracleBefore,
      `owner=${ownerRead.status} existing_get=${outsiderRead.status}/${outsiderRead.body?.error?.code} existing_submit=${outsiderSubmit.status}/${outsiderSubmit.body?.error?.code} missing_get=${outsiderMissingRead.status}/${outsiderMissingRead.body?.error?.code} missing_submit=${outsiderMissingSubmit.status}/${outsiderMissingSubmit.body?.error?.code} durable_tree=${snapshotRoot(activationOwnerOracleBefore)}->${snapshotRoot(activationOwnerOracleAfter)}`,
    );
    const anonymousExposedRead = await request(
      plane.daemonUrl,
      "GET",
      `/v1/goal-orchestration/goal-run-activations/${ownerDraftId}`,
      undefined,
      { "x-forwarded-host": "hypervisor.example.invalid" },
    );
    check(
      "exposed anonymous caller cannot read activation source, authority, or receipts",
      anonymousExposedRead.status === 401 &&
        anonymousExposedRead.body?.error?.code ===
          "goal_run_activation_authentication_required",
      `${anonymousExposedRead.status}/${anonymousExposedRead.body?.error?.code}`,
    );
    const exposedHeaders = { "x-forwarded-host": "hypervisor.example.invalid" };
    const absentGoalRunId = "gr_m4_absent_auth_preflight_probe";
    const lifecycleStateBefore = JSON.stringify(
      (await request(
        plane.daemonUrl,
        "GET",
        `/v1/goal-orchestration/goal-runs/${goalRunId}`,
      )).body?.goal_run,
    );
    const outsiderStart = await request(
      plane.daemonUrl,
      "POST",
      `/v1/goal-orchestration/goal-runs/${goalRunId}/start`,
      {},
      managedOutsiderHeaders,
    );
    const outsiderReconcile = await request(
      plane.daemonUrl,
      "POST",
      `/v1/goal-orchestration/goal-runs/${goalRunId}/reconcile`,
      {},
      managedOutsiderHeaders,
    );
    const outsiderRecovery = await request(
      plane.daemonUrl,
      "POST",
      `/v1/goal-orchestration/goal-runs/${goalRunId}/lifecycle-recovery`,
      { op_token: "lop_cross_owner_probe", resolution: "release" },
      managedOutsiderHeaders,
    );
    const anonymousLifecycleMutations = await Promise.all(
      [
        [`/v1/goal-orchestration/goal-runs/${goalRunId}/start`, {}],
        [`/v1/goal-orchestration/goal-runs/${goalRunId}/reconcile`, {}],
        [
          `/v1/goal-orchestration/goal-runs/${goalRunId}/lifecycle-recovery`,
          { op_token: "lop_anonymous_existing_probe", resolution: "release" },
        ],
        [`/v1/goal-orchestration/goal-runs/${absentGoalRunId}/start`, {}],
        [`/v1/goal-orchestration/goal-runs/${absentGoalRunId}/reconcile`, {}],
        [
          `/v1/goal-orchestration/goal-runs/${absentGoalRunId}/lifecycle-recovery`,
          { op_token: "lop_anonymous_absent_probe", resolution: "release" },
        ],
      ].map(([path, requestBody]) =>
        request(
          plane.daemonUrl,
          "POST",
          path,
          requestBody,
          exposedHeaders,
        ),
      ),
    );
    const outsiderEvents = await request(
      plane.daemonUrl,
      "GET",
      `/v1/goal-orchestration/goal-runs/${goalRunId}/events`,
      undefined,
      managedOutsiderHeaders,
    );
    const lifecycleStateAfter = JSON.stringify(
      (await request(
        plane.daemonUrl,
        "GET",
        `/v1/goal-orchestration/goal-runs/${goalRunId}`,
      )).body?.goal_run,
    );
    check(
      "GoalRun start, reconcile, recovery, and event projection enforce authentication/owner authorization before any existing or missing lifecycle truth",
      [outsiderStart, outsiderReconcile, outsiderRecovery].every(
        (response) =>
          response.status === 403 &&
          response.body?.error?.code === "goal_run_mutation_owner_mismatch",
      ) &&
        anonymousLifecycleMutations.every(
          (response) =>
            response.status === 401 &&
            response.body?.error?.code ===
              "goal_run_global_truth_authentication_required",
        ) &&
        outsiderEvents.status === 403 &&
        outsiderEvents.body?.error?.code ===
          "goal_run_global_truth_owner_mismatch" &&
        lifecycleStateBefore === lifecycleStateAfter,
      `start=${outsiderStart.status}/${outsiderStart.body?.error?.code} reconcile=${outsiderReconcile.status}/${outsiderReconcile.body?.error?.code} recovery=${outsiderRecovery.status}/${outsiderRecovery.body?.error?.code} anonymous=${anonymousLifecycleMutations.map((response) => `${response.status}/${response.body?.error?.code}`).join(",")} events=${outsiderEvents.status}/${outsiderEvents.body?.error?.code}`,
    );
    const unauthorizedResultCount = familyCount("work-result-registry");
    const unauthorizedDeltaCount = familyCount("outcome-delta-registry");
    const outsiderResultMutation = await request(
      plane.daemonUrl,
      "POST",
      `/v1/goal-orchestration/goal-runs/${goalRunId}/results`,
      {},
      managedOutsiderHeaders,
    );
    const outsiderDeltaMutation = await request(
      plane.daemonUrl,
      "POST",
      `/v1/goal-orchestration/goal-runs/${goalRunId}/outcome-deltas`,
      {},
      managedOutsiderHeaders,
    );
    const anonymousResultMutation = await request(
      plane.daemonUrl,
      "POST",
      `/v1/goal-orchestration/goal-runs/${goalRunId}/results`,
      {},
      exposedHeaders,
    );
    const anonymousDeltaMutation = await request(
      plane.daemonUrl,
      "POST",
      `/v1/goal-orchestration/goal-runs/${goalRunId}/outcome-deltas`,
      {},
      exposedHeaders,
    );
    const anonymousAbsentResultMutations = await Promise.all(
      ["results", "outcome-deltas"].map((family) =>
        request(
          plane.daemonUrl,
          "POST",
          `/v1/goal-orchestration/goal-runs/${absentGoalRunId}/${family}`,
          {},
          exposedHeaders,
        ),
      ),
    );
    const outsiderGenericResultMutation = await request(
      plane.daemonUrl,
      "POST",
      "/v1/hypervisor/work-results",
      { goal_ref: goalRun.goal_ref },
      managedOutsiderHeaders,
    );
    const outsiderGenericDeltaMutation = await request(
      plane.daemonUrl,
      "POST",
      "/v1/hypervisor/outcome-deltas",
      { goal_ref: goalRun.goal_ref },
      managedOutsiderHeaders,
    );
    const anonymousGenericResultMutation = await request(
      plane.daemonUrl,
      "POST",
      "/v1/hypervisor/work-results",
      { goal_ref: goalRun.goal_ref },
      exposedHeaders,
    );
    const anonymousGenericDeltaMutation = await request(
      plane.daemonUrl,
      "POST",
      "/v1/hypervisor/outcome-deltas",
      { goal_ref: goalRun.goal_ref },
      exposedHeaders,
    );
    check(
      "cross-owner and exposed anonymous callers cannot mutate GoalRun result or delta truth through either route family",
      [
        outsiderResultMutation,
        outsiderDeltaMutation,
        outsiderGenericResultMutation,
        outsiderGenericDeltaMutation,
      ].every(
        (response) =>
          response.status === 403 &&
          [
            "goal_run_mutation_owner_mismatch",
            "work_truth_goal_owner_mismatch",
          ].includes(response.body?.error?.code),
      ) &&
        [
          anonymousResultMutation,
          anonymousDeltaMutation,
          ...anonymousAbsentResultMutations,
        ].every(
          (response) =>
            response.status === 401 &&
            response.body?.error?.code ===
              "goal_run_global_truth_authentication_required",
        ) &&
        [anonymousGenericResultMutation, anonymousGenericDeltaMutation].every(
          (response) =>
            response.status === 401 &&
            response.body?.reason === "authentication_required",
        ) &&
        familyCount("work-result-registry") === unauthorizedResultCount &&
        familyCount("outcome-delta-registry") === unauthorizedDeltaCount,
      `outsider=${outsiderResultMutation.status}/${outsiderResultMutation.body?.error?.code},${outsiderDeltaMutation.status}/${outsiderDeltaMutation.body?.error?.code},${outsiderGenericResultMutation.status}/${outsiderGenericResultMutation.body?.error?.code},${outsiderGenericDeltaMutation.status}/${outsiderGenericDeltaMutation.body?.error?.code} anonymous=${anonymousResultMutation.status}/${anonymousResultMutation.body?.error?.code},${anonymousDeltaMutation.status}/${anonymousDeltaMutation.body?.error?.code},missing=${anonymousAbsentResultMutations.map((response) => `${response.status}/${response.body?.error?.code}`).join(",")},${anonymousGenericResultMutation.status}/${anonymousGenericResultMutation.body?.reason},${anonymousGenericDeltaMutation.status}/${anonymousGenericDeltaMutation.body?.reason} resultDelta=${familyCount("work-result-registry") - unauthorizedResultCount}/${familyCount("outcome-delta-registry") - unauthorizedDeltaCount}`,
    );
    const exposedGoalList = await request(
      plane.daemonUrl,
      "GET",
      "/v1/goal-orchestration/goal-runs",
      undefined,
      exposedHeaders,
    );
    const exposedGoalGet = await request(
      plane.daemonUrl,
      "GET",
      `/v1/goal-orchestration/goal-runs/${goalRunId}`,
      undefined,
      exposedHeaders,
    );
    const exposedResultList = await request(
      plane.daemonUrl,
      "GET",
      "/v1/hypervisor/work-results",
      undefined,
      exposedHeaders,
    );
    const exposedResultGet = await request(
      plane.daemonUrl,
      "GET",
      "/v1/hypervisor/work-results/m4-direct-negative-1",
      undefined,
      exposedHeaders,
    );
    const exposedDeltaList = await request(
      plane.daemonUrl,
      "GET",
      "/v1/hypervisor/outcome-deltas",
      undefined,
      exposedHeaders,
    );
    const exposedDeltaGet = await request(
      plane.daemonUrl,
      "GET",
      "/v1/hypervisor/outcome-deltas/m4-resultless-no-delta",
      undefined,
      exposedHeaders,
    );
    check(
      "exposed anonymous callers cannot enumerate or fetch GoalRun, WorkResult, or OutcomeDelta truth",
      [
        exposedGoalList,
        exposedGoalGet,
        exposedResultList,
        exposedResultGet,
        exposedDeltaList,
        exposedDeltaGet,
      ].every((response) => response.status === 401 || response.status === 403) &&
        exposedGoalList.body?.goal_runs === undefined &&
        exposedResultList.body?.work_results === undefined &&
        exposedDeltaList.body?.outcome_deltas === undefined,
      `goal=${exposedGoalList.status}/${exposedGoalGet.status} result=${exposedResultList.status}/${exposedResultGet.status} delta=${exposedDeltaList.status}/${exposedDeltaGet.status}`,
    );

    // Force the durable writer's post-rename uncertainty exactly at the GoalRun record. The first
    // response must refuse success even though the new record is visible. A fresh process with the
    // fault removed must certify that exact GoalRun and finish the already-submitted activation;
    // no second identity may be minted.
    await plane.stop();
    plane = await startActivationPlane({
      dataDir: unknownReceiptDataDir,
      env: { IOI_TEST_GOAL_RUN_ACTIVATION_RECEIPT_TYPE: "unregistered_test_receipt" },
    });
    const unknownReceiptDraft = await request(
      plane.daemonUrl,
      "POST",
      "/v1/goal-orchestration/goal-run-activations",
      { ...draftRequest, idempotency_key: "m4-goal-chat-unknown-receipt-type" },
    );
    check(
      "an unregistered receipt-obligation type refuses before activation or GoalRun identity",
      unknownReceiptDraft.status === 422 &&
        unknownReceiptDraft.body?.error?.code ===
          "goal_run_activation_receipt_obligation_type_unregistered" &&
        familyCount("goal-run-activations", unknownReceiptDataDir) === 0 &&
        familyCount("goal-runs", unknownReceiptDataDir) === 0,
      `${unknownReceiptDraft.status}/${unknownReceiptDraft.body?.error?.code}`,
    );
    await plane.stop();
    plane = await startActivationPlane({ dataDir: faultDataDir });
    const faultDraft = await request(
      plane.daemonUrl,
      "POST",
      "/v1/goal-orchestration/goal-run-activations",
      { ...draftRequest, idempotency_key: "m4-goal-chat-goalrun-durability-fault" },
    );
    const faultId = activationId(faultDraft.body.activation);
    await plane.stop();
    plane = await startActivationPlane({
      dataDir: faultDataDir,
      env: { IOI_TEST_FORCE_DIRSYNC_UNCONFIRMED: "goal-runs" },
    });
    const faultAuthorityChallenge = await request(
      plane.daemonUrl,
      "POST",
      `/v1/goal-orchestration/goal-run-activations/${faultId}/submit`,
      {
        schema_version: "ioi.goal-run-activation-submit-request.v1",
        expected_activation_hash: faultDraft.body.activation_hash,
        review_decision: "approve",
      },
    );
    const faultGrant = await mintActivationGrant(faultAuthorityChallenge);
    const uncertainAdmission = await request(
      plane.daemonUrl,
      "POST",
      `/v1/goal-orchestration/goal-run-activations/${faultId}/submit`,
      {
        schema_version: "ioi.goal-run-activation-submit-request.v1",
        expected_activation_hash: faultDraft.body.activation_hash,
        review_decision: "approve",
        wallet_approval_grant: faultGrant,
      },
    );
    check(
      "GoalRun durability uncertainty refuses success while retaining one retryable identity",
      uncertainAdmission.status === 500 &&
        uncertainAdmission.body?.error?.code === "goal_run_persist_failed" &&
        familyCount("goal-runs", faultDataDir) === 1,
      `${uncertainAdmission.status}/${uncertainAdmission.body?.error?.code}`,
    );
    await plane.stop();
    plane = await startActivationPlane({ dataDir: faultDataDir });
    const recoveredAdmission = await request(
      plane.daemonUrl,
      "POST",
      `/v1/goal-orchestration/goal-run-activations/${faultId}/submit`,
      {
        schema_version: "ioi.goal-run-activation-submit-request.v1",
        expected_activation_hash: faultDraft.body.activation_hash,
        review_decision: "approve",
        wallet_approval_grant: faultGrant,
      },
    );
    check(
      "fresh-process retry certifies the same GoalRun and completes the activation",
      recoveredAdmission.status === 201 &&
        recoveredAdmission.body?.activation?.status === "admitted" &&
        recoveredAdmission.body?.goal_run?.activation_ref ===
          recoveredAdmission.body?.activation?.activation_id &&
        readdirSync(join(faultDataDir, "goal-runs")).filter((name) => name.endsWith(".json"))
          .length === 1,
      `${recoveredAdmission.status}/${recoveredAdmission.body?.error?.code}`,
    );
  }
} finally {
  if (plane) await plane.stop();
  if (authorityResolver) await authorityResolver.stop();
  rmSync(dataDir, { recursive: true, force: true });
  rmSync(faultDataDir, { recursive: true, force: true });
  rmSync(unknownReceiptDataDir, { recursive: true, force: true });
}

for (const item of checks) {
  console.log(`${item.pass ? "PASS" : "FAIL"} ${item.name}${item.detail ? ` — ${item.detail}` : ""}`);
}
const failed = checks.filter((item) => !item.pass);
if (checks.length !== EXPECTED_CHECKS) {
  console.error(`FAIL verifier coverage changed: expected ${EXPECTED_CHECKS}, got ${checks.length}`);
  process.exitCode = 1;
} else if (failed.length) process.exitCode = 1;
else if (process.exitCode !== 2) {
  console.log(`M4 GoalRun activation isolated plane: PASS (${EXPECTED_CHECKS}/${EXPECTED_CHECKS})`);
}
