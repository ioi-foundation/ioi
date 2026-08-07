import { spawn } from "node:child_process";
import fs from "node:fs";
import net from "node:net";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const artifactRoot = path.join(
  root,
  ".artifacts",
  "implementation",
  "daemon-smoke",
);
const reportPath = path.join(artifactRoot, "report.json");
const binary = path.join(root, "target", "debug", "hypervisor-daemon");
const smokePrincipalId = "00000000-0000-4000-8000-000000000001";
let smokeSessionToken = "";
const report = {
  schema_version: "ioi.implementation-daemon-smoke-report.v1",
  status: "running",
  backend: {
    daemon: "target/debug/hypervisor-daemon",
    model_upstream: "loopback-unreachable",
    managed_runtime_provider: "provider://local/reference",
    foundry_trainer: "trainer-backend://ioi/reference-token-frequency/v1",
    identity_source:
      "daemon-issued one-boot bootstrap credential, durable operator membership, and daemon-issued bearer session",
  },
  assertions: [],
  interactions: [],
  objects: {},
  restart_count: 0,
};

fs.mkdirSync(artifactRoot, { recursive: true });

function writeReport() {
  fs.writeFileSync(reportPath, `${JSON.stringify(report, null, 2)}\n`);
}

function assertThat(condition, name, detail = {}) {
  if (!condition) throw new Error(`assertion failed: ${name}`);
  report.assertions.push({ name, status: "passed", ...detail });
}

function errorCode(body) {
  return typeof body?.error?.code === "string" ? body.error.code : null;
}

function expectStatus(response, expected, name) {
  assertThat(response.status === expected, name, {
    expected_status: expected,
    actual_status: response.status,
    error_code: errorCode(response.body),
  });
}

async function freePort() {
  return new Promise((resolve, reject) => {
    const server = net.createServer();
    server.once("error", reject);
    server.listen(0, "127.0.0.1", () => {
      const address = server.address();
      server.close((error) => {
        if (error) reject(error);
        else resolve(address.port);
      });
    });
  });
}

function delay(milliseconds) {
  return new Promise((resolve) => setTimeout(resolve, milliseconds));
}

async function startDaemon(dataDir) {
  const port = await freePort();
  const endpoint = `http://127.0.0.1:${port}`;
  const child = spawn(binary, [], {
    cwd: root,
    env: {
      ...process.env,
      IOI_HYPERVISOR_DAEMON_ADDR: `127.0.0.1:${port}`,
      IOI_HYPERVISOR_DATA_DIR: dataDir,
      IOI_HYPERVISOR_MODEL_UPSTREAM: "http://127.0.0.1:1/v1",
    },
    stdio: ["ignore", "pipe", "pipe"],
  });
  let spawnError = null;
  child.once("error", (error) => {
    spawnError = error;
  });
  let log = "";
  const retainLog = (chunk) => {
    log = `${log}${chunk}`.slice(-128_000);
  };
  child.stdout.on("data", retainLog);
  child.stderr.on("data", retainLog);
  const deadline = Date.now() + 30_000;
  let healthy = false;
  while (Date.now() < deadline) {
    if (spawnError) {
      throw new Error(
        `hypervisor-daemon could not start: ${spawnError.message}`,
      );
    }
    if (child.exitCode !== null) {
      throw new Error(
        `hypervisor-daemon exited before readiness (${child.exitCode}):\n${log}`,
      );
    }
    try {
      const response = await fetch(`${endpoint}/healthz`, {
        signal: AbortSignal.timeout(1_000),
      });
      if (response.ok) {
        healthy = true;
        break;
      }
    } catch {}
    await delay(100);
  }
  if (!healthy) {
    child.kill("SIGKILL");
    throw new Error(`hypervisor-daemon did not become healthy:\n${log}`);
  }
  const bootstrapToken =
    log.match(/ioi_bootstrap_[a-f0-9]{64}/gu)?.at(-1) ?? null;
  return {
    endpoint,
    bootstrapToken,
    log: () => log,
    async close() {
      if (child.exitCode !== null) return;
      const exited = new Promise((resolve) => child.once("exit", resolve));
      child.kill("SIGTERM");
      const graceful = await Promise.race([
        exited.then(() => true),
        delay(5_000).then(() => false),
      ]);
      if (!graceful && child.exitCode === null) {
        child.kill("SIGKILL");
        await exited;
      }
    },
  };
}

async function bootstrapAuthenticatedOperator(daemon) {
  if (!daemon.bootstrapToken) {
    throw new Error(
      `fresh daemon did not emit its one-boot bootstrap token:\n${daemon.log()}`,
    );
  }
  const response = await fetch(
    `${daemon.endpoint}/v1/hypervisor/auth/bootstrap`,
    {
      method: "POST",
      headers: {
        accept: "application/json",
        "content-type": "application/json",
      },
      body: JSON.stringify({
        token: daemon.bootstrapToken,
        password: "implementation-smoke-bootstrap-password-v1",
        email: "implementation-smoke@ioi.local",
      }),
      signal: AbortSignal.timeout(10_000),
    },
  );
  const body = await response.json();
  report.interactions.push({
    name: "bootstrap_authenticated_operator",
    method: "POST",
    route: "/v1/hypervisor/auth/bootstrap",
    status: response.status,
    error_code: errorCode(body),
  });
  expectStatus(
    { status: response.status, body },
    200,
    "fresh daemon bootstrap is admitted",
  );
  assertThat(
    typeof body.session_token === "string" &&
      body.session_token.startsWith("ioi_sess_"),
    "bootstrap returns a one-time daemon-issued session token",
  );
  smokeSessionToken = body.session_token;
}

async function api(daemon, name, method, route, body) {
  const response = await fetch(`${daemon.endpoint}${route}`, {
    method,
    headers:
      body === undefined
        ? {
            accept: "application/json",
            authorization: `Bearer ${smokeSessionToken}`,
          }
        : {
            accept: "application/json",
            authorization: `Bearer ${smokeSessionToken}`,
            "content-type": "application/json",
          },
    body: body === undefined ? undefined : JSON.stringify(body),
    signal: AbortSignal.timeout(10_000),
  });
  const text = await response.text();
  let parsed;
  try {
    parsed = text ? JSON.parse(text) : {};
  } catch {
    parsed = { non_json_response: text.slice(0, 2_000) };
  }
  report.interactions.push({
    name,
    method,
    route,
    status: response.status,
    error_code: errorCode(parsed),
  });
  return { status: response.status, body: parsed };
}

function encoded(value) {
  return encodeURIComponent(value);
}

function transitionRequest(expectedHead, idempotencyKey, toState, placement) {
  return {
    expected_head: expectedHead,
    idempotency_key: idempotencyKey,
    to_state: toState,
    transition_reason: "implementation_smoke",
    payment_status: "not_applicable",
    authority_scope_refs: [],
    authority_grant_refs: ["grant://implementation-smoke/managed-runtime"],
    policy_refs: ["policy://implementation-smoke/runtime"],
    required_controls: [],
    ...(placement ? { placement } : {}),
  };
}

async function run() {
  let dataDir = null;
  let daemon;
  try {
    fs.accessSync(binary, fs.constants.X_OK);
    dataDir = fs.mkdtempSync(
      path.join(os.tmpdir(), "ioi-implementation-daemon-smoke-"),
    );
    daemon = await startDaemon(dataDir);
    await bootstrapAuthenticatedOperator(daemon);

    const identity = await api(
      daemon,
      "authenticated_smoke_identity",
      "GET",
      "/v1/hypervisor/auth/whoami",
    );
    expectStatus(
      identity,
      200,
      "smoke principal resolves through a real session",
    );
    assertThat(
      identity.body.authenticated === true &&
        identity.body.principal?.principal_id === smokePrincipalId,
      "smoke identity is authenticated and exact",
    );
    assertThat(
      identity.body.principal?.tenant_refs?.includes("org://local"),
      "smoke tenant membership resolves from the daemon-owned membership chain",
    );

    const instanceId = "agent://implementation-smoke/worker-1";
    const instanceRoute = `/v1/hypervisor/managed-worker-instances/${encoded(instanceId)}`;
    const instanceCreate = {
      instance_id: instanceId,
      lifecycle_id: "lifecycle:implementation-smoke-worker-1",
      owner_ref: "org://local",
      worker_package_ref: "worker-package://implementation-smoke/reference/v1",
      config_revision_ref: "config-revision://implementation-smoke/worker/v1",
      runtime_policy: {
        persistence_profile: "persistent",
        idle_threshold_seconds: 300,
        minimum_warm_seconds: 60,
        wake_sources: ["user", "schedule"],
        maximum_cold_start_seconds: 120,
        maximum_restore_age_seconds: 3_600,
        checkpoint_cadence_seconds: 300,
        pre_stop_checkpoint_required: true,
        provider_idle_semantics: "stop",
        fallback_placement_refs: [],
        privacy_floor_ref: "policy://implementation-smoke/privacy",
        spend_ceiling_ref: "budget://implementation-smoke/spend",
        archive_retention_policy_ref: "policy://implementation-smoke/archive",
        minimum_backup_replicas: 1,
      },
      authority_grant_refs: ["grant://implementation-smoke/managed-runtime"],
      idempotency_key: "implementation-smoke-instance-create-v1",
    };
    const created = await api(
      daemon,
      "managed_instance_create",
      "POST",
      "/v1/hypervisor/managed-worker-instances",
      instanceCreate,
    );
    expectStatus(created, 201, "managed instance create is admitted");
    assertThat(
      created.body.instance?.state === "installed",
      "managed instance begins installed",
    );
    assertThat(
      created.body.instance?.agentgres?.replayed === false,
      "managed instance create is not a replay",
    );

    const createReplay = await api(
      daemon,
      "managed_instance_exact_replay",
      "POST",
      "/v1/hypervisor/managed-worker-instances",
      instanceCreate,
    );
    expectStatus(
      createReplay,
      201,
      "managed instance exact replay is accepted",
    );
    assertThat(
      createReplay.body.instance?.agentgres?.replayed === true,
      "managed instance exact replay is named",
    );
    assertThat(
      createReplay.body.instance?.agentgres?.head ===
        created.body.instance?.agentgres?.head,
      "managed instance replay retains the exact head",
    );

    const createConflict = await api(
      daemon,
      "managed_instance_same_key_different_bytes",
      "POST",
      "/v1/hypervisor/managed-worker-instances",
      {
        ...instanceCreate,
        config_revision_ref: "config-revision://implementation-smoke/worker/v2",
      },
    );
    expectStatus(
      createConflict,
      409,
      "managed instance same-key different bytes are refused",
    );
    assertThat(
      errorCode(createConflict.body) ===
        "event_stream_same_key_different_bytes",
      "managed instance conflict has the Agentgres byte-identity code",
    );

    const initializing = await api(
      daemon,
      "managed_instance_initializing",
      "POST",
      `${instanceRoute}/transitions`,
      transitionRequest(
        created.body.instance.agentgres.head,
        "implementation-smoke-instance-initializing-v1",
        "initializing",
      ),
    );
    expectStatus(
      initializing,
      200,
      "installed to initializing transition is committed",
    );
    assertThat(
      initializing.body.instance?.state === "initializing",
      "managed instance is initializing",
    );

    const placement = {
      runtime_node_ref: "runtime://implementation-smoke/local-node",
      daemon_profile_ref: "profile://implementation-smoke/reference-daemon",
      environment_ref: "environment://implementation-smoke/local-reference",
      provider_ref: "provider://local/reference",
      quote_ref: null,
      budget_reservation_ref: null,
      assignment_lease_ref: "lease://implementation-smoke/runtime-assignment",
      isolation_binding_ref:
        "workload-isolation-binding://implementation-smoke/reference",
      readiness_evidence_refs: [
        "evidence://implementation-smoke/local-reference-ready",
      ],
    };
    const active = await api(
      daemon,
      "managed_instance_active",
      "POST",
      `${instanceRoute}/transitions`,
      transitionRequest(
        initializing.body.instance.agentgres.head,
        "implementation-smoke-instance-active-v1",
        "active",
        placement,
      ),
    );
    expectStatus(active, 200, "initializing to active transition is committed");
    assertThat(
      active.body.instance?.state === "active",
      "managed instance is active",
    );
    assertThat(
      active.body.instance?.runtime_assignment?.status === "active",
      "runtime assignment is active",
    );
    assertThat(
      active.body.instance?.compute_session?.status === "ready",
      "compute session is ready",
    );
    assertThat(
      active.body.instance?.compute_session?.readiness_evidence_refs?.[0] ===
        "evidence://implementation-smoke/local-reference-ready",
      "readiness evidence is retained",
    );
    assertThat(
      active.body.instance?.last_transition?.admission?.archive_policy ===
        null &&
        active.body.instance?.last_transition?.admission?.restore_policy ===
          null &&
        active.body.instance?.last_transition?.admission?.export_policy ===
          null &&
        active.body.instance?.last_transition?.admission?.deletion_policy ===
          null,
      "managed lifecycle admission preserves explicit null policy records",
    );

    const openPolicyRefusal = await api(
      daemon,
      "managed_instance_open_policy_refused",
      "POST",
      `${instanceRoute}/transitions`,
      {
        ...transitionRequest(
          active.body.instance.agentgres.head,
          "implementation-smoke-open-policy-refused-v1",
          "idle",
        ),
        archive_policy: {
          archive_after: null,
          retain_for: null,
          storage_policy_ref: "policy://implementation-smoke/archive",
          unruled: true,
        },
      },
    );
    expectStatus(
      openPolicyRefusal,
      400,
      "managed lifecycle rejects open policy records",
    );
    assertThat(
      errorCode(openPolicyRefusal.body) ===
        "managed_runtime_transition_invalid",
      "open lifecycle policy refusal is typed",
    );

    const recipeId = "foundry-recipe://implementation-smoke/reference-v1";
    const recipeRoute = `/v1/hypervisor/foundry/recipes/${encoded(recipeId)}`;
    const recipeCreate = {
      recipe_id: recipeId,
      owner_ref: "org://local",
      predecessor_recipe_ref: null,
      expected_head: null,
      data_recipe_ref: "data-recipe://implementation-smoke/reference-v1",
      source_snapshot_refs: ["source-snapshot://implementation-smoke/input-v1"],
      institutional_learning_boundary_ref:
        "learning-boundary://implementation-smoke/reference",
      learning_source_rights_claim_refs: [
        "rights-claim://implementation-smoke/source-v1",
      ],
      tokenizer_ref: "tokenizer://implementation-smoke/whitespace-v1",
      sequence_format_ref: "format://implementation-smoke/json-row-v1",
      packing_policy_ref: "policy://implementation-smoke/no-packing",
      loss_mask_policy_ref: "policy://implementation-smoke/full-row-loss",
      harness_variant_refs: [
        "harness-variant://implementation-smoke/reference",
      ],
      environment_profile_ref:
        "environment-profile://implementation-smoke/local-reference",
      operators: [
        { kind: "normalize_whitespace", field: "text" },
        { kind: "filter_nonempty", field: "text" },
        { kind: "select_fields", fields: ["text", "source"] },
        { kind: "deduplicate", fields: ["text", "source"] },
      ],
      split_seed: 17,
      idempotency_key: "implementation-smoke-recipe-create-v1",
    };
    const recipe = await api(
      daemon,
      "foundry_recipe_create",
      "POST",
      "/v1/hypervisor/foundry/recipes",
      recipeCreate,
    );
    expectStatus(recipe, 201, "Foundry recipe revision is admitted");
    assertThat(
      recipe.body.recipe?.revision === 1,
      "Foundry recipe is immutable revision one",
    );
    assertThat(
      recipe.body.recipe?.agentgres?.replayed === false,
      "Foundry recipe create is not a replay",
    );

    const recipeReplay = await api(
      daemon,
      "foundry_recipe_exact_replay",
      "POST",
      "/v1/hypervisor/foundry/recipes",
      recipeCreate,
    );
    expectStatus(recipeReplay, 201, "Foundry recipe exact replay is accepted");
    assertThat(
      recipeReplay.body.recipe?.agentgres?.replayed === true,
      "Foundry recipe exact replay is named",
    );
    assertThat(
      recipeReplay.body.recipe?.content_hash ===
        recipe.body.recipe?.content_hash,
      "Foundry recipe replay retains its content hash",
    );

    const recipeConflict = await api(
      daemon,
      "foundry_recipe_same_key_different_bytes",
      "POST",
      "/v1/hypervisor/foundry/recipes",
      { ...recipeCreate, split_seed: 18 },
    );
    expectStatus(
      recipeConflict,
      409,
      "Foundry recipe changed bytes under one key are refused",
    );
    assertThat(
      errorCode(recipeConflict.body) === "foundry_idempotency_payload_conflict",
      "Foundry recipe conflict is typed",
    );

    const datasetRequest = {
      expected_recipe_head: recipe.body.recipe.agentgres.head,
      expected_recipe_content_hash: recipe.body.recipe.content_hash,
      rights_grant_refs: ["rights-grant://implementation-smoke/training-v1"],
      input_rows: [
        { text: "  alpha   beta  ", source: "fixture-a", ignored: true },
        { text: "alpha beta", source: "fixture-a", ignored: false },
        { text: "gamma delta", source: "fixture-b", ignored: true },
        { text: "   ", source: "fixture-empty", ignored: true },
      ],
      splits: { train: 10_000, validation: 0, test: 0 },
      idempotency_key: "implementation-smoke-dataset-materialize-v1",
    };
    const dataset = await api(
      daemon,
      "foundry_dataset_materialize",
      "POST",
      `${recipeRoute}/runs`,
      datasetRequest,
    );
    expectStatus(dataset, 201, "Foundry dataset materialization is admitted");
    assertThat(
      dataset.body.dataset_snapshot?.status === "materialized",
      "Foundry dataset is materialized",
    );
    assertThat(
      dataset.body.dataset_snapshot?.row_count === 2,
      "Foundry operators deterministically retain two rows",
    );

    const datasetReplay = await api(
      daemon,
      "foundry_dataset_exact_replay",
      "POST",
      `${recipeRoute}/runs`,
      datasetRequest,
    );
    expectStatus(
      datasetReplay,
      201,
      "Foundry dataset exact replay is accepted",
    );
    assertThat(
      datasetReplay.body.dataset_snapshot?.agentgres?.replayed === true,
      "dataset replay is named",
    );
    assertThat(
      datasetReplay.body.dataset_snapshot?.content_hash ===
        dataset.body.dataset_snapshot?.content_hash,
      "dataset materialization is content deterministic",
    );

    const programId = "trainpipe://implementation-smoke/reference-v1";
    const programRoute = `/v1/hypervisor/foundry/programs/${encoded(programId)}`;
    const programCreate = await api(
      daemon,
      "foundry_program_create",
      "POST",
      "/v1/hypervisor/foundry/programs",
      {
        program_id: programId,
        owner_ref: "org://local",
        foundry_spec_ref: null,
        dataset_snapshot_ref:
          dataset.body.dataset_snapshot.dataset_snapshot_ref,
        expected_recipe_content_hash: recipe.body.recipe.content_hash,
        training_mode: "sft",
        trainer_backend_profile_ref:
          "trainer-backend://ioi/reference-token-frequency/v1",
        text_field: "text",
        checkpoint_every_rows: 2,
        seed: 23,
        authority_grant_refs: ["grant://implementation-smoke/foundry-run"],
        rights_grant_refs: ["rights-grant://implementation-smoke/training-v1"],
        idempotency_key: "implementation-smoke-program-create-v1",
      },
    );
    expectStatus(programCreate, 201, "Foundry reference program is admitted");
    assertThat(
      programCreate.body.program?.status === "admitted",
      "Foundry program begins admitted",
    );
    assertThat(
      Array.isArray(programCreate.body.program?.token_counts) &&
        programCreate.body.program.token_counts.length === 0,
      "Foundry program initializes canonical token-count rows",
    );

    const programStart = await api(
      daemon,
      "foundry_program_start",
      "POST",
      `${programRoute}/start`,
      {
        expected_head: programCreate.body.program.agentgres.head,
        idempotency_key: "implementation-smoke-program-start-v1",
      },
    );
    expectStatus(programStart, 200, "Foundry program starts");
    assertThat(
      programStart.body.program?.status === "running",
      "Foundry program is running",
    );

    const programStep = await api(
      daemon,
      "foundry_program_step",
      "POST",
      `${programRoute}/step`,
      {
        expected_head: programStart.body.program.agentgres.head,
        idempotency_key: "implementation-smoke-program-step-v1",
        max_rows: 10,
      },
    );
    expectStatus(programStep, 200, "Foundry program step checkpoints");
    assertThat(
      programStep.body.program?.status === "completed",
      "bounded reference program completes",
    );
    assertThat(
      programStep.body.program?.current_checkpoint?.complete === true,
      "checkpoint is complete",
    );
    assertThat(
      programStep.body.program?.current_checkpoint?.restore_verified === false,
      "new checkpoint is not pre-declared restore verified",
    );
    assertThat(
      Array.isArray(programStep.body.program?.token_counts) &&
        programStep.body.program.token_counts.every(
          (row, index, rows) =>
            Object.keys(row).sort().join(",") === "count,token" &&
            typeof row.token === "string" &&
            Number.isSafeInteger(row.count) &&
            row.count > 0 &&
            (index === 0 || rows[index - 1].token < row.token),
        ),
      "Foundry token counts are closed strictly sorted rows",
    );

    const checkpointHash =
      programStep.body.program.current_checkpoint.artifact_hash;
    const checkpointTail = checkpointHash.replace(/^sha256:/, "");
    const checkpointPath = path.join(
      dataDir,
      "foundry-checkpoint-artifacts",
      `${checkpointTail}.json`,
    );
    assertThat(
      fs.existsSync(checkpointPath),
      "checkpoint bytes exist in daemon custody",
    );
    const checkpointBytes = fs.readFileSync(checkpointPath);
    const checkpointDocument = JSON.parse(checkpointBytes.toString("utf8"));
    assertThat(
      Array.isArray(checkpointDocument.model_state?.token_counts) &&
        JSON.stringify(checkpointDocument.model_state.token_counts) ===
          JSON.stringify(programStep.body.program.token_counts),
      "checkpoint bytes retain the canonical token-count rows",
    );
    fs.writeFileSync(
      checkpointPath,
      Buffer.concat([checkpointBytes, Buffer.from("\n")]),
    );
    const tamperedVerify = await api(
      daemon,
      "foundry_checkpoint_tampered_verify",
      "POST",
      `/v1/hypervisor/foundry/checkpoints/${encoded(checkpointHash)}/verify-restore`,
      {
        expected_program_head: programStep.body.program.agentgres.head,
        idempotency_key: "implementation-smoke-checkpoint-tampered-v1",
      },
    );
    expectStatus(tamperedVerify, 409, "tampered checkpoint bytes are refused");
    assertThat(
      errorCode(tamperedVerify.body) === "foundry_checkpoint_material_tampered",
      "tampered checkpoint refusal is typed",
    );

    fs.writeFileSync(checkpointPath, checkpointBytes);
    const restoredVerify = await api(
      daemon,
      "foundry_checkpoint_restored_verify",
      "POST",
      `/v1/hypervisor/foundry/checkpoints/${encoded(checkpointHash)}/verify-restore`,
      {
        expected_program_head: programStep.body.program.agentgres.head,
        idempotency_key: "implementation-smoke-checkpoint-restored-v1",
      },
    );
    expectStatus(restoredVerify, 200, "restored checkpoint bytes verify");
    assertThat(
      restoredVerify.body.verification?.verified === true,
      "checkpoint restore verification is true",
    );
    assertThat(
      restoredVerify.body.program?.current_checkpoint?.restore_verified ===
        true,
      "verified checkpoint state is retained on the program",
    );

    const qualification = await api(
      daemon,
      "foundry_program_qualification",
      "POST",
      `${programRoute}/qualify`,
      {
        expected_head: restoredVerify.body.program.agentgres.head,
        idempotency_key: "implementation-smoke-program-qualify-v1",
        evaluation_rows: [{ text: "alpha beta" }, { text: "gamma delta" }],
        quality_gate: {
          minimum_token_coverage: 0,
          maximum_mean_negative_log_likelihood: 100,
        },
        workload_fingerprint: {
          runtime_node_ref: "runtime://implementation-smoke/local-node",
          environment_ref: "environment://implementation-smoke/local-reference",
          trainer_backend_profile_ref:
            "trainer-backend://ioi/reference-token-frequency/v1",
          hardware_architecture: "x86_64",
          logical_cpu_count: 4,
          memory_bytes: 8_589_934_592,
          operating_system: "linux",
          daemon_release_ref: "release://ioi/hypervisor-daemon/dev",
        },
        cost_basis_ref: "cost://implementation-smoke/local-reference",
        failure_schedule_ref: "schedule://implementation-smoke/no-faults",
      },
    );
    expectStatus(qualification, 200, "Foundry qualification is measured");
    assertThat(
      qualification.body.qualification?.promotion_boundary
        ?.runtime_activation_performed === false,
      "qualification cannot activate a runtime route",
    );
    assertThat(
      qualification.body.qualification?.promotion_boundary?.proposal_only ===
        true &&
        qualification.body.qualification?.measurement
          ?.hardware_software_topology_fingerprint
          ?.trainer_backend_profile_ref ===
          "trainer-backend://ioi/reference-token-frequency/v1",
      "qualification remains proposal-only and binds a typed workload fingerprint",
    );

    const proposals = await api(
      daemon,
      "foundry_qualification_proposals",
      "GET",
      "/v1/hypervisor/foundry/qualification-proposals",
    );
    expectStatus(
      proposals,
      200,
      "Foundry qualification proposals are readable",
    );
    const proposal = proposals.body.qualification_proposals?.find(
      (candidate) => candidate.program_id === programId,
    );
    assertThat(
      proposal?.status === "proposed",
      "qualification remains a proposal",
    );
    assertThat(
      proposal?.activation_performed === false,
      "qualification proposal records no activation",
    );

    report.objects = {
      managed_instance: {
        instance_id: instanceId,
        revision: active.body.instance.revision,
        state: active.body.instance.state,
        assignment_status: active.body.instance.runtime_assignment.status,
        readiness_status: active.body.instance.compute_session.status,
      },
      foundry_recipe: {
        recipe_id: recipeId,
        revision: recipe.body.recipe.revision,
        content_hash: recipe.body.recipe.content_hash,
      },
      dataset_snapshot: {
        dataset_snapshot_ref:
          dataset.body.dataset_snapshot.dataset_snapshot_ref,
        content_hash: dataset.body.dataset_snapshot.content_hash,
        row_count: dataset.body.dataset_snapshot.row_count,
      },
      training_program: {
        program_id: programId,
        status: qualification.body.program.status,
        checkpoint_ref:
          qualification.body.program.current_checkpoint.checkpoint_ref,
        checkpoint_hash:
          qualification.body.program.current_checkpoint.artifact_hash,
        restore_verified:
          qualification.body.program.current_checkpoint.restore_verified,
        qualification_proposal_ref:
          qualification.body.program.qualification_proposal_ref,
        activation_performed: false,
      },
    };

    const persistedHeads = {
      instance: active.body.instance.agentgres.head,
      recipe: recipe.body.recipe.agentgres.head,
      program: qualification.body.program.agentgres.head,
    };
    await daemon.close();
    daemon = await startDaemon(dataDir);
    report.restart_count = 1;

    const restartedInstance = await api(
      daemon,
      "restart_managed_instance_read",
      "GET",
      instanceRoute,
    );
    expectStatus(
      restartedInstance,
      200,
      "managed instance survives daemon restart",
    );
    assertThat(
      restartedInstance.body.instance?.state === "active",
      "restarted managed instance remains active",
    );
    assertThat(
      restartedInstance.body.instance?.agentgres?.head ===
        persistedHeads.instance,
      "managed instance restart read retains the exact head",
    );

    const restartedRecipe = await api(
      daemon,
      "restart_foundry_recipe_read",
      "GET",
      recipeRoute,
    );
    expectStatus(
      restartedRecipe,
      200,
      "Foundry recipe survives daemon restart",
    );
    assertThat(
      restartedRecipe.body.recipe?.agentgres?.head === persistedHeads.recipe,
      "Foundry recipe restart read retains the exact head",
    );
    assertThat(
      restartedRecipe.body.recipe?.content_hash ===
        recipe.body.recipe.content_hash,
      "Foundry recipe restart read retains content bytes",
    );

    const restartedProgram = await api(
      daemon,
      "restart_foundry_program_read",
      "GET",
      programRoute,
    );
    expectStatus(
      restartedProgram,
      200,
      "Foundry program survives daemon restart",
    );
    assertThat(
      restartedProgram.body.program?.agentgres?.head === persistedHeads.program,
      "Foundry program restart read retains the exact head",
    );
    assertThat(
      restartedProgram.body.program?.status === "completed",
      "Foundry program remains completed",
    );
    assertThat(
      restartedProgram.body.program?.current_checkpoint?.restore_verified ===
        true,
      "checkpoint verification survives daemon restart",
    );

    const restartedDatasets = await api(
      daemon,
      "restart_foundry_dataset_list",
      "GET",
      "/v1/hypervisor/foundry/dataset-snapshots",
    );
    expectStatus(
      restartedDatasets,
      200,
      "Foundry dataset inventory survives daemon restart",
    );
    assertThat(
      restartedDatasets.body.dataset_snapshots?.some(
        (snapshot) =>
          snapshot.dataset_snapshot_ref ===
            dataset.body.dataset_snapshot.dataset_snapshot_ref &&
          snapshot.content_hash === dataset.body.dataset_snapshot.content_hash,
      ),
      "restarted dataset inventory retains the materialized snapshot",
    );

    const restartedProposals = await api(
      daemon,
      "restart_foundry_qualification_proposals",
      "GET",
      "/v1/hypervisor/foundry/qualification-proposals",
    );
    expectStatus(
      restartedProposals,
      200,
      "qualification proposal survives daemon restart",
    );
    assertThat(
      restartedProposals.body.qualification_proposals?.some(
        (candidate) =>
          candidate.program_id === programId &&
          candidate.activation_performed === false,
      ),
      "restarted qualification remains proposal-only",
    );

    report.status = "passed";
  } catch (error) {
    report.status = "failed";
    report.error = {
      name: error instanceof Error ? error.name : "Error",
      message: error instanceof Error ? error.message : String(error),
      daemon_log_tail: daemon?.log?.().slice(-16_000) ?? "",
    };
    throw error;
  } finally {
    if (daemon) await daemon.close();
    if (dataDir) fs.rmSync(dataDir, { recursive: true, force: true });
    writeReport();
  }
}

try {
  await run();
  console.log(
    `implementation daemon smoke passed; report: ${path.relative(root, reportPath)}`,
  );
} catch (error) {
  console.error(
    error instanceof Error ? (error.stack ?? error.message) : String(error),
  );
  process.exitCode = 1;
}
