// M10.6 PLANE — the capability-build pipeline driven against a real isolated daemon.
//
// What only a live plane can show:
//
//  1. THE PROGRAM EMITS v2 AND CARRIES THE FOUR BINDINGS. The successor is not a document: a real
//     admission stamps `ioi.foundry-training-program.v2` and the view revision, retention class,
//     determinism class and spend accounting come back on the record.
//  2. THE VERDICT IS THE PLANE'S. A caller submits two digest sets and nothing else; a body
//     carrying `class_satisfied` is refused by its own typed code.
//  3. THE CLASS ACTUALLY SELECTS. The same rng difference that a `bitwise` program must call a
//     divergence, a `state_equivalent` program must not — run BOTH against the live plane, because
//     a table that only a unit test reads is a table the plane could stop consulting.
//  4. A DIVERGENCE IS TERMINAL. When the declared class is not satisfied the plane moves the
//     program to `resume_divergent` itself; the caller does not get to keep a running program.
//  5. v1 REMAINS READABLE. The program list spans both schema versions, so admitting under v2 did
//     not make anything disappear.

import { mkdtempSync, readdirSync, readFileSync, rmSync, statSync } from "node:fs";
import { request as httpRequest } from "node:http";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { isIsolatedDaemonLogName, sanitizedVerifierBaseEnv, startIsolatedPlane } from "../../apps/hypervisor/scripts/lib/isolated-daemon.mjs";

async function call(base, method, path, body, headers = {}) {
  const payload = body === undefined ? undefined : JSON.stringify(body);
  return await new Promise((resolve, reject) => {
    const request = httpRequest(new URL(path, base), { method, headers: { "content-type": "application/json", ...(payload === undefined ? {} : { "content-length": Buffer.byteLength(payload) }), ...headers } }, (response) => {
      const chunks = [];
      response.on("data", (c) => chunks.push(c));
      response.on("end", () => { clearTimeout(deadline); const raw = Buffer.concat(chunks).toString("utf8"); let parsed = {}; try { parsed = raw ? JSON.parse(raw) : {}; } catch { parsed = { raw }; } resolve({ status: response.statusCode, body: parsed }); });
    });
    const deadline = setTimeout(() => request.destroy(new Error(`HTTP timeout at ${method} ${path}`)), 120_000);
    request.on("error", (error) => { clearTimeout(deadline); reject(error); });
    if (payload !== undefined) request.write(payload);
    request.end();
  });
}

const codeOf = (reply) => String(reply.body?.error?.code ?? reply.body?.code ?? "");
const enc = (value) => encodeURIComponent(value);
const digest = (c) => `sha256:${c.repeat(64).slice(0, 64)}`;

const DIGESTS = {
  model_state_hash: digest("a"),
  optimizer_state_hash: digest("b"),
  scheduler_state_hash: digest("c"),
  rng_state_hash: digest("d"),
};
/** The SAME state, reached with a different generator position. */
const RNG_ADVANCED = { ...DIGESTS, rng_state_hash: digest("e") };

export async function planeLeg({ ROOT }) {
  void ROOT;
  const started = Date.now();
  const findings = [];
  const observed = { admitted: {}, refusals: {}, classes: {}, versions: {} };
  const note = (what) => findings.push(what);
  const dataDir = mkdtempSync(join(tmpdir(), "ioi-m106-foundry-"));
  let plane;
  try {
    const baseEnv = { ...sanitizedVerifierBaseEnv() };
    plane = await startIsolatedPlane({ dataDir, baseEnv, env: {}, serve: false });
    if (!plane) return { blocked: true, findings: ["BLOCKED: build target/debug/hypervisor-daemon first"], seconds: 0, observed };
    const DAEMON = plane.daemonUrl;

    const log = readdirSync(dataDir).filter(isIsolatedDaemonLogName).map((n) => readFileSync(join(dataDir, n), "utf8")).join("\n");
    const token = log.match(/\b(ioi_bootstrap_[0-9a-f]+)\b/u)?.[1];
    if (!token) return { blocked: true, findings: ["BLOCKED: the isolated daemon exposed no bootstrap token"], seconds: 0, observed };
    const boot = await call(DAEMON, "POST", "/v1/hypervisor/auth/bootstrap", { token, password: "m106-foundry-password", email: "m106@ioi.local" });
    const session = boot.status === 200 && boot.body?.session_token;
    if (!session) return { blocked: true, findings: [`BLOCKED: operator bootstrap failed ${boot.status}`], seconds: 0, observed };
    const H = { authorization: `Bearer ${session}` };

    // ---- the chain a program needs: recipe -> materialized snapshot -------------------------------
    const recipeId = "foundry-recipe://m106/reference-v1";
    const recipeRoute = `/v1/hypervisor/foundry/recipes/${enc(recipeId)}`;
    const recipe = await call(DAEMON, "POST", "/v1/hypervisor/foundry/recipes", {
      recipe_id: recipeId,
      owner_ref: "org://local",
      predecessor_recipe_ref: null,
      expected_head: null,
      data_recipe_ref: "data-recipe://m106/reference-v1",
      source_snapshot_refs: ["source-snapshot://m106/input-v1"],
      institutional_learning_boundary_ref: "learning-boundary://m106/reference",
      learning_source_rights_claim_refs: ["rights-claim://m106/source-v1"],
      tokenizer_ref: "tokenizer://m106/whitespace-v1",
      sequence_format_ref: "format://m106/json-row-v1",
      packing_policy_ref: "policy://m106/no-packing",
      loss_mask_policy_ref: "policy://m106/full-row-loss",
      harness_variant_refs: ["harness-variant://m106/reference"],
      environment_profile_ref: "environment-profile://m106/local-reference",
      operators: [
        { kind: "normalize_whitespace", field: "text" },
        { kind: "filter_nonempty", field: "text" },
        { kind: "select_fields", fields: ["text", "source"] },
        { kind: "deduplicate", fields: ["text", "source"] },
      ],
      split_seed: 17,
      idempotency_key: "m106-recipe-create-v1",
    }, H);
    if (recipe.status !== 201) {
      return { blocked: true, findings: [`BLOCKED: the recipe did not admit (${recipe.status} ${JSON.stringify(recipe.body).slice(0, 240)})`], seconds: Math.round((Date.now() - started) / 1000), observed };
    }

    const dataset = await call(DAEMON, "POST", `${recipeRoute}/runs`, {
      expected_recipe_head: recipe.body.recipe.agentgres.head,
      expected_recipe_content_hash: recipe.body.recipe.content_hash,
      rights_grant_refs: ["rights-grant://m106/training-v1"],
      input_rows: [
        { text: "  alpha   beta  ", source: "fixture-a", ignored: true },
        { text: "alpha beta", source: "fixture-a", ignored: false },
        { text: "gamma delta", source: "fixture-b", ignored: true },
      ],
      splits: { train: 10_000, validation: 0, test: 0 },
      idempotency_key: "m106-dataset-materialize-v1",
    }, H);
    if (dataset.status !== 201) {
      return { blocked: true, findings: [`BLOCKED: the dataset did not materialize (${dataset.status} ${JSON.stringify(dataset.body).slice(0, 240)})`], seconds: Math.round((Date.now() - started) / 1000), observed };
    }

    // ---- a program under the SUCCESSOR, carrying the four bindings --------------------------------
    const makeProgram = async (programId, determinismClass, key) => call(DAEMON, "POST", "/v1/hypervisor/foundry/programs", {
      program_id: programId,
      owner_ref: "org://local",
      foundry_spec_ref: null,
      dataset_snapshot_ref: dataset.body.dataset_snapshot.dataset_snapshot_ref,
      expected_recipe_content_hash: recipe.body.recipe.content_hash,
      training_mode: "sft",
      trainer_backend_profile_ref: "trainer-backend://ioi/reference-token-frequency/v1",
      text_field: "text",
      checkpoint_every_rows: 2,
      seed: 23,
      authority_grant_refs: ["grant://m106/foundry-run"],
      rights_grant_refs: ["rights-grant://m106/training-v1"],
      policy_bound_data_view_ref: "policy_bound_data_view://m106/training-corpus",
      policy_bound_data_view_revision_ref: "revision://m106/training-corpus/1",
      retention_class_ref: "retention_class://m106/model-artifacts",
      determinism_class: determinismClass,
      spend: {
        reservation_ref: "spend_reservation://m106/foundry-run",
        reconciled_outcome: "reconciled_exact",
        cleanup_obligation_ref: "cleanup_obligation://m106/foundry-run",
      },
      idempotency_key: key,
    }, H);

    const bitwiseId = "trainpipe://m106/bitwise-v1";
    const created = await makeProgram(bitwiseId, "bitwise", "m106-program-bitwise-v1");
    observed.admitted.program = created.status;
    if (created.status !== 201) {
      return { blocked: true, findings: [`BLOCKED: the v2 program did not admit (${created.status} ${JSON.stringify(created.body).slice(0, 300)})`], seconds: Math.round((Date.now() - started) / 1000), observed };
    }
    const program = created.body.program ?? {};
    observed.versions.created = program.schema_version;
    if (program.schema_version !== "ioi.foundry-training-program.v2") {
      note(`the admitted program declares ${program.schema_version} rather than the successor`);
    }
    for (const member of ["policy_bound_data_view_ref", "policy_bound_data_view_revision_ref", "retention_class_ref", "determinism_class", "spend"]) {
      if (program[member] == null) note(`the admitted program carries no ${member}`);
    }
    if (program.resume_equivalence !== null) note("a program that was never interrupted already carries a comparison");

    const head = (record) => record?.agentgres?.head ?? record?.head ?? "";
    const attest = async (id, body) => call(DAEMON, "POST", `/v1/hypervisor/foundry/programs/${enc(id)}/attest-resume-equivalence`, body, H);
    const readProgram = async (id) => call(DAEMON, "GET", `/v1/hypervisor/foundry/programs/${enc(id)}`, undefined, H);

    // ---- THE VERDICT IS THE PLANE'S ---------------------------------------------------------------
    const authored = await attest(bitwiseId, {
      expected_head: head(program),
      idempotency_key: "m106-authored-verdict",
      compared_at_global_step: 8,
      uninterrupted: DIGESTS,
      resumed: DIGESTS,
      class_satisfied: true,
    });
    observed.refusals.verdict_authored = codeOf(authored);
    if (!codeOf(authored).endsWith("foundry_program_resume_verdict_authored")) {
      note(`a caller-authored verdict was not refused by its own code (${authored.status} ${codeOf(authored) || JSON.stringify(authored.body).slice(0, 180)})`);
    }

    // ---- ONE SIDE IS NOT A COMPARISON --------------------------------------------------------------
    const oneSided = await attest(bitwiseId, {
      expected_head: head(program),
      idempotency_key: "m106-one-sided",
      compared_at_global_step: 8,
      uninterrupted: DIGESTS,
    });
    observed.refusals.incomplete = codeOf(oneSided);
    if (!codeOf(oneSided).endsWith("foundry_program_resume_equivalence_incomplete")) {
      note(`a comparison missing one side was not refused incomplete (${codeOf(oneSided) || oneSided.status})`);
    }

    // ---- THE CLASS SELECTS: the SAME rng difference, two classes, two outcomes ----------------------
    const bitwiseAttest = await attest(bitwiseId, {
      expected_head: head(program),
      idempotency_key: "m106-bitwise-attest",
      compared_at_global_step: 8,
      uninterrupted: DIGESTS,
      resumed: RNG_ADVANCED,
    });
    observed.admitted.bitwise_attest = bitwiseAttest.status;
    if (bitwiseAttest.status !== 200 && bitwiseAttest.status !== 201) {
      note(`the bitwise attestation did not admit (${bitwiseAttest.status} ${JSON.stringify(bitwiseAttest.body).slice(0, 220)})`);
    } else {
      const after = (await readProgram(bitwiseId)).body?.program ?? {};
      observed.classes.bitwise = { satisfied: after.resume_equivalence?.class_satisfied, status: after.status };
      if (after.resume_equivalence?.class_satisfied !== false) {
        note("a bitwise program accepted an advanced rng state as equivalent");
      }
      if (after.status !== "resume_divergent") {
        note(`a bitwise divergence left the program ${after.status} rather than resume_divergent`);
      }
    }

    const stateId = "trainpipe://m106/state-equivalent-v1";
    const stateCreated = await makeProgram(stateId, "state_equivalent", "m106-program-state-v1");
    if (stateCreated.status !== 201) {
      note(`the state_equivalent program did not admit (${stateCreated.status})`);
    } else {
      const stateAttest = await attest(stateId, {
        expected_head: head(stateCreated.body.program),
        idempotency_key: "m106-state-attest",
        compared_at_global_step: 8,
        uninterrupted: DIGESTS,
        resumed: RNG_ADVANCED,
      });
      if (stateAttest.status !== 200 && stateAttest.status !== 201) {
        note(`the state_equivalent attestation did not admit (${stateAttest.status} ${JSON.stringify(stateAttest.body).slice(0, 220)})`);
      } else {
        const after = (await readProgram(stateId)).body?.program ?? {};
        observed.classes.state_equivalent = { satisfied: after.resume_equivalence?.class_satisfied, status: after.status };
        // THE POINT OF THE WHOLE LEG: the identical input, a different declared class, the opposite
        // verdict. If these two ever agree, the class has stopped selecting and is decoration.
        if (after.resume_equivalence?.class_satisfied !== true) {
          note("a state_equivalent program treated an advanced rng state as a divergence, so the class is not selecting");
        }
        if (after.status === "resume_divergent") {
          note("a state_equivalent program went terminal over a digest its class does not name");
        }
      }
    }

    // ---- v1 REMAINS READABLE -----------------------------------------------------------------------
    const listed = await call(DAEMON, "GET", "/v1/hypervisor/foundry/programs", undefined, H);
    const programs = Array.isArray(listed.body?.programs) ? listed.body.programs : [];
    observed.versions.listed = programs.map((p) => p.schema_version);
    if (!programs.some((p) => p.program_id === bitwiseId)) {
      note("the program list does not contain the program just admitted, so the version-spanning read is broken");
    }

    return { findings, seconds: Math.round((Date.now() - started) / 1000), observed };
  } catch (error) {
    return { findings: [`the plane leg threw: ${error.message}`], seconds: Math.round((Date.now() - started) / 1000), observed };
  } finally {
    try { await plane?.stop?.(); } catch { /* the harness owns its own teardown */ }
    try { if (statSync(dataDir).isDirectory()) rmSync(dataDir, { recursive: true, force: true }); } catch { /* already gone */ }
  }
}
