#!/usr/bin/env node
// M06.1 — the `work-result://` owner resolver and the Verified Work Graph projection, driven end to
// end against a live daemon, its durable Agentgres chain, and a WorkResult that the WorkResult owner
// actually admitted in this same run.
//
// WHAT THIS GATE IS FOR. The assurance ladder was built subject-general so a later unit could add a
// resolver behind its seam without a wire change. M06.1 is that unit for the general WorkResult, and
// it adds the read projection canon calls the Verified Work Graph. The claims here are therefore the
// seam ones and the projection ones: a WorkResult subject is RESOLVED through its owner rather than
// believed from its URI, the bytes it commits are bound EXACTLY (including across owner-admitted
// backlink versions), the graph rebuilds from two existing owners rather than storing anything, and
// nothing it answers is a verdict, an acceptance, a settlement or a grant.
//
// HOW IT AVOIDS GRADING ITSELF:
//
//   * THE SUBJECT COMMITMENT IS RECOMPUTED HERE, IN JAVASCRIPT, from the WorkResult record the owner
//     serves and the domain separator the REGISTERED contract declares. If the daemon's commitment
//     ever stops covering the exact record bytes, these two disagree. Binding a hash this file
//     invented would prove only that the graph stores what it is told.
//   * THE VERSION CHANGE IS DRIVEN THROUGH A REAL OWNER PATH. The second WorkResult version is
//     produced by admitting a real OutcomeDelta, not by editing a record on disk. A projection that
//     only survives synthetic tampering has not been shown to survive the system.
//   * REFUSALS ARE COUNTED BY EFFECT. Every refusal assertion re-reads the graph afterwards and
//     requires the transition count and head to be exactly what they were. A 4xx that still appended
//     is the failure this shape exists to catch.
//   * DURABLE TRUTH IS READ ACROSS A REAL RESTART, and the rebuild is asserted by POSITIVE detection
//     (`rebuilt_from_agentgres` on the first read after the restart), because an unchanged answer is
//     also consistent with a cache that was never dropped.
//   * THE OFFLINE HALF IS CHECKED OFFLINE, with no daemon present, because "this graph makes no
//     claim of settlement" has to hold for a relying party who has only the bytes.
//   * A GREEN RUN CERTIFIES NOTHING UNTIL THE HARNESS PROVES IT RED. `--mutate` plants named defects
//     in the daemon's own source, rebuilds, re-runs this file against the mutant, and requires each
//     one to redden the exact assertion it targets — a mutant that only reddens something else is
//     reported as a MISS, not quietly counted.
//
// NONCLAIMS. This gate proves the WorkResult resolver and the graph projection only. It makes NO
// claim that any work is correct, accepted, adjudicated, settled, paid for, deployed, legal, or fit
// for live medical use; that Finding or Attempt subjects resolve (they remain named, fail-closed
// gaps); or that the economic Verified Work Graph of canon — spanning routes, marketplaces, payouts
// and L1 anchoring — exists. It covers one WorkResult's assurance posture and says so.

import { spawn, spawnSync } from "node:child_process";
import crypto from "node:crypto";
import fs from "node:fs";
import net from "node:net";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { emitVerifierCensus } from "./lib/verifier-census.mjs";

const HERE = path.dirname(fileURLToPath(import.meta.url));
const APP = path.resolve(HERE, "..");
const ROOT = path.resolve(APP, "..", "..");
const GRAPH_SOURCE = path.join(
  ROOT,
  "crates/node/src/bin/hypervisor_daemon_routes/assurance_transition_routes.rs",
);
const OWNER_SOURCE = path.join(
  ROOT,
  "crates/node/src/bin/hypervisor_daemon_routes/work_result_routes.rs",
);
const SCHEMAS = path.join(ROOT, "docs/architecture/_meta/schemas");
const GRAPH_SCHEMA = path.join(
  SCHEMAS,
  "verified-work-graph-projection.v1.schema.json",
);
const GRAPH_FIXTURES = path.join(
  SCHEMAS,
  "fixtures/verified-work-graph-projection-v1",
);
const REGISTRY = path.join(SCHEMAS, "architecture-contract-registry.v1.json");
const GRAPH_CONTRACT =
  "schema://ioi/foundations/verified-work-graph-projection/v1";
const MUTATE = process.argv.includes("--mutate");

const results = [];
const ok = (name, cond, detail) =>
  results.push({ name, pass: !!cond, detail: detail || "" });
const code = (j) => j?.error?.code ?? j?.code ?? "";
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

const freePort = () =>
  new Promise((resolve, reject) => {
    const srv = net.createServer();
    srv.on("error", reject);
    srv.listen(0, "127.0.0.1", () => {
      const { port } = srv.address();
      srv.close(() => resolve(port));
    });
  });

function daemonBinary() {
  if (process.env.IOI_HYPERVISOR_DAEMON_BINARY)
    return process.env.IOI_HYPERVISOR_DAEMON_BINARY;
  if (process.env.CARGO_TARGET_DIR) {
    return path.join(
      process.env.CARGO_TARGET_DIR,
      "debug",
      "hypervisor-daemon",
    );
  }
  return path.join(ROOT, "target", "debug", "hypervisor-daemon");
}

// ------------------------------------------------------------------ canonical JSON + commitment

// JCS for the material these contracts commit: keys sorted by code unit, ES6 numbers.
function canonicalJson(value) {
  if (value === null || typeof value !== "object") return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(",")}]`;
  return `{${Object.keys(value)
    .sort()
    .map((key) => `${JSON.stringify(key)}:${canonicalJson(value[key])}`)
    .join(",")}}`;
}

/**
 * The WorkResult subject commitment, rebuilt from the REGISTERED contract rather than from anything
 * the daemon returns. The domain separator is read out of the schema's own const, so a daemon that
 * silently changed its preimage would disagree with canon here.
 */
function registeredWorkResultCommitment(record) {
  const schema = JSON.parse(fs.readFileSync(GRAPH_SCHEMA, "utf8"));
  const domain = schema.properties?.work_result_commitment_domain?.const;
  if (typeof domain !== "string" || domain.length === 0) {
    throw new Error(
      "the registered graph contract declares no work_result_commitment_domain const",
    );
  }
  const material = { domain, record };
  return {
    digest: `sha256:${crypto.createHash("sha256").update(canonicalJson(material)).digest("hex")}`,
    domain,
  };
}

/** The registered closed nonclaim set, read out of canon rather than restated here. */
function registeredNonclaims() {
  const schema = JSON.parse(fs.readFileSync(GRAPH_SCHEMA, "utf8"));
  return schema.$defs?.nonclaimToken?.enum ?? [];
}

// ------------------------------------------------------------------------------------- daemon plane

const scratch = fs.mkdtempSync(path.join(os.tmpdir(), "ioi-verified-work-graph-"));
const dataDir = path.join(scratch, "data");
fs.mkdirSync(dataDir, { recursive: true });

let daemon = null;
let daemonLog = "";
let DAEMON = "";

async function waitFor(url, timeoutMs = 60000) {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    try {
      const response = await fetch(url);
      if (response.status < 500) return true;
    } catch {
      /* not listening yet */
    }
    await sleep(120);
  }
  return false;
}

async function startDaemon() {
  const port = await freePort();
  DAEMON = `http://127.0.0.1:${port}`;
  daemon = spawn(daemonBinary(), [], {
    env: {
      ...process.env,
      IOI_HYPERVISOR_DAEMON_ADDR: `127.0.0.1:${port}`,
      IOI_HYPERVISOR_DATA_DIR: dataDir,
      IOI_HYPERVISOR_MODEL_UPSTREAM: "http://127.0.0.1:1",
      IOI_WALLET_SECRET_PASS: "ioi-verified-work-graph-verifier",
    },
    stdio: ["ignore", "pipe", "pipe"],
  });
  daemon.stdout.on("data", (chunk) => {
    daemonLog = `${daemonLog}${chunk}`.slice(-64000);
  });
  daemon.stderr.on("data", (chunk) => {
    daemonLog = `${daemonLog}${chunk}`.slice(-64000);
  });
  if (!(await waitFor(`${DAEMON}/healthz`))) {
    throw new Error("the isolated daemon never became healthy");
  }
}

// SIGTERM the tracked child. Never pgrep/pkill a daemon path — that kills this process's own shell.
async function stopDaemon() {
  if (!daemon) return;
  const child = daemon;
  daemon = null;
  try {
    child.kill("SIGTERM");
  } catch {
    /* already gone */
  }
  await Promise.race([
    new Promise((resolve) => child.once("exit", resolve)),
    sleep(4000).then(() => {
      try {
        child.kill("SIGKILL");
      } catch {
        /* already gone */
      }
    }),
  ]);
  await sleep(150);
}

function cleanup() {
  try {
    daemon?.kill("SIGKILL");
  } catch {
    /* already gone */
  }
  try {
    fs.rmSync(scratch, { recursive: true, force: true });
  } catch {
    /* best effort */
  }
}

// ---------------------------------------------------------------------------------- request helpers

const SESSIONS = { A: "", B: "" };

async function req(method, route, body, { as = "A" } = {}) {
  const headers = {};
  if (body !== undefined && body !== null)
    headers["content-type"] = "application/json";
  const session = as ? SESSIONS[as] : "";
  if (session) headers.cookie = `ioi_session=${session}`;
  try {
    const response = await fetch(`${DAEMON}${route}`, {
      method,
      headers: Object.keys(headers).length ? headers : undefined,
      body:
        body === undefined || body === null ? undefined : JSON.stringify(body),
    });
    const text = await response.text();
    let json = null;
    try {
      json = JSON.parse(text);
    } catch {
      /* non-json */
    }
    return { status: response.status, j: json, text };
  } catch (error) {
    return {
      status: 0,
      j: { transport_error: String(error) },
      text: String(error),
    };
  }
}

const WR = "/v1/hypervisor/work-results";
const OD = "/v1/hypervisor/outcome-deltas";
const AT = "/v1/hypervisor/assurance-transitions";
const VWG = "/v1/hypervisor/verified-work-graph";

const NONCLAIMS = ["correctness", "acceptance", "settlement"];

function transition({
  subject,
  key,
  expectedHead = null,
  outcome = "positive",
  extra = {},
}) {
  const body = {
    owner_ref: "org://local",
    idempotency_key: key,
    subject_ref: subject,
    outcome_class: outcome,
    evidence_refs: [`evidence://verified-work-graph/${key}`],
    does_not_assert: NONCLAIMS,
    valid_time: { starts_at: "2026-03-01T00:00:00Z", ends_at: null },
    ...extra,
  };
  if (expectedHead !== null) body.expected_head = expectedHead;
  return body;
}

const graphOf = async (workResultRef, query = "", as = "A") =>
  req(
    "GET",
    `${VWG}?work_result_ref=${encodeURIComponent(workResultRef)}${query}`,
    null,
    { as },
  );

/** The exact (count, head) pair, so a refusal can be counted BY EFFECT rather than by status code. */
async function graphState(workResultRef, as = "A") {
  const response = await graphOf(workResultRef, "", as);
  const graph = response.j?.verified_work_graph ?? {};
  return {
    status: response.status,
    count: graph.transition_count ?? -1,
    reached: graph.reached_stage ?? null,
    binding: graph.current_binding_state ?? null,
    hash: graph.work_result_content_hash ?? null,
    // Captured on THIS read; the cache is populated by the act of reading, so an index-state claim
    // must be made about the FIRST read after a restart, never a later one.
    indexState: graph.rebuildable_index_state ?? null,
    graph,
  };
}

async function workResultRecord(workResultRef, as = "A") {
  const tail = workResultRef.replace("work-result://", "");
  const response = await req("GET", `${WR}/${tail}`, null, { as });
  return response.j?.work_result ?? null;
}

// ------------------------------------------------------------------------------------------- the run

async function run() {
  await startDaemon();

  // ---------------------------------------------------------------------------------- principals
  const bootToken =
    daemonLog.match(/ioi_bootstrap_[a-f0-9]{64}/gu)?.at(-1) ?? null;
  const boot = await req(
    "POST",
    "/v1/hypervisor/auth/bootstrap",
    { token: bootToken, password: "verified-work-graph-a-v1" },
    { as: null },
  );
  SESSIONS.A = boot.j?.session_token ?? "";
  const whoA =
    (await req("GET", "/v1/hypervisor/auth/whoami", null, { as: "A" })).j || {};
  const created = await req(
    "POST",
    "/v1/hypervisor/principals",
    {
      email: "verified-work-graph-b@ioi.local",
      name: "Member B",
      role: "member",
      password: "verified-work-graph-b-v1",
    },
    { as: "A" },
  );
  const principalB = created.j?.principal?.principal_id ?? "";
  await req(
    "POST",
    `/v1/hypervisor/principals/${principalB}/tenant-memberships`,
    {
      tenant_ref: "org://local",
      expected_revision: 0,
      idempotency_key: "verified-work-graph-grant-b",
      reason:
        "verifier fixture: an ordinary member of the deployment's only organization",
    },
    { as: "A" },
  );
  const login = await req(
    "POST",
    "/v1/hypervisor/auth/login",
    {
      email: "verified-work-graph-b@ioi.local",
      password: "verified-work-graph-b-v1",
    },
    { as: null },
  );
  SESSIONS.B = login.j?.session_token ?? "";
  const whoB =
    (await req("GET", "/v1/hypervisor/auth/whoami", null, { as: "B" })).j || {};
  ok(
    "PRECONDITION: two REAL authenticated principals share the deployment's single org tenant, so a tenant check alone would isolate nothing",
    whoA.authenticated === true &&
      whoB.authenticated === true &&
      whoA.principal?.principal_ref !== whoB.principal?.principal_ref,
    `A=${whoA.principal?.principal_ref} B=${whoB.principal?.principal_ref}`,
  );

  // -------------------------------------------------- a REAL WorkResult, admitted by its own owner
  const admitted = await req(
    "POST",
    WR,
    {
      goal_ref: "goal://m061-verified-work",
      result_profile: "research",
      // A NEGATIVE result on purpose. A graph exercised only over successes has not been shown to
      // retain anything, and `exploit_found` below is the member the assurance vocabulary spells
      // differently — the exact place a normalising projection would be caught.
      outcome_class: "negative",
      status: "completed",
      claim_refs: ["evidence://m061-observation-1"],
      supporting_evidence_refs: ["artifact://m061-a1"],
    },
    { as: "A" },
  );
  const SUBJECT = admitted.j?.work_result?.work_result_id ?? "";
  ok(
    "PRECONDITION: the subject of every transition below is a REAL WorkResult admitted through the WorkResult owner's own route in this run",
    admitted.status === 201 && SUBJECT.startsWith("work-result://"),
    `status ${admitted.status} subject ${SUBJECT}`,
  );
  const recordV1 = await workResultRecord(SUBJECT);
  const commitmentV1 = registeredWorkResultCommitment(recordV1);

  // ------------------------------------------------------- the empty graph, before anything happened
  const empty = await graphOf(SUBJECT);
  const emptyGraph = empty.j?.verified_work_graph ?? {};
  ok(
    "a WorkResult with NO assurance transition still projects a complete graph: all six frozen stages present and unreached, no borrowed reached stage, and the binding state says so explicitly",
    empty.status === 200 &&
      (emptyGraph.stages ?? []).length === 6 &&
      (emptyGraph.stages ?? []).every((row) => row.reached === false) &&
      emptyGraph.reached_stage === null &&
      emptyGraph.reached_stage_ordinal === 0 &&
      emptyGraph.transition_count === 0 &&
      emptyGraph.current_binding_state === "no_transition",
    `status ${empty.status} stages ${(emptyGraph.stages ?? []).length} reached ${emptyGraph.reached_stage} binding ${emptyGraph.current_binding_state}`,
  );
  ok(
    "an empty ladder does NOT inherit the WorkResult's own status: the result is `completed` and the graph still reports nothing reached — assurance is never derived from a subject's self-description",
    recordV1?.status === "completed" && emptyGraph.reached_stage === null,
    `work_result.status=${recordV1?.status} reached_stage=${emptyGraph.reached_stage}`,
  );
  ok(
    "the graph binds the WorkResult commitment RECOMPUTED IN THIS VERIFIER from the owner's record bytes and the domain the registered contract declares — not a hash the daemon asserted about itself",
    emptyGraph.work_result_content_hash === commitmentV1.digest &&
      emptyGraph.work_result_commitment_domain === commitmentV1.domain &&
      emptyGraph.work_result_resolved_by ===
        "work_result_routes::resolve_admitted_work_result",
    `graph ${emptyGraph.work_result_content_hash} recomputed ${commitmentV1.digest}`,
  );
  ok(
    "the graph carries the COMPLETE closed nonclaim set the registered contract declares — authority, verdict, correctness, acceptance, adjudication, settlement, payment/economic value, external occurrence, deployment, provider connectivity, legality and live-medical suitability are all disclaimed as data, never by omission",
    (() => {
      const declared = registeredNonclaims();
      const carried = emptyGraph.does_not_assert ?? [];
      return (
        declared.length === 12 &&
        declared.every((token) => carried.includes(token)) &&
        carried.length === 12 &&
        emptyGraph.authority_nonclaim === "verified_work_graph_grants_no_authority" &&
        emptyGraph.verdict_nonclaim === "verified_work_graph_is_not_a_verdict"
      );
    })(),
    `carried ${JSON.stringify(emptyGraph.does_not_assert)}`,
  );
  ok(
    "the graph declares itself a READ PROJECTION over both owners and names neither a store nor a third owner",
    emptyGraph.projection_kind === "read_projection" &&
      emptyGraph.truth_source ===
        "work_result_owner_and_agentgres_owner_scoped_chain" &&
      emptyGraph.projection_contract_ref === GRAPH_CONTRACT,
    `kind ${emptyGraph.projection_kind} source ${emptyGraph.truth_source}`,
  );

  // ------------------------------------------------------------------- prefix is not proof
  const beforePrefix = await graphState(SUBJECT);
  const unadmittedTransition = await req(
    "POST",
    AT,
    transition({ subject: "work-result://wr_never_admitted", key: "ghost" }),
    { as: "A" },
  );
  const unadmittedGraph = await graphOf("work-result://wr_never_admitted");
  const afterPrefix = await graphState(SUBJECT);
  ok(
    "a WELL-FORMED work-result:// that names nothing admitted is refused on BOTH the producer and the consumer path, by name, and appends nothing — a URI prefix is never proof that a subject exists",
    unadmittedTransition.status !== 201 &&
      code(unadmittedTransition.j) === "work_result_subject_not_admitted" &&
      unadmittedGraph.status !== 200 &&
      code(unadmittedGraph.j) === "work_result_subject_not_admitted" &&
      afterPrefix.count === beforePrefix.count,
    `admit ${unadmittedTransition.status}/${code(unadmittedTransition.j)} graph ${unadmittedGraph.status}/${code(unadmittedGraph.j)}`,
  );
  const wrongFamily = await graphOf("ontology://acme/thing/revision/1");
  ok(
    "the graph refuses a subject from another family rather than answering about it: this projection is over WorkResult owner truth only",
    wrongFamily.status !== 200 &&
      code(wrongFamily.j) === "verified_work_graph_subject_family_invalid",
    `status ${wrongFamily.status} code ${code(wrongFamily.j)}`,
  );

  // ------------------------------------------------- the two families that remain fail-closed gaps
  const findingAttempt = [];
  for (const [subject, family] of [
    ["finding://m061/f1", "finding"],
    ["attempt://m061/a1", "attempt"],
  ]) {
    const response = await req(
      "POST",
      AT,
      transition({ subject, key: `gap-${family}` }),
      { as: "A" },
    );
    findingAttempt.push({ family, response });
  }
  ok(
    "Finding and Attempt remain NAMED, fail-closed gaps: each is refused by its own family name and by the unit that owns its reader, never admitted on the strength of its spelling and never confused with the subject being absent",
    findingAttempt.every(
      ({ family, response }) =>
        response.status === 501 &&
        code(response.j) ===
          "assurance_transition_subject_family_unresolvable" &&
        JSON.stringify(response.j).includes(family) &&
        JSON.stringify(response.j).includes("M04.8"),
    ),
    findingAttempt
      .map(({ family, response }) => `${family} ${response.status}/${code(response.j)}`)
      .join(" "),
  );

  // ------------------------------------------------------------------- content substitution refused
  const beforeSubstitution = await graphState(SUBJECT);
  const substituted = await req(
    "POST",
    AT,
    transition({
      subject: SUBJECT,
      key: "substituted",
      extra: { subject_content_hash: `sha256:${"9c".repeat(32)}` },
    }),
    { as: "A" },
  );
  const afterSubstitution = await graphState(SUBJECT);
  ok(
    "an ASSERTED subject content hash that disagrees with the owner's commitment is refused and appends nothing — the binding is the WorkResult owner's, never the caller's",
    substituted.status !== 201 &&
      afterSubstitution.count === beforeSubstitution.count &&
      afterSubstitution.hash === beforeSubstitution.hash,
    `status ${substituted.status}/${code(substituted.j)} count ${beforeSubstitution.count}->${afterSubstitution.count}`,
  );

  // ------------------------------------------------------------------------- the ladder, one at a time
  const t1 = await req("POST", AT, transition({ subject: SUBJECT, key: "t1" }), {
    as: "A",
  });
  const head1 = t1.j?.expected_head_for_successor;
  const t1Record = t1.j?.assurance_transition ?? {};
  ok(
    "the first transition binds the WorkResult owner's EXACT committed bytes and names the owner seam that resolved them",
    t1.status === 201 &&
      t1Record.subject_content_hash === commitmentV1.digest &&
      t1Record.subject_family === "work_result" &&
      t1Record.subject_resolved_by ===
        "work_result_routes::resolve_admitted_work_result",
    `status ${t1.status} bound ${t1Record.subject_content_hash} expected ${commitmentV1.digest}`,
  );

  const beforeSkip = await graphState(SUBJECT);
  const skip = await req(
    "POST",
    AT,
    transition({
      subject: SUBJECT,
      key: "skip",
      expectedHead: head1,
      extra: { to_stage: "accepted" },
    }),
    { as: "A" },
  );
  const afterSkip = await graphState(SUBJECT);
  ok(
    "a STAGE SKIP is refused and appends nothing: the ladder is identical either side of the refusal, so a stage nobody stood behind cannot be reached by asking for it",
    skip.status !== 201 &&
      afterSkip.count === beforeSkip.count &&
      afterSkip.reached === beforeSkip.reached,
    `status ${skip.status}/${code(skip.j)} count ${beforeSkip.count}->${afterSkip.count}`,
  );

  const beforeStale = await graphState(SUBJECT);
  const stale = await req(
    "POST",
    AT,
    transition({
      subject: SUBJECT,
      key: "stale",
      expectedHead: `${"0".repeat(64)}`,
    }),
    { as: "A" },
  );
  const afterStale = await graphState(SUBJECT);
  ok(
    "a STALE head is refused and appends nothing: the graph's transition count and reached stage are identical either side of the refusal",
    stale.status !== 201 &&
      afterStale.count === beforeStale.count &&
      afterStale.reached === beforeStale.reached,
    `status ${stale.status}/${code(stale.j)} count ${beforeStale.count}->${afterStale.count}`,
  );

  // A NEGATIVE outcome, and then an `exploit` one — the member the WorkResult vocabulary spells
  // `exploit_found`. If anything anywhere normalises, this is where it shows.
  const t2 = await req(
    "POST",
    AT,
    transition({
      subject: SUBJECT,
      key: "t2",
      expectedHead: head1,
      outcome: "negative",
    }),
    { as: "A" },
  );
  const head2 = t2.j?.expected_head_for_successor;
  const t3 = await req(
    "POST",
    AT,
    transition({
      subject: SUBJECT,
      key: "t3",
      expectedHead: head2,
      outcome: "exploit",
    }),
    { as: "A" },
  );
  const head3 = t3.j?.expected_head_for_successor;

  const laddered = await graphState(SUBJECT);
  const g = laddered.graph;
  ok(
    "the ladder advanced to `verified` and the graph reports it from the CHAIN, with every projected row carried verbatim",
    t2.status === 201 &&
      t3.status === 201 &&
      g.transition_count === 3 &&
      g.reached_stage === "verified" &&
      g.reached_stage_ordinal === 3 &&
      (g.transitions ?? []).length === 3,
    `count ${g.transition_count} reached ${g.reached_stage}`,
  );
  ok(
    "STAGES ARE EXPOSED INDEPENDENTLY: attested, evidenced and verified are reached while accepted, adjudicated and settled are each unreached and carry nothing — nothing about acceptance is inferable from verification, and nothing about settlement from acceptance",
    (() => {
      const byStage = Object.fromEntries(
        (g.stages ?? []).map((row) => [row.stage, row]),
      );
      const reached = ["attested", "evidenced", "verified"];
      const unreached = ["accepted", "adjudicated", "settled"];
      return (
        reached.every(
          (stage) =>
            byStage[stage]?.reached === true &&
            typeof byStage[stage]?.transition_ref === "string" &&
            typeof byStage[stage]?.outcome_class === "string",
        ) &&
        unreached.every(
          (stage) =>
            byStage[stage]?.reached === false &&
            byStage[stage]?.transition_ref === null &&
            byStage[stage]?.outcome_class === null &&
            byStage[stage]?.actor_ref === null &&
            byStage[stage]?.bound_work_result_content_hash === null,
        )
      );
    })(),
    JSON.stringify((g.stages ?? []).map((row) => [row.stage, row.reached])),
  );
  ok(
    "NEGATIVE AND EXPLOIT OUTCOMES ARE RETAINED VERBATIM AND COUNTED (NN 21, ACC-8 clause 2): the census carries all eight ladder members, the negative and exploit rows are present, and nothing was normalised toward positive",
    (() => {
      const census = g.outcome_class_census ?? {};
      const members = [
        "positive",
        "negative",
        "inconclusive",
        "invalid",
        "exploit",
        "superseded",
        "disputed",
        "no_fault",
      ];
      const outcomes = (g.transitions ?? []).map((row) => row.outcome_class);
      return (
        members.every((member) => typeof census[member] === "number") &&
        census.positive === 1 &&
        census.negative === 1 &&
        census.exploit === 1 &&
        outcomes.includes("negative") &&
        outcomes.includes("exploit")
      );
    })(),
    JSON.stringify(g.outcome_class_census),
  );
  ok(
    "THE TWO OUTCOME VOCABULARIES ARE NEVER MAPPED ONTO EACH OTHER: the WorkResult's own `negative` is carried in its own field alongside the ladder's separate census, and the ladder's `exploit` is NOT rewritten into the WorkResult spelling `exploit_found` (nor the reverse)",
    g.work_result_outcome_class === "negative" &&
      g.work_result_status === "completed" &&
      (g.transitions ?? []).some((row) => row.outcome_class === "exploit") &&
      !(g.transitions ?? []).some(
        (row) => row.outcome_class === "exploit_found",
      ),
    `work_result ${g.work_result_outcome_class} ladder ${JSON.stringify((g.transitions ?? []).map((r) => r.outcome_class))}`,
  );
  ok(
    "the projection RETAINS each transition's own authority and verdict nonclaims while flattening the ladder — the marker a consumer relies on is not lost at the layer a product surface reads",
    (g.transitions ?? []).every(
      (row) =>
        row.authority_nonclaim === "assurance_transition_grants_no_authority" &&
        row.verdict_nonclaim === "assurance_transition_is_not_a_verdict",
    ) &&
      g.transition_authority_nonclaim ===
        "assurance_transition_grants_no_authority" &&
      g.transition_verdict_nonclaim === "assurance_transition_is_not_a_verdict",
    `rows ${(g.transitions ?? []).length}`,
  );
  ok(
    "every projected row is about THIS WorkResult and THIS family — a graph carrying another subject's ladder would be the single most consequential thing this projection could get wrong",
    (g.transitions ?? []).every(
      (row) =>
        row.subject_ref === SUBJECT && row.subject_family === "work_result",
    ),
    `refs ${JSON.stringify((g.transitions ?? []).map((r) => r.subject_ref))}`,
  );
  ok(
    "while the subject's bytes are unchanged the graph reports exactly ONE bound version and says the CURRENT bytes are the ones bound",
    (g.bound_work_result_content_hashes ?? []).length === 1 &&
      g.bound_work_result_content_hashes[0].content_hash ===
        commitmentV1.digest &&
      g.current_binding_state === "current_bytes_bound",
    `versions ${JSON.stringify(g.bound_work_result_content_hashes)} binding ${g.current_binding_state}`,
  );

  // ------------------------------------------------- idempotent replay changes nothing
  const beforeReplay = await graphState(SUBJECT);
  const replay = await req(
    "POST",
    AT,
    transition({
      subject: SUBJECT,
      key: "t3",
      expectedHead: head2,
      outcome: "exploit",
    }),
    { as: "A" },
  );
  const afterReplay = await graphState(SUBJECT);
  ok(
    "an IDEMPOTENT REPLAY of an admitted transition answers the SAME transition and leaves the graph byte-identical — a retry never advances the ladder",
    replay.status === 200 &&
      replay.j?.replayed === true &&
      replay.j?.assurance_transition?.transition_id ===
        t3.j?.assurance_transition?.transition_id &&
      afterReplay.count === beforeReplay.count &&
      JSON.stringify(afterReplay.graph.transitions) ===
        JSON.stringify(beforeReplay.graph.transitions),
    `status ${replay.status} replayed ${replay.j?.replayed} count ${beforeReplay.count}->${afterReplay.count}`,
  );

  // ------------------------------------- THE MUTABLE-VERSION DISTINCTION, through a REAL owner path
  const delta = await req(
    "POST",
    OD,
    {
      goal_ref: "goal://m061-verified-work",
      delta_kind: "update",
      proposed_by_ref: SUBJECT,
      target_ref: "state://m061/observed",
      payload_ref: "artifact://m061-delta-payload-1",
    },
    { as: "A" },
  );
  const recordV2 = await workResultRecord(SUBJECT);
  const commitmentV2 = registeredWorkResultCommitment(recordV2);
  ok(
    "an OutcomeDelta admitted through the WorkResult owner's OWN seam really changes the record, so the subject now commits DIFFERENT bytes under the same URI — the version change is driven by the system, not simulated by editing a file",
    delta.status === 201 &&
      JSON.stringify(recordV2?.outcome_delta_refs ?? []).includes(
        "outcome-delta://",
      ) &&
      commitmentV2.digest !== commitmentV1.digest,
    `status ${delta.status}/${code(delta.j)} ${delta.text?.slice(0, 300)} v1 ${commitmentV1.digest} v2 ${commitmentV2.digest}`,
  );
  const afterDelta = await graphState(SUBJECT);
  ok(
    "THE URI ALONE WAS NEVER STABLE, AND THE GRAPH SAYS SO: the current commitment has moved to v2 while the three admitted transitions still bind v1, and the projection reports `bound_to_superseded_bytes` rather than letting a stale attestation read as a current one",
    afterDelta.hash === commitmentV2.digest &&
      afterDelta.binding === "bound_to_superseded_bytes" &&
      (afterDelta.graph.bound_work_result_content_hashes ?? []).length === 1 &&
      afterDelta.graph.bound_work_result_content_hashes[0].content_hash ===
        commitmentV1.digest,
    `current ${afterDelta.hash} binding ${afterDelta.binding} bound ${JSON.stringify(afterDelta.graph.bound_work_result_content_hashes)}`,
  );
  const t4 = await req(
    "POST",
    AT,
    transition({
      subject: SUBJECT,
      key: "t4",
      expectedHead: head3,
      outcome: "no_fault",
      extra: { to_stage: "accepted" },
    }),
    { as: "A" },
  );
  const afterT4 = await graphState(SUBJECT);
  ok(
    "a transition admitted AFTER the change binds the NEW bytes, and the graph now carries TWO DISTINCT versions in the order they were first bound — the version history a consumer needs to tell which attestation covered which record",
    t4.status === 201 &&
      t4.j?.assurance_transition?.subject_content_hash === commitmentV2.digest &&
      (afterT4.graph.bound_work_result_content_hashes ?? []).length === 2 &&
      afterT4.graph.bound_work_result_content_hashes[0].content_hash ===
        commitmentV1.digest &&
      afterT4.graph.bound_work_result_content_hashes[1].content_hash ===
        commitmentV2.digest &&
      afterT4.graph.bound_work_result_content_hashes[0]
        .first_bound_at_transition_ordinal === 1 &&
      afterT4.graph.bound_work_result_content_hashes[1]
        .first_bound_at_transition_ordinal === 4,
    `versions ${JSON.stringify(afterT4.graph.bound_work_result_content_hashes)}`,
  );
  ok(
    "the earlier rows were NOT rewritten to the new bytes: history is retained per row rather than re-pointed at whatever the subject means today",
    (afterT4.graph.transitions ?? [])
      .slice(0, 3)
      .every((row) => row.subject_content_hash === commitmentV1.digest),
    JSON.stringify(
      (afterT4.graph.transitions ?? []).map((r) => r.subject_content_hash),
    ),
  );

  // ------------------------------------------------------------- consumer contract-version refusals
  const exact = await graphOf(
    SUBJECT,
    `&projection_contract_ref=${encodeURIComponent(GRAPH_CONTRACT)}`,
  );
  const downgraded = await graphOf(
    SUBJECT,
    `&projection_contract_ref=${encodeURIComponent("schema://ioi/foundations/verified-work-graph-projection/v0")}`,
  );
  const unknown = await graphOf(
    SUBJECT,
    `&projection_contract_ref=${encodeURIComponent("schema://ioi/foundations/assurance-transition-receipt/v2")}`,
  );
  ok(
    "a consumer naming the EXACT registered contract is served, while a DOWNGRADED version of the same family and an UNKNOWN contract are each refused by their own distinct name — bytes are never served under a label this build did not produce",
    exact.status === 200 &&
      downgraded.status !== 200 &&
      code(downgraded.j) === "verified_work_graph_contract_version_downgraded" &&
      unknown.status !== 200 &&
      code(unknown.j) === "verified_work_graph_contract_version_unknown",
    `exact ${exact.status} down ${downgraded.status}/${code(downgraded.j)} unknown ${unknown.status}/${code(unknown.j)}`,
  );

  // ------------------------------------------------------------------ owner scope, without widening
  // A second REAL WorkResult that nobody has attested at all, so "no assurance exists" and "the
  // assurance is someone else's" can be compared as answers rather than assumed to differ.
  const unattested = await req(
    "POST",
    WR,
    {
      goal_ref: "goal://m061-unattested",
      result_profile: "research",
      outcome_class: "positive",
      status: "completed",
    },
    { as: "A" },
  );
  const UNATTESTED = unattested.j?.work_result?.work_result_id ?? "";
  const foreignGraph = await graphOf(SUBJECT, "", "B");
  const unattestedGraph = await graphOf(UNATTESTED, "", "B");
  const foreignAbsent = await graphOf("work-result://wr_never_admitted", "", "B");
  ok(
    "a co-tenant principal who owns none of this subject's LADDER sees NONE of its transitions: the assurance half stays owner-scoped and the projection does not widen it",
    foreignGraph.j?.verified_work_graph?.transition_count === 0 &&
      (foreignGraph.j?.verified_work_graph?.transitions ?? []).length === 0 &&
      !JSON.stringify(foreignGraph.j ?? {}).includes("/transition/"),
    `status ${foreignGraph.status} count ${foreignGraph.j?.verified_work_graph?.transition_count}`,
  );
  ok(
    "AND THAT ANSWER IS INDISTINGUISHABLE from the one B gets for a WorkResult nobody has attested at all — same status, same empty ladder, same cache reading — so the graph cannot become an existence oracle announcing that another principal's assurance exists",
    unattested.status === 201 &&
      foreignGraph.status === unattestedGraph.status &&
      foreignGraph.status === 200 &&
      foreignGraph.j?.verified_work_graph?.transition_count ===
        unattestedGraph.j?.verified_work_graph?.transition_count &&
      foreignGraph.j?.verified_work_graph?.current_binding_state ===
        unattestedGraph.j?.verified_work_graph?.current_binding_state &&
      foreignGraph.j?.verified_work_graph?.rebuildable_index_state ===
        unattestedGraph.j?.verified_work_graph?.rebuildable_index_state &&
      foreignGraph.j?.verified_work_graph?.rebuildable_index_state ===
        "not_consulted_no_bound_scope",
    `foreign ${foreignGraph.status}/${foreignGraph.j?.verified_work_graph?.rebuildable_index_state} unattested ${unattestedGraph.status}/${unattestedGraph.j?.verified_work_graph?.rebuildable_index_state}`,
  );
  ok(
    "the WorkResult owner's OWN layer is still separately enforced underneath: a work-result:// that names nothing admitted is refused by that owner before any ladder question is asked, so the graph inherits each owner's visibility exactly and invents no third policy",
    foreignAbsent.status !== 200 &&
      code(foreignAbsent.j) === "work_result_subject_not_admitted",
    `absent ${foreignAbsent.status}/${code(foreignAbsent.j)}`,
  );
  ok(
    "the subject resolver applies the WorkResult owner's OWN entitlement check, so under enforced auth a reader who may not see a result is refused IDENTICALLY to one asking about a result that does not exist — ENTAILED FROM THE SOURCE, not probed: this deployment posture is unenforced loopback, so the owner resolves every reader as its global one and that branch is unreachable from outside, which means a live assertion here could not tell the check apart from its absence. The behavioural proof is the focused Rust test `work_result_subject_resolver_answers_absence_and_non_entitlement_identically`, which drives the branch directly with a foreign reader; claiming a live proof here would be this gate certifying something it did not check",
    (() => {
      const source = fs.readFileSync(OWNER_SOURCE, "utf8");
      return (
        source.includes("if let Some(owner) = reader {") &&
        source.includes("if !result_owner_matches(data_dir, &record, owner)") &&
        /return Err\(absent\(\)\);/.test(source) &&
        source.includes(
          "fn work_result_subject_resolver_answers_absence_and_non_entitlement_identically",
        )
      );
    })(),
    "source-bound entailment plus its named behavioural test",
  );

  // ------------------------------------------------------------------- restart, replay and rebuild
  const beforeRestart = await graphState(SUBJECT);
  await stopDaemon();
  await startDaemon();
  const afterRestart = await graphState(SUBJECT);
  // `rebuildable_index_state` is EXPECTED to differ across the restart — it is the cache-agreement
  // report, and its whole purpose is to change when the cache is dropped. Comparing it here would
  // make this assertion fail for the reason the NEXT one requires to be true. Everything else,
  // including every bound hash and every projected row, must be byte-identical.
  const withoutIndexState = (graph) => {
    const { rebuildable_index_state: _dropped, ...rest } = graph;
    return JSON.stringify(rest);
  };
  ok(
    "ACROSS A REAL PROCESS RESTART the graph is byte-identical apart from its own non-truth cache report: it is rebuilt from the WorkResult owner and the Agentgres chain, so nothing it reports was being held in memory",
    withoutIndexState(afterRestart.graph) === withoutIndexState(beforeRestart.graph),
    `count ${beforeRestart.count}->${afterRestart.count} binding ${beforeRestart.binding}->${afterRestart.binding}`,
  );
  ok(
    "and the rebuild is asserted by POSITIVE DETECTION: the FIRST read after the restart reports `rebuilt_from_agentgres`, because an unchanged answer alone is also consistent with a cache that was never dropped",
    afterRestart.indexState === "rebuilt_from_agentgres",
    `index state ${afterRestart.indexState}`,
  );
  const secondRead = await graphState(SUBJECT);
  ok(
    "a second read then AGREES with the chain, which is what makes the previous assertion a detection rather than a constant",
    secondRead.indexState === "agreed_with_agentgres",
    `index state ${secondRead.indexState}`,
  );

  // ------------------------------------------------------------------------------- the offline half
  const registry = JSON.parse(fs.readFileSync(REGISTRY, "utf8"));
  const entry = (registry.contracts ?? []).find(
    (candidate) => candidate.contract_id === GRAPH_CONTRACT,
  );
  ok(
    "the projection is a REGISTERED contract with its own schema, invariant profile, generated Rust and TypeScript projections, and a positive/negative fixture corpus — the offline half a relying party holding only the bytes depends on",
    !!entry &&
      entry.schema_ref === "verified-work-graph-projection.v1.schema.json" &&
      (entry.cross_field_invariant_refs ?? []).length === 1 &&
      (entry.generated_targets ?? []).length === 2 &&
      (entry.positive_fixture_refs ?? []).length >= 3 &&
      (entry.negative_fixture_refs ?? []).length >= 12,
    `positives ${(entry?.positive_fixture_refs ?? []).length} negatives ${(entry?.negative_fixture_refs ?? []).length}`,
  );
  ok(
    "every registered negative fixture names the dimension it refuses on, and the invariant-class ones name the exact rule — a corpus whose members refuse for unstated reasons proves only that something was wrong",
    (entry?.negative_fixture_refs ?? []).every(
      (fixture) =>
        ["schema", "invariant"].includes(fixture.expected_failure) &&
        (fixture.expected_failure !== "invariant" ||
          typeof fixture.expected_rule_id === "string") &&
        fs.existsSync(path.join(SCHEMAS, fixture.path)),
    ),
    `${(entry?.negative_fixture_refs ?? []).length} negatives`,
  );
  ok(
    "the registered fixture corpus on disk matches the registry exactly — a fixture file that exists but is unregistered is checked by nothing",
    (() => {
      const onDisk = fs
        .readdirSync(GRAPH_FIXTURES)
        .filter((name) => name.endsWith(".json"))
        .sort();
      const registered = [
        ...(entry?.positive_fixture_refs ?? []),
        ...(entry?.negative_fixture_refs ?? []).map((f) => f.path),
      ]
        .map((p) => path.basename(p))
        .sort();
      return JSON.stringify(onDisk) === JSON.stringify(registered);
    })(),
    `on disk ${fs.readdirSync(GRAPH_FIXTURES).length}`,
  );
  ok(
    "the registered schema pins the nonclaim set as a CLOSED twelve with an explicit `contains` for each member, so a projection that quietly stopped disclaiming settlement or legality is a SCHEMA refusal rather than a passing count",
    (() => {
      const schema = JSON.parse(fs.readFileSync(GRAPH_SCHEMA, "utf8"));
      const nonclaims = schema.properties?.does_not_assert ?? {};
      const contains = (nonclaims.allOf ?? []).map(
        (clause) => clause?.contains?.const,
      );
      return (
        nonclaims.minItems === 12 &&
        nonclaims.maxItems === 12 &&
        nonclaims.uniqueItems === true &&
        contains.length === 12 &&
        contains.includes("settlement") &&
        contains.includes("legality") &&
        contains.includes("live_medical_suitability") &&
        contains.includes("payment_or_economic_value")
      );
    })(),
    "registered closed nonclaim set",
  );
  ok(
    "the registered schema admits exactly one `projection_kind`, so this family cannot become a second truth store without the contract refusing it — canon's 'the graph is not a single database, chain, or UI', as a checkable constraint",
    (() => {
      const schema = JSON.parse(fs.readFileSync(GRAPH_SCHEMA, "utf8"));
      return schema.properties?.projection_kind?.const === "read_projection";
    })(),
    "registered projection_kind const",
  );
}

// ------------------------------------------------------------------------------- mutation harness

// Each mutant names the ONE assertion it must redden. A mutant that reddens something else is a MISS.
const MUTANTS = [
  {
    id: "work-result-prefix-admitted-without-resolution",
    file: OWNER_SOURCE,
    reddens:
      "a WELL-FORMED work-result:// that names nothing admitted is refused on BOTH the producer and the consumer path, by name, and appends nothing — a URI prefix is never proof that a subject exists",
    from: "        .ok_or_else(absent)?;",
    to: "        .unwrap_or_else(|| serde_json::json!({\"outcome_class\":\"positive\",\"status\":\"completed\"}));",
  },
  {
    id: "subject-commitment-excludes-the-mutable-backlinks",
    file: OWNER_SOURCE,
    reddens:
      "THE URI ALONE WAS NEVER STABLE, AND THE GRAPH SAYS SO: the current commitment has moved to v2 while the three admitted transitions still bind v1, and the projection reports `bound_to_superseded_bytes` rather than letting a stale attestation read as a current one",
    // The exact pretense the design forbids: commit the receipt-scoped digest instead of the whole
    // record, and two owner-admitted versions collapse into one hash.
    from: '    let material = json!({\n        "domain": WORK_RESULT_COMMITMENT_DOMAIN,\n        "record": record,\n    });',
    to: '    let mut trimmed = record.clone();\n    if let Some(object) = trimmed.as_object_mut() {\n        object.remove("outcome_delta_refs");\n    }\n    let material = json!({\n        "domain": WORK_RESULT_COMMITMENT_DOMAIN,\n        "record": trimmed,\n    });',
  },
  {
    id: "owner-scope-ignored-by-the-subject-resolver",
    file: OWNER_SOURCE,
    // AIMED AT THE SOURCE-BOUND ASSERTION ON PURPOSE. The owner-entitlement branch is unreachable
    // in this gate's deployment posture — unenforced loopback resolves every reader as the owner's
    // global one — so a live assertion could not distinguish this mutant from correct code. The
    // branch is defence in depth for enforced-auth deployments, its behavioural proof is the named
    // focused Rust test, and its honest gate-level proof is entailment from the source.
    reddens:
      "the subject resolver applies the WorkResult owner's OWN entitlement check, so under enforced auth a reader who may not see a result is refused IDENTICALLY to one asking about a result that does not exist — ENTAILED FROM THE SOURCE, not probed: this deployment posture is unenforced loopback, so the owner resolves every reader as its global one and that branch is unreachable from outside, which means a live assertion here could not tell the check apart from its absence. The behavioural proof is the focused Rust test `work_result_subject_resolver_answers_absence_and_non_entitlement_identically`, which drives the branch directly with a foreign reader; claiming a live proof here would be this gate certifying something it did not check",
    from: "    if let Some(owner) = reader {",
    to: "    if let Some(owner) = None::<&str> {\n        let _ = (owner, reader);",
  },
  {
    id: "graph-derives-its-reached-stage-from-the-work-result-status",
    file: GRAPH_SOURCE,
    reddens:
      "an empty ladder does NOT inherit the WorkResult's own status: the result is `completed` and the graph still reports nothing reached — assurance is never derived from a subject's self-description",
    from: '    let reached_stage = ladder\n        .last()\n        .and_then(|document| document.get("to_stage").cloned())\n        .unwrap_or(Value::Null);\n    let reached_stage_ordinal',
    to: '    let reached_stage = ladder\n        .last()\n        .and_then(|document| document.get("to_stage").cloned())\n        .unwrap_or_else(|| if resolved.status == "completed" { json!("attested") } else { Value::Null });\n    let reached_stage_ordinal',
  },
  {
    id: "unreached-stages-populated-from-the-nearest-row",
    file: GRAPH_SOURCE,
    reddens:
      "STAGES ARE EXPOSED INDEPENDENTLY: attested, evidenced and verified are reached while accepted, adjudicated and settled are each unreached and carry nothing — nothing about acceptance is inferable from verification, and nothing about settlement from acceptance",
    from: '        let row = ladder\n            .iter()\n            .find(|document| document.get("to_stage").and_then(Value::as_str) == Some(*stage));',
    to: '        let row = ladder\n            .iter()\n            .find(|document| document.get("to_stage").and_then(Value::as_str) == Some(*stage))\n            .or_else(|| ladder.last());',
  },
  {
    id: "exploit-normalised-into-the-work-result-spelling",
    file: GRAPH_SOURCE,
    reddens:
      "THE TWO OUTCOME VOCABULARIES ARE NEVER MAPPED ONTO EACH OTHER: the WorkResult's own `negative` is carried in its own field alongside the ladder's separate census, and the ladder's `exploit` is NOT rewritten into the WorkResult spelling `exploit_found` (nor the reverse)",
    from: '        "transitions": ladder,',
    to: '        "transitions": ladder.iter().cloned().map(|mut row| {\n            if row.get("outcome_class").and_then(Value::as_str) == Some("exploit") {\n                row["outcome_class"] = json!("exploit_found");\n            }\n            row\n        }).collect::<Vec<_>>(),',
  },
  {
    id: "census-drops-the-members-with-no-rows",
    file: GRAPH_SOURCE,
    reddens:
      "NEGATIVE AND EXPLOIT OUTCOMES ARE RETAINED VERBATIM AND COUNTED (NN 21, ACC-8 clause 2): the census carries all eight ladder members, the negative and exploit rows are present, and nothing was normalised toward positive",
    from: '        census.insert((*outcome).to_string(), json!(count));',
    to: '        if count > 0 {\n            census.insert((*outcome).to_string(), json!(count));\n        }',
  },
  {
    id: "bound-versions-collapsed-to-the-current-bytes",
    file: GRAPH_SOURCE,
    reddens:
      "a transition admitted AFTER the change binds the NEW bytes, and the graph now carries TWO DISTINCT versions in the order they were first bound — the version history a consumer needs to tell which attestation covered which record",
    from: "    let current_binding_state = if ladder.is_empty() {",
    to: "    bound_versions.truncate(1);\n    let current_binding_state = if ladder.is_empty() {",
  },
  {
    id: "downgraded-contract-version-silently-served",
    file: GRAPH_SOURCE,
    reddens:
      "a consumer naming the EXACT registered contract is served, while a DOWNGRADED version of the same family and an UNKNOWN contract are each refused by their own distinct name — bytes are never served under a label this build did not produce",
    from: "        if asked != GRAPH_CONTRACT_ID {",
    to: "        if false && asked != GRAPH_CONTRACT_ID {",
  },
  {
    id: "graph-answers-any-subject-family",
    file: GRAPH_SOURCE,
    reddens:
      "the graph refuses a subject from another family rather than answering about it: this projection is over WorkResult owner truth only",
    from: "    if SubjectFamily::classify(work_result_ref) != Some(SubjectFamily::WorkResult) {",
    to: "    if false && SubjectFamily::classify(work_result_ref) != Some(SubjectFamily::WorkResult) {",
  },
  {
    id: "transition-nonclaims-stripped-while-flattening",
    file: GRAPH_SOURCE,
    reddens:
      "the projection RETAINS each transition's own authority and verdict nonclaims while flattening the ladder — the marker a consumer relies on is not lost at the layer a product surface reads",
    from: '        "transition_verdict_nonclaim": VERDICT_NONCLAIM,',
    to: '        "transition_verdict_nonclaim": "assurance_transition_is_a_verdict",',
  },
  {
    id: "graph-nonclaim-set-quietly-shortened",
    file: GRAPH_SOURCE,
    reddens:
      "the graph carries the COMPLETE closed nonclaim set the registered contract declares — authority, verdict, correctness, acceptance, adjudication, settlement, payment/economic value, external occurrence, deployment, provider connectivity, legality and live-medical suitability are all disclaimed as data, never by omission",
    from: '    "settlement",\n    "payment_or_economic_value",',
    to: '    "payment_or_economic_value",',
  },
  {
    id: "graph-declares-itself-durable",
    file: GRAPH_SOURCE,
    reddens:
      "the graph declares itself a READ PROJECTION over both owners and names neither a store nor a third owner",
    from: '        "projection_kind": "read_projection",',
    to: '        "projection_kind": "durable_store",',
  },
  {
    id: "finding-and-attempt-quietly-resolved",
    file: GRAPH_SOURCE,
    reddens:
      "Finding and Attempt remain NAMED, fail-closed gaps: each is refused by its own family name and by the unit that owns its reader, never admitted on the strength of its spelling and never confused with the subject being absent",
    from: "        other => Err(bad(\n            StatusCode::NOT_IMPLEMENTED,\n            \"assurance_transition_subject_family_unresolvable\",",
    to: "        other => Err(bad(\n            StatusCode::UNPROCESSABLE_ENTITY,\n            \"assurance_transition_subject_absent\",",
  },
  {
    id: "index-state-hardcoded-to-agreement",
    file: GRAPH_SOURCE,
    reddens:
      "and the rebuild is asserted by POSITIVE DETECTION: the FIRST read after the restart reports `rebuilt_from_agentgres`, because an unchanged answer alone is also consistent with a cache that was never dropped",
    from: "            let state =\n                projection_cache_state(&projection_cache_key(&scope, work_result_ref), &ladder);",
    to: '            let state = "agreed_with_agentgres";\n            let _ =\n                projection_cache_state(&projection_cache_key(&scope, work_result_ref), &ladder);',
  },
];

function rebuildDaemon() {
  const build = spawnSync(
    "cargo",
    ["build", "--locked", "-p", "ioi-node", "--bin", "hypervisor-daemon"],
    { cwd: ROOT, encoding: "utf8", stdio: ["ignore", "pipe", "pipe"] },
  );
  if (build.status !== 0) {
    throw new Error(
      `mutant daemon did not build:\n${build.stderr?.slice(-4000)}`,
    );
  }
}

async function runMutationBattery() {
  const sources = [...new Set(MUTANTS.map((mutant) => mutant.file))];
  const originals = new Map(
    sources.map((file) => [file, fs.readFileSync(file, "utf8")]),
  );
  const digests = new Map(
    sources.map((file) => [
      file,
      crypto.createHash("sha256").update(originals.get(file)).digest("hex"),
    ]),
  );
  const rows = [];
  try {
    for (const mutant of MUTANTS) {
      const original = originals.get(mutant.file);
      const occurrences = original.split(mutant.from).length - 1;
      // FAIL CLOSED ON AN ABSENT ANCHOR. A mutant whose target text has moved proves nothing, and
      // silently skipping it would shrink the battery without failing it.
      if (occurrences !== 1) {
        rows.push({
          id: mutant.id,
          outcome: "ANCHOR_LOST",
          detail: `${occurrences} matches in ${path.basename(mutant.file)}`,
        });
        continue;
      }
      fs.writeFileSync(mutant.file, original.replace(mutant.from, mutant.to));
      let outcome;
      let detail;
      try {
        rebuildDaemon();
        const child = spawnSync(
          process.execPath,
          [fileURLToPath(import.meta.url)],
          {
            cwd: ROOT,
            encoding: "utf8",
            env: { ...process.env, IOI_VERIFIER_CENSUS_DIR: "" },
            maxBuffer: 64 * 1024 * 1024,
          },
        );
        const output = `${child.stdout ?? ""}${child.stderr ?? ""}`;
        const targeted = output.includes(`FAIL  ${mutant.reddens}`);
        const anyFailure = child.status !== 0;
        outcome = targeted
          ? "RED_ON_TARGET"
          : anyFailure
            ? "RED_OFF_TARGET"
            : "SURVIVED";
        detail = targeted
          ? "the targeted assertion failed"
          : anyFailure
            ? "the run failed, but not on its target"
            : "the mutant passed unnoticed";
      } catch (error) {
        // A mutant that does not compile is INVALID, never "caught": a build failure would otherwise
        // read as a red gate while proving nothing about the assertion it aimed at.
        outcome = "INVALID_DID_NOT_COMPILE";
        detail = String(error?.message ?? error).slice(0, 200);
      } finally {
        fs.writeFileSync(mutant.file, original);
      }
      rows.push({ id: mutant.id, outcome, detail });
    }
  } finally {
    // RESTORE, THEN PROVE THE RESTORE. Leaving a planted mutant in the checkout is the one outcome
    // this harness must never produce, so the bytes are compared rather than assumed.
    let restored = true;
    for (const file of sources) {
      fs.writeFileSync(file, originals.get(file));
      const digest = crypto
        .createHash("sha256")
        .update(fs.readFileSync(file, "utf8"))
        .digest("hex");
      if (digest !== digests.get(file)) {
        restored = false;
        process.stderr.write(
          `\nFATAL: ${file} was NOT restored (${digests.get(file)} -> ${digest})\n`,
        );
      }
    }
    if (!restored) process.exit(2);
    rebuildDaemon();
    for (const file of sources) {
      process.stdout.write(
        `source restored and rebuilt; ${path.basename(file)} sha256 ${digests.get(file)}\n`,
      );
    }
  }
  for (const row of rows) {
    process.stdout.write(
      `${row.outcome === "RED_ON_TARGET" ? "RED " : "MISS"}  ${row.id} — ${row.outcome}: ${row.detail}\n`,
    );
  }
  const onTarget = rows.filter((row) => row.outcome === "RED_ON_TARGET").length;
  process.stdout.write(
    `\nverified-work-graph mutation battery: ${onTarget}/${MUTANTS.length} RED ON TARGET\n`,
  );
  process.exit(onTarget === MUTANTS.length ? 0 : 1);
}

if (MUTATE) {
  runMutationBattery().catch((error) => {
    process.stderr.write(`${error?.stack || error}\n`);
    process.exit(1);
  });
} else {
  run()
    .catch((error) => {
      ok("the verifier ran to completion", false, String(error?.stack || error));
    })
    .finally(async () => {
      await stopDaemon();
      cleanup();
      for (const result of results) {
        process.stdout.write(
          `${result.pass ? "ok  " : "FAIL"}  ${result.name}${result.detail ? ` — ${result.detail}` : ""}\n`,
        );
      }
      const passed = results.filter((result) => result.pass).length;
      process.stdout.write(
        `\nverified-work-graph: ${passed}/${results.length}\n`,
      );
      emitVerifierCensus({
        verifierId: "verified-work-graph",
        sourceUrl: import.meta.url,
        results,
      });
      process.exit(passed === results.length && results.length > 0 ? 0 : 1);
    });
}
