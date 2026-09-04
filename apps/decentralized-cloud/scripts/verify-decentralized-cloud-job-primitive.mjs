#!/usr/bin/env node
// M15.3 done-bar — the CloudJobRequest primitive.
//
// WHAT THIS GATE PROVES, and it says so in its own output rather than leaving the
// reader to infer it: admission, the caller_kind→authority resolution, budget
// discovered before any mutation, the full refusal set, and placement selected and
// RECEIPTED — all via `dry_run`, which stops after placement having contacted no
// provider. NOTHING IS SPENT by this gate, on any path.
//
// WHAT IT DOES NOT PROVE: the MID-RUN vanished-provider path. A provider that
// disappears while work is running rides the failover lane's existing proof and
// ACC-21 clause 6 on a live or simulator lifecycle. What is proven here is the
// ADMISSION-TIME case — no placement-eligible candidate at execute — which is
// recorded as `refused_no_placement` carrying the decision plane's own reason.
//
// The central invariant: a human and an agent submit the SAME envelope and get the
// SAME record. That is compared field by field, not asserted.
//
// Usage: node apps/decentralized-cloud/scripts/verify-decentralized-cloud-job-primitive.mjs

const DAEMON = (process.env.IOI_HYPERVISOR_DAEMON_URL || "http://127.0.0.1:8765").replace(/\/$/, "");

const results = [];
const ok = (name, cond, detail) => results.push({ name, pass: !!cond, detail: detail || "" });

async function call(method, path, body) {
  const res = await fetch(`${DAEMON}${path}`, {
    method,
    headers: { "content-type": "application/json", accept: "application/json" },
    body: body === undefined ? undefined : JSON.stringify(body),
  });
  let parsed = null;
  try {
    parsed = await res.json();
  } catch {
    parsed = null;
  }
  return { status: res.status, body: parsed };
}

const errCode = (r) => r.body?.error?.code || r.body?.code || r.body?.reason || `http_${r.status}`;

// The envelope every case starts from. Deliberately minimal and canonical: no venue,
// no credential, one intent, an existing budget.
const baseEnvelope = (over = {}) => ({
  caller_kind: "human",
  authority_ref: "wallet-grant://wg_gate",
  budget_ref: null, // filled from the discovered budget
  deadline: { max_duration_hours: 1 },
  redundancy: "none",
  receipt_requirements: ["placement", "provider-operation", "spend"],
  intent: {
    runtime_class: "compute.gpu_runtime",
    resource_classes: ["compute.gpu_runtime"],
    gpu: { required: true },
  },
  ...over,
});

async function run() {
  // ── A budget must exist for admission to be possible at all. ──
  const budgets = await call("GET", "/v1/hypervisor/resource/budgets");
  const list = budgets.body?.budgets || budgets.body?.items || [];
  const spend = list.find((b) => b.scope === "external_spend");
  ok("an external_spend budget exists for the job to draw on", !!spend,
    spend ? `budget://${spend.budget_id}` : "none found — create one before running this gate");
  if (!spend) return;
  const budgetRef = `budget://${spend.budget_id}`;

  // ── 1. The same envelope from both doors. ──
  const human = await call("POST", "/v1/hypervisor/cloud-jobs",
    baseEnvelope({ budget_ref: budgetRef }));
  ok("a human submission is admitted", human.status === 201, `HTTP ${human.status} ${errCode(human)}`);

  const agent = await call("POST", "/v1/hypervisor/cloud-jobs",
    baseEnvelope({ budget_ref: budgetRef, caller_kind: "agent", authority_ref: "capability-lease://cl_gate" }));
  ok("an agent submission is admitted", agent.status === 201, `HTTP ${agent.status} ${errCode(agent)}`);

  if (human.status === 201 && agent.status === 201) {
    const h = human.body.job;
    const a = agent.body.job;
    // Fields that MUST differ: the identity of the record itself, its intent, its
    // timestamp, and the authority. Everything else being equal is the invariant.
    const mustDiffer = new Set(["job_id", "job_ref", "intent_ref", "created_at", "caller_kind", "authority"]);
    const keys = [...new Set([...Object.keys(h), ...Object.keys(a)])];
    const differing = keys.filter((k) => JSON.stringify(h[k]) !== JSON.stringify(a[k]));
    const unexpected = differing.filter((k) => !mustDiffer.has(k));
    ok("the two doors produce the same record apart from identity and authority",
      unexpected.length === 0, unexpected.length ? `also differ: ${unexpected.join(", ")}` : `differ only in ${differing.join(", ")}`);
    ok("both records carry the same receipt requirements",
      JSON.stringify(h.receipt_requirements) === JSON.stringify(a.receipt_requirements));
    ok("both records carry the same budget", h.budget_ref === a.budget_ref, h.budget_ref);
    ok("neither record names a venue at admission",
      !JSON.stringify(h).includes("provider_kind") && !JSON.stringify(a).includes("provider_kind"));
    ok("the human door resolved to a wallet grant", h.authority?.mode === "wallet_grant", h.authority?.mode);
    ok("the agent door resolved to a lease draw-down",
      a.authority?.mode === "capability_lease_drawdown", a.authority?.mode);
    ok("neither authority claims the caller holds a credential",
      h.authority?.credential_held_by_caller === false && a.authority?.credential_held_by_caller === false);
    ok("budget was discovered before mutation on both",
      h.budget_discovery?.discovered_before_mutation === true &&
      a.budget_discovery?.discovered_before_mutation === true);
    ok("no fee object is minted by admission", h.fee_object_minted === false && a.fee_object_minted === false);
  }

  // ── 2. The refusal set. Each is a distinct named refusal, not a generic 4xx. ──
  const refusals = [
    ["a caller-supplied provider credential is refused typed",
      baseEnvelope({ budget_ref: budgetRef, api_key: "sk-live-should-never-be-here" }),
      "provider_credential_caller_supplied_refused"],
    ["a credential nested inside the intent is refused too",
      baseEnvelope({ budget_ref: budgetRef, intent: { runtime_class: "compute.gpu_runtime", secret: "x" } }),
      "provider_credential_caller_supplied_refused"],
    ["naming a venue is refused",
      baseEnvelope({ budget_ref: budgetRef, provider_kind: "vast" }),
      "venue_not_an_input_to_a_job"],
    ["an authority ref that contradicts caller_kind is refused",
      baseEnvelope({ budget_ref: budgetRef, caller_kind: "agent", authority_ref: "wallet-grant://wg_gate" }),
      "job_authority_mode_mismatch"],
    ["an unknown caller_kind is refused",
      baseEnvelope({ budget_ref: budgetRef, caller_kind: "daemon" }),
      "caller_kind_invalid"],
    ["a missing authority ref is refused",
      baseEnvelope({ budget_ref: budgetRef, authority_ref: "" }),
      "job_authority_ref_required"],
    ["warm_standby is refused BY NAME rather than downgraded to none",
      baseEnvelope({ budget_ref: budgetRef, redundancy: "warm_standby" }),
      "redundancy_posture_unsupported"],
    ["active_active is refused BY NAME",
      baseEnvelope({ budget_ref: budgetRef, redundancy: "active_active" }),
      "redundancy_posture_unsupported"],
    ["an invented posture is refused as unknown",
      baseEnvelope({ budget_ref: budgetRef, redundancy: "triple_redundant" }),
      "redundancy_posture_unknown"],
    ["a receipt kind that is never minted is refused",
      baseEnvelope({ budget_ref: budgetRef, receipt_requirements: ["placement", "audit-trail"] }),
      "receipt_requirement_unknown"],
    ["a job with no deadline is refused",
      baseEnvelope({ budget_ref: budgetRef, deadline: null }),
      "job_deadline_required"],
    ["a job with no budget is refused",
      baseEnvelope({ budget_ref: "" }),
      "budget_ref_required"],
    ["a budget that does not resolve is refused BEFORE any mutation",
      baseEnvelope({ budget_ref: "budget://does_not_exist" }),
      "budget_undiscovered_before_mutation"],
    ["a job with no intent is refused",
      baseEnvelope({ budget_ref: budgetRef, intent: null }),
      "job_intent_required"],
  ];

  for (const [name, envelope, expected] of refusals) {
    const r = await call("POST", "/v1/hypervisor/cloud-jobs", envelope);
    ok(name, r.status === 422 && errCode(r) === expected, `HTTP ${r.status} ${errCode(r)}`);
  }

  // ── 3. Budget order: the budget refusal must come BEFORE anything is created. ──
  const before = (await call("GET", "/v1/hypervisor/cloud-jobs")).body?.jobs?.length ?? 0;
  await call("POST", "/v1/hypervisor/cloud-jobs", baseEnvelope({ budget_ref: "budget://nope" }));
  const after = (await call("GET", "/v1/hypervisor/cloud-jobs")).body?.jobs?.length ?? 0;
  ok("a budget refusal creates no job record", before === after, `${before} → ${after}`);

  // ── 4. Execution: placement receipted, no provider contacted. ──
  if (human.status === 201) {
    const jobId = human.body.job.job_id;
    const exec = await call("POST", `/v1/hypervisor/cloud-jobs/${jobId}/execute`, { dry_run: true });
    if (exec.status === 200) {
      const job = exec.body.job;
      ok("execution reaches a decided placement", job?.state === "placed", job?.state);
      ok("the venue is recorded as evidence only after the decision", !!job?.placement?.venue,
        job?.placement?.venue || "none");
      ok("a placement receipt is bound to the job", Array.isArray(job?.receipts) && job.receipts.length >= 1,
        `${job?.receipts?.length ?? 0} receipt(s)`);
      ok("dry_run contacted no provider", exec.body?.dry_run === true && !job?.provider_operation);
    } else {
      // No eligible candidate is a legitimate outcome and must be recorded, not retried.
      ok("with no eligible candidate the job is recorded refused, with the decision plane's own reason",
        exec.status === 409 && errCode(exec) === "cloud_job_no_placement",
        `HTTP ${exec.status} ${errCode(exec)}`);
      const reread = await call("GET", `/v1/hypervisor/cloud-jobs/${jobId}`);
      ok("the refusal is persisted on the job rather than left open",
        reread.body?.job?.state === "refused_no_placement", reread.body?.job?.state);
    }
    const again = await call("POST", `/v1/hypervisor/cloud-jobs/${jobId}/execute`, { dry_run: true });
    ok("a job executes once — a second execute is refused",
      again.status === 409 && errCode(again) === "cloud_job_not_admitted",
      `HTTP ${again.status} ${errCode(again)}`);
  }

  // ── 5. The agent execution lane: the lease is the authority, and it is checked. ──
  //
  // Every refusal below must land BEFORE any provider is contacted. Placement is not a
  // local ranking — it refreshes candidates and reaches venues — so a lease that got as
  // far as placement would have been reported rather than refused.
  if (agent.status === 201) {
    const agentJob = agent.body.job.job_id;
    const r = await call("POST", `/v1/hypervisor/cloud-jobs/${agentJob}/execute`, { dry_run: true });

    // The gate accepts EITHER a working draw-down or a NAMED refusal, because both are
    // honest — what it refuses to accept is an agent executing under someone else's
    // authority, or a silent failure with no name on it.
    const named = [
      "capability_lease_absent",
      "capability_lease_revoked",
      "capability_lease_exhausted",
      "capability_lease_expired",
      "capability_lease_out_of_scope",
      "lease_predates_principal_binding",
      "lease_principal_no_longer_authorized",
    ];
    const code = errCode(r);
    ok("an agent job either draws down its lease or is refused by a NAMED lease reason",
      r.status === 200 || (r.status === 403 && named.includes(code)),
      `HTTP ${r.status} ${code}`);

    // A refusal must be recorded on the job, not merely returned — an authority refusal
    // that leaves no trace is one nobody can audit afterwards.
    if (r.status === 403) {
      const reread = await call("GET", `/v1/hypervisor/cloud-jobs/${agentJob}`);
      ok("an authority refusal is persisted on the job with its reason",
        reread.body?.job?.state === "refused_authority" && !!reread.body?.job?.refusal?.code,
        `${reread.body?.job?.state} / ${reread.body?.job?.refusal?.code}`);
      ok("the refusal happened before any provider was touched — no placement was recorded",
        !reread.body?.job?.placement, JSON.stringify(reread.body?.job?.placement || null));
    }

    // A lease this system never issued must never resolve to authority.
    const forged = await call("POST", "/v1/hypervisor/cloud-jobs",
      baseEnvelope({ budget_ref: budgetRef, caller_kind: "agent",
        authority_ref: "capability-lease://lease_forged_does_not_exist" }));
    if (forged.status === 201) {
      const f = await call("POST", `/v1/hypervisor/cloud-jobs/${forged.body.job.job_id}/execute`, { dry_run: true });
      ok("a lease that does not exist confers nothing",
        f.status === 403 && errCode(f) === "capability_lease_absent",
        `HTTP ${f.status} ${errCode(f)}`);
    }

    // ── The invariant the whole design rests on. ──
    // A human and an agent submit the same envelope; the records they produce may differ
    // ONLY in identity and in how authority was obtained. If an execution outcome ever
    // differs beyond that, one caller is being offered something the other is not.
    if (human.status === 201 && r.status === 200) {
      const h = await call("GET", `/v1/hypervisor/cloud-jobs/${human.body.job.job_id}`);
      const a = await call("GET", `/v1/hypervisor/cloud-jobs/${agentJob}`);
      const shape = (j) => {
        const { job_id, job_ref, intent_ref, created_at, caller_kind, authority, receipts,
                placement, ...rest } = j || {};
        return {
          rest,
          receiptKinds: (receipts || []).map((x) => x?.schema_version || x?.kind || null),
          placementKeys: placement ? Object.keys(placement).sort() : null,
        };
      };
      const hs = JSON.stringify(shape(h.body?.job));
      const as = JSON.stringify(shape(a.body?.job));
      ok("the two doors produce byte-identical execution records apart from identity and authority",
        hs === as, hs === as ? "identical" : `human ${hs.slice(0, 90)} vs agent ${as.slice(0, 90)}`);
    }
  }
}

run()
  .then(() => {
    let fail = 0;
    for (const r of results) {
      console.log(`  ${r.pass ? "PASS" : "FAIL"}  ${r.name}${r.detail ? `  (${r.detail})` : ""}`);
      if (!r.pass) fail++;
    }
    console.log(`\n${results.length - fail}/${results.length} passed`);
    console.log(
      "\nSCOPE: this gate proves admission, authority-mode resolution, budget-before-mutation,\n" +
      "the refusal set, and placement selected and receipted — via dry_run, which contacts no\n" +
      "provider. NOTHING IS SPENT on any path here. It does NOT prove the MID-RUN\n" +
      "vanished-provider path: that rides the failover lane's existing proof and ACC-21\n" +
      "clause 6 on a live or simulator lifecycle. The admission-time no-candidate case IS\n" +
      "proven, recorded as refused_no_placement with the decision plane's own reason.\n" +
      "M15.3 is PARTIAL: the agent execution lane is BUILT but UNREACHABLE. The resolver and\n" +
      "its named refusal ladder are live — an agent job now refuses by lease reason rather than\n" +
      "by 'not wired' — but agent draw-down needs an intent-scoped bound lease issued under\n" +
      "M03's delegation envelope (M03.12 mint), and no caller-facing issuance exists. Leases are\n" +
      "minted as a side effect of authorized operations, scoped to [account_ref, env_ref], never\n" +
      "to an intent. The happy path is proven in-process by the resolver's own tests, not here."
    );
    console.log(`decentralized.cloud job primitive: ${fail ? "FAIL" : "OK"}`);
    process.exit(fail ? 1 : 0);
  })
  .catch((e) => {
    console.error("gate crashed:", e);
    process.exit(1);
  });
