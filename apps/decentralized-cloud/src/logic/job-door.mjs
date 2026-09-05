// THE JOB DOOR — the write side, framework-free.
//
// Two calls and no third. Admission creates a PROPOSAL and authorizes nothing; the
// dry run stops at the placement receipt and touches no provider. There is no
// function here that runs a job for real, and that is not an omission — a real
// execution is metered provider spend, it needs an explicit owner authorization
// naming amount, venue ceiling, offer hash and teardown, and no such authorization can
// arrive through a web form.
//
// The surface could not reach a real execution even if this module tried: the proxy
// OVERWRITES `dry_run` to true on every execute, server-side, after parsing the body.
// Proven rather than asserted — a request carrying `dry_run: false` came back from the
// daemon with `dry_run: true` and a job in state `placed`, with no provider touched.

import { envelope } from "./classify.mjs";

async function post(path, body) {
  const started = Date.now();
  try {
    const res = await fetch(path, {
      method: "POST",
      headers: { "content-type": "application/json", accept: "application/json" },
      body: JSON.stringify(body),
    });
    const parsed = await res.json().catch(() => ({}));
    return { ok: res.ok, status: res.status, body: parsed, ms: Date.now() - started };
  } catch (err) {
    // A network failure is not an admission and is not a refusal. It is a state in
    // which the outcome is UNKNOWN from here, and the surface says exactly that rather
    // than picking whichever of the two is easier to render.
    return {
      ok: false,
      status: 0,
      body: {
        state: "job_door_unreachable",
        reason:
          `the request did not complete (${String(err)}) — whether the job was admitted ` +
          "is unknown from this surface, and it will not guess",
      },
      ms: Date.now() - started,
    };
  }
}

// The request the form composes. `caller_kind` is "human" and this door sends no
// other value: the agent lane resolves through a CapabilityLease draw-down, and this
// surface has no lease to draw down and no business minting one.
export function composeRequest({ budgetRef, authorityRef, hours, devices, minGb, redundancy }) {
  return {
    schema_version: "ioi.cloud.job-request.v1",
    caller_kind: "human",
    intent: {
      runtime_class: "compute.gpu_runtime",
      gpu: { required: true, devices: Number(devices), min_gb: Number(minGb) },
    },
    deadline: { max_duration_hours: Number(hours) },
    budget_ref: budgetRef,
    authority_ref: authorityRef,
    redundancy,
    receipt_requirements: ["placement", "provider-operation", "spend", "failover", "offline-verifiable"],
  };
}

export const admit = (request) => post("/api/jobs", request);

// The dry run. `dry_run` is deliberately NOT passed: it is not this module's to set,
// and a caller reading this file should not come away believing it could be.
export const dryRun = (jobId, idempotencyKey) =>
  post(`/api/jobs/${encodeURIComponent(jobId)}/dry-run`, { idempotency_key: idempotencyKey });

// A refusal, read by CODE. The daemon's codes are the vocabulary the surface speaks:
// `job_deadline_required`, `budget_undiscovered_before_mutation`,
// `job_authority_mode_mismatch`, `redundancy_posture_unsupported`. Each carries its own
// sentence and the surface renders that sentence rather than a summary of it — the
// daemon's message says why in the daemon's own terms, and a paraphrase is a second
// place for the reason to drift from the rule.
export function refusal(result) {
  if (result.ok) return null;
  const { code, detail } = envelope(result);
  return { code, detail, status: result.status };
}

// What a job record actually carries, so the surfaces read one shape. Every field is
// read from the daemon's own record; nothing here supplies a default that could be
// mistaken for the daemon having said it.
export function jobView(job) {
  if (!job) return null;
  return {
    id: job.job_id || null,
    state: job.state || null,
    callerKind: job.authority?.caller_kind || null,
    authorityMode: job.authority?.mode || null,
    authorityRef: job.authority?.authority_ref || null,
    budgetRef: job.budget_ref || null,
    budgetDiscoveredBeforeMutation: job.budget_discovery?.discovered_before_mutation ?? null,
    redundancy: job.redundancy ?? null,
    receiptRequirements: Array.isArray(job.receipt_requirements) ? job.receipt_requirements : [],
    receipts: job.receipts && typeof job.receipts === "object" ? job.receipts : null,
    placement: job.placement || job.decision || null,
    createdAt: job.created_at || job.at || null,
  };
}
