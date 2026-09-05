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

// ── The gate's own records, labelled rather than deleted ────────────────────
//
// The face gate admits a real job on every run, to prove the door against the running
// daemon rather than a fixture. Those records are real and they accumulate.
//
// They are NOT cleaned up. ioi-c0's ruling, and it is the right one: a gate that
// erases its own records is one more artifact the estate cannot audit. So each one is
// TAGGED at admission instead — the daemon passes `evidence_refs` through verbatim
// from the request body into the persisted record, so the tag lives in the daemon's
// own copy and not in a list this surface keeps on the side.
//
// This constant is exported so the gate that WRITES the tag and the surface that
// FILTERS on it use the same string. Two copies of a magic value that must agree are
// two sources and a wish — the same fault as two copies of the Z path, and the
// filter silently showing nothing would be the way it announced itself.
export const GATE_ORIGIN_REF = "gate://verify-decentralized-cloud-face";

export const isGateAdmitted = (job) =>
  Array.isArray(job?.evidence_refs) && job.evidence_refs.includes(GATE_ORIGIN_REF);

// ── What a receipt IS, rather than where it sat in a list ────────────────────
//
// THE DEFECT THIS REPLACES. `receipts` came through as `typeof === "object"`, which is
// true of an ARRAY, and the Receipts surface then rendered `Object.keys(receipts)` as
// chips. On an array those keys are indices, so a blind reviewer measured 27 rows, a
// header reading "18 carrying receipts", 18 rows carrying a chip, and the set of every
// distinct chip value on the page being ["0"].
//
// A column headed *Receipts* was showing a loop counter, on the surface whose whole
// thesis is that no number appears without its provenance. The header count beside it
// was correct, which is what made it survive: the page looked internally consistent.
//
// Nothing caught it. The field contract asserted `receipts` EXISTS and said nothing
// about its shape, and a shape assumption is exactly as much a fact about the daemon
// as a field name is — the same lesson as reading `provider_kind` off a body that
// sends `source`, one level in.
//
// So the shape is now read once, here, and what the surface renders is the receipt's
// KIND and its auditable anchors.
const RECEIPT_KIND = (r) => {
  // The daemon names the kind twice, and both are real evidence rather than a guess:
  // the ref's URI scheme and the schema version. The scheme is preferred because it is
  // what the rest of the estate addresses receipts by.
  const scheme = String(r?.receipt_ref || "").split("://")[0];
  if (scheme) return scheme;
  const schema = String(r?.schema_version || "");
  const m = schema.match(/^ioi\.hypervisor\.([a-z-]+)\.v\d+$/);
  return m ? m[1] : null;
};

export function receiptViews(receipts) {
  // An object keyed by kind and an array of receipt records are both plausible and the
  // daemon sends the array. Both are handled, and neither is turned into indices.
  const list = Array.isArray(receipts)
    ? receipts
    : receipts && typeof receipts === "object"
      ? Object.values(receipts)
      : [];
  return list.map((r) => ({
    kind: RECEIPT_KIND(r),
    ref: r?.receipt_ref || null,
    root: r?.receipt_root || null,
    at: r?.at || null,
    // The fee facts, carried rather than summarised. "no fee minted" is the claim this
    // product is most often asked to prove, so it is rendered from the record's own
    // two fields instead of inferred from one.
    feeMinted: r?.fee_object_minted ?? null,
    noFee: r?.no_fee ?? null,
    note: r?.note || null,
  }));
}

// What a job record actually carries, so the surfaces read one shape. Every field is
// read from the daemon's own record; nothing here supplies a default that could be
// mistaken for the daemon having said it.
export function jobView(job) {
  if (!job) return null;
  return {
    id: job.job_id || null,
    evidenceRefs: Array.isArray(job.evidence_refs) ? job.evidence_refs : [],
    gateAdmitted: isGateAdmitted(job),
    state: job.state || null,
    callerKind: job.authority?.caller_kind || null,
    authorityMode: job.authority?.mode || null,
    authorityRef: job.authority?.authority_ref || null,
    budgetRef: job.budget_ref || null,
    budgetDiscoveredBeforeMutation: job.budget_discovery?.discovered_before_mutation ?? null,
    redundancy: job.redundancy ?? null,
    receiptRequirements: Array.isArray(job.receipt_requirements) ? job.receipt_requirements : [],
    receipts: receiptViews(job.receipts),
    placement: job.placement || job.decision || null,
    // The venue the placement chose, lifted so the ledger can carry it as a column.
    // A receipts ledger that cannot say WHERE the work was placed is a ledger missing
    // the fact most people open it for.
    venue: job.placement?.venue || job.decision?.venue || null,
    quoteRef: job.placement?.quote_ref || null,
    // Whether a fee object exists for this job at all. There is deliberately no
    // "amount" here: a fee exists only as a minted receipt, and nothing on this
    // surface can produce one, so an amount column would be empty on every row
    // forever. An always-empty column is a question the page keeps asking and never
    // answers; the ledger states the absence once instead.
    feeMinted: job.fee_object_minted ?? null,
    createdAt: job.created_at || job.at || null,
  };
}
