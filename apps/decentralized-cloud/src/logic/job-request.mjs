// ONE PRIMITIVE, TWO DOORS — as data, so the claim can be checked rather than read.
//
// The surface claims a human's request and an agent's are the same CloudJobRequest,
// differing in exactly one field. In the vanilla surface those two objects were
// literals inside a render function, and the gate proved the claim by matching them
// out of the source with a regular expression and evaluating the captures with
// `new Function`. That worked, and it was a gate reading a transformed copy of the
// thing rather than the thing.
//
// Here they are module constants, framework-free, so the gate IMPORTS them and
// compares field by field. The assertion now runs against the same objects the
// surface renders — there is no parse step between the claim and its proof.
//
// THE ONLY FIELD THAT MAY DIFFER IS THE AUTHORITY. If these two ever drift apart in
// any other field, one of the two callers is being offered a privilege the other is
// not, and that is how a second spine starts: not by anyone deciding to build one,
// but by two doors to one primitive quietly growing apart.

export const HUMAN_REQUEST = {
  schema_version: "ioi.cloud.job-request.v1",
  intent: { runtime_class: "compute.gpu_runtime", gpu: { required: true, devices: 1, min_gb: 24 } },
  deadline: { max_duration_hours: 4 },
  budget_ref: "external-spend-budget://esb_…",
  // A wallet grant a person signs at submit.
  authority_ref: "wallet-grant://wg_…",
  redundancy: "none",
  receipt_requirements: ["placement", "provider-operation", "spend", "failover", "offline-verifiable"],
};

export const AGENT_REQUEST = {
  ...HUMAN_REQUEST,
  // A CapabilityLease draw-down: a NARROWING of a grant a human made earlier, never a
  // new grant an agent made for itself.
  authority_ref: "capability-lease://cl_… (draw-down)",
};

// Neither door names a venue: the venue is EVIDENCE in the receipt, not an input to
// the request. Neither carries a provider credential: the caller never holds one.
// Both statements are asserted by the face gate against these objects.
