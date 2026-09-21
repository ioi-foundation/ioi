// The PUBLISHED NEGATIVE VECTOR CORPUS for a C8 v3 portable evidence bundle: forty fully-resealed semantic
// mutations, each one field of one object, with every dependent hash rewritten so the binding layer is
// perfectly consistent. A bundle that fails only because a hash no longer matches proves nothing about
// semantics; these are the vectors that make a verifier read what the evidence SAYS.
//
// ONE OWNER, TWO CONSUMERS (M06.11, R-218). M06.7's relying-party gate drives this corpus against the canonical
// verifier; M06.11's conformance gate drives the same corpus against the canonical AND the clean-room verifier
// and compares their typed refusal codes. Before this module the table lived inside the relying-party gate, so
// the second consumer would have been a second, drifting definition of "the corpus" — the defect the fixture
// emitter already exists to prevent one layer down.
//
// Each entry names the ROLE of the object it mutates (a key of the fixture's `refs` map), never a resolved ref,
// so a consumer that renamed a subject cannot silently mutate nothing. `mutateCertificate` entries edit the
// certificate itself, which is why their `object` is null.

/** The forty vectors, in the order the corpus was first sealed. */
export const NEGATIVE_CORPUS = Object.freeze([
  { name: "result-verdict", object: "result", mutate: (v) => { v.all_rows_within_threshold = false; } },
  { name: "result-scenario", object: "result", mutate: (v) => { v.summaries[0].scenario = "paper_unknown_4v"; } },
  { name: "result-pass-count", object: "result", mutate: (v) => { v.summaries[0].metrics.injection_tps.values.pop(); } },
  { name: "result-threshold", object: "result", mutate: (v) => { v.summaries[0].metrics.injection_tps.threshold = 0.2; } },
  { name: "request-provider", object: "request", mutate: (v) => { v.provider_ref = "provider://akash/other"; } },
  { name: "request-address", object: "request", mutate: (v) => { v.provider_address = "akash19zzh7whjt4vfwxd5wtj3tjtyatnpntfhldshd8"; } },
  { name: "request-image", object: "request", mutate: (v) => { v.image_digest = `sha256:${"9".repeat(64)}`; } },
  { name: "request-source", object: "request", mutate: (v) => { v.benchmark_source_commit = "9".repeat(40); } },
  { name: "request-operation", object: "request", mutate: (v) => { v.operation = "delete"; } },
  { name: "readiness-status", object: "readiness", mutate: (v) => { v.status = "pending"; } },
  { name: "readiness-replicas", object: "readiness", mutate: (v) => { v.ready_replicas = 0; } },
  { name: "readiness-provider", object: "readiness", mutate: (v) => { v.provider_ref = "provider://akash/other"; } },
  { name: "readiness-image", object: "readiness", mutate: (v) => { v.image_digest = `sha256:${"9".repeat(64)}`; } },
  { name: "retrieval-auth", object: "retrieval", mutate: (v) => { v.authenticated = false; } },
  { name: "retrieval-result", object: "retrieval", mutate: (v) => { v.result_hash = `sha256:${"9".repeat(64)}`; } },
  { name: "environment-provider", object: "environment", mutate: (v) => { v.provider_ref = "provider://akash/other"; } },
  { name: "environment-class", object: "environment", mutate: (v) => { v.environment_class = "unmeasured"; } },
  { name: "campaign-status", object: "campaign", mutate: (v) => { v.status = "partial"; } },
  { name: "campaign-result", object: "campaign", mutate: (v) => { v.result_hash = `sha256:${"9".repeat(64)}`; } },
  { name: "isolation-network", object: "isolationEvidence", mutate: (v) => { v.network_posture = "egress_enabled"; } },
  { name: "isolation-bypass", object: "isolationEvidence", mutate: (v) => { v.direct_protected_effect_invocations = 1; } },
  { name: "isolation-invoker", object: "isolationEvidence", mutate: (v) => { v.final_invoker_calls = 0; } },
  { name: "isolation-host-mount", object: "isolationRequirements", mutate: (v) => { v.host_mount_policy = "read_only"; } },
  { name: "isolation-daemon-socket", object: "isolationRequirements", mutate: (v) => { v.daemon_socket_exposed = true; } },
  { name: "secret-finding", object: "secret", mutate: (v) => { v.secret_findings = 1; } },
  { name: "secret-credential", object: "secret", mutate: (v) => { v.provider_credential_observed = true; } },
  { name: "envelope-topup", object: "envelope", mutate: (v) => { v.facet_template.auto_topup = true; } },
  { name: "envelope-image", object: "envelope", mutate: (v) => { v.facet_template.image_digests = [`sha256:${"9".repeat(64)}`]; } },
  { name: "draw-decision", object: "drawReceipt", mutate: (v) => { v.decision = "refused"; } },
  { name: "draw-atomicity", object: "drawReceipt", mutate: (v) => { v.atomic_consumption = false; } },
  { name: "trajectory-decision", object: "decision", mutate: (v) => { v.decision = "deny"; } },
  { name: "trajectory-constraint", object: "decision", mutate: (v) => { v.constraint_results[0].satisfied = false; } },
  { name: "trajectory-count", object: "after", mutate: (v) => { v.admitted_call_count = 0; } },
  { name: "trajectory-provider", object: "after", mutate: (v) => { v.provider_refs = []; } },
  { name: "settlement-lease", object: "settlement", mutate: (v) => { v.lease_status = "open"; } },
  { name: "settlement-exposure", object: "settlement", mutate: (v) => { v.open_unknown_exposure_microusd = 1; } },
  { name: "settlement-teardown", object: "settlement", mutate: (v) => { v.teardown_verified = false; } },
  { name: "terminal-result", object: "terminal", mutate: (v) => { v.result_verified = false; } },
  { name: "journal-predecessor", object: null, mutate: null, mutateCertificate: (v) => { v.journal_binding.outcome_predecessor_root = `sha256:${"9".repeat(64)}`; } },
  { name: "journal-no-advance", object: null, mutate: null, mutateCertificate: (v) => { v.journal_binding.outcome_root = v.journal_binding.intent_root; } },
]);

/** The corpus size, pinned: a battery that ran over a shrunken corpus would pass while proving less. */
export const NEGATIVE_CORPUS_SIZE = 40;

/** Resolve one vector against a fixture's `refs` map, refusing a role the fixture does not carry. */
export function resolveVector(vector, refs) {
  if (vector.object === null) return { ...vector, objectRef: null };
  const objectRef = refs?.[vector.object];
  if (!objectRef) throw new Error(`negative corpus names a role this fixture does not carry: ${vector.object}`);
  return { ...vector, objectRef };
}
