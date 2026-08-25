// The exact, byte-derived difference between an active standing envelope and one
// candidate request.
//
// Forty near-identical requests hiding one widening is an operator-attention
// attack, and the defence is not a longer prompt: it is a typed delta the
// operator can read in one line. This engine computes that delta — and it names
// each widening with the SAME refusal code the daemon's own containment check
// emits, so an approval surface can never highlight a delta enforcement would
// not refuse, nor stay silent about one it would. The daemon remains the only
// enforcer; this is a projection of its bounds, never a second one.

const asSet = (value) => (Array.isArray(value) ? value : []);
const num = (value) => (typeof value === "number" && Number.isFinite(value) ? value : null);

// (facet, envelope pointer, refusal code) triples, mirroring
// validate_standing_provider_facets in the daemon's provider routes.
const MEMBERSHIP_FACETS = [
  ["sdl_hash", "sdl_hashes", "standing_sdl_outside_envelope"],
  ["image_digest", "image_digests", "standing_image_outside_envelope"],
  ["registry_host", "registry_hosts", "standing_registry_outside_envelope"],
  ["result_credential_ref", "result_destination_refs", "standing_result_destination_outside_envelope"],
  ["result_tls_server_certificate_sha256", "result_transport_certificate_hashes", "standing_result_transport_outside_envelope"],
];
const EXACT_FACETS = [
  ["auto_topup", "auto_topup", "standing_auto_topup_outside_envelope"],
  ["teardown_policy", "teardown_policy", "standing_teardown_outside_envelope"],
  ["ceiling_denom", "pricing_ceiling.denom", "standing_ceiling_denom_outside_envelope"],
];

export const AUTHORITY_DELTA_CODES = [
  "standing_provider_id_outside_envelope",
  "standing_operation_outside_envelope",
  "standing_provider_selector_mode_outside_envelope",
  "standing_provider_selection_outside_envelope",
  "standing_provider_address_outside_envelope",
  "standing_deposit_outside_envelope",
  "standing_ceiling_outside_envelope",
  "standing_duration_outside_envelope",
  ...EXACT_FACETS.map(([, , code]) => code),
  ...MEMBERSHIP_FACETS.map(([, , code]) => code),
].sort();

const pointer = (object, path) => path.split(".").reduce((value, key) => (value == null ? value : value[key]), object);

export function computeAuthorityDelta({ envelope, facets, op, provider_id }) {
  const template = envelope?.facet_template;
  if (!template) throw new Error("standing envelope has no facet template");
  const widenings = [];
  const within = [];
  const note = (facet, code, envelopeBound, requested, widened) => {
    if (widened) widenings.push({ facet, code, envelope_bound: envelopeBound, requested });
    else within.push(facet);
  };

  note("provider_id", "standing_provider_id_outside_envelope", template.provider_id, provider_id,
    template.provider_id !== provider_id);
  note("operation", "standing_operation_outside_envelope", asSet(template.operations), op,
    !asSet(template.operations).includes(op));
  note("provider_selector.mode", "standing_provider_selector_mode_outside_envelope",
    template.provider_selector?.mode, facets?.provider_selector?.mode,
    template.provider_selector?.mode !== facets?.provider_selector?.mode);
  note("provider_selector.selection", "standing_provider_selection_outside_envelope",
    template.provider_selector?.selection, facets?.provider_selector?.selection,
    template.provider_selector?.selection !== facets?.provider_selector?.selection);
  note("provider_address", "standing_provider_address_outside_envelope",
    asSet(template.provider_selector?.provider_addresses), facets?.provider_address,
    !asSet(template.provider_selector?.provider_addresses).includes(facets?.provider_address));

  // Numeric ceilings widen when the request asks for MORE than the envelope
  // permits; asking for less is not a delta the operator must adjudicate.
  const depositMicrousd = num(facets?.deposit_usd) === null ? null : Math.round(facets.deposit_usd * 1_000_000);
  note("deposit_usd", "standing_deposit_outside_envelope", template.per_operation_deposit_microusd, depositMicrousd,
    depositMicrousd === null || depositMicrousd > (template.per_operation_deposit_microusd ?? 0));
  const requestedCeiling = Number.parseInt(String(facets?.ceiling_amount ?? ""), 10);
  const allowedCeiling = Number.parseInt(String(template.pricing_ceiling?.amount ?? ""), 10);
  note("ceiling_amount", "standing_ceiling_outside_envelope", template.pricing_ceiling?.amount, facets?.ceiling_amount,
    !Number.isSafeInteger(requestedCeiling) || !Number.isSafeInteger(allowedCeiling) || requestedCeiling > allowedCeiling);
  note("max_duration_seconds", "standing_duration_outside_envelope", template.max_duration_seconds, facets?.max_duration_seconds,
    num(facets?.max_duration_seconds) === null || facets.max_duration_seconds > (template.max_duration_seconds ?? 0));

  for (const [facet, path, code] of EXACT_FACETS) {
    note(facet, code, pointer(template, path), facets?.[facet], pointer(template, path) !== facets?.[facet]);
  }
  for (const [facet, set, code] of MEMBERSHIP_FACETS) {
    note(facet, code, asSet(template[set]), facets?.[facet], !asSet(template[set]).includes(facets?.[facet]));
  }

  return {
    schema_version: "ioi.foundations.authority-delta.v1",
    standing_envelope_ref: envelope.standing_envelope_ref,
    standing_envelope_hash: envelope.body_hash,
    widened: widenings.length > 0,
    widenings: widenings.sort((left, right) => left.code.localeCompare(right.code)),
    within_envelope_facets: within.sort(),
  };
}

// The decision a delta implies. A request inside the envelope is admitted under
// the standing authority the operator already granted — that is the whole point
// of a standing envelope, and repeating it two hundred times does not make it a
// new decision. A widening is never silent: it is denied, or escalated when the
// policy names a step-up path for exactly that facet.
export function admissionForDelta(delta, policy = {}) {
  if (!delta.widened) return { decision: "admit", reason_codes: [], escalated_facets: [] };
  const escalatable = new Set(policy.step_up_facets || []);
  const codes = delta.widenings.map((entry) => entry.code);
  const everyWideningEscalatable = delta.widenings.every((entry) => escalatable.has(entry.facet));
  return {
    decision: everyWideningEscalatable ? "step_up_required" : "deny",
    reason_codes: codes,
    escalated_facets: everyWideningEscalatable ? delta.widenings.map((entry) => entry.facet) : [],
  };
}
