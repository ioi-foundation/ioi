// A verifier's memory fixtures go through the ONE writer memory entries have (R-240, verifier hazard sweep 2, 2026-09-29).
//
// WHY THIS EXISTS. Since ledger XXXII (M13.7) the memory-entry family is PROPOSAL-ONLY: a direct
// `POST /v1/hypervisor/memory-entries` or `PATCH /v1/hypervisor/memory-entries/:id` answers
// 409 `memory_entry_direct_mutation_refused`, because those verbs persisted a record with no receipt. The
// three intelligence verifiers (ioi-agent-intelligence-cockpit, portable-memory-vault,
// memory-graph-explainability) still built their fixture vault through the direct verbs, so every entry was
// refused and every projection/redaction/graph clause after it read an empty vault (12/25, 14/23, a crash).
// This is the product's own lane, driven the way an operator drives it:
//
//   propose   POST /v1/hypervisor/memory-mutation-proposals   { operation: add | supersede | archive, … }
//   approve   POST /v1/hypervisor/memory-mutation-proposals/:id/approve   → a `hypervisor.memory-mutation` receipt
//   read      GET  /v1/hypervisor/memory-entries/:id           (the durable record the approval applied)
//
// A fixture entry is operator-authored, so its proposal names `source_authority: "user"` and the reviewer
// accepts it (`quality_state: "accepted"`) — what a direct operator create stored. A model/run claim would
// arrive as a `candidate`, which the projection planner excludes by default; a fixture that silently became a
// candidate would change every inclusion decision the verifiers assert. A supersede keeps the entry's own
// quality_state for the same reason (the approval otherwise stamps `candidate` on the patch). An entry's
// status (`revoked`, `archived`, `active`) moves by a supersede naming it, exactly as the patch did.
//
// Every call answers { status, j, proposal, record }: `status`/`j` are the refusing answer (proposal create,
// else approval) or the approval's; `record` is the entry read back after the approval (null when refused).
// A proposal whose approval is refused is rejected at once, so a refused fixture leaves no open review item.

const LIVE_POSTURES = Object.freeze(["token-lease:bound", "open", "local-none"]);

/**
 * The connector a connector_derived fixture entry names: the first lease-ready one on the stack, else an OPEN
 * connector registered through the product's own route (POST /v1/hypervisor/connectors, requires_credential false,
 * a base_url nothing listens on — it is named, never called). On the owner's populated daemon one always existed;
 * on a fresh stack the connector-derived clauses were skipped (and a vault export held one entry too few).
 * Returns the connector record, or null when the registration is refused.
 */
export async function liveConnectorFixture(jd, label) {
  const listed = (await jd("GET", "/v1/hypervisor/connectors")).j?.connectors || [];
  const live = listed.find((c) => LIVE_POSTURES.includes(c.auth_posture));
  if (live) return live;
  const safe = String(label).replace(/[^a-z0-9-]+/giu, "-").slice(0, 40);
  const made = await jd("POST", "/v1/hypervisor/connectors", {
    service: `verifier-${safe}`, name: `Verifier ${safe}`, kind: "http", base_url: "http://127.0.0.1:9", requires_credential: false,
    allowed_tools: [{ name: "notes.list", method: "GET", path: "/notes" }],
  });
  const connector = made.j?.connector || null;
  return connector && LIVE_POSTURES.includes(connector.auth_posture) ? connector : null;
}

const MUTATION_TYPE_OF_KIND = Object.freeze({
  preference: "preference",
  instruction: "procedure",
  fact: "fact",
  tool_affordance: "tool_affordance",
  connector_derived: "connector_observation",
});

const mutationTypeOf = (kind) => MUTATION_TYPE_OF_KIND[kind] || "fact";
const idOf = (ref) => String(ref || "").split("/").pop();

/**
 * The memory proposal lane over a verifier's own request function `jd(method, path, body) → { status, j }`
 * (its stack's operator signs every call). options.reason names the fixture on each proposal.
 */
export function memoryProposalLane(jd, { reason = "verifier fixture", sourceRunRef = null } = {}) {
  async function apply(body) {
    const proposed = await jd("POST", "/v1/hypervisor/memory-mutation-proposals", {
      reason,
      source_authority: "user",
      ...(sourceRunRef ? { source_run_ref: sourceRunRef } : {}),
      ...body,
    });
    const created = proposed.j?.proposal;
    if (proposed.status !== 201 || !created?.mutation_id) return { status: proposed.status, j: proposed.j, proposal: null, record: null };
    const approved = await jd("POST", `/v1/hypervisor/memory-mutation-proposals/${encodeURIComponent(created.mutation_id)}/approve`);
    const proposal = approved.j?.proposal || null;
    if (approved.status !== 200 || proposal?.review_state !== "approved") {
      await jd("POST", `/v1/hypervisor/memory-mutation-proposals/${encodeURIComponent(created.mutation_id)}/reject`, { reason: "verifier fixture: the approval was refused" });
      return { status: approved.status, j: approved.j, proposal: created, record: null };
    }
    const read = await jd("GET", `/v1/hypervisor/memory-entries/${encodeURIComponent(idOf(proposal.applied_ref))}`);
    return { status: approved.status, j: approved.j, proposal, record: read.j?.record || null };
  }
  return {
    /** A new entry: an `add` proposal, accepted by the operator. */
    create(entry) {
      return apply({ operation: "add", mutation_type: mutationTypeOf(entry?.entry_kind), suggested: { quality_state: "accepted", ...entry } });
    },
    /** Change an existing entry (body, status, …): a `supersede` proposal that keeps its title and quality. */
    supersede(entry, changes) {
      return apply({
        operation: "supersede",
        mutation_type: mutationTypeOf(entry?.entry_kind),
        target_ref: entry?.entry_ref,
        suggested: { title: entry?.title, quality_state: entry?.quality_state || "accepted", ...changes },
      });
    },
    /** Archive an entry: an `archive` proposal. */
    archive(entry) {
      return apply({ operation: "archive", mutation_type: mutationTypeOf(entry?.entry_kind), target_ref: entry?.entry_ref });
    },
  };
}
