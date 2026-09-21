# ADR 0055: The Outward MCP Gateway Profile Is A Registered Contract On One Ref Scheme, Its Eighth Kind Is Source-Neutral, And Its "Heavy Builder GoalRun" Clause Is Retyped

Status: Accepted

Date: 2026-09-21

Relates to: [ADR 0032](./0032-independently-implemented-client-definition.md)
(the named axes an outward consumer is measured on, which this profile does not
add a fourth to), [ADR 0034](./0034-thread-fork-is-the-delegation-primitive-subagents-are-its-surface.md)
(the delegation primitive an admitted external invocation resolves into rather
than beside), and the owner ruling R-192 (2026-09-18), which removed goal pursuit
from the Hypervisor.

## Context

Canon has specified the outward Hypervisor MCP Gateway since before the MVP
program began. It describes a `HypervisorMCPGatewayProfile` in sixty members, an
eleven-route API, seven profile kinds, a package-requirement envelope that is
deliberately not a profile, and a local-agent pairing admission proof. None of it
is built. Both mounted gateway routes refuse typed-unavailable, no schema is
registered, and nothing in the daemon reads or writes a profile record.

That is a normal state for unbuilt work. Four things about it are not normal, and
each would silently mislead the unit that builds it.

**One object, two ref schemes, both live.** Canon writes the profile's identity as
`mcp_gateway://project-auditor-readonly`. The System genesis schema enforces
`^mcp-gateway://…/revision/sha256:…`. The legacy alias map already maps the first
to the second, and the genesis compiler accepts both. An object with two spellings
has two identities, and the moment a profile is stored under one and resolved
under the other, the refusal will read as "no such profile" rather than as the
authoring mistake it is.

**An eighth profile kind exists in the program's private notes and nowhere else.**
`capability_construction_eval` — the source-neutral builder surface — appears in
the unit manifest, the module document and the journey, and in zero tracked canon,
schema, fixture or line of code. The acceptance journey already speaks of "the v2
profile kinds" as though a v2 were registered. It is not; there is one kind list,
of seven, in two canon documents.

**The unit's own check text names a plane this estate deleted.** It requires the
gate to "invoke the sole heavy builder GoalRun end to end through one
source-neutral `capability_construction_eval` profile". R-192 ruled goal pursuit
out of the Hypervisor four months into the program: the GoalRun routes, the
admission kernel and the profile plane were deleted, goal pursuit became the
ioi.ai application's composition over generic thread-orchestration primitives, and
the daemon today mounts no goal route at all. The one composition that survives
records that a bounded pursuit exists and explicitly does not start execution. A
check text that cannot be executed is not a high bar; it is an unfalsifiable one,
and a unit closed against it would be closed against nothing.

**A package requirement is not a profile, and the schemas already enforce that.**
The System manifest carries `mcp_gateway_requirements` under an immutable
requirement scheme; the genesis carries `mcp_gateway_profiles` under the profile
scheme; a source gate asserts the manifest schema does not contain the string
`mcp_gateway_profiles` at all. This separation is correct and easy to erase by
accident while building the thing that sits between the two.

## Decision

**1. The canonical ref scheme is `mcp-gateway://`, hyphenated.** It is what the
registered schemas already enforce, what the genesis compiler normalizes to, and
what the alias map already points at. Canon's underscored examples are retyped in
the same cut that registers the contract. The requirement envelope keeps
`mcp-gateway-requirement://`. One object, one spelling.

**2. A v2 successor adds `capability_construction_eval` and changes nothing
else.** The seven v1 kinds — `discovery_readonly`, `project_session`,
`connector_preview`, `operator_proposal`, `effectful_approved`,
`foundry_eval_training`, `receipts_replay_proof` — keep their exact meanings and
their exact v1 contract. The eighth is the source-neutral builder surface, and
`foundry_eval_training` remains what it already is: the optional first-party
training specialization, separately admitted. A v1 profile presented to a v2
reader, and a v2 profile presented to a v1 reader, both refuse; canon says nothing
about cross-version behaviour today, so this ADR is where it is said.

**3. The "heavy builder GoalRun" clause is RETYPED, not waived.** What that clause
was reaching for is the strongest claim the gateway can make: that an external
builder invocation admitted through one subject-scoped profile reaches **the same
final invoker, under the same contract resolution, with the same receipt
obligations, as the native path** — and that the MCP path can neither widen what
the native path would allow nor execute what it would refuse. That claim does not
need goal pursuit. It needs one real tool invocation through one admitted
`capability_construction_eval` profile reaching
`RuntimeAgentService.handle_action_execution` through an admitted
`RuntimeToolContract`, measured against the native call on a fresh idempotency
namespace. The application-composed goal run stays where R-192 put it: it is
ioi.ai's, it is named as an absence with its owner, and it is not executed by a
Hypervisor gate.

This is a narrowing of the words and not of the proof. The deleted reading asked
for a plane; this reading asks for the equivalence, which is what the acceptance
was ever about.

**4. The profile plane is mounted at canon's `/v1/mcp/gateways/*`, and the two
existing outward tool routes resolve a profile instead of refusing
unconditionally.** `/v1/hypervisor/mcp-gateway/tools` and its invoke sibling stay
where they are — they are the outward tool surface, classified in the daemon's
closed MCP route table, and moving them would break consumers for a cosmetic
reason. What changes is that they resolve an admitted profile revision and refuse
typed-unavailable only when none resolves. Every route added under
`/v1/mcp/gateways/` joins the closed classification table in the same cut, because
that table refuses at daemon startup and not in a test.

**5. Packaging a requirement still creates nothing.** The manifest's requirement
lane and the genesis's profile lane stay separate, the source pin that enforces
the separation stays, and resolving a requirement remains an evaluation of one
immutable revision against one proposed use — never an issuance.

## Consequences

The unit that builds this registers three contracts where none exist today: the
requirement envelope, the v1 profile and its v2 successor. It writes canon's
cross-version rule, which canon has never had. It retypes three GoalRun residues
in the gateway sections of `contracts.md` and `doctrine.md` that the R-192 pass
has not reached, and it retypes the acceptance journey's own heavy-builder
sentence to match decision 3.

Two negative pins go red by design when the profile lands: the source gate that
asserts the gateway refuses through `mcp_gateway_profile_unavailable`, and the
daemon test that asserts the outward invoke carries no `result` and no `tools`.
Both are correct today. Both must be deliberately retyped to assert the new
boundary — a profile-resolving surface that still refuses without one — rather
than deleted. Deleting a negative pin because the thing it forbids became
permitted is how a boundary is lost.

The eighth kind means the acceptance journey's phrase "the v2 profile kinds"
becomes true rather than aspirational, and ACC-1 clauses 8 and N6 gain executable
evidence where they carry the journey's only two typed absences with nothing
behind them.

This ADR does not decide whether the gateway ever exposes a non-tool primitive
positively. Those primitives normalize through M01.10's registered decision, and
four of the five have no canonical owner to normalize to. The gateway exposes what
the estate can honestly serve and refuses the rest in the same registered
envelope.
