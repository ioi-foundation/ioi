# ADR 0025: Make The Hypervisor App The Primary Human Attach Journey After Binding

- Status: Accepted
- Date: 2026-07-29
- Owners: Hypervisor Core clients and surfaces / daemon runtime / execution horizons
- Refines: ADR 0008, ADR 0013, ADR 0021
- Unaffected: ADR 0019, ADR 0020, ADR 0022 (attach does not create a
  GoalRun or move GoalRun ownership)
- Confidence: settled for the conditional product routing and retirement rule;
  implementation remains gated by the existing six-point binding bar.

## Acceptance Record

Drafted 2026-07-29 and parked, unaccepted, in wip commit `2e9091e32`; landed
2026-08-05 under canon-agenda item R-04, which found the file absent from the
working tree and from this directory's index while
`components/daemon-runtime/doctrine.md` and
`components/hypervisor/core-clients-surfaces.md` already cited it as accepted.
The decision text below is the parked text; it was checked against current canon
before landing and still matches it — the six-point binding bar it depends on is
live at [`_meta/execution-horizons.md`](../architecture/_meta/execution-horizons.md)
§ external-surface integrity rule, and both citing owners already carry this
decision's substance as current prose. Only the acceptance record and one
consequence bullet naming a since-deleted program estate are new. The candidate
App implementation and journey scripts that shared the parked commit did **not**
land with it: the scripts are exactly the proof apparatus retired on 2026-08-05,
and an ADR does not need its candidate implementation to be an accepted
decision.

## Context

The Authority Gateway is the early compatibility ingress for agents and tools
that already run elsewhere. Hypervisor also defines App, Web, CLI/headless,
SDK clients, and the MCP Gateway as clients or protocol gateways over the same
Core. Canon did not state when the native App should become the default simple
attach journey or what may be retired after that transition. Designating it
before it is bound would turn a presentation surface into product truth;
leaving the priority permanently undefined would retain transitional launcher
sprawl after a first-party journey exists.

`execution-horizons.md` already supplies the binding rule. One content-bound
replacement must compile from canonical registrations, read real
daemon/Agentgres state, route consequential work through authority, receipts,
and the actual final invoker, handle negative and recovery states, pass its
operational/accessibility/product-truth journey, and retain no externally
derived production fallback. All six hold or the surface is not bound.

## Decision

1. **The Hypervisor App becomes the default first-party human/simple attach
   journey only after one exact release passes all six binding conditions.**
   Until then it is a candidate surface and the currently supported ingress
   remains the truthful route.

2. **The bound journey is complete, not a launcher button.** It selects a
   declared agent/harness profile, binds the repository and existing
   Work/Session context, previews the exact effect and mediation coverage,
   obtains applicable authority, invokes or refuses through the daemon final
   invoker, exposes independently verifiable admission/effect receipts, then
   revokes and demonstrates denial/recovery.

3. **Primary is product routing, not ownership or exclusivity.** The App stays
   a client; the daemon stays the policy-enforcement and execution owner; the
   applicable authority provider stays the issuer; Agentgres stays durable
   truth; Work stays a projection. Direct attachment creates no GoalRun.
   GoalRun appears only through an explicitly selected run-on/graduation path.

4. **Client and gateway categories remain.** CLI/headless remains first-class
   for automation, conformance, and recovery. MCP remains a protocol gateway.
   Editor and harness integrations remain compatibility adapters. Individual
   attach launcher implementations are replaceable; those categories are not.

5. **Retirement is exact and per launcher.** A launcher may be retained as a
   supported compatibility surface or retired only after its successor is
   bound, migration/export evidence exists, the launcher is removed from the
   claimed journey, and negative reachability proves no alias, redirect,
   deep-link, or hidden production fallback remains.

6. **Binding is release-specific.** A successor App release re-passes all six
   conditions. Rollback may select a previously bound first-party release, but
   never an unbound or externally derived fallback.

## Consequences

- The App is not primary merely because it renders the intended interaction.
- App binding and launcher retirement are judged on their own evidence rather
  than inferred from Authority Gateway mechanism equivalence or from an entry
  appearing in the application catalog. The six binding conditions and the
  per-launcher retirement rule are the standard; no separate program record is
  required to hold them, and none exists to appeal to.
- An attach/effect claim remains fenced until issuer resolution, atomic
  grant/lease consumption, receipt verification, and the exact final-invoker
  path close for the selected release.
- Existing category, topology, Work, and GoalRun contracts remain unchanged.

## Rejected Alternatives

- **Designate the current App primary by intent.** Rejected: intent, visual
  parity, mock state, or a passing launcher test is not binding evidence.
- **Retire CLI, MCP, or editor categories with the cutover.** Rejected: primary
  human routing does not erase automation, protocol, conformance, recovery, or
  compatibility contracts.
- **Create a separate App authority or runtime lane.** Rejected: every modality
  converges on the same daemon policy-enforcement point and final invoker.
- **Create a GoalRun on attach.** Rejected: attachment binds Work/Session
  context; GoalRun begins only at the existing explicit activation crossing.

## Cost Of Being Wrong And Reversal

If the App proves unsuitable as the default human journey, product routing can
return to another already bound first-party client. No owner, schema, category,
or GoalRun contract changes. Reversal must preserve receipts and migration
evidence and cannot revive a retired hidden fallback.

## Canonical References

- [`../architecture/_meta/execution-horizons.md`](../architecture/_meta/execution-horizons.md)
- [`../architecture/components/hypervisor/core-clients-surfaces.md`](../architecture/components/hypervisor/core-clients-surfaces.md)
- [`../architecture/components/daemon-runtime/doctrine.md`](../architecture/components/daemon-runtime/doctrine.md)
- [`0008-ioi-authority-gateway-sidecar-adoption-wedge.md`](./0008-ioi-authority-gateway-sidecar-adoption-wedge.md)
- [`0013-hypervisor-core-clients-surfaces-and-adapters.md`](./0013-hypervisor-core-clients-surfaces-and-adapters.md)
- [`0021-first-proof-selection-and-attach-lane-sequencing.md`](./0021-first-proof-selection-and-attach-lane-sequencing.md)
