# Final Question Pass Gap Map

Date: 2026-04-16
Scope: `docs/plans/question-answers/`
Goal: compare the fully answered Claude corpus against the current IOI runtime
after the parity-plus and domain-topology sprints.

Refined closure plan:

- `docs/plans/claude-harness-final-gap-closure-plan.md`
- `docs/evidence/route-hierarchy/2026-04-16-final-gap-reuse-session-validation.md`

Validation note:

- The retained-session weather parity prompt pair is now desktop-validated in
  `2026-04-16-final-gap-reuse-session-validation.md`.
- This closes the concrete follow-up continuity blocker that previously kept
  the weather specialized-lane proof from being fully end to end.
- The broader gap verdicts below remain useful as a corpus-wide map of where
  more domain families still need the same strength of proof.

## Verdict

We do **not** yet exceed Claude in every area covered by the full
question-and-answer corpus.

Current state:

- Discovery corpus questions `1-43`: still `better`
  - See `docs/evidence/route-hierarchy/2026-04-15-claude-question-matrix.md`
- Follow-up domain-topology questions `44-62`:
  - `10` are now `better`
  - `9` are still `partial`
  - `0` are clearly `worse`

The important distinction:

- We now exceed Claude wherever the answer exposed hidden or emergent runtime
  behavior that IOI can encode explicitly.
- We are still only partial where the answer exposed product/runtime features
  that require more than typed receipts:
  - richer domain-specific fallback policies
  - more explicit lane verification
  - stronger widget-state continuity
  - fuller cross-source ranking enforcement
  - more flexible presentation arbitration for specialized domains

## Questions Now Better

| Q | Verdict | Why IOI is now better | Main seams |
|---|---|---|---|
| 44 | better | We now explicitly canonicalize high-value turns into typed lane and request frames instead of relying on emergent routing only. | `crates/api/src/studio/domain_topology.rs`, `crates/types/src/app/studio.rs` |
| 45 | better | Top-level lane families and first-class runtime objects are now typed and inspectable. | `crates/types/src/app/studio.rs`, `apps/autopilot/src-tauri/src/kernel/studio/content_session/route_contract.rs` |
| 46 | better | We retain primary lane plus secondary assists explicitly rather than describing multi-lane behavior post hoc. | `crates/api/src/studio/domain_topology.rs` |
| 47 | better | High-value specialized domains are no longer just prompt-patterned in IOI; they have shared extraction and typed request framing. | `crates/api/src/studio/intent_signals.rs`, `crates/api/src/studio/domain_topology.rs` |
| 48 | better | Specialized-domain request shapes are now explicit runtime objects instead of latent regularities. | `crates/types/src/app/studio.rs`, `crates/api/src/studio/domain_topology.rs` |
| 49 | better | Minimum inferred slots and clarification-required slots are represented directly in the request frames. | `crates/types/src/app/studio.rs`, `crates/api/src/studio/domain_topology.rs` |
| 52 | better | Connector-backed and built-in specialized domains now share one lane/source ontology rather than separate routing stories. | `crates/api/src/studio/domain_topology.rs`, `apps/autopilot/src-tauri/src/kernel/studio/content_session/connectors.rs` |
| 58 | better | We now maintain a typed objective/task/checkpoint model in runtime state instead of leaving long-form planning mostly implicit. | `crates/types/src/app/studio.rs`, `crates/api/src/studio/domain_topology.rs` |
| 59 | better | The methodology-agnostic primitives are now real runtime constructs, not only design advice. | `crates/types/src/app/studio.rs`, `docs/plans/studio-route-first-decompose-second-plan.md` |
| 61 | better | Planned and reactive lane transitions are now first-class retained receipts with reasons and evidence. | `crates/api/src/studio/domain_topology.rs`, `apps/autopilot/src/windows/SpotlightWindow/components/ExecutionRouteCard.tsx` |

## Remaining Partial Gaps

### Q50: clarify vs assume policy by specialized domain

Current state:

- We now retain `missing_slots` and `clarification_required_slots`.
- We do **not** yet encode a sufficiently strong per-domain assumption policy
  that says when to proceed anyway versus when to force clarification.

Gap:

- Behavior is structured, but not yet benchmarked or enforced strongly enough
  to claim we exceed across all specialized lanes.

Likely next seams:

- `crates/api/src/studio/domain_topology.rs`
- `apps/autopilot/src-tauri/src/kernel/studio/content_session/clarification.rs`
- `apps/autopilot/src-tauri/src/kernel/studio/prepare.rs`

### Q51: staying in specialized lanes vs falling back to generic search/browser/direct

Current state:

- We have lane-first topology and narrow-tool preference.
- We do **not** yet have a comprehensive, explicit domain fallback contract for
  each specialized lane.

Gap:

- We can explain and inspect the selected lane, but we do not yet prove
  lane-stay vs fallback behavior for all specialized domains with the same
  strength as the original route-precedence contract.

Likely next seams:

- `crates/services/src/agentic/runtime/service/step/route_projection.rs`
- `crates/api/src/studio/domain_topology.rs`
- `apps/autopilot/src-tauri/src/kernel/studio/prepare.rs`

### Q53: specialized-domain result presentation arbitration

Current state:

- We have explicit route family, output intent, and retained lane/request state.
- Specialized domain lanes still mostly land in their native presenter shape.

Gap:

- We do **not** yet have a fully explicit arbitration layer deciding between
  inline prose, widget, map, artifact, and downloadable file for specialized
  domains with collection/comparison/ongoing-utility semantics.

Likely next seams:

- `crates/api/src/studio/planning/routing.rs`
- `apps/autopilot/src-tauri/src/kernel/studio/content_session.rs`
- `crates/api/src/studio/payload.rs`

### Q54: transformation and synthesis over structured specialized-tool results

Current state:

- IOI can synthesize around structured results.
- The transformation policy is still mostly lane behavior, not a typed
  specialized-domain post-processing contract.

Gap:

- We do not yet expose a clear contract for when structured tool results should
  be passed through, summarized, compared, or converted into artifacts.

Likely next seams:

- `apps/autopilot/src-tauri/src/kernel/studio/prepare.rs`
- domain-specific tool widget preparation flows
- capabilities / desktop prompt coverage

### Q55: domain semantics in schema vs hidden instructions

Current state:

- IOI is better on route receipts and typed framing.
- We still depend heavily on instructions and runtime logic outside raw tool
  schemas.

Gap:

- This is only partially closed unless we move more domain semantics into
  typed contracts or schema-adjacent metadata rather than prompt/doctrine.

Likely next seams:

- route-contract payload schema
- internal tool metadata and capability registry
- specialized tool descriptors

### Q56: domain-specific sensitivity to argument precision, grounding, and continuation

Current state:

- Tool normalization/coercion is explicit and measurable.
- We do not yet have a per-domain sensitivity model that guides routing,
  clarification, or retries.

Gap:

- We can observe repair, but not yet reason from an explicit domain-risk model.

Likely next seams:

- `apps/autopilot/src-tauri/src/kernel/studio/content_session/route_contract.rs`
- tool normalization observations
- specialized-domain benchmark cases

### Q57: retained UI/widget state influencing later route choice

Current state:

- `retained_lane_state` now exists.
- True runtime widget state is still not bridged into the agent uniformly.

Gap:

- We do not yet exceed Claude on actual cross-turn artifact/widget runtime
  continuity because the agent still largely sees retained structure, not live
  widget interaction state.

Likely next seams:

- artifact/widget event bridge
- `apps/autopilot/src/windows/SpotlightWindow/components/ArtifactRendererHost.tsx`
- Studio retained-trace and send-prompt style plumbing

### Q60: lane-specific success criteria and verification gates

Current state:

- Research, coding, computer-use, and artifact lanes already have meaningful
  verifier surfaces.
- Specialized lanes such as weather, sports, places, recipe, and messaging do
  not yet have equally explicit success criteria and verification gates.

Gap:

- We do not yet exceed Claude here because the domain-specific lanes are better
  typed than his, but not yet fully verified.

Likely next seams:

- route/lane verifier expansion
- capabilities suite / desktop prompt validation
- Spotlight summaries for specialized lanes

### Q62: source ranking across specialized tools, connectors, search, memory, and retrieval

Current state:

- We now retain `candidate_sources` and `selected_source`.
- We do not yet have a thoroughly enforced and benchmarked cross-source
  ranking engine covering memory, conversation retrieval, connectors,
  specialized tools, search, and direct answer in one explicit policy.

Gap:

- The receipt is there; the full ranking doctrine is not yet closed.

Likely next seams:

- `crates/api/src/studio/domain_topology.rs`
- `apps/autopilot/src-tauri/src/kernel/studio/content_session/connectors.rs`
- memory / conversation retrieval route tests

## Practical Summary

The runtime now clearly exceeds Claude on:

- typed route and lane contracts
- explicit domain frames
- normalized specialized request objects
- multi-lane composition
- retained lane transitions
- methodology-agnostic orchestration state
- inspector truth

The runtime is still only partial on:

- domain-specific clarify-vs-assume policy
- lane-stay vs fallback enforcement
- specialized presentation arbitration
- structured-result transformation policy
- encoding more semantics outside hidden instructions
- domain risk profiles
- true retained widget/runtime state
- specialized-domain verification gates
- full cross-source ranking policy

## Next Sprint Shape

The focused execution plan now lives in:

- `docs/plans/claude-harness-final-gap-closure-plan.md`
- `docs/plans/question-answers/I Live Parity Query Prompts/`

Its added constraints matter:

- parity widgets must exist for every validated domain
- desktop validation is required for closure
- long-form multi-domain polish from Question `75` is part of the closure bar,
  not a separate optional follow-on
