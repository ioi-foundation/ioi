# 2026-04-16 Specialized Domain Policy Pass

## Scope

This pass consolidated specialized-domain policy into a shared layer and closed the main kernel seam that was still bypassing clarification for missing domain slots.

Shipped seams:

- `crates/api/src/studio/specialized_policy.rs`
- `crates/api/src/studio/domain_topology.rs`
- `crates/api/src/studio/intent_signals.rs`
- `apps/autopilot/src-tauri/src/kernel/studio/content_session.rs`
- `apps/autopilot/src-tauri/src/kernel/studio/content_session/clarification.rs`

## What Changed

1. Specialized request frames now carry a shared policy contract for:
   - clarification vs assumption
   - lane-stay vs fallback
   - presentation surface
   - transformation shape
   - sensitivity and verification posture
   - source-ranking rationale

2. `studio_outcome_request` now promotes request-frame clarification slots into an actual clarification gate before specialized execution starts.

3. Places clarification copy now recognizes semantic `location` blocking slots in addition to lower-level slot names like `search_anchor`.

4. Places anchor parsing now supports bare follow-up answers such as `Near Williamsburg, Brooklyn.` and preserves multi-segment location strings instead of dropping everything after the comma.

## Validation

Rust validation:

- `RUSTFLAGS='-Awarnings' cargo test -p ioi-api weather_missing_scope_uses_domain_specific_fallback_reason --quiet`
- `RUSTFLAGS='-Awarnings' cargo test -p ioi-api message_compose_domain_policy_bundle_is_explicit_and_medium_risk --quiet`
- `RUSTFLAGS='-Awarnings' cargo test -p ioi-api places_anchor_phrase_parses_bare_follow_up_prefixes --quiet`
- `RUSTFLAGS='-Awarnings' cargo test -p ioi-api places_anchor_phrase_preserves_multi_segment_locations --quiet`
- `RUSTFLAGS='-Awarnings' cargo test -p autopilot message_compose_clarification_uses_domain_specific_prompt_and_options --quiet`
- `RUSTFLAGS='-Awarnings' cargo test -p autopilot places_clarification_uses_domain_specific_anchor_options --quiet`
- `RUSTFLAGS='-Awarnings' cargo test -p autopilot places_request_frame_promotes_missing_anchor_into_clarification_gate --quiet`
- `RUSTFLAGS='-Awarnings' cargo check -p ioi-api --quiet`
- `RUSTFLAGS='-Awarnings' cargo check -p autopilot --quiet`

Live desktop validation:

- Manifest: [live-specialized-domain-policy/2026-04-16T18-31-22Z/manifest.json](/home/heathledger/Documents/ioi/repos/ioi/docs/evidence/route-hierarchy/live-specialized-domain-policy/2026-04-16T18-31-22Z/manifest.json)
- Prompt: `Find coffee shops open now.`
- Result:
  - phase = `Gate`
  - route = `tool_widget_places`
  - route family = `research`
  - presentation surface = `places_widget`
  - blocking slots = `location`
  - clarification question = `Which neighborhood, city, or anchor location should Studio search around?`

This is the expected parity-plus behavior for the unresolved places turn: stay in the specialized lane, surface a typed clarification, and avoid falling through into `prepare.rs` failure.

## Residual Note

The current `dev_reuse_session_probe.py` harness is still unreliable on clarification-gated turns. In the retained runs under `live-specialized-domain-policy/2026-04-16T18-44-15Z`, the runtime correctly exposes the clarification gate, but the probe submits the clarification option copy into history instead of the literal follow-up prompt. That is a probe/control limitation, not the specialized-domain policy runtime.

Separately, one fresh `dev_start_intent_probe.py` run for a fully-resolved places prompt hit a local kernel companion startup failure under a new desktop profile (`2026-04-16T18-46-56Z`), which appears unrelated to the domain-policy changes.
