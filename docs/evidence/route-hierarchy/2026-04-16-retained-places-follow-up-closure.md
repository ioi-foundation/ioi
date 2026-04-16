# Retained Places Follow-Up Closure

Date: 2026-04-16

## Summary

Retained clarification follow-ups for the places lane now stay in the specialized tool-widget lane and complete truthfully in the real desktop app.

The validated live run is retained at:

- `docs/evidence/route-hierarchy/live-final-gap-reuse-native-final/2026-04-16T20-04-52Z/manifest.json`

## What Changed

- Extended retained widget follow-up detection so elliptical clarification replies like `Near Williamsburg, Brooklyn.` are treated as contextual follow-ups instead of being replanned as generic conversation turns.
- Preserved active retained widget state when rebuilding non-artifact Studio sessions so topology refresh does not discard specialized lane context.
- Hardened places retrieval with a bounded provider fallback chain:
  - nearby Overpass search first
  - anchor-aware Nominatim search fallback if nearby POI search times out or returns upstream errors

## Live Validation

Run:

- `AUTOPILOT_LOCAL_GPU_DEV=1 python3 apps/autopilot/scripts/dev_reuse_session_probe.py --profile desktop-localgpu --initial-prompt 'Find coffee shops open now.' --follow-up-prompt 'Near Williamsburg, Brooklyn.'`

Observed result:

- initial turn: `Gate`
- follow-up turn: `Complete`
- `session_reused = true`
- `follow_up_user_occurrences = 1`
- `reply_present = true`
- retained selected route: `tool_widget_places`
- retained route family: `research`
- retained primary tools: `places_search`, `places_map_display_v0`

Follow-up answer:

```text
Here are a few coffee shops near williamsburg, brooklyn:
- Mozaik — 522 Metropolitan Avenue (0.1 mi away)
- Brooklyn Roasting Company — 543 Metropolitan Avenue (0.1 mi away)
- 7 Grain Army — 88 Roebling Street, Brooklyn (0.2 mi away)
- Parlor Coffee — Address unavailable (0.2 mi away)
- Oslo Coffee — 133 Roebling Street, Brooklyn (0.2 mi away)
```

Desktop log confirmation:

- follow-up routing stayed `ToolWidget`
- routing hints included `tool_widget:places`, `retained_widget_follow_up`, and `retained_widget_state_applied`

## Targeted Checks

- `cargo test -p autopilot contextual_retained_places_follow_up_prefers_active_widget_lane_for_elliptical_anchor_reply --quiet`
- `cargo test -p autopilot attach_non_artifact_session_preserves_retained_widget_state_during_topology_refresh --quiet`
- `cargo check -p autopilot --quiet`
