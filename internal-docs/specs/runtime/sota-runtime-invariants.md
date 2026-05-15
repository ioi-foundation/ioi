# SOTA+ Chat/Artifact Runtime Invariants

Status: implementation scaffold active

The runtime is a bounded execution system. Models propose actions; the runtime
settles them. Product surfaces may request work, but consequential work must pass
through the runtime kernel and produce verifier-checkable authority.

## Non-Negotiable Invariants

1. No consequential action without a persisted policy decision.
2. No approval-gated action without an approval grant bound to the exact request, policy, authority scope, audience, and deadline.
3. No tool call without a scoped capability lease or an explicit simulation-only classification.
4. No action settlement without a receipt bundle.
5. No model output directly mutates canonical state.
6. No event stream is authoritative over persisted settlement state.
7. No artifact promotion without validation evidence.
8. No retry or repair without its own authority and receipt.
9. No external side effect without precondition and postcondition evidence.
10. No long-running operation without a deadline and cancellation behavior.
11. No production or marketplace profile with dev/unconfined capabilities enabled.

## Consequential Graph Nodes

The legacy Studio graph surface is now treated as the chat/artifact graph surface.
Consequential graph node types are:

- `browser`
- `code`
- `tool`
- `web_search`
- `web_read`
- `transcribe_audio`
- `synthesize_speech`
- `vision_read`
- `generate_image`
- `edit_image`
- `generate_video`

These nodes must either carry settlement authority or fail closed. `GovernanceTier::Silent`
may suppress user interruption, but it must not auto-approve approval-required work.

## Kernel Direction

New runtime primitives live under `crates/services/src/agentic/runtime/kernel/`.
The kernel modules now define approval scope matching, policy provenance,
deadlines, invocation envelopes, target-specific evidence manifests, executable
plan validation, scope leases, settlement bundle v2 refs, artifact promotion
receipts, trace authority split, operator interventions, runtime profile
validation, marketplace admission contracts, and model runtime error classes.

Existing `desktop_agent` behavior remains the compatibility baseline while graph,
workflow, connector, plugin, MCP, browser/computer-use, model, and artifact promotion
paths migrate behind the same invariants.

## Profile Guardrail

Production, marketplace, and validator profiles are fail-closed. Startup and raw
driver seams must reject browser no-sandbox, development filesystem MCP, unverified
or unconfined MCP, unconfined plugins/connectors, disabled receipt strictness, and
disabled external approval enforcement.
