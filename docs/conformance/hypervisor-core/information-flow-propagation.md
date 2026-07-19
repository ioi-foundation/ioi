# Information-flow propagation conformance

Status: active conformance profile.
Canonical inputs:
[`security-privacy-policy-invariants.md`](../../architecture/foundations/security-privacy-policy-invariants.md),
[`common-objects-and-envelopes.md`](../../architecture/foundations/common-objects-and-envelopes.md),
and [`connectors-tools/contracts.md`](../../architecture/components/connectors-tools/contracts.md).
Last audited: 2026-07-16.

## Required Cut 3B1 behavior

A conforming Cut 3B1 runtime must:

1. validate every parent `InformationFlowLabel` and the exact
   `RuntimeToolContract` at the owning boundary;
2. require independently admitted effect authority and recompute its effective
   label from the actual parent set plus the canonical request hash;
3. preserve the most restrictive confidentiality, integrity, egress, purpose,
   retention, and full derivation closure;
4. treat raw MCP, browser, and model results as untrusted, content-only values;
5. run admission immediately before the real external/storage invoker so a
   denial proves zero invoker calls; and
6. refuse missing parents, unknown axes, undeclared destinations, forged public
   effect labels over restrictive parents, and private-plus-untrusted egress.

The scoped built seams are non-MCP HTTP connector invocation, MCP
`tools/call`/`tools/list`, hosted-provider blocking/stream calls,
the browser typed-action handler, Agentgres memory record write/edit persistence,
signed automation-webhook admission, and room-scoped WorkResult/OutcomeDelta
label-ref preservation. An OutcomeDelta unions its bound WorkResult's label
refs with any additional refs before its record and receipt are committed.

The browser seam classifies every browser variant routed by `ToolExecutor`.
Navigation uses the exact requested URL; other consequential actions use the
cached active URL, and both bind the complete serialized `AgentTool`. Pure
reads validate their parent set before the driver call. Missing context,
missing destination, or pre-effect refusal must make the action-driver closure
structurally unreachable. Every returned browser result receives an untrusted,
non-authoritative external-observation label. This is held conformance: the
production action-execution owner does not yet supply `BrowserInformationFlowContext`,
so browser actions fail closed until canonical parent propagation is wired.

## Required adversarial evidence

The `ifc` conformance tier must exercise:

- the shared Rust and TypeScript adversarial fixture matrix;
- mutation invalidation for destination, request, and reviewed representation;
- missing/invalid parent refusal before storage or external invocation;
- forged public-effect-label refusal over private/untrusted actual parents;
- raw model output remaining untrusted even when its private input was verified;
- MCP denial before driver resolution and hosted-model denial before any socket
  accepts a connection;
- every routed browser variant having an explicit observation/consequential
  class, with missing context, missing cached destination, and failed admission
  producing zero browser-action driver calls;
- restrictive memory relabeling where a replayed prior label is a parent, not a
  trusted replacement; and
- webhook body/signature mutation, stale/future timestamps, nonce conflict,
  exact replay, token rotation, pending-dispatch concurrency, and forged or
  legacy launch records; and
- an OutcomeDelta being unable to discard an inherited WorkResult label ref;
  plus
- successful compilation of the Hypervisor daemon route containing the actual
  memory persistence seam.

Run:

```bash
npm run hypervisor-conformance:ifc
```

## Explicit nonclaims

This profile does not claim Cut 3B2 coverage for MCP resources, prompts,
elicitation, tasks, or Apps; browser network-stack interception, redirect or
ambient-request destination enforcement, response/download-byte propagation,
resolved pointer-coordinate binding, history-target or target-tab URL
enforcement, canonical browser context propagation from the production
execution owner, or general computer-use actions; OutcomeRoom discussion
messages, artifact-byte resolution, or a general label registry; inbound
connector subscriptions other than the signed automation-webhook vertical;
other connector families; or estate-wide `ContextCell` propagation.
WorkResult/OutcomeDelta coverage proves ref preservation, not independent
verification of every referenced label.
Uncovered surfaces must remain typed-unavailable, fail closed when they reach a
guarded seam without context, or explicitly report unpropagated status until
their owners implement and test the same contract.
