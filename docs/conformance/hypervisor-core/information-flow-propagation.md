# Information-flow propagation conformance

Status: target conformance contract with registered information-flow and
declassification schemas, fixtures, and generated projections. No estate-wide
runtime enforcement seam is claimed.
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

The current machine-contract substrate validates `InformationFlowLabel` and
`DeclassificationApproval` shapes and emits deterministic Rust/TypeScript
projections. Current master does not mount the shared label derivation and
exact-effect admission contract below at connector, MCP, hosted-model, browser,
memory, webhook, WorkResult, or OutcomeDelta effect boundaries. Existing
fields or adjacent policy checks in those owners are implementation precedents,
not a Cut 3B1 pass.

A conforming browser seam must classify every routed action, bind the actual
destination and serialized action, validate parent labels before the driver
call, and label external results untrusted. No current browser execution path
may be cited as satisfying that contract merely because it has a policy check
or URL field.

## Required adversarial evidence

A future `ifc` conformance tier must exercise:

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

Current machine-contract evidence is limited to:

```bash
npm run check:architecture-contracts
npm run test:architecture-contract-projections
```

## Explicit nonclaims

Those commands validate the positive public and private/untrusted label
fixtures, missing-instruction-authority rejection, exact declassification
binding, missing-reviewed-representation rejection, and generated projection
parity. They do not invoke a storage, network, model, browser, webhook, or room
owner.

This profile does not claim current Cut 3B1 runtime coverage, including the
connector, MCP tool, hosted-model, browser, memory, webhook, WorkResult, and
OutcomeDelta seams named above. It also does not claim Cut 3B2 coverage for MCP
resources, prompts, elicitation, tasks, or Apps; browser network-stack
interception, redirect or ambient-request destination enforcement,
response/download-byte propagation, resolved pointer-coordinate binding,
history-target or target-tab URL enforcement, canonical browser context
propagation from the production execution owner, or general computer-use
actions; OutcomeRoom discussion messages, artifact-byte resolution, or a
general label registry; inbound connector subscriptions other than the signed
automation-webhook vertical; other connector families; or estate-wide
`ContextCell` propagation.
The presence of label-ref fields on WorkResult or OutcomeDelta does not prove
ref preservation, label resolution, derivation closure, or independent
verification.
Uncovered surfaces must remain typed-unavailable, fail closed when they reach a
guarded seam without context, or explicitly report unpropagated status until
their owners implement and test the same contract.
