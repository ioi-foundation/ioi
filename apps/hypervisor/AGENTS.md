# Agent guide — Hypervisor App

**Before changing any UX, read [docs/design-system.md](docs/design-system.md).** It is the
ground-truth index to the ported product experience. Preserve that experience while replacing
its data, authority, and runtime assumptions with IOI-owned contracts.

## Non-negotiable migration invariant

- **The ported app UX is the executable product seed.** The owned bundle under
  `product-ui/owned/public`, `scripts/serve-product-ui.mjs`, the IOI API adapter, and the
  ported surface modules under `surfaces/` are the current starting product. Do not delete
  them in order to substitute a newly observed or re-authored shell.
- Raw captures, comparative readouts, `/__apps/*` reference routes, screenshots, and dormant
  source material are evidence only. Retiring those reference lanes does not authorize
  retiring the corresponding ported app surface.
- Source ownership means adopting and editing the exact ported implementation, then rebinding
  it in place to IOI daemon contracts. It does not mean recreating the visible result in a
  parallel React tree from observation.
- A new first-party client is allowed when a canonical product journey has no suitable ported
  seed. In particular, `ioi.ai` may use a dedicated React client for GoalRun and OutcomeRoom.
  That client remains a protocol client over daemon-owned truth and is not a replacement for
  the Hypervisor ported-app estate.

## App-by-app cutover rule

For each app or workspace, in this order:

1. Resolve its canonical owner, class, route, primary job, context, and operational-journey
   work item.
2. Identify the exact ported seed and preserve its visual, interaction, deep-link, focus,
   narrow-layout, and accessibility baseline.
3. Admit the owner contracts and daemon projection required by that app; never infer authority
   or launchability in the client.
4. Rebind the ported implementation in place, or extract/adopt its exact owned source when a
   build-system conversion is necessary. Do not substitute a lookalike implementation.
5. Prove populated and empty behavior plus denial, fault, stale/conflict, recovery,
   migration, receipt, and non-overclaim paths.
6. Cut over only that app's canonical route. Retire only its superseded reference route,
   fixture, or adapter branch after positive parity and negative no-fallback proof.

The bundle/server boundary may be retired only after every live ported app has an individually
admitted replacement or in-place binding, the retained app census has no unresolved seed, and
the old boundary has typed refusal and no-fallback proof. A mass deletion is forbidden.

## Runtime and verification

- Run the current product with
  `npm run serve:product-ui --workspace=@ioi/hypervisor-app` (default `:4173`).
- The daemon owns execution, policy, approvals, model mounting, connector calls, secrets,
  receipts, replay, workspace mutation, and durable product-surface compilation. The client
  projects truth and sends typed requests.
- Use semantic design tokens, preserve light/dark and reduced-motion behavior, and verify the
  exact affected app in both themes.
- Every cutover must run the surface-module, source-neutrality, contract, negative-path,
  runtime-layout, and application-specific journey checks. Pixel parity alone is not product
  membership or operational proof.
