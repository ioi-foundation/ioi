# ADR 0010: Define Verifiable Bounded Agency As Execution-Boundary Alignment

- Status: Accepted
- Date: 2026-05-22
- Owners: IOI architecture / daemon runtime / wallet.network / Agentgres / policy

Current-canon refinement (2026-07-19): the ownership list below records the
decision's original wallet-centered context. Under `INV-10`, local/domain
governance selects the applicable authority provider for ordinary local
authority; wallet.network owns portable principal-to-approval-authority binding
and is mandatory only for portable delegated authority and designated
high-risk external scopes. The bounded-agency decision is unchanged: every
consequential action still requires exact scoped authority and a receipt.

## Context

IOI needs a precise canonical claim for alignment security. Product and
investor-facing language can easily overstate the architecture as solving all
AI alignment, proving model cognition, or depending on a single proof backend.

The durable architecture is narrower and stronger: autonomous actors may reason
probabilistically, but consequential effects must cross a deterministic,
policy-checked, authority-scoped, receipted execution boundary.

Existing architecture already supports this shape:

- the IOI daemon owns execution semantics and effect admission;
- wallet.network owns authority grants, secrets, payments, approvals, and
  revocation;
- Agentgres owns operation-backed domain truth and receipt metadata;
- IOI L1 anchors public rights, settlement, roots, disputes, and governance;
- CIRC and CEC separate semantic collapse from effect execution and completion
  evidence.

## Decision

IOI adopts **verifiable bounded agency** as its canonical alignment-security
thesis.

The accepted claim is **execution-boundary alignment**:

> workers may reason, synthesize, propose, and improve probabilistically, but
> only bounded, authorized, receipted effects may cross into reality.

Canonical architecture must frame this as an authority and execution model, not
as proof that a neural network's private goals or latent objectives are safe.

The architecture also adopts the following boundaries:

- Worker self-improvement may improve logic, package, workflow, model route,
  policy requirements, tools, and training profile, but it may not self-grant
  broader authority.
- Policy widening requires an external authority path such as user approval,
  wallet.network grant, organization policy, domain governance, or IOI L1
  governance.
- Credential isolation is mandatory: raw long-lived secrets, refresh tokens,
  wallets, and BYOK keys live in wallet.network or equivalent authority planes,
  not in model-facing runtimes.
- Deterministic harness techniques such as fixed seeds, controlled clocks,
  dry-run fixtures, replayable capsules, and single-shot effect execution are
  runtime/conformance strategies, not universal claims that all physical or
  remote environments become perfectly deterministic.
- zkVM proofs, attestations, formal checks, policy-subset proofs, and
  regression gates may strengthen upgrade or continuity assurance, but no
  single proving backend, including SP1, is canonical by default for all IOI
  upgrades.

## Consequences

- Product language should say IOI addresses alignment at the execution
  boundary, not that IOI solves all cognitive alignment.
- Architecture docs should avoid claims that IOI bypasses model evaluation,
  Worker Training, verifier quality, routing quality, or prompt hardening.
- Security docs should treat bounded authority, explicit grants, receipts,
  replay, and revocation as the core safety mechanism for consequential work.
- Implementation specs may introduce stronger proof profiles, but those profiles
  must be scoped to specific upgrade, runtime, or settlement paths.
- Investor-facing claims can use stronger category language such as
  "Sovereign Agent Infrastructure" and "Verifiable Autonomous Systems" when they
  preserve the execution-boundary claim boundary.

## Non-Goals

- Do not claim IOI proves every model's private cognition or goals are safe.
- Do not canonize a pathogen, skull, straw, or containment-facility metaphor as
  architecture doctrine.
- Do not require SP1, a zkVM, a TEE, controlled clocks, PRNG control, or a
  specific deterministic fixture strategy for every IOI execution path.
- Do not imply a worker can never become more powerful; externally authorized
  policy widening is allowed.

## Canonical References

- `docs/architecture/foundations/verifiable-bounded-agency.md`
- `docs/architecture/foundations/security-privacy-policy-invariants.md`
- `docs/architecture/components/daemon-runtime/doctrine.md`
- `docs/architecture/components/wallet-network/doctrine.md`
- `docs/architecture/components/agentgres/doctrine.md`
- `docs/conformance/agentic-runtime/CIRC.md`
- `docs/conformance/agentic-runtime/CEC.md`
