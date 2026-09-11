# ADR 0053: The MVP Is The Governed Runtime — Marketplace, Commerce And Decentralized Cloud Are Product Tracks, And The Alpha Profile Widens Toward Useful Work

- Status: Accepted
- Date: 2026-09-10
- Owners: Hypervisor core surfaces / daemon runtime / providers and
  environments / execution horizons / the private implementation program
- Refines: ADR 0052, ADR 0051, ADR 0027, ADR 0021
- Confidence: working_ruling (owner-ruled 2026-09-10 — "proceed to your
  discretion" on the five usefulness moves; recorded under the standing
  owner-authority rule that canon is ruled and then kept moving, never stalled)

## Context

The bounded alpha (ADR 0052) is qualified: 38/38 from source and 46/46 on
packages without a checkout on `8281d915e`, packaged release with update and
rollback, restart recovery, backup and restore, receipts on every consequential
act, and — since 2026-09-10 — a connector authority plane that speaks one
language (ADR 0052 § 8). Confidence that the alpha is achieved is the strongest
thing the estate has.

What is low is confidence that the alpha is worth using, and the private
implementation program's own accounting says why. On 2026-09-10 the release
gate `ACC-R` covered 174 `mvp_required` units: 59 with a real, executable
check (34 %), 26 partial (15 %), 89 with no executable proof (51 %). The
unproven mass sits in marketplace productization (`M14`: 0 of 14), commerce and
settlement (`M07.6`–`M07.8`, `M11.4`), decentralized cloud (`M15.1`–`M15.4`),
the worker-profile conformance units (`M12.11`–`M12.14`), the north-star
network proof (`M12.7`) and their journeys (`ACC-17`, `ACC-19`, `ACC-21`). None
of those is the governed runtime the alpha proves; each is a product in its own
right with its own gates and, for decentralized.cloud, its own program (ADR
0051). Scoped as one MVP, the release story is hostage to work that will not
finish as one thing.

At the same time the alpha delivers little work: one local 7B model through a
generic CLI shim, host-process execution the doctrine refuses to call isolation
(ADR 0027), and no journey a user recognizes as work done. The governance story
pays off only once agents do consequential things.

## Decision

### 1. Release accounting covers the governed runtime; marketplace, commerce and decentralized cloud are product tracks

The private manifest gains a fourth program scope, **`product_track`**: a
separate product with its own gates, its own owner and its own release
accounting. A `product_track` unit keeps every check and every piece of
evidence it has today; it may depend on governed-runtime (`mvp_required`)
units; it is never a prerequisite of any unit in the release graph; and
`ACC-R` neither covers it nor depends on its journeys. It is not
`post_mvp_pull`: a product track proceeds in parallel, on its owner's
schedule, and proposing work on it is never a sequencing violation.

The set, as the transitive closure under the program's cross-scope rule (an
`mvp_required` unit cannot depend on a non-MVP unit), each named:

- marketplace and managed-worker productization: `M14.1`–`M14.14`, and the
  worker-package and worker-profile conformance units `M12.11`–`M12.14`;
- commerce and settlement: `M07.6`, `M07.7`, `M07.8`, and the network service
  invocation and settlement envelope `M11.4`;
- decentralized cloud: `M15.1`–`M15.4` (ADR 0051's program keeps its gates);
- the north-star network proof `M12.7`, which depends on marketplace
  economics;
- their journeys: `ACC-17`, `ACC-19`, `ACC-21`.

`ACC-16`, `ACC-18` and `ACC-20` stay in the MVP: they prove the runtime
(observed work as a governed source, consequential worker profiles, one
governed machine), not a marketplace. The runtime economics units
`M07.1`–`M07.5` stay: budgets, route rights, reconciled spend, cost-shape
comparison and substrate metering are part of governed execution. The flagship
proofs `M12.3`–`M12.6` keep their existing standing (separate class, never
summed with the alpha) and are not moved by this ruling; moving them is a
further owner call.

Re-derived on the same tree, the release accounting covers **143 units: 58
real (41 %), 23 partial (16 %), 62 without executable proof (43 %)**. Nothing
was authored or built by this decision; the numbers moved because the
definition did.

### 2. The supported alpha profile widens in three declared steps

Each is a unit in the private manifest with its own acceptance and closure
test; none is claimed built by this ruling, and
[`bounded-alpha-profile.md`](../architecture/components/hypervisor/bounded-alpha-profile.md)
§ *Declared widenings* carries their status.

- **`M13.9` — a remote frontier model route in the supported profile.** The
  session composer selects it like the local route; the daemon's model-mount
  proxy performs the provider call with a credential sealed to the route
  record (`POST /v1/hypervisor/model-routes/:id/credential`), so the harness
  environment stays secret-free (the consumer journey's non-possession
  clause). Qualification: the essential journey passes with the remote route
  selected, receipts name the route, the credential is never observable in
  the session environment, and the process-environment key path stays
  refused by default. A live run needs the operator's own provider credential
  and is recorded with its cost; without one the lane records a typed absence.
- **`M13.10` — an isolated execution venue in the supported profile.** The
  existing cloud-hypervisor microVM provider (real KVM boundary, no guest
  network device, workspace staged over vsock, pinned and hash-verified
  toolchain) becomes a selectable venue for the session harness. The model
  endpoint reaches the guest only through a brokered, admitted channel — a
  different profile from the hostile-guest one, exactly as the provider's own
  rule states; a NIC is never silently attached. Qualification: the essential
  journey passes with the venue selected, the harness runs inside the guest,
  the host checkout is untouched, receipts name the venue, and the host's
  readiness is measured by `scripts/phase1/verify-vm-toolchain.mjs` (PASS on
  the qualification host on 2026-09-10: cloud-hypervisor and firecracker
  monitors ready). ADR 0052's non-goal stands: no parallel container runtime
  and no OCI ergonomics; this pulls the provider the estate already has.
- **`M13.11` — the flagship developer journey.** From an issue to a reviewed
  pull request through a governed SCM connector named in the session's
  authority profile: reads and writes within a standing envelope draw
  silently, the push or publish is an exact-effect review the operator
  approves, every crossing is receipted, and revoking the connection ends the
  authority. Qualification: a composed verifier over the estate's own fixture
  SCM target proves the governed path end to end; a live GitHub run is
  optional and separately authorized. The unit claims the governed path,
  never the quality of the work.

### 3. The next kernel program is the exact-effect review chain

`M03.15` (generic exact-effect review for every acting subject) → `M01.9`
(bounded interactive computer-use stream) → `M13.6` (the browser head) →
`ACC-15`'s last clause. It is the only fully startable kernel chain, and the
consumer-loop proof the usefulness story rests on. Nothing in decisions 1 and
2 gates it or is gated by it.

## Non-Goals

- No unit is deleted, no check is weakened, and no product track loses a gate
  or its evidence; only the release definition moves.
- No claim that any widening is built. The supported and unqualified tables in
  the profile change only when a widening's qualification bar is met.
- No new container runtime, no OCI or Dockerfile ergonomics (ADR 0052).
- No change to the frozen AFT surfaces, to decentralized.cloud's own program
  (ADR 0051), or to the flagship class's first-proof ruling (ADR 0021).

## Consequences

- The private manifest declares `product_track`, sets it on the units named
  above, drops `ACC-17`, `ACC-19` and `ACC-21` from `ACC-R`'s dependencies,
  and adds `M13.9`–`M13.11`; `scripts/implementation-program.mjs` admits the
  value and forbids a `product_track` unit from being a prerequisite of a
  release-graph unit.
- `bounded-alpha-profile.md` gains § *Declared widenings* with the three
  units, their bars and their status; `execution-horizons.md` § *The
  Hypervisor base-platform alpha* records that release accounting covers the
  governed runtime.
- The shipped-products register is unchanged: every lane keeps its posture.

## Cost Of Being Wrong And Reversal

Decision 1 is a scoping ruling: reversal sets the scope values back and the
same units re-enter `ACC-R`; no evidence is lost either way. Decision 2
declares units; reversal deletes three manifest rows and one profile section.
Decision 3 orders work that was already next.

## Amendment 1 (2026-09-11): the worker-construction track

Ruled by the MVP owner under the estate owner's delegation of 2026-09-11
("you own the MVP"), owner-reversible. `ACC-16` (observed work becomes a
governed worker source) and `ACC-18` (consequential worker profiles) were kept
in the MVP above as proofs of the runtime. As specified they are not: `ACC-16`'s
learned profiles need isolated Foundry construction and independent evaluation,
`ACC-18`'s interactive profile names the product-track `M14.14` game-platform
fixture — a cross-scope dependency by construction — and both hang off `M01.9`,
the bounded interactive computer-use stream with seven prerequisites, through
`M13.8` (demonstration capture) and `M10.7` (interactive worlds). The governed
runtime's own proof that consequential effects cannot hide is already carried by
`M03.15` (exact-effect review for every acting subject), `ACC-15` and the
flagship developer journey `M13.11`.

Decision: `ACC-16`, `ACC-18`, `M01.9`, `M13.6`, `M13.8` and `M10.7` — exactly
the closure under the cross-scope rule — move to `product_track` as the
worker-construction track (a product track by the same logic as the
marketplace: worker productization), and `ACC-R` drops the two gates. `ACC-15` clause 7
(the browser head) is ruled out at MVP depth: the supported profile has no
browser or computer-use tool family, so no MVP run operates a browser; the
composed runner records the clause as ruled out on record, never as a pass.
`ACC-20` stays. Reversal sets six scope values back and re-adds two gate
dependencies; no evidence is lost either way.

## Canonical References

- [`../architecture/components/hypervisor/bounded-alpha-profile.md`](../architecture/components/hypervisor/bounded-alpha-profile.md)
- [`../architecture/_meta/execution-horizons.md`](../architecture/_meta/execution-horizons.md)
- [`../architecture/components/model-router/doctrine.md`](../architecture/components/model-router/doctrine.md)
- [`../architecture/components/hypervisor/providers-and-environments.md`](../architecture/components/hypervisor/providers-and-environments.md)
- [`./0052-hypervisor-bounded-alpha-profile-and-base-platform-acceptance.md`](./0052-hypervisor-bounded-alpha-profile-and-base-platform-acceptance.md)
- [`./0051-decentralized-cloud-public-face-job-primitive-and-supply-registry.md`](./0051-decentralized-cloud-public-face-job-primitive-and-supply-registry.md)
- [`./0027-require-workload-bound-isolation-for-autonomous-execution.md`](./0027-require-workload-bound-isolation-for-autonomous-execution.md)
