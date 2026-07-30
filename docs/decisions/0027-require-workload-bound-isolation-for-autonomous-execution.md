# ADR 0027: Require Workload-Bound Isolation For Autonomous Execution

- Status: Accepted
- Date: 2026-07-29
- Owners: shared WorkRun objects / Providers and Environments / daemon runtime /
  security and conformance
- Refines: ADR 0010, ADR 0013, ADR 0020
- Unaffected: Work/GoalRun placement; System and application topology;
  authority-grant v1/v2 bytes and semantics
- Confidence: settled for fail-closed selection, binding, effect, output, and
  cleanup semantics; backend-specific enforcement remains profile-gated.

## Context

A process, container, worktree, or “internet denied” label does not by itself
bound capable autonomous code. Shared package paths, host mounts, credentials,
control sockets, caches, network brokers, output extraction, VMM processes, and
recovery all remain attack-relevant. A VM reduces blast radius but proves
nothing unless the selected backend and every crossing are bound to the exact
workload and current evidence.

Existing canon already requires a real kernel boundary for untrusted or
cross-tenant work and routes consequential effects through authority and a
final invoker. The missing decision is to compile that posture per WorkRun and
fail closed when the required boundary cannot be established.

## Decision

1. **Risk selects a lower bound.** Untrusted, dependency-installing, networked,
   credential-using, or mutating WorkRuns require a fresh workload-bound VM or
   stronger admitted boundary by default. A caller may request a stronger
   profile but cannot weaken the compiled requirement.

2. **Every admitted run binds exact evidence.** The shared WorkRun envelope and
   runtime assignment reference immutable isolation requirements and a binding
   that names owner/trust domain, workload, runtime, backend capability and
   current enforcement declarations, image, network identity, brokers,
   permitted crossings, TTL, output policy, and cleanup obligation.

3. **Missing boundary means refusal.** No isolation-required route may fall
   back to host command execution, a shared checkout, host service health
   checks, ambient mounts, credentials, daemon/container sockets, or an
   unregistered backend. Unknown or unsupported capabilities refuse before
   launch.

4. **Effects remain outside the guest.** Guest work produces an untrusted,
   content-bound proposal. Consequential SCM, provider, deployment, credential,
   or external-network effects cross the existing authorized final invoker.
   Direct guest attempts must produce zero real invocations.

5. **Output is quarantined and transactional.** Export enters an isolated,
   bounded staging area, rejects unsafe entries and resource exhaustion,
   manifests and validates allowed output, and atomically admits it. Restore
   uses the same prepare/apply/cancel shape and never destroys trusted state
   before validation succeeds.

6. **Connectivity and dependencies are explicit.** Each selected strong
   profile has a per-workload identity and deny-by-default network posture.
   Dependency access uses a separately contained least-privilege broker with
   exact ecosystem, package, version/digest, destination, method, size, and
   budget policy. Broker credentials are not guest-readable.

7. **Terminal state includes cleanup truth.** Success, denial, failure,
   cancellation, timeout, restart, and uncertain dispatch either verify removal
   of every workload-owned resource or retain a durable cleanup/reconciliation
   obligation. Unknown cleanup is never rewritten as success.

8. **Hostile-to-boundary work requires a disposable host.** Work intended to
   attack a guest kernel, VMM, broker, or host boundary is refused on an
   ordinary shared host unless a separately admitted disposable-host profile
   is selected.

## Consequences

- `WorkRunEnvelope`, `RuntimeAssignmentEnvelope`, workload isolation
  requirements/binding, backend capability evidence, enforcement coverage,
  output admission, and cleanup evidence form one content-bound chain.
- VM boot is not a containment claim. Claims name the exact profile, current
  evidence, limitations, and regression/withdrawal rule.
- Shared caches and guest protocols stay unavailable to untrusted profiles
  until authentication, bounds, owner/trust-domain scoping, no-follow path
  safety, quotas, cancellation, and fault evidence close.
- The requirement strengthens the existing daemon/authority path without
  creating a service, plane, or alternate Work lifecycle.

## Rejected Alternatives

- **Host fallback for availability.** Rejected: it inverts the admitted risk
  decision at the execution primitive.
- **VM boot as proof.** Rejected: host, VMM, guest agent, broker, network,
  credentials, output, and recovery remain within the boundary.
- **Secrets inside the guest.** Rejected: operation-scoped capabilities and
  out-of-guest final invokers preserve the existing authority owner.
- **A new isolation or package-broker plane.** Rejected: these are profiles and
  composed services under existing owners.

## Cost Of Being Wrong And Reversal

The default can be narrowed only by withdrawing the corresponding security
claim and explicitly selecting a weaker risk profile. Existing WorkRun,
GoalRun, authority, and receipt identities remain unchanged. No reversal may
silently restore host fallback for a run already admitted as isolated.

## Canonical References

- [`../architecture/foundations/objects/work-execution.md`](../architecture/foundations/objects/work-execution.md)
- [`../architecture/components/hypervisor/providers-and-environments.md`](../architecture/components/hypervisor/providers-and-environments.md)
- [`../architecture/components/daemon-runtime/doctrine.md`](../architecture/components/daemon-runtime/doctrine.md)
- [`../architecture/foundations/security-privacy-policy-invariants.md`](../architecture/foundations/security-privacy-policy-invariants.md)
- [`0010-verifiable-bounded-agency-and-execution-boundary-alignment.md`](./0010-verifiable-bounded-agency-and-execution-boundary-alignment.md)
