# ADR 0026: Separate Deployment, Resource Relationship, And Autonomy Capabilities

- Status: Accepted
- Date: 2026-07-29
- Owners: Hypervisor Core clients and surfaces / Providers and Environments /
  execution horizons / public claim owners
- Refines: ADR 0013, ADR 0016, ADR 0021
- Unaffected: IOI category and owner topology; Work and GoalRun placement; all
  existing authority, receipt, and v1/v2 contracts
- Confidence: settled for classification, ownership, product bundles, and
  claim gating; particular backend profiles remain selected implementation work.

## Context

The prior product description grouped hosted deployment, node-root deployment,
and autonomy into peer “Type 1”, “Type 2”, and “Type 3” substrate modes. That
mixed three independent questions: where the controller runs, whose compute it
manages, and which autonomous capabilities are enabled. It also risked implying
that autonomy is a standardized hypervisor type or replaces the VMM beneath it.

Hypervisor must perform recognizable compute-management jobs without moving
machine or environment truth into a new plane. Conventional virtualization is
the trustable floor and adoption route; governed autonomy is an optional
capability above it.

## Decision

1. **Classification uses three nonexclusive facets.** A released profile names:
   controller deployment (`hosted_ordinary_os` or `node_root_appliance`),
   resource relationship (`local`, `customer_attached`, or `managed_provider`),
   and an enabled capability set drawn from `manual_operations`,
   `governed_workruns`, `standing_automations`, and `bounded_systems`.

2. **No facet grants capability.** Facets describe a selected profile. Current
   backend capability evidence, desired/observed state, authority, receipts,
   and final-invoker proof remain mandatory for every consequential operation.

3. **Four claim/conformance bundles project existing owners.** Hypervisor
   Workstation, Hypervisor Infrastructure, Autonomous Systems, and HypervisorOS
   are owner-qualified bundles, not new apps, planes, primitives, or truth
   stores. They may coexist. A user may remain in manual machine management
   indefinitely without creating a System, AutomationRun, or GoalRun.

4. **Claims close independently.** A Workstation proof does not establish an
   attached-estate, secure-sandbox, node-root, migration, or HA claim. An
   Infrastructure proof means Hypervisor manages the admitted external estate;
   it does not make IOI the underlying Type-1 VMM. HypervisorOS remains a
   conditional future node-root product until its own installer, lifecycle,
   update, recovery, enforcement, hardware, and support evidence closes.

5. **Public language is capability-honest.** “Autonomy virtualization plane”
   is the ordinary description. “Type 3” is not presented as a standard or as
   a replacement for Type 1/2. Host and guest support, adapters, devices,
   snapshots, migration, HA, isolation, and custody are limited to the exact
   current compatibility and evidence profile.

6. **Ownership is unchanged.** Providers and Environments own governed compute
   posture; the daemon owns admission and execution; Agentgres owns durable
   truth; the applicable authority provider owns authority; clients project
   the same state. Backend and vendor names remain adapter/evidence details.

## Consequences

- The former combined substrate-mode description is removed before promotion
  into a schema or enum contract.
- Canon and first-party surfaces expose familiar machine inventory, create or
  import, console/access, lifecycle, reconciliation, snapshot/restore, and
  cleanup jobs without requiring autonomy vocabulary.
- Workstation and Infrastructure branch from common capability and lifecycle
  evidence; neither blocks the selected autonomous-product proof unless that
  proof explicitly traverses it.
- HypervisorOS can be activated later without changing the category or owner
  topology.

## Rejected Alternatives

- **Type 1 + Type 2 = Type 3.** Rejected: these labels do not compose and answer
  different questions.
- **A new compute plane or VM ontology.** Rejected: existing provider,
  environment, workload, node, image, snapshot, access, change-plan, authority,
  receipt, and cleanup owners remain sufficient.
- **Mandatory autonomy for machine users.** Rejected: autonomy is an explicit
  capability crossing, never a prerequisite for ordinary compute operations.
- **Immediate HypervisorOS or universal workstation claims.** Rejected:
  architecture intent and a microVM boot are not product evidence.

## Cost Of Being Wrong And Reversal

The facets and bundles are projections over existing owners. A profile can be
withdrawn or narrowed without migrating durable machine, Work, GoalRun,
authority, or receipt identity. Reversal must not revive the combined enum or
infer a capability from deployment location.

## Canonical References

- [`../architecture/components/hypervisor/core-clients-surfaces.md`](../architecture/components/hypervisor/core-clients-surfaces.md)
- [`../architecture/components/hypervisor/providers-and-environments.md`](../architecture/components/hypervisor/providers-and-environments.md)
- [`../architecture/_meta/execution-horizons.md`](../architecture/_meta/execution-horizons.md)
- [`0013-hypervisor-core-clients-surfaces-and-adapters.md`](./0013-hypervisor-core-clients-surfaces-and-adapters.md)
- [`0016-hypervisor-systems-work-and-application-taxonomy.md`](./0016-hypervisor-systems-work-and-application-taxonomy.md)
