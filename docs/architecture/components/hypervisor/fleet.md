# Hypervisor Fleet

Status: deprecated terminology stub.
Canonical owner: none for live architecture.
Supersedes: prior canon that treated Fleet as a separate Hypervisor
application surface, posture layer, or product lane.
Superseded by: [`providers-and-environments.md`](./providers-and-environments.md).
Last alignment pass: 2026-06-17.

## Deprecated Definition

`Hypervisor Fleet` is deprecated live canon.

Do not model Fleet as:

```text
a separate app
a separate application surface
a separate posture layer
a separate runtime
a separate source of environment truth
```

The useful capability remains, but it belongs directly to Hypervisor:

```text
Hypervisor manages sessions, environments, providers, infrastructure posture,
access leases, services, tasks, ports, logs, archive refs, restore refs, and
zero-to-idle state.
```

Current doctrine:

```text
Sessions are the unit.
Provider and infrastructure posture are cross-session Hypervisor views.
Hypervisor Daemon executes lifecycle operations.
wallet.network authorizes spend, access, secrets, SCM auth, and declassification.
Agentgres records admitted truth, receipts, state roots, archive refs, and
restore validity.
Storage backends hold payload bytes.
```

Use [`providers-and-environments.md`](./providers-and-environments.md) for the
canonical object model and implementation boundary.
