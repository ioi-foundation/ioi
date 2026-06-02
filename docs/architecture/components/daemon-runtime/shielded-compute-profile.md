# Deprecated: Shielded Compute Profile

Status: deprecated compatibility stub.
Canonical owner: [`private-workspace-ctee.md`](./private-workspace-ctee.md).
Supersedes: none.
Superseded by: [`private-workspace-ctee.md`](./private-workspace-ctee.md).
Last alignment pass: 2026-06-01.

Use **Private Workspace backed by cTEE** for new live architecture, product
language, implementation plans, and reader paths.

Deprecated wording:

```text
Shielded Compute Profile
Shielded Workspace
Protected Workspace
```

Canonical wording:

```text
Private Workspace backed by cTEE
Open Private Workspace
```

The old phrase meant the daemon-owned cTEE execution/privacy contract for
persistent rented GPU nodes. The current canon makes the user-facing primitive
the private workspace itself:

```text
Private Workspace UI
  normal user files/folders/project view

cTEE
  backing execution/privacy contract

Agentgres
  refs, commits, receipts, state roots, restore/import truth

storage backends
  encrypted payload bytes

wallet.network
  keys, declassification, signing, autonomy leases, revocation
```

Do not use this file as a canonical owner.
