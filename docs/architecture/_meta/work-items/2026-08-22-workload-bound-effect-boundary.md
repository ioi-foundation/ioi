# Workload-bound effect boundary — 2026-08-22

Status: spend-free local T2 implementation slice; real KVM probe passed; global floor not yet promoted.
Canonical owner: `docs/architecture/components/hypervisor/providers-and-environments.md#local-hostile-guest-enforcement-profile`.
Doctrine status: reference
Implementation status: partial
Implementation refs:
  - `docs/decisions/0027-require-workload-bound-isolation-for-autonomous-execution.md`
  - `crates/node/src/bin/hypervisor_daemon_routes/microvm.rs`
  - `crates/node/src/bin/hypervisor_daemon_routes/workload_effect_boundary.rs`
  - `scripts/check-workload-bound-effect-boundary.mjs`
Last implementation audit: 2026-08-22 (local live probe passed; daemon route and complete fault matrix remain open)

This record is the implementation and evidence boundary for the first
`trusted_host_hostile_guest/no-nic-v1` slice. It performs no provider mutation
and moves no money. It must not be cited as U1 execution, worker-secret
non-possession, production non-bypassability, or a complete T2 exit.

## Implemented boundary

- Every Cloud Hypervisor, Firecracker, and QEMU launch passes an observed
  pre-launch floor requiring zero virtual network devices, zero host mounts,
  and zero host-control sockets.
- Generic environment VMs truthfully remain `environment_scoped`; only a spec
  carrying the exact WorkRun, isolation-binding ref/hash, and principal emits
  `fresh_per_workrun`.
- Workspace ingress and egress remain length bounded. Guest output enters a
  quarantine archive parser accepting relative regular files/directories only;
  traversal, symlink, hardlink, FIFO, device, truncated, extended, over-count,
  and over-size shapes refuse.
- The guest-visible capability is an opaque bearer bound to one canonical
  request, isolation binding, principal, proposal nonce, audience, resource,
  result destination, and expiry. Persistent state retains its hash, not the
  plaintext handle.
- Proposal bytes must be exact JCS. Noncanonical, duplicate-key-equivalent,
  malformed, and oversized byte streams refuse before the final invoker.
- The broker durably records `claimed` before the final invoker. Replay after a
  terminal result refuses; restart over an ambiguous claim becomes
  `reconciliation_required` and never invokes again.
- The broker contains no provider client, provider credential resolver, wallet
  signer, C2 writer, or secret-unsealing path.

## Registered contracts

- `schema://ioi/components/hypervisor/vm-enforcement-declaration/v1`
- `schema://ioi/components/hypervisor/workload-bound-effect-proposal/v1`
- `schema://ioi/components/hypervisor/workload-effect-consumption-receipt/v1`

Each has generated Rust and TypeScript projections plus a positive and negative
fixture. The daemon validates emitted declarations, proposals, and consumption
receipts through those generated Rust projections.

## Real-host evidence

The pinned toolchain verifier passed before the live probe:

| Component | Version / digest |
|---|---|
| Cloud Hypervisor | `v52.0`, `sha256:829af01ff075bb96c4f183905134c453a88d68cbabdc6b87df21098842581ee9` |
| Guest kernel | `6.18.15+deb13-cloud-amd64`, `sha256:a648d875afe6b21c30197394ef270c15626b3c38249dbb3189d9f646e13f1e9e` |
| Initramfs | `sha256:9c5c2fe89138f4a011723be47ca4ab5e50bef17f2213a065b77f74d306adf7c1` |
| Guest agent | `sha256:438412463207315fb512ae4699b6f600cf6d0b3ef8e6801e3c9b1c89dfb8cff4` |
| Host capability | `/dev/kvm` present; Cloud Hypervisor ready |

Command:

```text
npm run check:workload-bound-effect-boundary -- --live
```

Observed on 2026-08-22:

| Fact | Result |
|---|---|
| Guest privilege | UID 0 |
| VM instance scope | `fresh_per_workrun` |
| Guest interfaces | loopback only |
| Raw-IP, loopback-to-host, metadata, and DNS attempts | refused/unreachable |
| Protected host device/socket/environment material | none found by the named probes |
| Direct host-canary invocations | `0` |
| Authenticated final-invoker calls | `1` |
| Capability replay | refused |
| Output admission | bounded archive validated into quarantine |
| Monitor after teardown | observably terminal |

Mutation command:

```text
npm run mutate:workload-bound-effect-boundary
```

It detected both a planted virtual network device in the Cloud Hypervisor
launch and a planted second provider client inside the guest broker.

## Trusted computing base and residuals

The selected local profile trusts host hardware/firmware, Linux/KVM, Cloud
Hypervisor, the pinned guest kernel/initramfs and guest agent, the Hypervisor
daemon, durable filesystem core, archive validator/importer, capability broker,
and final invoker. It does not claim resistance to compromise of those parts.

This slice does not yet establish the complete T2 exit because:

- the broker is composed with a mock protected effect in the live probe, not a
  daemon provider route under a real C2/authority admission;
- the owner has not selected the final local backend/TCB for the integrated
  capstone;
- IPv6, UDP, proxy/tunnel, DNS-exfiltration, package/dependency, inherited-FD,
  guest/daemon kill-window, and cleanup-obligation campaigns are not yet all
  present as live rows;
- Firecracker and QEMU are enforced by the same pre-launch fields but were not
  exercised by this live row; and
- the check is intentionally absent from global verifier floors until the
  daemon-route composition and complete failure matrix pass.
