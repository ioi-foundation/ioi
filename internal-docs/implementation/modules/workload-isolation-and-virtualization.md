---
module_id: workload-isolation-and-virtualization
module_class: method
title: Workload isolation and conventional virtualization proof method
sequencer: program/sequence.v1.json
status_owner: work-item records
stage_ids: [M3, M6, M9, M10, FUTURE]
canon_owners:
  - docs/architecture/components/hypervisor/providers-and-environments.md
  - docs/architecture/components/hypervisor/core-clients-surfaces.md
  - docs/architecture/components/daemon-runtime/doctrine.md
  - docs/architecture/foundations/security-privacy-policy-invariants.md
---

# Workload Isolation And Virtualization Method

This module owns program method, not canon semantics or product status. It
requires risk-to-isolation selection, exact current backend capability versus
observed enforcement, immutable WorkRun/environment/lease binding, per-job
mount/secret/network/dependency-broker controls, out-of-guest effects,
quarantined output, conventional desired/observed machine lifecycle, and
cleanup/restore/substitution/escape-oriented fault proof.

Backend and provider names remain replaceable adapter evidence. Every selected
operation proves exact support or returns typed unsupported. A live claim needs
live evidence; declared or simulated evidence can exercise projections only.

The proof branches after common capability and isolation evidence: autonomous
product, Workstation, and attached Infrastructure are independently closable.
HypervisorOS activates only through its named future gate.
