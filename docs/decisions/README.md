# Architecture Decision Records

This directory contains accepted architecture decisions that should survive
implementation churn, documentation refactors, and context compaction.

ADRs record durable product/protocol/runtime decisions and their consequences.
Canonical architecture prose still lives under `docs/architecture/`; ADRs
explain the accepted decision when that history remains useful.

## Accepted ADRs

- [ADR 0001: Remove SCS And Adopt `ioi-memory` For Product Memory](./0001-scs-deprecation-and-memory-runtime-successor.md)
- [ADR 0002: Make The IOI Daemon The Canonical Execution Endpoint](./0002-execution-authority-and-client-boundaries.md)
- [ADR 0003: Define Agentgres As Operation-Backed Domain Truth](./0003-agentgres-operation-backed-domain-truth.md)
- [ADR 0004: Define Worker, MoW, And Worker Training As Labor Architecture](./0004-worker-mow-and-training-doctrine.md)
- [ADR 0005: Make Domain Ontologies And Data Recipes The Semantic Data Plane](./0005-domain-ontologies-and-data-recipes.md)
- [ADR 0006: Define Capability, Authority, And Work-Graph Vocabulary](./0006-capability-authority-and-work-graph-vocabulary.md)
- [ADR 0007: Adopt IDE-First Hypervisor With Runtime And Workbench Substrates](./0007-autopilot-ide-first-two-substrate-architecture.md) (superseded by ADR 0013)
- [ADR 0008: Adopt IOI Authority Gateway As The Sidecar Adoption Wedge](./0008-ioi-authority-gateway-sidecar-adoption-wedge.md)
- [ADR 0009: Switch Hypervisor IDE Shell From Tauri To The Electron/VS Code Fork](./0009-switch-autopilot-ide-shell-from-tauri-to-electron-vscode-fork.md) (superseded by ADR 0013)
- [ADR 0010: Define Verifiable Bounded Agency As Execution-Boundary Alignment](./0010-verifiable-bounded-agency-and-execution-boundary-alignment.md)
- [ADR 0011: Canonicalize Hypervisor Nodes As Local Settlement Domains](./0011-hypervisor-nodes-and-governed-autonomous-system-chains.md)
- [ADR 0012: Define IOI As Autonomous-System Settlement Layer And AIIP As Work Interop](./0012-ioi-autonomous-system-settlement-and-aiip.md)
- [ADR 0013: Define Hypervisor Core, Clients, Surfaces, And Adapter Targets](./0013-hypervisor-core-clients-surfaces-and-adapters.md) (refined by ADR 0014)
- [ADR 0014: Make Hypervisor An IDE-Of-IDEs And Session Estate](./0014-hypervisor-ide-of-ides-and-session-estate.md)
