# Contract Glossary and Canonical Paths

Status: Iteration 0 Foundation
Scope: Terminology freeze and canonical contract type locations

## Precedence
1. `docs/CIRC.md` and `docs/CEC.md` remain the normative behavior contracts.
2. This file freezes shared terminology and canonical path references for operational docs.
3. If terminology in operational docs conflicts with CIRC/CEC, CIRC/CEC take precedence.

## Canonical Paths
- Intent/capability ontology types: `crates/types/src/app/agentic/security/intent.rs`
- Tool contract type: `crates/types/src/app/agentic/tools/agent_tool.rs`
- Canonical workload type path: `crates/types/src/app/events.rs`
- Public event IPC mirror: `crates/ipc/proto/public/v1/public.proto`
- Workload control IPC contract: `crates/ipc/proto/control/v1/control.proto`

## Frozen Glossary
- **Intent**: Canonical semantic action class describing what the user wants.
- **Capability**: Primitive permission/isolation boundary describing what is fundamentally allowed.
- **Tool**: Concrete execution mechanism that provides one or more primitive capabilities.
- **Workload**: A supervised execution unit (local or remote) that emits typed activity and receipt evidence.
- **Lease**: Policy-scoped, time-bounded capability grant that constrains a workload's allowed actions.

## Drift Guard Notes
- Operational docs must not reference deprecated workload/service placeholder paths.
