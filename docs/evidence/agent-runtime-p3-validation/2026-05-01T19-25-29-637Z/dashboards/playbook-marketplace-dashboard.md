# Playbook Marketplace Dashboard

Validated playbooks, negative learning, decay, override rules, and gated promotion use the runtime contracts below.

| Contract | Source |
| --- | --- |
| TaskFamilyPlaybook | crates/types/src/app/runtime_contracts.rs |
| NegativeLearningRecord | crates/types/src/app/runtime_contracts.rs |
| BoundedSelfImprovementGate | crates/types/src/app/runtime_contracts.rs |
| Builtin playbooks | crates/services/src/agentic/runtime/agent_playbooks.rs |

| Status | P3 item | Guide | Evidence |
| --- | --- | --- | --- |
| Complete | Playbook marketplace/operator view | guide:2412 | All anchors present |
