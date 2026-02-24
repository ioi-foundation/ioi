# Capability Execution Contract (CEC)

Status: Draft v0.2  
Owners: Agentic Platform  
Scope: Post-resolution execution discipline for inference-driven, device-adaptive tasks

## 1. Purpose
CEC defines how the agent executes intents that depend on host-specific environments. It complements CIRC:
- CIRC governs `which intent` wins based on semantic reasoning.
- CEC governs `how execution must proceed` before completion is allowed.

CEC prevents topology shortcuts (app-name assumptions, static registry mapping, string heuristics) and enforces that cross-platform execution is handled dynamically via inference and system primitives.

## 2. Core Principle
For device-adaptive tasks, execution MUST NOT rely on hardcoded OS integration bridges. Execution MUST follow an inference-driven lifecycle:
1. Environment Discovery
2. Dynamic Provider Synthesis / Selection
3. Execution
4. Dynamic Verification
5. Terminal Response

Skipping discovery or verification, or relying on a zero exit code as proof of state change, MUST block terminal completion.

## 3. Contract Fields (Intent-Scoped)
Each applicable intent may define an execution contract with:
- `requires_host_discovery: bool`
- `provider_selection_mode: dynamic_synthesis | capability_only`
- `fallback_chain: [native, install_with_approval, script]`
- `required_receipts: [string]`
- `required_postconditions: [string]`

These fields are authoritative for execution gating, not prompt text.

## 4. Receipt Model
Execution must emit structured evidence markers. Canonical shape:
- `receipt::<name>=true`
- `postcondition::<name>=true`

Minimum standard receipts:
- `receipt::host_discovery`
- `receipt::provider_selection`
- `receipt::execution`
- `receipt::verification`

### 4.1 Inference-Driven Verification
When execution relies on dynamically synthesized payloads (e.g., executing a bash script via `sys.exec`), the verification phase MUST also be dynamically synthesized.
- The system MUST NOT assume success based solely on a process exiting without error.
- `receipt::verification` MUST contain a cryptographic commit to the dynamically generated read-state command (e.g., running `ps aux | grep [process]` or querying a native dbus state) used to definitively prove the postcondition.

## 5. Completion Gate
`agent__complete` (or any terminal completed status) MUST be blocked when:
- any required receipt is missing
- any required postcondition is missing
- `requires_host_discovery=true` and `receipt::host_discovery` is absent

On violation, runtime MUST emit `ERROR_CLASS=ExecutionContractViolation` with missing keys.

## 6. Policy Routing Semantics & The Fallback Chain
Provider selection MUST be inference-driven when `provider_selection_mode=dynamic_synthesis`. The agent MUST dynamically evaluate the host environment against the defined fallback chain. 

Fallback chain semantics:
1. `native`: Inferring and synthesizing an integration with an existing OS application (e.g., AppleScript to `Clock.app`, or `dbus-send` to `gnome-clocks`).
2. `install_with_approval`: Yielding execution to prompt the user for permission to install a standard native application via the host's package manager.
3. `script`: Synthesizing a primitive shell/background process (e.g., `nohup bash -c 'sleep 900' &`) when native UI apps are absent, invasive, or denied.

A lower-priority route is valid only after evidenced failure, unavailability, or user-denial of higher routes.

## 7. Non-Goals
CEC does not define semantic ranking, capability definitions, or intent ambiguity policy. Those remain in CIRC.

## 8. Conformance (Minimum)
A CEC-conformant implementation must pass:
1. completion blocked when required receipts or postconditions are absent
2. discovery-required intents cannot complete without active environment polling (discovery receipt)
3. fallback chain order is dynamically respected and evidenced
4. no static OS-topology registry can bypass the inference-driven discovery phase
5. synthesized executions must be paired with synthesized state verifications

## 9. CI Recommendations
CI should enforce:
- execution-contract gate tests per intent class
- snapshot tests for emitted receipt/postcondition keys
- lint rules blocking hardcoded OS app names in the core execution codebase (forcing them into the LLM context)

## 10. Relationship to CIRC
CIRC + CEC form the full contract:
- CIRC: intent resolution correctness (What the user wants)
- CEC: execution correctness (How the LLM achieves it on the local topology)
