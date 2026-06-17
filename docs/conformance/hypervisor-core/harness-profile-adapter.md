# Harness Profile Adapter Conformance

Status: active Hypervisor Core conformance invariant; v1.0
Owners: Hypervisor Core, harness profile adapters, worker/module adapters.
Canonical owner: this file for the minimum contract that lets heterogeneous
harnesses execute under Hypervisor without becoming separate authority or
completion substrates.
Supersedes: product or implementation prose that treats Codex, Claude Code,
DeepSeek harnesses, local CLIs, hosted workers, or custom agent runtimes as
ungoverned execution peers beside Hypervisor Core.
Superseded by: none.
Last alignment pass: 2026-06-17.

## Purpose

Hypervisor may route work through many harnesses and model runtimes. This
contract defines what any selected harness adapter must expose before it can
participate in governed autonomous work.

The adapter is a bridge, not a runtime owner:

```text
Hypervisor Core owns policy, authority gates, sessions, receipts, and replay.
The harness performs bounded cognition or execution inside an admitted profile.
The adapter translates between the harness-native interface and Hypervisor
objects.
```

## Required Adapter Descriptor

Every adapter MUST publish a descriptor:

```yaml
HarnessProfileAdapter:
  adapter_id: harness_adapter:...
  adapter_version: semver
  harness_family: codex | claude_code | deepseek | local_cli | module | worker | service | custom
  supported_surfaces:
    - workbench
    - terminal
    - browser
    - remote_vm
    - hosted_worker
    - model_mount
  primitive_capabilities:
    - prim:fs.read
    - prim:fs.write
    - prim:sys.exec
  authority_scope_requirements:
    - scope:...
  supported_receipts:
    - resolver
    - action_proposal
    - gate_result
    - execution
    - observation
    - verification
    - terminal
  state_projection:
    reads:
      - context_chamber
      - workspace_projection
      - model_mount_projection
    writes:
      - normalized_observation
      - artifact_ref
      - receipt
  secret_handling:
    durable_plaintext_secrets: false
    brokered_secret_required_for:
      - scope:...
  ctee_compatible: true | false
  replay_support: none | receipt_only | deterministic_replay | simulator
```

## Required Runtime Mapping

An adapter MUST map harness-native events into Hypervisor objects:

| Harness-native event | Hypervisor object |
| --- | --- |
| intent guess, task classification, planner selection | CIRC resolver receipt or declared external resolver receipt |
| proposed tool/model/action call | `ActionProposal` |
| permission request | `GateResult` request material |
| command/tool/model execution | `ExecutionResult` |
| stdout, diff, browser state, test output, API result | `NormalizedObservation` |
| generated file, screenshot, dataset, trace, model output | `ArtifactRef` / `PayloadRef` |
| completion claim | terminal receipt candidate, never terminal truth alone |

## Authority Rules

Adapters MUST NOT:

- hold wallet.network root secrets;
- mint `scope:*` grants;
- widen policy;
- bypass step-up;
- execute consequential effects without a Hypervisor/domain gate;
- treat harness-native approval prompts as wallet.network approvals;
- treat harness memory as Agentgres truth.

Adapters MAY request capabilities or authority. Hypervisor Core and
wallet.network decide.

## Completion Rules

Adapters MUST satisfy CEC terminal-state requirements:

- completion depends on typed receipts and observations;
- harness reply text is observability, not proof;
- hidden retries inside the same admitted effect are forbidden;
- repair loops open new proposals with new gates and receipts;
- verification failure yields `failed`, `partial`, `blocked`, or `unverified`,
  not silent success.

## State And Memory Rules

Harness-native memory is not canonical. Persistent skills, workspace memory,
Agent Wiki / ioi-memory state, and Agentgres operational state must be projected
through the canonical owner for that state.

Adapters may cache session-local state, but durable claims require admitted
operations, receipts, artifact refs, or memory writes under the relevant policy.

## Conformance Profiles

Profile A: Read-Only Harness
- descriptor includes read primitives only;
- no `scope:*` grant required unless protected data is accessed;
- completion is receipt-backed.

Profile B: Local Workbench Harness
- file reads/writes and shell execution are gated by primitive capabilities;
- code patches produce observations and receipts;
- verification is typed.

Profile C: Remote Worker Harness
- AIIP or worker invocation envelope is signed;
- authority lease and receipt obligations are explicit;
- remote completion cannot bypass local/domain terminal gates.

Profile D: Private Workspace Harness
- protected workspace state is never mounted as provider-readable plaintext;
- private projections, model mounts, and capability exits emit cTEE-compatible
  receipts.

Profile E: External CLI/TUI Harness
- CLI/TUI is treated as an adapter target or harness source;
- terminal output does not become completion truth;
- process execution routes through Hypervisor Core/domain gates.

## Anti-Patterns

- Making a harness adapter a second daemon.
- Treating a third-party harness as inherently trusted because it is useful.
- Letting harness-specific prompt budget, model family, or retry policy hide in
  workflow code instead of declared profile policy.
- Bypassing Agentgres with private harness state.
- Treating adapter availability as semantic intent evidence.
- Treating harness completion text as a receipt.
