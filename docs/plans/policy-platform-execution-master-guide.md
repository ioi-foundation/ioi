# Policy Platform Execution Master Guide

Owner: daemon runtime / policy / approvals / Autopilot / workflow compositor

Status: future-platform leg, ready for implementation

Created: 2026-05-15

## Executive Verdict

The local computer-use harness now has scoped policy receipts for read-only,
approval-required, approved, and fail-closed actions. The remaining policy
deferral is broader: IOI needs one cross-domain policy execution platform that
governs computer use, shell/tools, connectors, hosted workers, model routing,
skills/hooks, repository publishing, artifacts, and memory.

The goal is not more UI gates. The goal is one deterministic policy substrate
whose decisions are replayable, inspectable, and shared by daemon/API/SDK/CLI,
TUI, Autopilot, and React Flow.

## Doctrine

- Policy decisions are runtime facts, not UI state.
- Every consequential action has an authority scope and policy decision ref.
- React Flow can configure policy, but the daemon evaluates and records it.
- Approval UI is a projection of policy state.
- Policy failure must fail closed with recovery guidance.
- Local, hosted, and cloud daemon deployments use the same policy envelopes.

## Policy Domains

| Domain | Examples |
| --- | --- |
| Computer use | Browser, GUI, sandbox, device, screenshots, profile access. |
| Coding tools | Shell, file writes, git, tests, package installs, network access. |
| Connectors | GitHub, Gmail, Drive, Slack, calendars, CRM. |
| Model routing | Provider choice, privacy tier, fallback, cost ceiling. |
| Skills/hooks | Prompt injection, hook side effects, trust and version pinning. |
| Repository publishing | Branch creation, PRs, comments, review gates. |
| Memory/artifacts | Retrieval, persistence, redaction, export. |
| Hosted workers | Remote execution, task authority, cleanup, retained logs. |

## Canonical Objects

The policy platform should standardize:

- `AuthorityScope`
- `PolicySubject`
- `PolicyResource`
- `PolicyIntent`
- `PolicyDecisionReceipt`
- `ApprovalRequest`
- `ApprovalDecision`
- `RiskAssessment`
- `TrustProfile`
- `BudgetPolicy`
- `PrivacyTier`
- `RetentionPolicy`
- `RecoveryPolicy`
- `PolicyReplayRecord`

## Execution Loop

```text
normalize_intent
-> resolve_subject
-> resolve_resource
-> compute_authority_scope
-> evaluate_policy
-> request_approval_if_needed
-> bind_decision_to_action
-> execute_or_fail_closed
-> verify_outcome
-> record_replay
```

## Workflow Projection

React Flow should expose:

- `Policy Gate` for explicit pause/continue boundaries;
- `Approval` for human/operator decision points;
- `Authority Scope` config on tools, connectors, computer-use nodes, and
  worker nodes;
- policy inspector tabs for advanced users;
- receipt links from run history and timeline rows.

Policy nodes should represent execution boundaries. Policy variants should be
config sections, not separate node spam.

## Autopilot Workbench

Autopilot should show:

- why an action was allowed, blocked, or paused;
- authority scope and resource;
- trust profile and privacy tier;
- approval request and decision;
- budget/cost impact when relevant;
- linked action and verification receipts;
- fail-closed recovery options.

## Validation Plan

Required tests:

- policy decisions round-trip through daemon/API/SDK/CLI/TUI;
- React Flow policy config compiles to deterministic manifests;
- approval decisions bind to exactly one action or lease;
- stale or missing approval refs fail closed;
- policy replay reconstructs decision state from events;
- connector, shell, computer-use, and hosted-worker actions use the same policy
  envelope;
- Autopilot inspector shows decision, scope, action, and verification links.

## Definition Of Done

This leg is complete when:

- all consequential runtime actions use one policy envelope;
- policy decisions are replayable from runtime events;
- approval UI never becomes a shadow policy store;
- cross-domain actions fail closed without required authority;
- workflow authors can configure policy without learning internal runtime ids;
- advanced users can inspect raw policy receipts and replay records.
