# Autopilot Local App and Workflow Canvas Specification

Status: canonical architecture authority.
Canonical owner: this file for Autopilot, workflow canvas, harness-as-workflow, and local GUI boundaries.
Supersedes: overlapping plan prose when Autopilot ownership conflicts.
Superseded by: none.
Last alignment pass: 2026-05-01.

## Canonical Definition

**Autopilot is the local canonical Web4 application and user-facing runtime for building, running, inspecting, and governing autonomous workflows and workers.**

It is the default local execution environment for users who want private/local control, local files, local models, local connectors, and editable workflows.

## Core Role

Autopilot provides:

- workflow canvas;
- agent harness;
- local IOI runtime bridge;
- local-first UX;
- connector/tool management;
- model mounting and routing UI;
- worker install/run interface;
- run rooms and task coordination;
- agent office/project coordination;
- artifact and receipt inspection;
- wallet.network approval surface;
- Agentgres client/runtime integration.

## What Autopilot Owns

Autopilot owns the user-facing local product experience:

- workflow authoring;
- default harness inspection and fork path;
- local runtime configuration;
- local execution and debugging;
- local stores and projections;
- local/private files;
- local model endpoints;
- connector setup surfaces;
- human approvals and interruption UX;
- run timeline;
- artifact viewer;
- diagnostics.

## What Autopilot Does Not Own

Autopilot does not own:

- IOI L1 settlement contracts;
- global marketplace state;
- root user secrets except through wallet.network;
- first-party marketplace Agentgres domains;
- remote execution nodes;
- Filecoin/CAS payload availability;
- provider economics.

## Workflow Canvas

The workflow canvas is the construction language for bounded autonomous work.

It should support:

- triggers;
- model nodes;
- tool nodes;
- connector nodes;
- parser nodes;
- adapter nodes;
- decision nodes;
- loop/barrier nodes;
- human gates;
- output/materialization nodes;
- subgraphs;
- tests and fixtures;
- proposals;
- activation checklist;
- replay/debug panes.

## Harness-as-Workflow

The default agent harness should become a blessed workflow template.

Phases:

1. Render default harness as read-only graph.
2. Expose model/tool/verifier/approval/output slots.
3. Allow validated forks.
4. Allow proposal-only AI-authored workflow edits.
5. Package forked harnesses as worker/workflow manifests.

The default harness remains neutral infrastructure. It must not silently cannibalize marketplace workers.

## Local vs Hosted Execution

Autopilot can execute locally or request external execution.

```text
Local:
  user machine, local files, local models, local connectors

Hosted:
  hosted IOI daemon

DePIN:
  Akash-like or other compute node

Enterprise Secure:
  TEE-verified or customer VPC runtime
```

Autopilot should choose placement according to policy, privacy, cost, latency, and user preference.

## Relationship to Marketplaces

Users may use Autopilot to:

- browse aiagent.xyz workers;
- install worker packages;
- order sas.xyz services;
- download packages from Filecoin/CAS/CDN;
- run workers locally;
- monitor hosted runs;
- review delivery bundles;
- approve authority grants;
- inspect receipts.

Autopilot is not required for all marketplace users, but it is the best local/private/power-user runtime.

## Local State

Autopilot should split state into:

### Ephemeral UI State

- selected tab;
- panel layout;
- hover/focus;
- modal state;
- unsaved form text;
- transient filters.

### Agentgres/Runtime State

- workflows;
- runs;
- tasks;
- artifacts;
- receipts;
- projections;
- local caches;
- mutation queues;
- worker installs;
- standing orders;
- project rooms;
- subscription cursors.

## Invariants

1. Workflow UI must not create a second runtime truth path.
2. Every visible node must have honest runtime status.
3. The default harness is a neutral orchestrator/fallback, not a marketplace competitor.
4. Local execution should preserve user privacy by default.
5. wallet.network must authorize sensitive capabilities.
6. Agentgres must record durable run/receipt/artifact state where relevant.

## One-Line Doctrine

> **Autopilot is where users build and run Web4 locally: workflows become workers, workers act under authority, and outcomes remain inspectable.**
