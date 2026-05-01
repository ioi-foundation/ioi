# aiagent.xyz Worker Marketplace Specification

## Canonical Definition

**aiagent.xyz is the canonical Web4 marketplace application for portable digital workers.**

It discovers, compares, installs, invokes, meters, licenses, and settles worker packages. It is an application domain with its own kernel + Agentgres backend and IOI L1 smart-contract settlement rails.

## What aiagent.xyz Is

aiagent.xyz is:

- a React/Web marketplace interface;
- an Agentgres-backed application domain;
- an IOI L1 contract user;
- a worker discovery and procurement surface;
- a package/license/quality/reputation system;
- a gateway to local, hosted, DePIN, and TEE worker execution.

It is not a separate chain by default.

## What aiagent.xyz Owns

aiagent.xyz owns:

- worker listings;
- worker manifests;
- publisher profiles;
- worker versions;
- capability descriptions;
- pricing/licensing metadata;
- quality ledgers;
- contribution records;
- install records;
- usage records;
- reputation projections;
- search/ranking;
- install/run UX.

## What aiagent.xyz Does Not Own

aiagent.xyz does not own:

- the user's raw secrets;
- all worker execution;
- IOI L1 itself;
- Filecoin/CAS payload bytes;
- local Autopilot state;
- every service outcome delivery;
- wallet authority.

## Worker Package

A worker package should include:

```text
manifest
worker definition
harness workflow
capability requirements
model policy
tool requirements
connector requirements
memory schema
artifact schema
receipt policy
pricing/license terms
deployment profile
```

Package payloads may live on Filecoin/CAS/CDN and be referenced by signed manifests.

## Marketplace Contracts on IOI L1

aiagent.xyz should use IOI L1 contracts for:

- publisher registration;
- worker publication;
- manifest/version commitment;
- license/install right;
- usage settlement;
- contribution root commitment;
- reputation root commitment;
- disputes;
- payouts.

## Agentgres Domain State

aiagent.xyz Agentgres tracks:

- listing metadata;
- search indexes;
- worker versions;
- install history;
- run/invocation summaries;
- quality and reputation records;
- contribution accounting;
- reviews;
- package refs;
- delivery/receipt refs.

## Execution Modes

When a user invokes a worker:

1. **Local Autopilot** — package is downloaded and run locally.
2. **Hosted worker** — provider/IOI runtime runs it.
3. **DePIN mutual blind** — minimized capsule runs on compute node.
4. **Enterprise secure** — TEE/customer VPC/local runtime required.
5. **API/inter-agent call** — external app or worker invokes capability endpoint.

## User Without Autopilot

A user can still use aiagent.xyz directly:

```text
browser UI
→ marketplace order/install/run request
→ runtime router selects hosted/provider/DePIN/TEE node
→ result artifacts and receipts delivered through browser
```

Autopilot is optional local execution, not required for all marketplace use.

## Marketplace Neutrality

aiagent.xyz must not become a worker cannibalization mechanism.

Required rules:

1. No silent cloning of worker internals into the default harness.
2. Worker packages declare license and visibility rights.
3. Worker usage emits contribution receipts.
4. Routing decisions are explainable and user-controllable.
5. Users may run default/local execution when external capability is not required.
6. Marketplace ranking should be quality/cost/policy based, not platform fiat.

## Quality and Reputation

Workers should accumulate measurable records:

- task success;
- failure class;
- cost;
- latency;
- verification score;
- human override rate;
- refund/dispute rate;
- domain-specific benchmark results;
- contribution value.

## One-Line Doctrine

> **aiagent.xyz sells portable workers, not prompts: workers expose responsibilities, receipts, capabilities, and measurable outcomes.**

