# sas.xyz Service-as-Software Marketplace Specification

## Canonical Definition

**sas.xyz is the canonical Web4 marketplace application for autonomous service outcomes.**

It lets users order outcomes produced by workers, workflows, providers, and runtime nodes under escrow, SLA, receipts, and delivery acceptance.

## What sas.xyz Is

sas.xyz is:

- a React/Web service marketplace interface;
- an Agentgres-backed application domain;
- an IOI L1 smart-contract user;
- an outcome-ordering and delivery system;
- a workflow/worker composition surface;
- a service escrow and SLA layer.

It is not a separate chain by default.

## Difference From aiagent.xyz

```text
aiagent.xyz = marketplace for workers/capabilities
sas.xyz     = marketplace for delivered outcomes/services
```

aiagent.xyz sells reusable digital workers. sas.xyz sells packaged services such as weekly audits, report generation, support resolution, research deliverables, CAD artifacts, or workflow automation outcomes.

## What sas.xyz Owns

sas.xyz owns:

- service listings;
- provider profiles;
- service manifests;
- order lifecycle;
- SLA terms;
- delivery bundles;
- acceptance/dispute state;
- provider/customer messaging;
- service quality ledgers;
- service reputation;
- outcome packaging;
- workflow composition references.

## What sas.xyz Does Not Own

sas.xyz does not own:

- user raw secrets;
- all runtime compute;
- local Autopilot execution;
- IOI L1 itself;
- Filecoin/CAS payload bytes;
- aiagent.xyz worker marketplace state except through refs/integrations.

## Service Order Lifecycle

```text
User orders service
→ sas.xyz Agentgres creates ServiceOrder operational state
→ IOI L1 contract locks escrow / records order commitment
→ runtime router selects execution venue
→ worker/workflow executes through IOI daemon
→ artifacts and receipts are produced
→ delivery bundle recorded in sas.xyz Agentgres
→ user accepts, rejects, or disputes
→ IOI L1 contract releases payout / refund / slashing
```

## IOI L1 Contract Interactions

sas.xyz should use IOI L1 contracts for:

- service publication;
- service order commitment;
- escrow lock;
- SLA bond;
- delivery acceptance;
- payout release;
- refunds;
- disputes;
- provider bond slashing;
- reputation root commitments.

## Agentgres Domain State

sas.xyz Agentgres tracks:

- rich service metadata;
- service search/ranking projections;
- order state;
- run state;
- delivery artifacts;
- evidence bundles;
- user/provider messages;
- receipts;
- quality records;
- support/dispute evidence;
- operational billing projections.

## User Without Autopilot

Users can interact directly with sas.xyz in a browser:

```text
browser order
→ hosted/provider/DePIN/TEE IOI runtime executes
→ delivery bundle appears in sas.xyz UI
→ wallet.network handles approvals/payment
```

Autopilot is optional for users who want local/private execution, local workflow editing, or local connector/model control.

## Managed vs Local Service

sas.xyz may support two modes:

### Local Install/Run

The service workflow is installed into Autopilot and run locally.

### Managed Outcome

A provider/hosted IOI runtime executes and delivers the outcome.

Both modes should emit receipts and delivery bundles.

## Delivery Bundle

A service delivery should include:

```text
output artifacts
evidence bundle
execution receipts
validation results
policy/capability summary
quality summary
acceptance/dispute metadata
```

## One-Line Doctrine

> **sas.xyz does not sell software tools. It sells verifiable autonomous outcomes.**

