# 020 — Console UX: information architecture, shell, pages, flows, wireframes

**Spec sections:** 4, 5, 6, 7, 8. **Depends on:** 010, 160. **Defines:** navigation,
page contracts, flows, progressive disclosure; routes, view models, status vocabulary,
design components. **Required diagrams:** shell, page maps, critical journeys.

## 4. Information architecture

Use one console with organization and project scopes, plus a separate Provider Console.

### Project navigation

```text
Overview

Applications
  Applications
  Deployments

Compute
  Services
  Instances
  Jobs & Workflows
  Clusters
  Capacity & Reservations

AI
  Inference Endpoints
  Models
  Training Runs

Data
  Databases
  Caches
  Queues
  Object Storage
  Volumes
  Archives

Network
  Private Networks
  Gateways & Load Balancers
  Domains & DNS
  CDN
  Addresses & Egress

Observe
  Service Health
  Logs
  Metrics
  Traces
  Alerts & Incidents
  Events

Security
  Access
  Workload Identities
  Secrets & Keys
  Policies
  Audit

Supply
  Placement Policies
  Provider Pools
  Regions & Capacity
  Providers
  Resource Market

Settings
  General
  Quotas
  Integrations
  API & Webhooks
  Import & Export

Persistent footer
  Billing
  Documentation
  Support
  Platform Status
```

### Organization navigation

```text
Overview
Projects
People & Access
Policies & Provider Pools
Billing
  Overview
  Usage
  Budgets
  Invoices
  Payment Methods
  Reservations & Commitments
  Credits & Adjustments
Audit
Settings
```

The project-level Billing link opens organization billing with the current project filter applied.

### Why this hierarchy

**Applications is the default workspace.** Most developers should spend their time in application detail, deployments, logs, and cost.

**Compute is not a competing resource model.** Its Services page is an infrastructure-oriented view of the same Service objects shown inside applications.

**AI is a workflow specialization.** Inference Endpoints and Training Runs reuse service, job, model-artifact, and allocation primitives.

**Data combines storage and managed data services.** Developers should see the persistence layer together rather than navigate separate "Storage" and "Database" universes.

**Supply is the expert layer.** Providers, markets, provenance, and placement policy belong together. They are not necessary steps in deploying an application.

The navigation above is the target architecture. Unshipped services are omitted from production navigation—not presented as a wall of disabled placeholders.

## 5. Global console shell

### 5.1 Persistent shell

```text
Top bar:
[Cloud / Console ▾] [Organization ▾] [Project ▾]
[Search resources, commands, docs…] [Create +] [Activity] [Help] [Account]

Left:
Contextual navigation rail

Content:
Breadcrumb
Page title + resource status + primary action
Scope/filter controls
Main content

Optional right drawer:
Resource inspector, operation details, or AI assistant
```

Do **not** use a global region selector that silently filters away resources. Region is a page filter or resource property. The project selector determines authorization context; it must not be confused with geography.

Every deep link contains stable resource IDs. Names are display attributes and may change.

Switching organizations clears incompatible search state, selected resources, and assistant context.

### 5.2 Visual direction

Use a quiet infrastructure interface:

| Element      | Selected treatment                                                       |
| ------------ | ------------------------------------------------------------------------ |
| Top bar      | Approximately 56 px; stable across console scopes                        |
| Side rail    | Approximately 232 px expanded; icon-only collapse                        |
| Content      | 24 px desktop gutters; restrained maximum width on forms                 |
| Tables       | Primary operational surface; adjustable 36/44 px row density             |
| Typography   | Neutral sans-serif; monospaced IDs, commands, timestamps                 |
| Type scale   | 12 px metadata, 14 px body, 16 px section labels, 24 px page titles      |
| Color        | Neutral surfaces, one restrained accent, semantic status colors          |
| Status       | Icon + text; never color alone                                           |
| Detail pages | Compact summary followed by tabs, not stacked marketing cards            |
| Charts       | Shared time range, explicit units, deployment and incident annotations   |
| Theme        | Light and dark with equal functionality and contrast                     |
| Motion       | Limited to useful progress; no permanently animated infrastructure globe |

Use clear status language: **Healthy**, **Updating**, **Degraded**, **Waiting for capacity**, **Action required**.

### 5.3 Search and command system

`⌘K`/`Ctrl+K` opens the command palette. `/` focuses search when the user is not editing text.

Search has five result classes:

```text
Resources
Navigation
Commands
Documentation
Supply
```

Examples resolve into structured queries:

| Input                  | Interpretation                                                 |
| ---------------------- | -------------------------------------------------------------- |
| `gpu`                  | GPU-backed instances, endpoints, jobs, and relevant navigation |
| `h100`                 | Accelerator model filter plus matching resources               |
| `project foo`          | Project-name search                                            |
| `deployment api-prod`  | Deployment/resource search                                     |
| `logs payment-service` | Open Logs with a resolved service filter                       |
| `provider france`      | Providers with eligible French facilities                      |
| `cheapest a100`        | Current eligible offers sorted by normalized delivered price   |
| `storage > 1tb`        | Storage resources exceeding the selected capacity metric       |
| `failed deployments`   | Deployment status filter                                       |

Natural-language interpretation produces visible filter chips. The user can inspect or edit the interpretation.

Search results show freshness. Capacity search never presents stale advertised inventory as guaranteed availability.

Authorization applies **before snippets and autocomplete results are displayed**. Mutation commands always re-read the resource and reauthorize against current state.

Typing `> migrate api-prod` opens a planning flow. It does not execute a migration.

### 5.4 Responsive behavior

Desktop supports dense tables and a persistent inspector.

Tablet collapses the rail and moves the inspector into an overlay.

Mobile prioritizes incident review, logs, cost, approval, and safe operational actions. Complex topology editing and large placement comparisons remain desktop-oriented. Tables reduce to essential columns with row-detail sheets rather than shrinking text.

## 6. Page architecture

### 6.1 Shared page contracts

Every collection page uses:

```text
Title + primary create action
Small summary strip
Filters + saved views
Resource table
Pagination / streaming refresh
Optional selected-resource inspector
```

Every important resource detail uses:

```text
Breadcrumb
Name + status + stable ID + primary actions
Operational summary
Tabs:
  Overview
  Configuration
  Observability
  Events
  Access
  Cost
  Placement, when applicable
```

Individual resource types replace generic tabs where more precise names are useful.

Every page distinguishes:

* No resources exist.
* Filters match nothing.
* The user lacks access.
* Data is temporarily unavailable.
* Data is stale.
* A resource exists but provisioning is blocked.

### 6.2 Overview, Applications, Compute, and AI

| Destination             | Collection or landing-page contents                                                         | Important detail structure                                                            |
| ----------------------- | ------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------- |
| Organization Overview   | Attention queue; project health table; current spend; recent work; create project           | Cross-project drill-down without exposing unauthorized resources                      |
| Project Overview        | Application health; recent deployments; spend and forecast; active incidents; quick actions | Dependency summary and scoped activity                                                |
| Applications            | Name, health, services, latest deployment, endpoint, region, current cost                   | Overview, Services, Deployments, Data, Domains, Topology, Settings                    |
| Deployments             | Application/service, revision, author, source commit, rollout, duration, result             | Summary, Changes, Timeline, Build, Runtime Logs, Replicas, Placement, Cost            |
| Compute hub             | Running capacity by runtime; blocked requests; expiring reservations                        | Links into resource-specific views                                                    |
| Services                | Name, application, replicas ready/desired, resources, endpoint, rollout, rate               | Overview, Revisions, Scaling, Connections, Logs, Metrics, Placement, Access, Cost     |
| Instances               | Name, runtime, CPU/RAM/GPU, state, zone, network, attached data, rate                       | Overview, Console, Hardware, Network, Volumes, Metrics, Placement, Recovery, Cost     |
| Jobs & Workflows        | Name, queue, state, progress, attempts, checkpoint age, deadline, cost                       | Runs, Steps, Inputs/Outputs, Logs, Checkpoints, Placement, Retry Policy, Cost         |
| Clusters                | Version, node pools, health, region, supported profile, upgrades due                        | Overview, Node Pools, Workloads, Network, Storage, Access, Upgrades, Events           |
| Capacity & Reservations | Reserved units, interval, utilization, expiry, cancellation terms                           | Coverage, Allocations, Terms, Renewal, Financial Commitment                           |
| AI hub                  | Endpoint health; queued inference; GPU utilization; model activity                          | Links to endpoint, model, and training views                                          |
| Inference Endpoints     | Model version, runtime, ready replicas, throughput, latency, GPU class, cost                | Overview, Playground, API, Model, Scaling, Metrics, Requests, Placement, Access, Cost |
| Models                  | Name, immutable version, format, size, license metadata, compatibility                      | Artifacts, Validation, Supported Runtimes, Endpoint Usage, Access                     |
| Training Runs           | Model, dataset version, accelerator topology, progress, checkpoint age, spend               | Configuration, Metrics, Logs, Checkpoints, Artifacts, Placement, Cost                 |

The inference playground respects data policy. It does not automatically retain sensitive prompts.

### 6.3 Data

| Destination    | Collection columns and controls                                          | Important detail structure                                                   |
| -------------- | ------------------------------------------------------------------------ | ---------------------------------------------------------------------------- |
| Data hub       | Data health, capacity, protection gaps, backup failures                  | "Create data resource" selector with semantic differences                    |
| Databases      | Engine/version, topology, health, storage, connections, backup age, cost | Overview, Connections, Replicas, Metrics, Backups, Maintenance, Access, Cost |
| Caches         | Engine profile, capacity, eviction rate, availability mode               | Connections, Memory, Replication, Persistence, Metrics, Access               |
| Queues         | Queue type, backlog, oldest message, throughput, dead letters            | Messages, Consumers, Delivery Policy, Dead Letters, Metrics, Access          |
| Object Storage | Bucket, class, logical bytes, versions, region, protection state         | Objects, Configuration, Lifecycle, Replication, Access, Metrics, Cost        |
| Volumes        | Type, size, locality, writer mode, attachment, protection                | Attachments, Snapshots, Replicas, Performance, Recovery, Access, Cost        |
| Archives       | Dataset/version, bytes, providers, proof freshness, retrieval status     | Manifest, Copies, Evidence, Retrieval Jobs, Retention, Cost                  |

A bucket detail page exposes **Objects** prominently. A volume detail page exposes **Attachments and Recovery** prominently. They must not look interchangeable.

### 6.4 Network

| Destination               | Landing/list contents                                                | Important detail structure                                                |
| ------------------------- | -------------------------------------------------------------------- | ------------------------------------------------------------------------- |
| Network hub               | Endpoints, connection failures, public exposure, egress trend        | Connectivity graph with unhealthy paths                                   |
| Private Networks          | Name, mode, region scope, connected services, policies               | Connections, Names, Routes if supported, Policies, Flow Logs, Diagnostics |
| Gateways & Load Balancers | Endpoint, protocol, healthy backends, traffic, deployment generation | Listeners, Backends, Routing, TLS, Health Checks, Metrics, Access         |
| Domains & DNS             | Domain, verification, records, attached endpoint, certificate state  | Records, Ownership, Routing, Certificates, History                        |
| CDN                       | Distribution, origins, cache-hit ratio, bandwidth, purge status      | Origins, Cache Rules, Purges, Security, Geography, Logs, Cost             |
| Addresses & Egress        | Address, gateway, direction, portability scope, utilization          | Bindings, Allowed Destinations, NAT, Flow Logs, Cost                      |

The network mode is always visible: **Service Network** or **Routed Network**.

### 6.5 Observe and Security

| Destination         | Landing/list contents                                              | Detail or workspace                                               |
| ------------------- | ------------------------------------------------------------------ | ----------------------------------------------------------------- |
| Service Health      | SLO status, error budget, availability, latency, dependency health | Shared timeline with deployments and incidents                    |
| Logs                | Query editor, resource filters, time range, live-tail control      | Structured fields, trace links, attempt/provider facets           |
| Metrics             | Metric explorer, saved dashboards, units, aggregation              | Resource-aware charts and comparison intervals                    |
| Traces              | Service, latency distribution, error rate, sampled traces          | Waterfall, spans, logs, deployment and placement context          |
| Alerts & Incidents  | Severity, impact, owner, age, acknowledgement                      | Timeline, affected graph, evidence, actions, postmortem           |
| Events              | Resource, operation, type, reason, source, time                    | Event payload and linked operation                                |
| Access              | Users, teams, bindings, inherited permissions                      | Effective-access evaluator and policy explanation                 |
| Workload Identities | Service identity, current attempts, issuer, expiry, assurance mode | Grants, credential history, revocation, resource access           |
| Secrets & Keys      | Name, type, version, rotation status, consumers                    | Versions, Access, Rotation, Audit; plaintext not shown by default |
| Policies            | Scope, version, mode, violations, affected resources               | Policy editor, simulator, change history, approvals               |
| Audit               | Actor, action, target, result, source, time                        | Evidence record, authorization decision, plan and operation links |

### 6.6 Supply

| Destination        | Landing/list contents                                                    | Important detail structure                                                   |
| ------------------ | ------------------------------------------------------------------------ | ---------------------------------------------------------------------------- |
| Placement Policies | Constraints, referenced pools, resources using policy, violations        | Editor, Simulation, Eligible Capacity, Version History                       |
| Provider Pools     | Membership mode, qualified operators, regions, capacity freshness        | Members, Predicates, Exclusions, Eligibility Evidence, Usage                 |
| Regions & Capacity | Logical regions, service availability, capacity pressure, incidents      | Region Contract, Latency Cells, Failure Domains, Supported Classes           |
| Providers          | Operator, facilities, capability classes, evidence, observed performance | Identity, Facilities, Hardware, Offers, Reliability, Attestations, Incidents |
| Resource Market    | Hardware and service offers, comparable rates, freshness, terms          | Offer detail, normalized cost, evidence, reservation/deployment action       |

The market is an advanced destination, not the default home page.

### 6.7 Billing and Settings

| Destination                | Contents                                                                                         |
| -------------------------- | ------------------------------------------------------------------------------------------------ |
| Billing Overview           | Posted usage, estimated unbilled usage, forecast, available credit, commitments, payment status  |
| Usage                      | Group by project/application/service/SKU/label; quantity, rate, amount; export and drill-through |
| Budgets                    | Alerts, admission limits, approved continuity reserves, forecast thresholds                      |
| Invoices                   | Final invoices, payments, credits, adjustments, tax documents where applicable                   |
| Payment Methods            | Hosted card/ACH setup; optional supported crypto-payment rail                                    |
| Reservations & Commitments | Capacity obligations, renewal, unused capacity, cancellation terms                               |
| Credits & Adjustments      | Service credits, refunds, corrections, linked reasons                                            |
| General Settings           | Names, ownership, project home region, deletion protection                                       |
| Quotas                     | Current use, requested increases, hard limits, approval status                                   |
| Integrations               | Git repositories, registries, identity providers, telemetry exports                              |
| API & Webhooks             | Credentials metadata, webhook destinations, delivery attempts, schemas                           |
| Import & Export            | Resource manifests, migration assessments, data export jobs, portability reports                 |

## 7. Core UX flows

| Flow                | Selected experience                                                                                                                                                                  |
| ------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| Onboarding          | Sign in → create organization → choose project home jurisdiction → add payment method → create project → choose App, GPU Inference, or Job. No wallet step.                          |
| Deploy app          | Connect repository or provide OCI image → detect/build configuration → add dependencies → choose location and service profile → review plan → deploy → open endpoint and logs.       |
| Deploy GPU          | Choose Endpoint or Job → select model/image → declare accelerator requirements → choose location, duration/scaling, and interruption policy → review delivered-price quote → deploy. |
| Create storage      | Choose Objects, Block Volume, or Archive → see persistence/locality semantics → select class and residency → configure protection and retention → review price → create.             |
| Create network      | Choose Service Network by default → add service connections and access rules. Routed Network is offered only where eligible infrastructure exists.                                   |
| Add domain          | Enter domain → verify ownership → display required DNS records → attach endpoint → issue certificate → verify public HTTPS.                                                          |
| Debug failure       | Open affected resource → see impact and reason → correlated deployment/log/metric timeline → inspect proposed remediation → execute within permissions.                              |
| View placement      | Open Placement tab → inspect logical region, physical allocations, failure domains, evidence, and dependency coverage.                                                               |
| Set provider policy | Select policy template → edit hard constraints → simulate against current supply and existing resources → inspect shortages/disruptions → approve version.                           |
| Inspect spend       | Open Billing scoped to project → compare periods → group by service and SKU → inspect quantity/rate changes → drill into usage evidence.                                             |
| Migrate workload    | Select target policy → produce migration plan with data movement, interruption, temporary cost, and rollback limits → approve → monitor staged replacement.                          |

### Empty and blocked states

An empty Applications page should offer **Deploy from repository**, **Deploy container**, and **Run an example**, with a cost preview.

A failed deployment should say:

> No eligible capacity meets your US-only, verified-operator, and $0.20/replica-hour limits.

It should show the blocking constraints separately and offer **Wait**, **Change policy**, or **Change price limit**. It must not silently deploy elsewhere.

### AI-assisted operations

The assistant uses this path:

```text
Authorized read
→ evidence-backed explanation
→ structured proposed change
→ plan and diff
→ policy and cost evaluation
→ approval
→ operation
→ verification
→ audit
```

Examples:

* "Why is prod-api degraded?" returns affected replicas, evidence timestamps, likely cause, and uncertainty.
* "Make it survive one provider failure" evaluates the dependency graph and surviving capacity, not only replica count.
* "Reduce monthly cost by 20%" proposes changes with estimated savings and explicit assumptions; it does not invent a guaranteed saving.
* "Move to providers with p95 below 50 ms" must bind that latency to a specific source, destination, metric, and measurement window.

The model never receives unrestricted cloud credentials. Logs and provider messages are untrusted input, not instructions. Rollback means a new, authorized operation; it does not imply that database changes or external side effects can be undone automatically.

## 8. Textual wireframes

All values below are illustrative fixtures.

### 8.1 Console home

```text
┌──────────────────────────────────────────────────────────────────────────┐
│ Cloud   Acme ▾   All projects ▾   Search…        Create +   Activity   ◉ │
├──────────────────┬───────────────────────────────────────────────────────┤
│ Overview         │ Good afternoon                                       │
│ Projects         │                                                      │
│ People & Access  │ Attention                                            │
│ Policies & Pools │ ! commerce-prod: API redundancy reduced    [Inspect] │
│ Billing          │ ! GPU reservation expires tomorrow         [Review] │
│ Audit            │                                                      │
│ Settings         │ Projects                    Health       Spend MTD   │
│                  │ commerce-prod               Degraded     $382.10     │
│                  │ inference-batch             Healthy      $194.20     │
│                  │ development                 Healthy       $21.40     │
│                  │                                                      │
│                  │ Recent work                 Quick actions            │
│                  │ API revision 42 deployed    [Deploy app] [Run GPU job]│
│                  │ Model batch completed       [Create project]         │
│ Docs / Support   │                                                      │
└──────────────────┴───────────────────────────────────────────────────────┘
```

### 8.2 Project overview

```text
commerce-prod                                         [Create resource +]
US control-plane home · Production · Project ID: prj_…

Health: Degraded      Applications: 3      Current estimated rate: $1.84/h

Needs attention
API: 2/3 replicas healthy; service remains available.       [Open incident]

Applications
Name          Health       Deployment       Endpoint          Rate
storefront    Healthy      rev-18           shop.example      …
commerce      Degraded     rev-42           api.example       …
worker        Healthy      rev-09           Private           …

Recent deployments                         Spend trend
rev-42  API image update  14:32              [7-day chart]
rev-18  Frontend update   13:08              [View usage]

[Application topology]  [All resources]  [Project activity]
```

### 8.3 Applications

```text
Applications                                          [Deploy application]
[Applications] [Deployments]

Search…   Health ▾   Region ▾   Label ▾   [Saved views]

Name          Health      Services  Latest deploy  Endpoint       Cost
commerce      Degraded    4         rev-42         api.example    …
storefront    Healthy     1         rev-18         shop.example   …
reporting     Healthy     2         rev-09         Private        …

Selected: commerce
API · PostgreSQL · Cache · Object bucket
Issue: replacement capacity pending
[Open application] [View logs] [Create deployment]
```

### 8.4 Application detail

```text
Applications / commerce                       Degraded     [Deploy update]

2/3 API replicas ready · Data healthy · Public HTTPS available
Endpoint: api.example                                      [Open] [Copy]

[Overview] Services Deployments Data Domains Topology Settings

Service        Revision  Ready  Latency p95  Errors  Rate
api            rev-42    2/3    84 ms        0.2%    …
worker         rev-09    2/2    —            0.0%    …

Dependencies
PostgreSQL: Healthy · Cache: Healthy · api-data: Protected

Current incident
Provider allocation unavailable → replacing replica 2
[Timeline] [Placement] [Explain with assistant]

Latest deployment: rev-42 · image digest sha256:… · by Alex
```

### 8.5 Deployment creation

```text
Deploy application
Source → Configure → Data & network → Placement → Review

Source
[Repository] [Container image]
Image: ghcr.io/acme/api@sha256:…

Resources
CPU [4]   Memory [16 GiB]   Replicas [3]

Data
api-data: Private object bucket · Standard replicated
[Add dependency]

Placement
Logical region [US East]
Service profile [Resilient]
Advanced ▸ Provider pool / anti-affinity / trust / locality

Review
Compute ceiling: $0.20 per replica-hour
Data and network: separately itemized
No eligible plan may exceed approved limits.

[Back]                                  [Generate deployment plan]
```

### 8.6 Deployment detail

```text
commerce / Deployment rev-42                      Updating · Serving rev-41

[Overview] Changes Timeline Build Logs Replicas Placement Cost

Plan: plan_…      Operation: op_…      Approved by: Alex
Image: sha256:…   Policy: production-v7

Progress
✓ Validated
✓ Capacity acquired
✓ Network and data connected
● Verifying new replicas
○ Shift traffic
○ Retire previous revision

Replica   Attempt   Status      Provider       Readiness
1         a-201     Healthy     Operator A     Passed
2         a-202     Starting    Operator B     2/3 checks
3         a-203     Healthy     Operator C     Passed

[Pause rollout] [Cancel new revision] [Inspect approved plan]
```

### 8.7 GPU marketplace

```text
Supply / Resource Market                           Snapshot: 14:32:10 UTC

GPU [A100 ▾]   Region [Europe ▾]   Trust [Verified ▾]
Memory ▾   Interconnect ▾   Availability ▾   Interruption ▾

Offers matching policy: 12
Advertised capacity ≠ reserved capacity

Operator  GPU / form factor  Memory  Location  Retail quote  Freshness
A         A100 PCIe          …       DE        … / GPU-h    12 s
B         A100 SXM           …       FR        … / GPU-h    18 s
C         A100 PCIe          …       NL        … / GPU-h    24 s

Selected offer
Compute + required host resources + network assumptions
Evidence: hardware / location / operator identity
Reservation terms and quote expiry

[Deploy with this preference] [Reserve capacity] [Compare]
```

### 8.8 GPU deployment

```text
Deploy GPU workload

Mode: [Inference endpoint] [Batch job] [Direct instance]

Model / image: …
Accelerator: [H100]  Count [1]  Minimum usable memory […]
Host CPU […]  Host RAM […]  Scratch […]

Location: [Europe]
Availability: [Interruptible] [On-demand] [Reserved]

Recovery
Checkpoint/output bucket: inference-data
Restart policy: [Resume from application checkpoint]
Live migration: Not included

Duration / scaling
Job deadline […]       Maximum spend […]

Quote
Compute …   Model transfer …   Storage …   Egress …
[Advanced placement]                         [Review plan]
```

### 8.9 Storage

```text
Data / Object Storage                                  [Create bucket]

Protection: 8 healthy · 1 resynchronizing
Logical data: …       Versioned data: …       Archive copies: …

Bucket       Class       Region    Bytes   Protection      Access
api-data     Standard    US East   …       3 copies        Private
models       Standard    Europe    …       3 copies        Private
exports      Archive     US        …       Verified        Private

Selected: api-data
[Objects] Configuration Lifecycle Replication Access Metrics Cost

Object key                  Size        Version       Modified
uploads/2026/…              …           v-…           …
results/batch-…             …           v-…           …

Endpoint: private service connection
Semantics: Object API; not a mountable block volume
```

### 8.10 Network

```text
Network / production-private                       Healthy

Mode: Service Network
Scope: commerce-prod
Private connectivity follows service identity, not provider IP.

[Connections] Names Policies Flow Logs Diagnostics

From          To             Protocol      Policy       Health
api           postgres       TCP           Allow        Healthy
api           cache          TCP           Allow        Healthy
worker        api-data       Object API    Allow        Healthy
frontend      postgres       —             Deny         Enforced

Public ingress
api.example → edge gateways → api service

[Add connection] [Inspect path] [Create routed network]
```

### 8.11 Observability

```text
Observe / Service Health
Project: commerce-prod   Service: api   Time: Last 1 hour ▾

Availability       Latency p95       Error rate       Ready replicas
…                  …                …                2 / 3

[Shared timeline: requests / errors / latency / deployment markers]

14:31:05  Replica 2 unhealthy
14:31:15  Backend removed from ingress
14:31:35  Replacement allocation requested

[Logs] [Metrics] [Traces] [Events]
Query: service.id = svc_api AND severity >= warning

Time       Attempt   Message
14:31:05   a-202     Upstream connection unavailable
…

[Open incident] [Explain degradation]
```

### 8.12 Provider pool

```text
Supply / Provider Pools / production-us              Version 7

Mode: Dynamic eligibility
Used by: 18 services · 3 databases · 2 reservations

[Policy] Eligible Providers Exclusions Simulation History

Requirements
Jurisdiction: United States
Operator identity: Independently verified
Facility evidence: Current
Permitted networks: Akash + Direct
Community/unverified supply: Excluded

Eligible now: 11 operators / 17 facilities
Capacity freshness: 30 seconds

Simulation against current deployments
16 unchanged · 2 require migration · 1 has no feasible placement

[Edit draft] [Export policy] [Review policy update]
```

### 8.13 Physical placement

```text
commerce / api / Placement

Logical region: US East
Latency cell: Ashburn-1
Protection: one qualified operator failure, subject to dependency coverage

Replica  Operator   Facility   Jurisdiction  Protocol  Hardware  Evidence
1        A          VA-01      US            Akash     …         Current
2        B          VA-04      US            Direct    …         Current
3        C          VA-07      US            Akash     …         Current

[Application] [Geography] [Providers] [Network] [Failure domains] [Cost]

Shared dependencies
Ingress: 2 edge operators
Object data: 3 storage operators
Identity/keys: Platform-managed

Warning: replicas 1 and 3 share an upstream network dependency.
[Inspect evidence] [Simulate failure] [Plan relocation]
```

### 8.14 Billing

```text
Billing / Overview                      Organization: Acme
Project filter: commerce-prod           Period: September

Posted usage       Estimated unbilled       Forecast       Available credit
$367.40            $14.70                   …              …

Usage is current through 14:30 UTC.
Funds reserved for future execution are shown separately.

[Usage] Budgets Invoices Payments Commitments Adjustments

Service       Compute   Data   Network   Other   Total
api           …         …      …         …       …
postgres      …         …      …         …       …
inference     …         …      …         …       …

Changes versus previous period
GPU-hours +… · Egress +… · Unit price unchanged

[View usage evidence] [Export] [Create budget]
```

### 8.15 IAM

```text
Security / Access                                      [Add binding]

[People & Teams] Service Accounts Effective Access History

Principal          Role               Scope             Conditions
team:platform      Operator           commerce-prod     MFA
team:developers    Developer          development       —
svc:api-runtime    Object Writer      api-data          Workload-bound

Inherited organization controls
✓ Public databases denied
✓ US residency required
✓ Production data deletion requires additional approval

Evaluate access
Principal […]  Action […]  Resource […]
[Explain decision]

No direct secret-reading permission is implied by deployment permission.
```

### 8.16 Provider console

```text
Cloud / Provider Console ▾     Operator A       Search…       Account

Overview
Infrastructure      Fleet health: 42 healthy · 1 quarantined
Capacity & Offers   Allocated GPU capacity: … / …
Workloads           Estimated earnings: …
Networking
Storage             Attention
Health              ! Node n-17 requires attestation renewal
Trust               ! Maintenance overlaps a reservation
Earnings
API & Agents        Capacity
Team & Settings     Hardware   Available   Reserved   In use
                    H100       …           …          …
                    CPU        …           …          …

                    Workloads
                    ID      Profile      State      SLA status
                    w-…     GPU job      Running    Healthy

                    [Register node] [Publish offer] [Plan maintenance]
```

### 8.17 Provider detail

```text
Supply / Providers / Operator A

Identity: Verified legal operator
Facilities: 4
Qualified profiles: Container / GPU / Service Network
Evidence last checked: …

[Overview] Facilities Hardware Offers Reliability Attestations Incidents

Reliability by service class
Class       Observation window   Sample size   Availability   Confidence
GPU jobs    …                    …             …              …
Containers  …                    …             …              …

Evidence
Operator identity       Independent review     Expires …
Facility location       Verified documentation Expires …
GPU attestation         Supported subset       Current
Renewable energy        Supplier claim         Not independently verified

[View allocations using provider] [Exclude from pool]
```

### 8.18 Global search and command palette

```text
┌──────────────────────────────────────────────────────────────────────┐
│ Search resources, docs, supply…                                      │
│ > make api survive one provider failure                              │
├──────────────────────────────────────────────────────────────────────┤
│ Interpreted scope: commerce-prod / api                               │
│                                                                      │
│ Proposed command                                                     │
│ Plan resilience upgrade                                              │
│ Evaluates compute, data, ingress, identities, and surviving capacity. │
│                                                                      │
│ Related resources                                                    │
│ api service · production-us pool · api-data bucket                   │
│                                                                      │
│ No changes will execute from this search.                            │
│ [Generate plan]                                     Esc: close       │
└──────────────────────────────────────────────────────────────────────┘
```
