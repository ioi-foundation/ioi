# 270 — Architecture diagrams

Status: adopted product specification (owner, 2026-09-08); design baseline September 7, 2026.
Canonical owner: this file for the architecture diagrams.
Doctrine status: canonical
Implementation status: planned (the selected architecture, adopted 2026-09-08; nothing here is a claim that the product exists — what the Hypervisor daemon implements today is in `../cloud.md`)

**Spec section:** 27. Mermaid sources; each is referenced from the document it
illustrates.

## 27.1 System topology

```mermaid
flowchart TB
    U["Console / CLI / SDK / Terraform / AI"] --> API["Unified Cloud API"]
    API --> CP["Project Control-Plane Cell"]
    CP --> REG["Desired State and Operations"]
    CP --> SCH["Placement and Acquisition"]
    CP --> NET["Network Control"]
    CP --> DATA["Data Control"]
    CP --> MONEY["Pricing and Financial Ledger"]

    SCH --> AD["Provider Adapters"]
    AD --> AK["Akash-like Supply"]
    AD --> GPU["GPU Networks"]
    AD --> DC["Independent Datacenters"]

    NET --> EDGE["Edge Gateways and Relays"]
    DATA --> HOT["Qualified Hot Storage Cells"]
    DATA --> ARC["Filecoin-backed Archive"]

    MONEY --> SET["Treasury and Native Settlement"]
    EDGE --> AK
    EDGE --> GPU
    EDGE --> DC
```

## 27.2 Control-plane architecture

```mermaid
flowchart LR
    CMD["Authorized Command"] --> TX["Resource + Outbox Transaction"]
    TX --> DB[("Core PostgreSQL")]
    DB --> PUB["Outbox Publisher"]
    PUB --> BUS["Durable Event Bus"]
    BUS --> CTRL["Controllers"]
    CTRL --> PLAN["Planner / Scheduler"]
    PLAN --> JOURNAL["Operation Step Journal"]
    JOURNAL --> EFFECT["Bounded External Effect"]
    EFFECT --> OBS["Observed State"]
    OBS --> DB
    SWEEP["Periodic Reconciliation Sweep"] --> CTRL
```

## 27.3 Deployment sequence

```mermaid
sequenceDiagram
    actor User
    participant API
    participant Core
    participant Planner
    participant Money
    participant Adapter
    participant Fabric
    participant Health

    User->>API: Request plan
    API->>Core: Save proposed revision
    Core->>Planner: Resolve and place
    Planner-->>User: Plan, quote, constraints
    User->>API: Approve plan hash
    API->>Money: Authorize bounded spend
    API->>Core: Activate desired revision
    Core->>Adapter: Acquire with durable intent
    Adapter-->>Core: Native resource evidence
    Core->>Fabric: Connect network and data
    Core->>Health: Verify workload and endpoint
    Health-->>Core: Ready evidence
    Core-->>User: Healthy endpoint
```

## 27.4 Provider acquisition

```mermaid
flowchart TD
    P["Approved Placement"] --> I["Persist External Intent"]
    I --> Q{"Quote and Policy Still Valid?"}
    Q -- No --> B["Block / Replan"]
    Q -- Yes --> A["Acquire Native Resource"]
    A --> R{"Outcome Known?"}
    R -- Yes --> V["Verify Ownership and Capabilities"]
    R -- No --> D["Discover by Intent / Transaction / Native ID"]
    D --> R
    V --> OK["Record Allocation"]
    V --> C["Compensate Unsupported or Partial Result"]
```

## 27.5 Payment and settlement

```mermaid
flowchart LR
    C["Customer USD Payment"] --> CASH["Payment Clearing"]
    CASH --> LEDGER[("Financial Ledger")]
    QUOTE["Accepted USD Quote"] --> HOLD["Spend Grant"]
    HOLD --> LEDGER
    USAGE["Qualified Usage"] --> RATE["Rating"]
    RATE --> INV["Customer Invoice"]
    INV --> LEDGER

    LEDGER --> TRE["Treasury Authorization"]
    TRE --> NATIVE["Native Funds / Escrow"]
    NATIVE --> PROV["Provider Settlement"]
    PROV --> REC["Reconciliation"]
    REC --> LEDGER
```

## 27.6 Storage topology

```mermaid
flowchart TB
    APP["Application Identity"] --> GW["Private Object Gateway"]
    GW --> KMS["Platform Key Service"]
    GW --> CELL["Hot Storage Cell"]
    CELL --> A["Storage Operator A"]
    CELL --> B["Storage Operator B"]
    CELL --> C["Storage Operator C"]

    CELL --> EXP["Versioned Encrypted Export"]
    EXP --> MAN["Independent Archive Manifest"]
    EXP --> F1["Archive Provider 1"]
    EXP --> F2["Archive Provider 2"]
    F1 --> VERIFY["Proof and Retrieval Tests"]
    F2 --> VERIFY
```

## 27.7 Network topology

```mermaid
flowchart TB
    CLIENT["Internet Client"] --> DNS["Platform DNS"]
    DNS --> E1["Edge Operator 1"]
    DNS --> E2["Edge Operator 2"]
    E1 --> REL["Authenticated Origin Fabric"]
    E2 --> REL

    REL --> A["API Attempt at Provider A"]
    REL --> B["API Attempt at Provider B"]
    A --> PRIVATE["Private Service Connections"]
    B --> PRIVATE
    PRIVATE --> DB["Database Service"]
    PRIVATE --> OBJ["Object Service"]

    A -. "Qualified routed profile" .-> WG["WireGuard Private Routing"]
    B -. "Qualified routed profile" .-> WG
```

## 27.8 Failure and rescheduling

```mermaid
sequenceDiagram
    participant Probe
    participant Health
    participant Edge
    participant Recovery
    participant Adapter
    participant Identity
    participant Ledger

    Probe->>Health: Corroborated failure evidence
    Health->>Edge: Remove failed attempt
    Health->>Recovery: Repair required
    Recovery->>Recovery: Check policy, capacity, fencing
    Recovery->>Adapter: Acquire replacement
    Adapter-->>Recovery: New allocation
    Recovery->>Identity: Issue new attempt credentials
    Recovery->>Health: Verify replacement
    Health->>Edge: Admit healthy replacement
    Recovery->>Adapter: Release stale allocation
    Recovery->>Ledger: Reconcile overlap and obligations
```

## 27.9 Identity and authentication

```mermaid
flowchart LR
    HUMAN["Human / CI Identity"] --> AUTH["Authentication"]
    AUTH --> POLICY["Authorization and Policy"]
    POLICY --> PLAN["Approved Plan"]
    PLAN --> GRANT["Scoped Execution Grant"]

    NODE["Provider / Node Evidence"] --> VERIFY["Identity Verification"]
    GRANT --> VERIFY
    VERIFY --> WID["Attempt-bound Workload Identity"]
    WID --> SECRET["Scoped Secret Release"]
    WID --> NET["Private Connection Authorization"]
    WID --> DATA["Data Access Authorization"]
```

## 27.10 Data and event architecture

```mermaid
flowchart TB
    API["Commands"] --> CORE[("Core DB")]
    CORE --> OUT["Transactional Outbox"]
    OUT --> BUS["Durable Event Bus"]

    BUS --> CTRL["Reconcilers"]
    BUS --> INDEX["Search / Topology Views"]
    BUS --> AUDIT["Audit Pipeline"]
    BUS --> BILL["Billing Consumers"]

    BILL --> MONEY[("Financial Ledger")]
    MONEY --> MOUT["Financial Outbox"]
    MOUT --> BUS

    WORK["Workloads / Gateways"] --> OTEL["Telemetry Ingestion"]
    OTEL --> ANALYTICS[("Metrics / Logs / Traces")]
    CORE --> QUERY["Authorized Query API"]
    ANALYTICS --> QUERY
    INDEX --> QUERY
```
