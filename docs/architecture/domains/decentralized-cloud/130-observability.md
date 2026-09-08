# 130 — Observability: identity model, pipeline, storage, health and incidents, topology

**Spec section:** 17. **Depends on:** 010, 080, 170. **Defines:** logical/physical
telemetry, retention, topology history, incident evidence; OTLP conventions, query
API, SLO records. **Required diagrams:** ingestion, identity continuity, incident
correlation.

## 17. Observability

### 17.1 Identity model

Telemetry carries both logical and physical dimensions:

```text
organization_id
project_id
application_id
service_id
deployment_id
logical_replica_slot
workload_attempt_id
allocation_id
provider_id
facility_id
region_id
```

Default queries group by logical service. Physical dimensions are facets for diagnosis.

Migration changes `attempt_id` and `allocation_id`, not `service_id`.

### 17.2 Pipeline

```text
Application / supervisor / gateway
→ OpenTelemetry collector
→ regional ingestion
→ metrics, logs, and trace backends
→ resource-aware query API
→ console and external export
```

Collectors use bounded local buffering and persistent queues where appropriate. OpenTelemetry's documentation explicitly notes that persistent queues improve resilience but still have loss conditions such as disk failure or exhausted storage; the product should expose ingestion gaps rather than imply lossless telemetry. ([OpenTelemetry][15])

### 17.3 Selected storage

Use:

```text
Metrics: Prometheus-compatible time-series storage
Logs and traces: indexed analytical storage
Long-term exports: object storage
Audit: separate append-only security pipeline
Billing evidence: separate financial ingestion
```

Do not make customer billing depend on sampled traces or ordinary application logs.

### 17.4 Health and incidents

Combine:

* External synthetic requests from multiple vantage points.
* Gateway-observed failures and latency.
* Workload readiness and liveness.
* Provider-agent observations.
* Storage/database health.
* Protocol/network health.

Show **observed degradation** separately from **diagnosed cause**.

### 17.5 Topology experience

Offer these lenses over one dependency graph:

```text
Application
Logical resources
Geography
Providers
Network paths
Failure domains
Cost
Assurance / decentralization
```

Selecting a node opens a consistent inspector. Selecting a dependency shows connection health, traffic, latency, authorization, and shared failure domains.

A time slider reconstructs topology during an incident. Large deployments cluster by service or facility; the interface never requires navigating a thousand-node hairball.

[15]: https://opentelemetry.io/docs/collector/resiliency/
