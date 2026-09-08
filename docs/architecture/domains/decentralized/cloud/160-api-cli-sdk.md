# 160 — API, CLI, SDK and integrations

Status: adopted product specification (owner, 2026-09-08); design baseline September 7, 2026.
Canonical owner: this file for the API, CLI, SDK and integrations.
Doctrine status: canonical
Implementation status: planned (the selected architecture, adopted 2026-09-08; nothing here is a claim that the product exists — what the Hypervisor daemon implements today is in `../cloud.md`)

**Spec section:** 20. **Depends on:** 010, 030, 090, 170. **Defines:** API
conventions, CLI/SDK/Terraform behavior, webhooks, compatibility; OpenAPI, errors,
pagination, idempotency, operation streams. **Required diagrams:** request lifecycle,
tool-to-API mapping.

## 20. API + CLI + SDK

### 20.1 API design

Use REST for customer resources, asynchronous Operations for changes, and streaming events for progress.

```text
/v1/organizations
/v1/organizations/{org}/projects

/v1/projects/{project}/applications
/v1/projects/{project}/services
/v1/projects/{project}/deployments
/v1/projects/{project}/jobs
/v1/projects/{project}/job-runs

/v1/projects/{project}/compute/instances
/v1/projects/{project}/clusters
/v1/projects/{project}/inference-endpoints
/v1/projects/{project}/models

/v1/projects/{project}/storage/buckets
/v1/projects/{project}/storage/volumes
/v1/projects/{project}/storage/archives
/v1/projects/{project}/databases

/v1/projects/{project}/networks
/v1/projects/{project}/endpoints
/v1/projects/{project}/domains

/v1/projects/{project}/identities
/v1/projects/{project}/secrets
/v1/projects/{project}/policies

/v1/provider-pools
/v1/providers
/v1/regions
/v1/offers
/v1/reservations

/v1/plans
/v1/operations
/v1/events
/v1/logs:query
/v1/metrics:query
/v1/traces:query

/v1/billing/accounts/{account}/usage
/v1/billing/accounts/{account}/invoices
/v1/billing/accounts/{account}/budgets
```

`/gpus` is a discovery/filtering surface over accelerator capacity, not a second canonical instance database.

### 20.2 Example desired-state bundle

This example uses object storage, not a shared writable block volume.

```yaml
apiVersion: cloud.example/v1
kind: Application

metadata:
  name: api-production
  project: commerce-prod

spec:
  services:
    api:
      image: ghcr.io/example/api@sha256:IMAGE_DIGEST

      resources:
        vcpu: 4
        memory: 16GiB

      replicas: 3

      placement:
        region: us-east
        latencyCell: auto
        providerPool: verified-us
        minDistinctOperators: 3
        maxReplicasPerFacility: 1

      connections:
        objects:
          bucket: api-data
          permissions: [read, write]

      endpoint:
        protocol: https
        port: 8080
        healthCheck:
          path: /healthz

      recovery:
        mode: restart
        replacementWithinApprovedPolicy: true

  data:
    api-data:
      kind: Bucket
      class: standard
      access: private
      residency: US
      retentionPolicy: retain-on-application-delete

  economics:
    computeRateCeiling:
      amount: "0.20"
      currency: USD
      unit: replica-hour
    budgetRef: commerce-production
    repairOverlapCharge: platform
```

### 20.3 Plan and execution

```http
POST /v1/plans
Idempotency-Key: client-generated-key
Content-Type: application/json
```

Response:

```json
{
  "planId": "plan_123",
  "status": "FEASIBLE",
  "expiresAt": "2026-09-07T18:35:00Z",
  "changes": [],
  "quote": {
    "computeHourlyUSD": "0.54",
    "otherCharges": "itemized-separately"
  },
  "requiredApprovals": ["project-deploy"]
}
```

Execution:

```http
POST /v1/operations
Content-Type: application/json
```

```json
{
  "planId": "plan_123",
  "planHash": "sha256:...",
  "approvalRef": "approval_..."
}
```

Return `202 Accepted`, an operation ID, and an event-stream location.

Use `If-Match` for version-sensitive mutations. Errors include machine-readable reason, blocking constraints, retryability, and operation reference.

### 20.4 CLI

```bash
dcloud login
dcloud project use commerce-prod

dcloud init
dcloud plan -f cloud.yaml
dcloud apply --plan plan_123

dcloud services list
dcloud logs api --follow
dcloud events --operation op_123

dcloud placement inspect api --explain
dcloud placement simulate api --failure operator

dcloud usage --project commerce-prod --group-by service
dcloud export --project commerce-prod
```

The CLI defaults to interactive review. Automation requires explicit noninteractive approval or a preauthorized execution policy.

### 20.5 Developer integrations

| Integration       | Contract                                                                                                    |
| ----------------- | ----------------------------------------------------------------------------------------------------------- |
| SDKs              | Generated typed clients for TypeScript, Python, and Go; consistent retries and operation polling            |
| Terraform         | CRUD/import over canonical resources; async operation handling; protection against unintended data deletion |
| Kubernetes        | Qualified clusters plus controllers that map selected custom resources to cloud APIs                        |
| GitHub            | Repository app, scoped checkout, signed webhooks, isolated builds, deployment checks                        |
| CI/CD             | OIDC federation and short-lived deployment authority                                                        |
| Registry          | OCI pull/push, digest pinning, scoped pull credentials                                                      |
| Webhooks          | Signed payloads, event IDs, retries, delivery logs, replay window                                           |
| OpenTelemetry     | Standard ingestion and export with tenant-scoped authentication                                             |
| Local development | Manifest validation, mock connections, local environment generation                                         |

Never create a separate "AI-only" mutation API.
