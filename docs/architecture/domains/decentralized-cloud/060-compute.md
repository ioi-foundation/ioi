# 060 — Compute: services, jobs, VMs, GPU execution, packaging, runtime compatibility, recovery

**Spec section:** 13. **Depends on:** 030, 040, 080, 090. **Defines:** runtime
profiles, deployment bundle, attempt lifecycle. **Required diagrams:** four-layer
mapping, rollout, checkpoint recovery.

## 13. Compute

### 13.1 Four-layer mapping

| User abstraction | Control-plane abstraction                  | Provider contract                     | Native implementation                                      |
| ---------------- | ------------------------------------------ | ------------------------------------- | ---------------------------------------------------------- |
| Service          | Replica slots and rollout                  | `RunContainer`                        | Provider Kubernetes workload, direct runtime, supported VM |
| Function         | Request-activated Service profile          | Fast startup and isolation capability | Qualified function runtime; later phase                    |
| Job              | JobRun and attempts                        | `RunBatch`                            | Container job or dedicated allocation                      |
| VM               | ComputeInstance                            | `CreateVM`                            | KVM/cloud API/provider VM                                  |
| GPU endpoint     | Service + ModelVersion + accelerator claim | `RunGPU`                              | GPU container or qualified GPU VM                          |
| Training run     | Gang-scheduled JobRun                      | Accelerator topology reservation      | Single-node or qualified fabric-connected group            |
| Cluster          | Managed control plane + node pools         | Node lifecycle and network profile    | Qualified VMs/bare metal                                   |
| Bare metal       | Dedicated ComputeInstance                  | Exclusive node lease                  | Provider-operated machine under agreed controls            |

### 13.2 Runtime profiles

Define versioned profiles:

```text
container-standard
container-service-connect
vm-routed
gpu-container
gpu-vm
gpu-confidential
batch-interruptible
baremetal-dedicated
```

A provider implements a profile only after passing conformance tests.

An OCI-compatible image does not automatically imply compatible networking, GPU drivers, storage attachment, isolation, or kernel behavior.

Pin:

```text
CPU architecture
image digest
runtime profile
GPU model and form factor
usable accelerator memory
GPU count and partition mode
driver/runtime compatibility
interconnect topology
network profile
storage locality
```

### 13.3 Deployment packaging

For simple applications, produce a signed deployment bundle containing:

```text
application image digest
optional platform supervisor/proxy digest
resource limits
health checks
service connections
identity binding
telemetry configuration
recovery policy
```

Where a provider cannot inject a sidecar or configure networking, support a documented portable supervisor package only with customer consent. The derived image digest and added platform components are visible in the plan.

Do not silently modify a customer's signed image.

### 13.4 GPU placement

GPU scheduling uses qualified compatibility sets, not product-name ordering.

For multi-GPU workloads, the placement request specifies whether devices must share:

* A host.
* A high-bandwidth accelerator fabric.
* An RDMA-capable network group.
* A driver and runtime compatibility profile.

Do not schedule tightly coupled tensor-parallel training across arbitrary Internet-connected providers.

### 13.5 Recovery

Default recovery mechanisms:

| Workload              | Recovery mechanism                                                |
| --------------------- | ----------------------------------------------------------------- |
| Stateless service     | Restart elsewhere and rejoin endpoint                             |
| Batch inference       | Retry idempotent work units using persistent inputs/outputs       |
| Training              | Restore application checkpoint                                    |
| VM                    | Recreate from image and retained data; optional snapshot recovery |
| Database              | Engine-specific replication and safe failover                     |
| GPU process migration | Optional qualified profile, never universal default               |

NVIDIA's current checkpoint tooling includes migration-related capabilities, but also documents unsupported memory cases and checkpoint/restore limitations. Therefore, use application-level checkpoints as the baseline portability contract and qualify transparent process migration separately by exact software/hardware profile. ([GitHub][4])

### 13.6 Worked full-stack application

This is a Phase 2 deployment:

| Component                         | Selected placement                                                        |
| --------------------------------- | ------------------------------------------------------------------------- |
| Next.js static assets             | CDN/edge distribution                                                     |
| Next.js server-rendered component | Managed Service on qualified compute                                      |
| Node API                          | Three replicas across eligible independent operators                      |
| PostgreSQL                        | Three-member managed database topology in one qualified latency cell      |
| Redis-compatible cache            | Co-located managed cache; explicitly non-authoritative where possible     |
| Object storage                    | Standard hot replicated bucket                                            |
| Archive                           | Encrypted object versions exported to Filecoin-backed storage             |
| H100 inference                    | Two qualified GPU service replicas, each sized for admitted failover load |
| DNS/TLS                           | Platform-managed endpoint and certificate                                 |

The API, database, and cache are placed for measured locality. The GPU endpoint may be elsewhere only if the application's latency policy permits it.

When one compute provider disappears, ingress removes its API replica, surviving inference capacity continues serving, and replacement allocations are acquired. If the lost provider also hosted a database member, database recovery follows its separate fencing and promotion rules.

The application retains its domains, service IDs, bucket, model version, logs, and deployment history.

[4]: https://github.com/NVIDIA/cuda-checkpoint
