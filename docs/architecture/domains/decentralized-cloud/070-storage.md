# 070 — Storage: classes, hot storage foundation, object, block, Filecoin archive, encryption, managed databases

**Spec section:** 14. **Depends on:** 010, 040, 090, 190. **Defines:** object, block,
filesystem, archive, replication, and deletion semantics; storage APIs,
attachment/fencing contract, archive manifest. **Required diagrams:** storage cells,
write path, repair, archive restore.

> **Estate note (ADR 0001 §2):** the estate's CAS archive plane sits behind the archive
> contract in 14.5; the hot tier in 14.2 is a new foundation.

## 14. Storage

### 14.1 Selected storage classes

| Class             | Implementation                                                      | Semantics                                                | Recovery                                   |
| ----------------- | ------------------------------------------------------------------- | -------------------------------------------------------- | ------------------------------------------ |
| Scratch           | Provider-local disk/NVMe                                            | Ephemeral; no persistence guarantee                      | Recreate                                   |
| Local Persistent  | Provider-local retained volume                                      | Survives supported restarts, not arbitrary provider loss | Backup/restore only                        |
| Replicated Block  | Qualified storage cell using replicated block service               | Single-writer by default; locality constrained           | Fence, reattach, or restore                |
| Shared Filesystem | Qualified filesystem service                                        | Explicit POSIX/multi-writer contract                     | Service-specific recovery                  |
| Standard Object   | Replicated hot object service                                       | Published S3-compatible API subset                       | Survives admitted storage-operator failure |
| Archive           | Encrypted immutable versions on archival/warm decentralized storage | Retrieval may require a job; retention is explicit       | Restore to hot tier                        |
| Cache             | Reconstructible local/regional copies                               | Not authoritative                                        | Refill                                     |

### 14.2 Hot storage foundation

Build Standard Object and Replicated Block on **platform-operated storage cells using dedicated infrastructure from qualified operators**.

Select Ceph as the initial storage engine:

* RADOS Gateway for object access.
* RBD for block volumes.
* CephFS for a later shared-filesystem product.

Ceph publishes separate object and block interfaces; its S3 compatibility is a documented API surface rather than an assertion that every AWS S3 behavior is identical. Its replicated pools also expose explicit replica and minimum-I/O settings. ([Ceph Documentation][5])

The platform's selected Standard profile is:

```text
Three storage copies
Three qualified operator/facility failure domains
Minimum two copies for continued protected I/O
Quorum-protected storage metadata
No automatic reduction to one-copy operation
Independent backup/export path
```

This is admitted only inside tested latency cells. It is not a worldwide Ceph cluster stretched across arbitrary providers.

### 14.3 Object behavior

Publish and test a compatibility matrix covering:

```text
PUT / GET / HEAD / DELETE
ListObjectsV2
Range reads
Multipart upload
Versioning
Presigned access
Lifecycle transitions
Conditional operations supported by the chosen release
```

The product contract defines consistency per operation. Unsupported behavior returns an explicit error.

The resource registry owns bucket configuration and policy. The storage engine owns the operational object namespace. Archive manifests and backup metadata are retained outside the sole failure domain of the live storage cell.

### 14.4 Block and filesystem behavior

A block volume declares:

```text
capacity
storage cell
performance class
attachment mode
current writer
fencing generation
snapshot policy
recovery point objective
```

A single-writer block volume cannot be attached read-write to three independent API replicas.

RBD exclusive-lock and blocklisting mechanisms are useful building blocks, but the cloud's attachment controller must still coordinate ownership and fencing. Do not mistake possession of a volume reference for permission to write. ([Ceph Documentation][6])

### 14.5 Filecoin integration

Initially, use Filecoin-backed services for encrypted immutable archive/export copies. Keep the active application read/write path on the hot storage tier.

The adapter records:

```text
object version or dataset manifest
ciphertext content references
provider/data-set or deal references
proof observations
retention obligation
retrieval endpoints
retrieval test results
payment references
```

Current Filecoin documentation describes warm storage, proof of data possession, payment rails, and retrieval infrastructure. These may qualify for additional service classes after testing, but possession evidence alone does not establish the platform's required end-to-end latency or application availability. ([Filecoin Documentation][7])

### 14.6 Encryption and deletion

Encrypt tenant objects before placing archive copies on external providers. Use tenant-scoped envelope keys; retain key-recovery metadata separately from a single storage supplier.

Server-side encryption does not automatically protect plaintext from every operator involved in a normal, non-confidential compute path.

Deletion distinguishes:

```text
Logical object deletion
Version-retention expiry
Live replica removal
Archive-contract expiry
Key destruction where applicable
```

Do not promise immediate physical erasure from immutable or independently retained storage.

### 14.7 Managed databases

Run PostgreSQL on qualified nodes in a tested latency cell, with engine-level replication, backups, and a separate consensus/fencing mechanism.

Use strict synchronous durability for the protected tier and promote only a standby eligible under that durability contract. PostgreSQL and Patroni document the distinction between synchronous replication and configurations that may continue without a synchronous standby. ([PostgreSQL][8])

The contract must state which commits qualify as durable, including the effect of client-selected durability overrides.

If the old primary cannot be safely fenced or promotion safety cannot be established, stop automatic promotion and surface **Write availability blocked to protect data**.

[5]: https://docs.ceph.com/en/latest/radosgw/s3/
[6]: https://docs.ceph.com/en/reef/rbd/rbd-exclusive-locks/
[7]: https://docs.filecoin.io/build-on-filecoin/filecoin-onchain-cloud
[8]: https://www.postgresql.org/docs/current/warm-standby.html
