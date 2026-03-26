# mHNSW Retrieval Verification Notes

Historical note: this document describes the retired certifying retrieval path
that used to sit behind the removed `SCS` crate. The lower-level `mHNSW`
structures still live in `crates/state`, but the product-memory crate and its
public benchmark harness were removed during the `ioi-memory` migration.

This document records the single-level certifying retrieval contract that was
implemented for IOI `mHNSW`.

All guarantees are scoped to the committed corpus/index state.

## Single-Level Contract: Certifying Retrieval

Every retrieval is executed in certifying mode.

Invariant:

1. retrieval MUST return top-k results produced under a deterministic policy
2. retrieval MUST emit a verifiable lower-bound certificate
3. retrieval MUST fail closed if certificate generation or verification fails

There is no optimistic Level 1/Level 2 split in this contract.

## Search Policy

`RetrievalSearchPolicy` controls retrieval behavior:

1. `k`
2. `ef_search`
3. `candidate_limit`
4. `distance_metric`
5. `embedding_normalized`

Defined in:
`crates/state/src/tree/mhnsw/proof.rs`

## Index Commitment Semantics

Implemented in:
`crates/state/src/tree/mhnsw/graph.rs` and `crates/state/src/tree/mhnsw/mod.rs`

1. `HnswGraph::index_root()` commits graph parameters and node hashes
2. `MHnswIndex::root_commitment()` returns index root commitment
3. `commit_version()` returns actual root hash (or hash of commitment bytes)
4. `verify_proof()` enforces key/value/proof/commitment consistency

## Certified Retrieval Flow

Historical implementation:
retired with the removal of the `SCS` crate

`VectorIndex::search_hybrid_with_certificate(...)` executes:

1. decode index payloads into `(frame_id, frame_type, visual_hash, vector)`
2. L2-normalize vectors and query for metric-consistent certificate math
3. build deterministic coarse quantizer partition over committed points
4. compute per-cluster lower bounds using triangle inequality
5. run branch-and-bound cluster traversal
6. score visited cluster members exactly and maintain strict top-k (distance then id tie-break)
7. build `LowerBoundCertificate`
8. verify `LowerBoundCertificate` against committed quantizer/index roots
9. return hits plus `CertifiedRetrievalProof`

If any step fails, retrieval fails.

## Lower-Bound Certificate Math

Historical implementation:
retired with the removal of the `SCS` crate

Metric contract:

1. lower-bound certificates are verified in L2 space
2. cosine retrieval uses normalized vectors so ordering is consistent with L2

Cluster bound:

`LB(cluster) = max(0, ||q-c||_2 - R)`

where:

1. `q` is query vector
2. `c` is cluster centroid
3. `R` is committed cluster radius

Let `d_k` be returned kth distance in L2. Retrieval is certifying when every pruned cluster satisfies:

`LB(cluster) >= d_k`

## Coarse Quantizer Commitment

Committed structures:

1. `CoarseQuantizerCluster`
   `cluster_id`, `centroid`, `radius_l2`, `member_count`, `membership_root`
2. `CoarseQuantizerManifest`
   `dimensions`, metric, normalization, cluster list, `quantizer_root`

`quantizer_root` commits metadata and sorted cluster summaries.

## Proof Structures

1. `RetrievalProof`
   traversal proof over mHNSW ANN traversal state
2. `CertifiedRetrievalProof`
   `LowerBoundCertificate`, `quantizer_root`, `visited_cluster_ids`, `candidate_count_total`

Historical implementation:
retired with the removal of the `SCS` crate

## Retrieval Receipt Contract

`WorkloadMemoryRetrieveReceipt` records:

1. query and index roots
2. policy params (`k`, `ef_search`, `candidate_limit`)
3. candidate counts and truncation flag
4. metric/normalization flags
5. proof pointer/hash
6. `certificate_mode = "single_level_lb"`
7. success/error classification

Defined in:

1. `crates/types/src/app/events.rs`
2. `crates/ipc/proto/public/v1/public.proto`
3. `crates/validator/src/standard/orchestration/grpc_public/events_handlers.rs`

## Historical Artifact Integration

Historical implementation:
retired with the removal of the `SCS` crate

1. `VectorIndex` stores optional coarse quantizer metadata
2. `VectorIndexArtifact` persists optional `coarse_quantizer`
3. `VectorIndexManifest` stores optional quantizer summary reference
4. `SovereignContextStore::commit_index(...)` writes quantizer summary into TOC manifest

## Historical Public API Surface

Historical implementation:
retired with the removal of the `SCS` crate

1. `VectorIndex::search_hybrid_with_certificate(...)`
2. `VectorIndex::set_coarse_quantizer(...)`
3. `VectorIndex::build_lower_bound_certificate(...)`
4. `VectorIndex::verify_lower_bound_certificate(...)`

## Test Coverage

Implemented tests cover:

1. traversal proof roundtrip and tamper rejection
2. deterministic candidate truncation semantics
3. quantizer commitment determinism
4. lower-bound certificate verification and invalid-bound rejection
5. artifact roundtrip persistence for coarse quantizer metadata
6. single-level certifying benchmark profiles

## Benchmark Harness

The old benchmark harness was removed together with the `SCS` crate during the
memory-runtime migration.

Datasets:

1. `best_case`: separated clusters (easy pruning)
2. `worst_case`: overlapping clusters (adversarial pruning)

Strategies compared:

1. exact brute-force scan
2. fixed-policy ANN (`search_with_policy`)
3. adaptive ANN (iterative `ef_search` / `candidate_limit` escalation)
4. certifying branch-and-bound (LB termination + certificate verification)

Gates (env-configurable):

1. `IOI_MHNSW_BENCH_MIN_BEST_SPEEDUP` (default `1.05`)
2. `IOI_MHNSW_BENCH_MAX_WORST_SLOWDOWN` (default `1.80`)

Invariant checks:

1. certifying strategy recall@k is exact (`>= 0.9999`)
2. certifying lower-bound gap is non-negative (within epsilon)
3. generated certificates verify against committed quantizer metadata
