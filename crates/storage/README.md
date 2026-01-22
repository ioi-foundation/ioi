# IOI Persistent Storage Layer

This crate implements the durable storage backend for the IOI Kernel. It is responsible for persisting the state tree nodes, block history, and transaction receipts.

The implementation uses **`redb`**, a pure-Rust embedded database similar to LMDB but with ACID guarantees and safety.

## The Performance Challenge

In a high-throughput blockchain, the "Commit" phase is often the bottleneck.
1.  **Merkle Re-hashing:** Updating the state tree generates thousands of new nodes.
2.  **Indexing:** Inserting these nodes into a B-Tree (redb) involves complex rebalancing and disk IOPS.
3.  **Latency:** If the consensus loop waits for the B-Tree index to settle, block times explode.

## The Solution: Decoupled WAL (`src/wal.rs`)

The IOI Storage layer implements a **Write-Ahead Log (WAL)** that decouples durability from indexing.

### 1. Fast Path (Synchronous)
When `commit_block` is called:
1.  The `StateDiff` (list of new nodes + deleted keys) is serialized.
2.  The diff is appended to the **Append-Only WAL File**.
3.  An `fsync` is issued to flush the OS buffers to disk.
4.  **ACK:** The function returns immediately. The block is durable.

### 2. Slow Path (Asynchronous)
A background thread (`redb_epoch_store.rs`) continuously polls the memory buffer:
1.  It reads the committed `StateDiff`.
2.  It opens a `redb` write transaction.
3.  It inserts the nodes into the complex B-Tree tables (`NODES`, `VERSIONS`, `CHANGES`).
4.  It commits the `redb` transaction.

### Benefits
*   **Low Latency:** Block commit time is proportional to `Write_Bytes / Disk_Speed`, effectively independent of database size.
*   **Crash Safety:** If the node crashes before the background thread finishes, the `redb` index is stale. However, on restart, the node replays the WAL to restore the in-memory state and resumes indexing, ensuring zero data loss.
*   **Throughput:** By batching multiple blocks into a single `redb` transaction in the background, we amortize the B-Tree rebalancing cost.

## WAL Compaction
The WAL grows indefinitely. A compaction process runs periodically to:
1.  Check which blocks have been fully indexed into `redb`.
2.  Truncate the WAL, removing entries older than the last indexed height.