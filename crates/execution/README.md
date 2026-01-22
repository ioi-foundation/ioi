# IOI Execution Engine

The `ioi-execution` crate implements the state transition logic of the blockchain.

While traditional EVM chains process transactions sequentially (one after another), the IOI Kernel utilizes an **Optimistic Parallel Execution** engine inspired by **Block-STM** (Software Transactional Memory). This allows non-conflicting transactions (e.g., two different agents paying two different providers) to execute simultaneously on different CPU cores, significantly increasing throughput.

## Parallel Execution Architecture

The parallel engine is composed of two primary internal components working in tandem: **Multi-Version Memory** and the **Scheduler**.

### 1. Multi-Version Memory (`src/mv_memory.rs`)

**MVMemory** is the ephemeral, in-memory storage layer used during the execution of a block. It replaces the standard "World State" trie during the parallel phase.

*   **Versioned Storage:** Instead of storing `Key -> Value`, it stores `Key -> List<(TxIndex, Value)>`.
*   **Optimistic Reads:** When Transaction #5 reads key `A`, it searches the list for the write with the highest index $i < 5$. If found, it reads that speculative value. If not, it falls back to the committed storage (Base State).
*   **Recording Read Sets:** Every read operation is recorded. This "Read Set" is later used by the validation phase to detect conflicts.
*   **Writes:** Writes are inserted into the version list. If Transaction #3 writes to key `A` *after* Transaction #5 has already read it, Transaction #5's read is now invalid (phantom read).

### 2. The Scheduler (`src/scheduler.rs`)

The **Scheduler** orchestrates the worker threads. It ensures that transactions are processed in an order that converges to the same result as sequential execution.

*   **Task Dispatch:** Worker threads ask the scheduler for the next task. The scheduler prioritizes tasks in this order:
    1.  **Validation:** Check if a previously executed transaction is still valid given recent writes.
    2.  **Execution:** Run a transaction that hasn't been executed yet.
*   **Incarnations:** If validation fails for Transaction #N (because a lower-index transaction modified its input), the scheduler **aborts** it. Transaction #N enters a new "Incarnation" and is re-queued for execution.
*   **Dependency Handling:** The scheduler manages the "watermark" of completed transactions. Once all transactions up to index $N$ are validated, the block prefix $0..N$ is considered final.

## The Execution Flow

1.  **Prepare:** The `ExecutionMachine` initializes the `MVMemory` (snapshot of state) and the `Scheduler`.
2.  **Spawn:** A thread pool is spawned matching the number of available CPU cores.
3.  **Loop:** Each thread grabs a task (Execute or Validate) from the Scheduler.
    *   **Execute:** Runs the VM. Writes go to `MVMemory`. Reads are logged.
    *   **Validate:** Re-reads the Read Set from `MVMemory`. If values match the initial read, success. If mismatch, abort.
4.  **Commit:** Once all transactions are validated, the `MVMemory` is flushed to the canonical State Tree (`IAVL` or `Jellyfish`) in a deterministic batch.