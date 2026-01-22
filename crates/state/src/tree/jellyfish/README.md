# Jellyfish Merkle Tree (JMT)

The **Jellyfish Merkle Tree (JMT)** is the high-performance state backend for the IOI Kernel, optimized for the high-throughput requirements of an AI-centric blockchain.

While IAVL (used in Cosmos) is a self-balancing binary tree, JMT is a **LSM-Tree backed Sparse Merkle Tree**. It decouples the logical tree structure from the physical storage layout, allowing it to leverage the raw speed of the underlying KV store (`redb` or RocksDB).

## Key Features

1.  **Nibble-Based Addressing:**
    *   The tree is a base-16 (hexary) radix tree. Keys are hashed into 32 bytes (64 nibbles).
    *   Traversal follows the nibbles of the key hash. This makes path lengths predictable and reduces the height of the tree compared to binary trees (height $\log_{16} N$ vs $\log_2 N$).

2.  **Compact Proofs:**
    *   Unlike IAVL, JMT does not store rebalancing metadata (height/size) in every node.
    *   Internal nodes only store the 16 children hashes.
    *   Proof size is significantly smaller, critical for IBC and light client verification.

3.  **Parallel Hashing:**
    *   JMT is designed for **batch updates**. When a block is committed, the changes are applied as a sorted batch.
    *   The tree hashing algorithm (`tree.rs`) uses `rayon` to compute sub-tree hashes in parallel.
    *   This removes the "Merkle Root Calculation" bottleneck common in sequential blockchains.

4.  **Versioned Storage:**
    *   JMT nodes are immutable. When a node changes, a new version is written.
    *   This supports **Time-Travel Queries**: You can query the state at any previous block height without archiving or re-syncing.

## Node Structure (`node.rs`)

*   **`InternalNode`**: Contains a sparse array of up to 16 children hashes.
*   **`LeafNode`**: Contains the full Key Hash and the Value Hash.
*   **`NullNode`**: Represents an empty subtree.