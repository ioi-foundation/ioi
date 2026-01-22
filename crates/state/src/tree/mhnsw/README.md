# Merkelized HNSW (mHNSW)

The **mHNSW** is a novel data structure that combines **Hierarchical Navigable Small World** (HNSW) graphs with **Merkle Trees**.

It provides **Verifiable Vector Search**.

## The Problem: Agency vs. Hallucination

In standard RAG (Retrieval-Augmented Generation), an agent queries a vector database (like Pinecone or Milvus) to find relevant context. However, for high-stakes autonomous agents, this introduces trust issues:
1.  **Omission:** Did the database hide the *most* relevant document?
2.  **Hallucination:** Did the database invent a document that doesn't exist?
3.  **Staleness:** Is this search result from an old version of memory?

## The Solution: Proof of Retrieval

The mHNSW creates a cryptographic commitment to the *entire graph structure*. Every node in the graph is hashed, and the hash includes the hashes of its neighbors.

### Node Structure

A node in the mHNSW commits to:
1.  **Vector:** The raw float embedding (e.g., 384 dimensions).
2.  **Payload:** The content hash or pointer (Frame ID).
3.  **Neighbors:** For each layer in the hierarchy, the sorted list of neighbor IDs.

```rust
Hash(Node) = SHA256(
    ID || Vector || Payload || 
    Hash(Layer0_Neighbors) || ... || Hash(LayerN_Neighbors)
)
```

This creates a Merkle-DAG. The "Root Hash" of the entry point node effectively fingerprints the entire index.

### Verifying a Search

When the Workload performs a search (e.g., "Find memories related to 'login'"), it returns two things:
1.  **Results:** The nearest neighbor nodes.
2.  **Traversal Proof:** A trace of the greedy search algorithm.

**Verification Logic:**
The verifier (Client or Validator) replays the search step-by-step:
1.  Start at the Entry Point (verified against the Root Hash).
2.  At each step, look at the neighbors provided in the proof.
3.  **Verify Distance:** Calculate the distance between the Query Vector and all neighbors.
4.  **Verify Greed:** Confirm that the next node chosen in the trace is indeed the one with the smallest distance.

If the search logic was followed honestly, the prover *must* arrive at the same result. If they omitted a closer neighbor, the distance check would fail or the neighbor list hash wouldn't match the committed node hash.