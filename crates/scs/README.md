# Sovereign Context Substrate (SCS)

The **Sovereign Context Substrate (SCS)** is the high-performance, verifiable memory storage engine for IOI Agents. It serves as the agent's "Hard Drive," storing a timeline of observations, thoughts, and actions.

Unlike a standard database or filesystem, the SCS is designed for **Proof of Recall**. It ensures that when an agent retrieves a memory (e.g., "What did I see 5 minutes ago?"), it can cryptographically prove that the data is authentic and that the search process was not manipulated.

## The `.scs` File Format

The SCS uses a custom binary format optimized for append-only writes and zero-copy reads via memory mapping.

### Binary Layout

The file is structured as a log. New data is appended to the end, and the Table of Contents (TOC) is moved forward.

```text
[  Header (64 bytes)  ]  <-- Fixed size. Contains offset to current TOC.
+---------------------+
|      Frame #0       |  <-- Raw Payload (e.g., PNG image bytes)
+---------------------+
|      Frame #1       |
+---------------------+
|         ...         |
+---------------------+
|      Frame #N       |
+---------------------+
|  Vector Index Seg   |  <-- Serialized mHNSW Artifact (Periodic snapshots)
+---------------------+
|  Table of Contents  |  <-- Serialized Metadata for all Frames + Index
+---------------------+
```

### Components

1.  **Header:**
    *   Contains the **Magic Bytes** (`IOI-SCS!`) and version info.
    *   Stores the `toc_offset`. When the file is opened, the reader jumps here to load the index.

2.  **Frames:**
    *   The atomic unit of memory.
    *   **Payload:** The raw data (Observation, Thought, or Action).
    *   **Metadata:** Block height, timestamp, and a checksum.
    *   **mHNSW Root:** Each frame is stamped with the root hash of the vector index at the moment of capture. This binds the *data* to the *state of memory*.

3.  **Table of Contents (TOC):**
    *   A list of `Frame` metadata structs.
    *   Since payloads are stored raw in the body, the TOC remains small and fast to load.
    *   **Append Operation:** To add a frame, we overwrite the old TOC with the new Frame data, write a new TOC after it, and update the Header pointer.

## Usage

```rust
let store = SovereignContextStore::open("memory.scs")?;

// 1. Zero-Copy Read
// Returns a slice &[u8] pointing directly to mmapped memory.
let image_data = store.read_frame_payload(frame_id)?; 

// 2. Append (Atomic)
store.append_frame(
    FrameType::Observation, 
    &new_data, 
    block_height, 
    current_index_root
)?;
```