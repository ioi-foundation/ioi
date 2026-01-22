# GUI Driver ("Eyes & Hands")

This module provides the IOI Kernel with the ability to perceive and interact with the host operating system's graphical user interface. It serves as the physical interface for "Self-Driving" desktop agents.

## Components

### 1. Vision (`vision.rs`)
*   **Capture:** Uses `xcap` to capture screenshots of the active display.
*   **Format:** Returns raw PNG bytes.
*   **Privacy:** These bytes are fed into the **Semantic Scrubber** before ever leaving the device or being stored in the SCS.

### 2. Accessibility (`platform.rs`)
*   **Tree Parsing:** Uses platform-specific APIs (via `accesskit` or native stubs) to read the UI Accessibility Tree (DOM).
*   **Semantic Filtering:** The raw tree is too large for an LLM context window. The driver applies heuristics (`accessibility.rs`) to prune irrelevant nodes (invisible elements, empty containers) and produces a compact XML representation.

### 3. Action Injection (`operator.rs`)
*   **Input Simulation:** Uses `enigo` to simulate hardware events (Mouse Move, Click, Scroll, Key Press).
*   **Atomic Vision Lock:**
    *   *The Problem:* The screen might change between the time the agent "sees" a button and the time it clicks it (TOCTOU race condition).
    *   *The Solution:* The `Click` event includes an `expected_visual_hash`. The driver takes a fresh screenshot, computes a Perceptual Hash (pHash), and compares it to the expected hash. If the Hamming distance is too high (screen changed significantly), the click is aborted to prevent accidental mis-clicks.