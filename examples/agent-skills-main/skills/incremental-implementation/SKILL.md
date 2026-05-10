---
name: incremental-implementation
description: Implement coding changes in narrow, verified slices with scoped edits and explicit handoff notes.
---

# Incremental Implementation

Use this skill when a workflow needs to move a codebase forward without widening the blast radius.

1. Identify the smallest coherent slice that creates user-visible progress.
2. Read the local patterns before changing files.
3. Keep edits scoped to the slice and avoid unrelated cleanup.
4. Validate the changed surface before moving to the next slice.
5. Record what changed, what passed, and any remaining blocker.
