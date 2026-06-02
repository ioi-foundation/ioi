# Stage 4 Failure Analysis

No functional failure was reproduced in this support slice.

The discovered gap was observability: clients could not inspect policy lease state, and bridge runtime controls collapsed Auto-review/Default permissions provenance. That made daemon ownership hard to prove even when policy enforcement existed.

Remaining failure-prone areas are intentionally left open for live proof:

- signed allow-once approval grant consumption and expiry
- operator denial and revocation UX
- symlink/sibling/ignored-file sandbox effect probes
- default network denial and redacted output probes
