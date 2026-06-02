# Stage 4 Fixes Applied

- Added `RuntimePolicyLeaseSnapshot` and related structs under the Rust runtime.
- Exposed effective policy lease state from `inspect_thread`.
- Preserved Auto-review versus Default permissions provenance instead of flattening both into `default-safe`.
- Kept deterministic code limited to policy/sandbox observation and validation; no product answers are authored by this layer.
