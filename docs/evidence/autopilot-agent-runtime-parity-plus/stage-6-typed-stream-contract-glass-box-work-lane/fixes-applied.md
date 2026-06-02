# Stage 6 Fixes Applied

- Added `ioi.runtime.event.product_projection.v1` to runtime bridge events.
- Added `payload_summary` to kernel-derived and bridge-authored typed events.
- Marked full event payloads with `payload_detail_visibility: runs_tracing`.
- Added source-ref extraction for safe product/source-chip projections.
- Added focused Rust tests proving safe projection boundaries and bridge event constructor coverage.
