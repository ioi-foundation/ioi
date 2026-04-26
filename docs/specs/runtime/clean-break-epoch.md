# Clean-Break Runtime Epoch

Status: active cutover contract

This repository is moving to a clean runtime epoch. Compatibility shims, legacy product names, old serialized schema aliases, and runtime migrations that only preserve pre-epoch local state should be removed instead of extended.

## Active Vocabulary

Use these names for new active code and docs:

- chat/artifact runtime
- runtime kernel
- graph runtime
- workflow runtime
- runtime workbench
- projection trace
- settlement trace
- artifact promotion receipt

`Studio` is historical naming. It should not appear in active runtime APIs, commands, scripts, or product surface names after the cutover.

## Rejected Legacy Inputs

After this epoch, runtime code should reject rather than migrate:

- legacy graph command names such as `run_studio_graph`
- old graph node aliases such as `model` when `responses` is required
- old artifact fields such as `swarmPatchReceipts`
- trace projection aliases that export projection events as `receipts`
- unversioned Local Engine control-plane documents
- legacy tool aliases such as `sys_exec`
- deprecated PII string-target APIs

## Authority Rule

Compatibility parsing must not create executable authority. Model/tool output may be parsed into proposal material, but consequential execution requires a canonical runtime-kernel invocation envelope with policy, capability, deadline, and receipt obligations.

## State Reset Rule

If old local state cannot be loaded without a compatibility migration, fail closed with a deterministic reset/regenerate error. Do not silently revive old runtime shapes.

## Protocol Epoch Exception

Consensus and execution timing fields that mirror seconds and milliseconds are protocol-state concerns, not local runtime shims. Removing helpers such as `latest_timestamp_ms_or_legacy` and `timestamp_millis_to_legacy_seconds` requires an explicit chain/state epoch reset with replay fixtures. Until that branch lands, the compatibility semantics must remain isolated to consensus/execution protocol code and must not leak into chat/artifact runtime APIs.
