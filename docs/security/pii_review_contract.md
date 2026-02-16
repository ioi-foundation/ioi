# PII Review Contract (Consensus-Critical)

## Scope
This document defines the deterministic review contract for PII-gated resume flows across:

- `desktop_agent` service state + execution
- validator ante checks (`firewall`)
- validator ingestion semantic prechecks

The contract is fail-closed and consensus-critical.

## State Keys (Desktop Agent Namespace)

- Request key: `pii::review::request::<decision_hash>`
- Scoped-exception usage key: `pii::review::exception_usage::<exception_id>`

Both keys are stored under `desktop_agent` service namespace.

## Request Schema

- Type: `PiiReviewRequest`
- Required version: `request_version = 3`
- Request must match expected CIM assist identity:
  - `assist_kind = "cim_v0"`
  - `assist_version = "cim-v0.1"`
  - `assist_identity_hash = expected_assist_identity().2`
- New requests must be persisted at the request key above.
- Requests failing version/identity checks are treated as invalid.

## Deterministic Invariants

1. Expected hash binding:
- `expected_request_hash = pending_gate_hash.unwrap_or(pending_tool_hash)`
- `approval_token.request_hash` must equal `expected_request_hash`

2. Request binding:
- For review-bound resumes, request must exist at `request::<expected_request_hash>`
- `request.decision_hash` must equal `expected_request_hash`

3. Deadline semantics:
- Valid if `now_ms <= deadline_ms`
- Invalid if `now_ms > deadline_ms` (reject fail-closed)

4. Action semantics:
- If request exists, `approval_token.pii_action` is mandatory
- If no request exists, `approval_token.pii_action` must be absent

5. Scoped-exception usage:
- Usage decode failures are invalid (fail-closed)
- Next usage must use checked increment (`checked_add`)
- Overflow is invalid (fail-closed)

6. Scoped-exception verification:
- `GrantScopedException` must map to pending decision hash
- Must verify deterministic destination/action binding
- Must satisfy low-severity-only eligibility rules
- Must respect policy gates and max-uses/expiry constraints

## Resume Action Matrix

`ApproveTransform`
- Requires review request + valid deadline + matching hash
- Sets deterministic transform-enabled behavior for this resume evaluation
- Continues execution through transform-first enforcement

`Deny`
- Requires review request + valid deadline + matching hash
- Marks gate denied
- Fails current step closed (pending action not executed)

`GrantScopedException`
- Requires review request + valid deadline + matching hash
- Requires deterministic scoped-exception verification
- Consumes one monotonic usage
- Allows only scoped eligible raw override path

## Failure-Closed Conditions

Resume must reject on any of:

- hash mismatch
- missing request for review-bound token
- missing `pii_action` for request-bound resume
- unsupported request version
- assist kind/version/identity mismatch
- deadline exceeded
- invalid scoped-exception usage state decode
- usage overflow
- scoped-exception verification failure (policy/binding/eligibility/expiry/overuse)

## Parity Requirement

The same deterministic rule set is enforced in:

- `crates/services/src/agentic/desktop/service/actions/resume.rs`
- `crates/validator/src/firewall/mod.rs`
- `crates/validator/src/standard/orchestration/ingestion.rs`
