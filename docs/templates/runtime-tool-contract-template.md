# Runtime Tool Contract Template

Use this template when adding or changing a runtime tool. The implementation must project into `RuntimeToolContract`, emit receipts, and pass policy before any effectful action.

## Identity

- Stable tool id:
- Display name:
- Owning module:
- Surface adapters:
- Effect class:
- Risk domain:

## Inputs

- JSON schema:
- Required fields:
- Redacted fields:
- Read-before-write requirements:
- Stale-state guards:
- Device, symlink, and path boundary handling:

## Authority

- Policy target:
- Approval required:
- Approval scope fields:
- Denial behavior:
- Cancellation behavior:
- Production fail-closed behavior:

## Execution

- Timeout default:
- Timeout maximum:
- Concurrency class:
- Retry policy:
- Dry-run preview:
- Postcondition checks:

## Receipts

- Receipt kind:
- Required receipt fields:
- Evidence refs:
- Redaction proof:
- Replay reconstruction fields:
- Failure class and recovery suggestion:

## Validation

- Unit tests:
- Integration tests:
- Golden event or receipt test:
- CLI/API/UI/harness/compositor coverage:
- Scorecard dimensions covered:

