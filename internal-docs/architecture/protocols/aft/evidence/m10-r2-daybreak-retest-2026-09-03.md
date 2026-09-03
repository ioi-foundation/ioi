# AFT M10 R2 independent remediation retest

> **Automated review only.** The reviewer was an owner-commissioned,
> context-isolated OpenAI Codex agent using `gpt-daybreak-blue-latest`. This is
> not human peer review, professional assurance, cryptographic certification,
> or a signed Gate-15 report.

## Immutable target

- Tag: `aft-pq-v1-review-candidate-r2-2026-09-03`
- Annotated tag object: `4b93f0f1eb495ad69fb6288c238d81f90abfdb75`
- Commit: `3ce40fca41b5303f10205cff47b15df90573acdb`
- Review clone: `/tmp/ioi-m10-r2-audit.FGWZ0r/audit`
- Shared checkout edits: none

The reviewer stated that it did not author the candidate, selected its attack
method independently, received no instruction to suppress findings, and had no
known organizational or financial conflict.

## Disposition

`FAIL / REPAIR_REQUIRED`

No critical or high finding remained open. Two medium findings blocked Gate
15, and the isolated four-validator fixture did not reach its terminal
checkpoint before the reviewer was instructed to stop.

## Prior findings

| ID | R2 state | Evidence |
|---|---|---|
| `AFT-M10-001` | Closed | The tracked clean-room verifier, committed goldens, clean-clone execution, complete receipt, and seven validly re-enveloped negatives ran. |
| `AFT-M10-002` | Closed by claim correction | Production correctly authorizes from pre-consequence runtime-v3 evidence; the completed portable receipt is post-consequence evidence and cannot non-circularly authorize the same effect. |
| `AFT-M10-003` | Signer defect closed; integrated retest incomplete | The isolated build includes `ioi-signer`; four encrypted signer processes and a full-mesh four-validator cluster were observed. |
| `AFT-M10-004` | Closed | The V1 key store validates every suite parameter, consumes salt/nonce, zeroizes the KEK, and refuses header mutations. |
| `AFT-M10-005` | Closed within stated scope | Production ML-DSA, KEM, shared-secret, record-key, and validator serialization paths use zeroizing storage or explicit erasure. |
| `AFT-M10-006` | Open, medium | A failed strict-PQ replacement left `pq_channels == None`, which also enabled classical consensus gossip/direct relay. |

## New finding

### `AFT-M10-007`: clean-room schema and full-vector disagreement

Severity: medium. The Python verifier did not recursively reject unknown
fields and checked selected `claimed_achieved` coordinates rather than deriving
and comparing the complete vector. The reviewer created a fresh independently
allowed ML-DSA envelope, recomputed the canonical receipt hash, and showed that
Python accepted both:

1. an unknown signed top-level field; and
2. a false `claimed_achieved.constituent_hashes` value.

The Rust verifier rejected the same receipt/trust pairs for an unknown field
and a derived-vector mismatch respectively.

Required repair: close every typed receipt/trust object schema, independently
derive the complete `GuaranteeVectorV1`, compare it exactly (including roots,
theorem IDs, assumptions, profiles, nullable coordinates, and collateral), and
retain both attacks as permanent validly re-enveloped negatives.

## Reproduced results

| Check | Result |
|---|---|
| Format and diff checks | Pass |
| Theorem assumptions | Pass, 28 blocks |
| Claim discipline | Pass |
| Production authorization | Pass, one modeled mutation owner |
| Formal census | Pass, 44 modules: 31 executable plus 13 manual |
| `ioi-crypto --lib` | Pass, 64/64 |
| `ioi-networking --lib` | Pass, 14/14 |
| Exact validator feature suite | Pass, 260/260 |
| PQ interoperability | Pass for bidirectional deterministic ML-DSA-44 and SLH-DSA-SHA2-128s |
| Portable-assurance suite | Pass, 5/5 |
| Python complete receipt and seven negatives | Pass before differential attacks |
| Agentgres consequence suite | Pass, 12/12 |
| Four-validator hash-fallback fixture | Incomplete, interrupted after 911.36 seconds |

Before interruption the four-validator run built the isolated node profile,
launched four signer processes, reached full-mesh readiness, advanced through
height 3, staged height 4, and exchanged scoped timeout votes through view 3.
It did not demonstrate height 5, the virtual-block decision, restart, or
post-restart height 7. Exit 130 is therefore recorded as incomplete, not as a
protocol failure.

## Limits

The review did not establish human or institutional review, provider
correctness, side-channel resistance, adaptive-corruption security,
shared-filesystem anti-snapshot custody, arbitrary-network delivery, or
at-most-once semantics outside the modeled atomic idempotency-register
resource.

Gate 15 remained closed at R2 pending remediation and immutable retest of
`AFT-M10-006`, `AFT-M10-007`, and the integrated release artifact.
