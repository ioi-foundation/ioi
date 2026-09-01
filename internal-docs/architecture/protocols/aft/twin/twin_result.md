# Clean-Room Twin Result — UBC Seal-Share Verifier (AFT-CB P4.5b)

Status: completed internal in-session twin result; non-canonical.
Authority: AFT canonical owners and accepted ADRs win on drift; this result is
not an external audit, neutral certification, or independent adoption proof.

**Provenance label (owner ruling, verbatim scope): in-session clean-room
twin. Establishes specification clarity and vector agreement. NOT an
external audit, independent peer review, public adversarial validation,
or organizationally-independent implementation.**

## Setup

A fresh-context implementer was given `seal_share_verifier_spec.md` and
`conformance_vectors.json` and NO access to the Rust reference
(`crates/validator/src/common/guardian/seal_signer.rs`). It produced an
independent Go implementation (`clean_room_twin.go`) using only Go's
standard `crypto/ed25519`. The vectors themselves are exported from the
reference by a generator test that self-checks reference agreement, so
the twin is compared against the reference's actual verdicts, not against
hand-authored expectations.

## Result: full agreement

| Group | Vectors | Twin outcome |
|---|---|---|
| accept | 6 | 6/6 accepted |
| reject | 3 (`flipped_sig`, `wrong_hash`, `wrong_index`) | 3/3 rejected |
| extraction | `cert_x` × `cert_y` | offenders `[0, 1]` == expected |

Exit code 0. No accept vector rejected; no reject vector accepted; the
double-signer extraction returned exactly the expected offender set.

## Findings

1. **The scheme is standard RFC 8032 Ed25519.** The twin verified all six
   accept signatures with Go's stock `crypto/ed25519` — no bespoke
   variant, no Ed25519ph/ctx, no custom cofactor handling was needed.
   This is a genuinely useful, independently-checkable fact for any
   later external review: the load-bearing signature check is a standard
   primitive, so its security rests on RFC 8032, not on estate-specific
   crypto.

2. **The message layout in §2 is unambiguous enough to reproduce.** The
   twin built the 59-byte `domain-tag ‖ seal_index(BE64) ‖ seal_hash`
   message and matched on every accept AND on the `wrong_index` reject
   (which only fails if the big-endian seal_index binding is exactly
   right). Byte order and field order were reproduced without a
   disagreement.

3. **The extraction rule in §5 is unambiguous enough to reproduce.** Same
   `member_index` + same `seal_index` + different `seal_hash` → offender;
   sorted, de-duplicated. Reproduced exactly.

4. **One specification gap, non-exercised, now closed.** §4 step 1 named
   malformed-length rejects for `public_key` and `signature` but was
   silent on a malformed-length `seal_hash`. The twin inferred the reject
   from §2.3 (`seal_hash` is fixed at 32 bytes) and it did not affect
   conformance (no vector exercises a malformed `seal_hash`). Per the
   spec's own §7 discipline, the text — not the code — was corrected: §4
   now states the `seal_hash` length reject explicitly. This is a clarity
   fix, not a behavior change.

## What this closes and does not close

- **Closes (P4.5b's stated purpose):** the seal-share verifier spec is
  clear enough that an independent implementer reproduces it exactly, and
  the reference's behavior on the conformance set is reproducible from a
  standard-library Ed25519 implementation. The one latent ambiguity found
  is now removed.
- **Does NOT close:** organizational independence, external audit, or any
  gate that requires an out-of-session party. Those remain owner-order,
  non-loop items and are unaffected by this result.
