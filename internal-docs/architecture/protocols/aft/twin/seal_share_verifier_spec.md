# Seal-Share Verifier — Specification for an Independent Implementation

Status: retained internal twin-input specification; non-canonical.
Authority: AFT canonical owners and accepted ADRs win on drift; this file is
evidence of the frozen in-session packet, not a public protocol owner.

**AFT-CB P4.5b. This document specifies the UBC seal-share verifier and
the double-signer extraction procedure with enough precision that an
independent implementation, written from THIS document and the
conformance vectors ALONE (no access to the reference source), agrees on
every vector. Agreement is evidence about the specification's clarity;
disagreement is a specification-ambiguity finding to be adjudicated
against this text.**

The seal-share verifier is the smallest surface whose correctness carries
uniqueness (T1) and forensic attribution (T7): a Unanimous Boundary Close
is an n-of-n bundle of these shares, and the extraction procedure names
every double-signer of a conflicting pair from the shares alone.

## 1. Objects

A **seal share** has five fields:

| Field | Type | Encoding in the vectors |
|---|---|---|
| `member_index` | unsigned 32-bit integer | JSON number |
| `seal_index` | unsigned 64-bit integer | JSON number |
| `seal_hash` | 32 bytes | lowercase hex, 64 chars |
| `public_key` | 32 bytes (an Ed25519 public key) | lowercase hex, 64 chars |
| `signature` | 64 bytes (an Ed25519 signature) | lowercase hex, 128 chars |

## 2. The signed message (domain-separated tuple)

A share's signature is over a message constructed by concatenating, in
this exact order, with no separators or length prefixes:

1. the **domain tag**: the ASCII bytes of the string `aft::seal-share::v1`
   (exactly 19 bytes: `61 66 74 3a 3a 73 65 61 6c 2d 73 68 61 72 65 3a 3a 76 31`);
2. the `seal_index` encoded as an **8-byte big-endian** unsigned integer;
3. the `seal_hash` (the 32 raw bytes).

So the message is 19 + 8 + 32 = 59 bytes. Nothing else is included — not
`member_index`, not `public_key`.

## 3. Signature scheme

**Ed25519 as specified in RFC 8032** (the standard, pure Ed25519 — not
Ed25519ph, not Ed25519ctx). The `public_key` is a 32-byte Ed25519 public
key; the `signature` is a 64-byte Ed25519 signature. Verification is the
standard RFC 8032 verify over the 59-byte message of §2.

## 4. `verify_seal_share(share) -> accept | reject`

1. Decode `public_key` (must be exactly 32 bytes), `signature` (must be
   exactly 64 bytes), and `seal_hash` (must be exactly 32 bytes). A
   malformed length in ANY of the three is a **reject**. (The `seal_hash`
   length rule was made explicit here after the in-session clean-room
   twin flagged §4 as silent on it — §2.3 already fixes `seal_hash` at 32
   bytes, so a non-32-byte value is malformed; no conformance vector
   exercises it, but the spec now states it rather than relying on the
   reader to infer it.)
2. Construct the 59-byte message per §2 from `seal_index` and `seal_hash`.
3. Run RFC 8032 Ed25519 verification of `signature` over the message under
   `public_key`. **accept** iff verification succeeds; **reject** otherwise.

The verifier consults ONLY the share's own fields — no external state, no
other shares. This is what makes each share individually attributable.

## 5. `extract_double_signers(cert_x, cert_y) -> [member_index] | error`

Given two certificates (each a list of seal shares — the two conflicting
UBCs for one slot):

1. **Verify every share** in `cert_x` and every share in `cert_y` with §4.
   If ANY share fails verification, the whole procedure is an **error**
   (return an error, do not return a partial offender list).
2. A `member_index m` is an **offender** iff there exists a share `x` in
   `cert_x` and a share `y` in `cert_y` with:
   - `x.member_index == y.member_index == m`, AND
   - `x.seal_index == y.seal_index`, AND
   - `x.seal_hash != y.seal_hash` (they signed CONFLICTING roots for the
     same seal index).
3. Return the offenders as a list of `member_index`, **sorted ascending,
   with duplicates removed**.

A member that signed the same root in both, or appears in only one
certificate, is NOT an offender.

## 6. Conformance vectors

`conformance_vectors.json` (sibling file) contains:

- `accept`: seal shares your `verify_seal_share` must **accept**.
- `reject`: seal shares (a byte-flipped signature, a wrong seal hash, a
  wrong seal index — each against an otherwise-valid share) your verifier
  must **reject**.
- `extraction`: two certificates `cert_x`, `cert_y` and the
  `expected_offenders` your `extract_double_signers` must return.

Your implementation **conforms** iff: every `accept` vector accepts, every
`reject` vector rejects, and `extract_double_signers(cert_x, cert_y)`
returns exactly `expected_offenders`.

## 7. What a disagreement means

If your implementation, faithfully following §§2–5, DISAGREES with a
vector, the disagreement is a **specification-ambiguity finding** — this
document failed to determine the behavior, and it (not your code) is what
gets corrected. Report the exact field and the two behaviors. The most
likely ambiguity surfaces are: the message byte order (§2), whether the
scheme is standard RFC 8032 Ed25519 (§3), and the offender-set ordering
(§5.3).
