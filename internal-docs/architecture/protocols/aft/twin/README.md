# In-Session Clean-Room Twin — UBC Seal-Share Verifier (AFT-CB P4.5b)

**What this is, and what it is NOT.** An independent Go reimplementation
of the UBC seal-share verifier and double-signer extractor, written by a
procedurally-isolated fresh-context implementer from `seal_share_verifier_spec.md`
and `conformance_vectors.json` ALONE — with no access to the Rust
reference. It agrees with the reference on every conformance vector.

Per the owner ruling on in-session substitutes: this establishes
**specification clarity and vector agreement**. It does NOT establish
organizational independence, and it is not an external audit or an
independent third-party implementation. It is labeled accordingly
wherever it is cited.

## Files

- `seal_share_verifier_spec.md` — the Rust-free specification the twin was
  built from (message layout, RFC 8032 Ed25519, verify rule, extraction).
- `conformance_vectors.json` — vectors exported from the Rust reference by
  the generator test `twin_conformance_vectors`
  (`crates/validator/src/common/guardian/seal_signer/tests.rs`), which
  self-checks that the reference verifier agrees with every labelled
  verdict, so the vectors cannot drift from the reference.
- `clean_room_twin.go` + `go.mod` — the independent Go implementation.
- `twin_result.md` — the adjudicated result and findings.

## Running the twin

```
cp clean_room_twin.go conformance_vectors.json go.mod /some/empty/dir/ && cd /some/empty/dir
mv clean_room_twin.go main.go
GOFLAGS=-mod=mod go run main.go
```

Expected: `SUMMARY: ALL PASS — accept 6/6, reject 3/3, extraction ok`.

## Regenerating the vectors from the reference

```
AFT_TWIN_VECTORS=1 cargo test --locked -p ioi-validator -- twin_conformance_vectors
```
This rewrites `conformance_vectors.json`; without the env var the test
runs as a self-check that the reference agrees with the committed
vectors.
