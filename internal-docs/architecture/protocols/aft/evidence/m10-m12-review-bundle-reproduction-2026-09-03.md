# M10/M12 private review-bundle reproduction — 2026-09-03

Status: **PASS — LOCAL TRANSFER-PACKAGE EVIDENCE ONLY**.

This evidence validates `.github/scripts/prepare_aft_review_bundles.sh`. It does
not commission, perform, or substitute for either independent review.

## Candidate identities

| Review | Annotated tag | Commit | Tag object |
|---|---|---|---|
| M10 | `aft-pq-v1-review-candidate-2026-09-03` | `09aaf34b63c8fa8520c4de014a6d72f6360f7e16` | `3db5f4d08fb5819ab586982f0be60be626ed527b` |
| M12 | `aft-maximal-visibility-lower-bound-candidate-r2-2026-09-03` | `225f56992392054251d6337608c4695deb7d00e3` | `8f83ecfec1e9ba15213dea4a94d2d2b6394648dd` |

The script fails before packaging if either ref is absent, lightweight, moved,
or resolves to a different commit or tag object.

## Positive reproduction

Two new empty temporary directories were independently populated with:

```text
bash .github/scripts/prepare_aft_review_bundles.sh "${output_dir}"
```

For each run, the script:

1. verified both annotated tag types, commits, and tag objects;
2. generated one self-contained Git bundle per candidate with
   `pack.threads=1`;
3. passed `git bundle verify` for both bundles;
4. cloned each bundle into a separate temporary checkout;
5. checked detached `HEAD` and the imported annotated-tag object against the
   constants above; and
6. generated and passed strict SHA-256 verification for both bundles and the
   manifest.

The two runs were then compared with `cmp`. Both bundle files, both manifests,
and both `SHA256SUMS` files were byte-identical on the tested host.

| Artifact | Size | SHA-256 |
|---|---:|---|
| `aft-pq-v1-review-candidate-2026-09-03.bundle` | 521 MiB | `8eaf42a0699277f6033956ea866106512d1ae904a41aceabf513bd1bb3adad39` |
| `aft-maximal-visibility-lower-bound-candidate-r2-2026-09-03.bundle` | 521 MiB | `18030388c2200d14fe4bda953a7138277c720cccb80f063178b26a52a410c186` |

The object IDs, not these package-instance hashes, are the durable candidate
identities. A different compatible Git implementation may choose a different
valid pack encoding. The sender and reviewer must verify the `SHA256SUMS`
shipped with the particular transfer and then independently resolve the commit
and annotated tag object.

## Negative tests

The script returned exit status 2 and emitted a specific refusal for each of:

- no output-directory argument;
- an existing non-empty output directory; and
- `/` as the output directory.

It also refuses the repository root and any existing non-directory target. It
does not upload, push, sign, or transmit the bundles.

## Disclosure boundary

Each bundle contains the complete Git object history reachable from its review
tag. The owner must approve the recipient and transfer channel. The generated
temporary packages were deleted after verification, are not committed
evidence, and did not change either immutable candidate.
