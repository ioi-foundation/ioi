# AFT PQ fuzz targets

The `aft_pq_decoders` target treats ML-DSA key/signature imports and every
untrusted PQ-channel wire object as attacker-controlled bytes. Decoders must
return a refusal without panicking, allocating without the configured bound,
or accepting non-canonical ML-DSA hint encodings.

Reproduce a bounded CI campaign with:

```sh
RUSTFLAGS='--cfg rustix_use_libc' cargo +nightly fuzz run aft_pq_decoders \
  --fuzz-dir fuzz/aft-pq-crypto -- -runs=100000 -max_len=16384
```

Long-running release campaigns should retain the generated corpus and crash
artifacts as CI evidence rather than committing ephemeral local output.

The `aft_seal_signer_state` target drives the production durable SLH-DSA
signer through provision, sign, restart, snapshot rollback, ciphertext
corruption/truncation, concurrent-anchor acquisition and exhaustion. It checks
every emitted successor link and treats slot reuse, malformed-state acceptance,
wrong-custody acceptance or exhaustion reopening as a crash. Run a bounded
state campaign with:

```sh
RUSTFLAGS='--cfg rustix_use_libc' cargo +nightly fuzz run aft_seal_signer_state \
  --fuzz-dir fuzz/aft-pq-crypto -- -runs=256 -max_len=17
```

This target complements the deterministic crash-window tests in
`ioi-validator`; it intentionally uses the production filesystem anchor,
encrypted state and FIPS 205 implementation rather than a reduced test signer.
The fuzz-only `rustix_use_libc` selection avoids an obsolete internal-rustc
attribute used by a transitive dependency on current nightly compilers; it
does not change any production build.
