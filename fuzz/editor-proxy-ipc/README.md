# IPC v2 codec fuzz targets (BUILD-DELTA #85 U1)

Three targets over `ioi-editor-proxy-ipc` (`crates/editor-proxy-codec`), DESIGN v2 (2):

- `p2d_decode`: raw proxy -> daemon bytes; `data[0]` picks the daemon phase and receive flags.
- `d2p_decode`: raw daemon -> proxy bytes; `data[0]` picks the proxy phase and flags, `data[1] % 5`
  descriptor-facts selectors follow.
- `ipc_sequence`: structure-aware operation sequences driving both machines (receive flags, typed
  and raw frames, F0 results, send prepare/results, time advance, verdicts, shutdown, bounded
  REPEAT blocks; at most 16384 operations per input, bounded queues).

Every invariant failure panics with a message starting `INVARIANT`. The committed seeds
(`corpus/<target>/seed-*`) are produced by the codec's unit test
`tests::replay::t_replay_committed_seeds_equal_their_builders` (`IPC_SEED_OUT=<dir>` writes them);
the named sequence seeds reach 65 unanswered ADMITs, 2000 exchanges then a refused 2001st, the
window boundary, duplicate/unknown/failed/WouldBlock verdicts, a second WELCOME, both truncation
flags, id maximum/exhaustion, clock regression and every purpose/mode/outcome/descriptor
combination. The stable replay (`cargo test -p ioi-editor-proxy-ipc`) checks the same assertions
without nightly.

A bounded campaign (nightly, offline):

```sh
cargo +nightly fuzz run p2d_decode --fuzz-dir fuzz/editor-proxy-ipc -- -runs=200000 -max_len=600
cargo +nightly fuzz run d2p_decode --fuzz-dir fuzz/editor-proxy-ipc -- -runs=200000 -max_len=600
cargo +nightly fuzz run ipc_sequence --fuzz-dir fuzz/editor-proxy-ipc -- -runs=50000 -max_len=4096
```

The raw decoders' `max_len=600` is not the session limit; the sequence target's limit is its
operation count. Campaign corpora and crash artifacts are evidence of a ticket, not committed here.
