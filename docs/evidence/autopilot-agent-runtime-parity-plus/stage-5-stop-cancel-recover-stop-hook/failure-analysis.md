## Failure Analysis

The Stage 5 work uncovered a separate broad completion-suite regression:

```text
cargo test -p ioi-services completion --lib
failed:
- model_authored_market_answer_rejects_generic_fundamentals_without_typed_quote_metrics
- model_authored_market_answer_rejects_nominal_price_axis_and_missing_market_caps
```

Those tests are outside the stop/cancel/stop-hook slice and appear tied to the legacy market-currentness completion contract layer. They were not changed by this Stage 5 patch. They should be handled in the next runtime cleanup slice as part of removing deterministic answer-shaping remnants and replacing brittle market-output tests with model/tool/result/model behavioral benchmarks.

Focused Stage 5 checks passed:

```text
cargo test -p ioi-services stop_hook --lib
cargo test -p ioi-services stop_hook_blocks_chat_reply --lib
cargo test -p ioi-node --features local-mode --bin ioi-runtime-bridge control -- --nocapture
cargo build -p ioi-node --features local-mode --bin ioi-runtime-bridge
```
