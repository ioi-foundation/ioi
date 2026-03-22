# Throughput Scaling Plan

Last updated: 2026-03-22 09:32 EDT
Owner: active Codex session
Status: living plan

## Goal

Raise honest AFT throughput toward fabric-scale aggregate write throughput without cheating the architecture.

Interpretation:

- the single-domain goal is a strong, trustworthy per-lane ceiling, not a vanity number
- the aggregate goal is many healthy domains, not one overloaded lane
- a throughput win does not count if it hides replay debt, routing churn, projection lag, or unsafe methodology

## Current Baseline

Trustworthy native AFT bulk proof point:

- scenario: `guardian_majority_4v` / `base_final`
- attempted: `16384`
- accepted: `16384`
- committed: `16384`
- blocks: `1`
- injection TPS: `21370.89`
- sustained TPS: `9647.66`
- source log: `/tmp/ioi-aft-bin-256x64-1000ms-metricfix-1774116995.log`

Current local exploration note:

- no newer local run from this session beat that baseline
- the best post-change diagnostic `1024 x 4` run on this workstation stayed at `2110.90` sustained TPS with `3632` tx landing on the target height: `/tmp/ioi-aft-1024x4-jf-warm-pause8-wavefix-fanout2-1774183114.log`

## Guardrails

- do not use IDE-attached heavy local runs; use isolated units
- do not trust probes after harness changes until release artifacts are refreshed
- do not promote sampled-status throughput numbers for fast probes
- do not hide replay churn, spill, or target-height misses behind a single TPS number
- do not optimize by collapsing AFT/FQF into a hidden global sequencer or by putting large payloads on the hot path

## Current Focus

- keep AFT benchmark methodology honest and reproducible
- recover reproducible target-height fill on trustworthy local or remote measurement environments
- resume higher-value ceiling work only after the measurement environment stops dominating results

## Rolling Window

### Recently Completed

- fixed fast-probe wave pacing so pauses now follow absolute wave deadlines instead of compounding on top of slow wave execution
- added an ingress preflight for aligned fast probes: the harness now logs `ingress_status_p50/p95` and an estimated submission service budget before choosing a due block
- added optional `IOI_AFT_BENCH_CPUSET` support to the isolated runner so local probes can reserve a dedicated core range
- tried target-height leader preference and kept it opt-in only; current local evidence says it can over-concentrate ingress on a busy desktop instead of improving fill
- updated the yellow paper AFT benchmark section so its native-measurement methodology matches the current AFT harness semantics

### In Progress

- local throughput exploration is currently bottlenecked by the host machine, not by replay churn
- repeated isolated `1024 x 4` AFT reruns stayed zero-churn but still spilled or underfilled while the workstation remained busy with VS Code, browser, and other interactive processes
- the current task is to separate harness behavior from host interference before claiming another scaling improvement

### Next 5 Tasks

1. Re-run `1024 x 4` and `512 x 2` only in a quieter slot or on a less interactive host.
2. Add a compact host-load snapshot to benchmark logs so noisy-slot evidence is recorded next to throughput results.
3. Keep target-height leader pinning opt-in until quiet-slot evidence says it helps.
4. If quiet-slot reruns still underfill, upgrade the service-budget model to use actual selected-ingress round timing, not status RTT alone.
5. Resume larger ceiling probes only after target-height fill becomes reproducible again.

### Risks

- host-machine interference can masquerade as an ingress or packing regression even when isolated runs stay zero-churn
- stale release artifacts still invalidate direct-binary evidence if the guarded refresh path is skipped
- cargo-driven release rebuilds remain disruptive enough to freeze the desktop
- target-height leader pinning can overload one local ingress surface on a busy workstation
- sampled status can still lag authoritative commit detection by hundreds of milliseconds on noisy runs

### Decisions

- keep the `16384` one-block bulk proof as the current trustworthy AFT baseline until a better trustworthy measurement is obtained
- keep wave scheduling on absolute deadlines
- keep `IOI_AFT_BENCH_CPUSET` available as an operator tool, not a claimed throughput fix
- keep target-height leader preference opt-in only (`IOI_AFT_BENCH_PREFER_TARGET_HEIGHT_LEADER`)
- keep the ingress preflight and estimated submission-service-budget logging in place because they make due-slot misses explicit
- treat this workstation as the immediate bottleneck for further local scaling exploration until quieter-slot or dedicated-host evidence says otherwise
