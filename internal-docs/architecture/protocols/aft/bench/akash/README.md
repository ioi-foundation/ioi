# AFT paper-benchmark on Akash — RES-P4.3 Stage 1 (console deploy)

Turnkey kit to run the AFT paper-benchmark matrix on a rented Akash lease and
retrieve a **variance-caveated, NON-GATING** reference table. This does **not**
close RES-P4.3: its gate is "reproduces within stated variance on re-run,"
which needs a reserved/pinned runner. A generic Akash lease is a container on a
heterogeneous third-party provider — another variable box, and a re-run may
even land on a different host. What this kit buys:

1. a reference number off *our* dev box (which runs CI on every merge and is
   actively used), on a spec we control; and
2. the first real Akash workload, de-risking the image + SDL ahead of Stage 2
   (routing deployments through the hypervisor's own Akash adapter).

## Honest reproducibility rules (for the number to mean anything)

- **Pin one provider.** Select the SAME provider on every re-run and record its
  provider address. Akash SDL filters by attributes, not provider address, so
  the pin is enforced by *your* bid selection, not the SDL alone.
- **Request whole-core dedicated CPU.** Oversubscribed vCPU is the main
  variance source. Prefer a provider that advertises dedicated CPU.
- **Warmups + repeats.** `AFT_BENCH_WARMUPS` discarded passes, then
  `AFT_BENCH_REPEATS` measured passes; report min/median/max and the spread.
- **Record the manifest.** The runner prints an `===AFT-BENCH ENVIRONMENT
  MANIFEST===` block (commit, CPU model, cores, mem, kernel, rustc, governor).
  Keep it with the numbers. The host **kernel is the provider's** — a caveat.
- Label the result table **RELATIVE-COMPARISON-ONLY / NON-GATING** wherever it
  is cited, per the RES-P4.3 residual (`../../specs/p4_measured_costs.md`).

## Build (private registry — mandatory)

The image carries proprietary source at the pinned commit. Push to a **private**
registry only.

```bash
# From the repo root, build a clean archive of the pinned commit as the context:
git archive 98a04f163 | tar -x -C /tmp/ioi-pinned
docker build \
  -f internal-docs/architecture/protocols/aft/bench/akash/Dockerfile \
  -t REGISTRY_HOST/ORG/aft-bench:98a04f163 \
  /tmp/ioi-pinned
docker push REGISTRY_HOST/ORG/aft-bench:98a04f163
```

Building the image compiles the workspace once (release). Prefer building in CI
or on an idle machine, not the shared dev box under load. (A GHCR build job is
the clean home for this — a Stage 2 follow-up.)

## Deploy (Akash console — your spend)

1. Edit `deploy.sdl`: set `image`, `credentials` (private registry token), CPU
   units, and the max `amount`.
2. In console.akash.network → **Deploy image / custom SDL**, paste `deploy.sdl`.
3. Review bids, **pick your pinned provider**, create the lease, send the
   manifest. CPU-only; ignore GPU providers.

Cost: single-digit-dollar range for a CPU lease held briefly; the $1 trial
covers a smoke. **Spend and the wallet are yours — this kit never spends.**

## Retrieve + tear down

```bash
# Stream the results (Markdown tables between ===AFT-BENCH RUN k/N=== markers):
akash provider lease-logs --dseq <DSEQ> --provider <PROVIDER> --follow

# When you have all N runs' tables + the manifest, CLOSE THE LEASE:
akash tx deployment close --dseq <DSEQ> --from <KEY>
```

The container holds (`sleep infinity`) after the runs so logs stay retrievable;
it does **not** self-close — closing is manual so you don't lose output and
don't get billed for an auto-restart re-running the matrix.

## What the runner does

`run-bench.sh` → env manifest → `AFT_BENCH_WARMUPS` discarded warmups →
`AFT_BENCH_REPEATS` measured passes of
`cargo test --release -p ioi-cli --features consensus-aft,vm-wasm,state-jellyfish -- --ignored --nocapture test_aft_paper_benchmark_matrix`,
each wrapped in run markers. Scenarios (via `IOI_AFT_BENCH_SCENARIO`):
`paper_guardian_majority_4v`, `paper_guardian_majority_7v`,
`paper_asymptote_4v`, `paper_asymptote_7v` (n ∈ {4, 7}; empty = full matrix).
Output is a Markdown table per pass — retrieve via lease-logs.

## Stage 2 (separate)

Routing the deployment through the hypervisor's own Akash adapter is a distinct
cut: [crates/drivers/src/provisioning/akash.rs](../../../../../../crates/drivers/src/provisioning/akash.rs)
currently STUBS `provision()` (generates SDL, logs it; the sign-tx →
broadcast → bids → lease → manifest flow is a comment). The merged Akash DePIN
work is the candidate/quote plane only (source-quoted USD, never authority).
This bench image is the intended first end-to-end workload once that live-lease
path is built (needs a funded wallet + owner spend authorization).
