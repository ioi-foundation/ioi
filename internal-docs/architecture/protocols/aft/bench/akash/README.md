# AFT paper benchmark through the certified Hypervisor path

This kit executes U1 after C7/C8. It does not add an alternate authority path: the normal provider-operation proposal, exact wallet-bound challenge, C2 intent, provider effect, authenticated result retrieval, teardown, settlement, C2 outcome, and C8 verification remain the only path.

The deliverable is not another deployment. It is a defensible RES-P4.3 table containing the four canonical scenarios at `n ∈ {4,7}`, five measured passes per campaign, a second campaign on the same provider, variance verdicts, an environment manifest, and the correct honesty class.

## Fixed protocol

Read [measurement-protocol.md](measurement-protocol.md) before building the image. The collector refuses partial matrices, duplicate rows, missing metrics, non-finite values, or any row where attempted, accepted, and committed counts differ. The runner never silently retries and never exits after a paid workload begins, preventing Akash from restarting it and repeating the campaign.

`run-bench.sh` produces:

- `environment.json`;
- one raw and one normalized JSON artifact per measured pass;
- `result.json` and `result.md` with count, median, min/max, MAD, sample CV, deterministic bootstrap interval, and the within-campaign variance verdict;
- `artifact-manifest.json` and `manifest.sha256`;
- `status.json`, whose state is `complete` only after every validation passes.

Only the canonical states `starting`, `warmup`, `measuring`, `complete`, and `failed` are accepted. Authenticated result and manifest retrieval remains closed until `complete`; the result server then verifies the campaign identity, byte length, and SHA-256 against `artifact-manifest.json` on every read.

## Immutable private image

The image contains proprietary source and must remain private. Build from a clean, committed revision and require the full commit at build time:

```bash
git archive <FULL_COMMIT> | tar -x -C <EMPTY_BUILD_DIRECTORY>
docker build \
  --build-arg IOI_COMMIT=<FULL_COMMIT> \
  -f internal-docs/architecture/protocols/aft/bench/akash/Dockerfile \
  -t <PRIVATE_REGISTRY>/aft-bench:<FULL_COMMIT> \
  <EMPTY_BUILD_DIRECTORY>
docker push <PRIVATE_REGISTRY>/aft-bench:<FULL_COMMIT>
docker inspect --format='{{index .RepoDigests 0}}' <PRIVATE_REGISTRY>/aft-bench:<FULL_COMMIT>
```

The provider plan and SDL must use the resulting `@sha256:` digest, never a mutable tag.

The repository's `Build private AFT benchmark image` workflow supports the
first publication without exposing proprietary source. If the GHCR package is
absent, it first pushes a source-free `FROM scratch` bootstrap image, verifies
through the GitHub Packages API that the newly created package is private, and
only then builds and pushes the source-bearing benchmark image. Existing
packages must already report private visibility. A lookup failure other than a
typed 404 refuses the workflow rather than guessing that the package is absent.

## Secret boundary

Do not put registry credentials or the result bearer token in the SDL, driver, shell history, proposal, evidence bundle, or chat. Bind them as two sealed generic-connector credentials:

- `registry_credential_ref`: a sealed bearer whose plaintext is JSON with `username` and `password` fields;
- `result_credential_ref`: a sealed random bearer token of at least 32 characters.

The proposal carries only `connector://conn_…` references and the SDL sentinels. The daemon injects plaintext after the C2 intent commits, sends the expanded SDL directly to Akash, and does not persist it. A seeded canary scan refuses the result bundle if a known test canary appears in any artifact.

After `start` discovers the provider endpoint, `logs` performs authenticated retrieval of `/status`, `/environment`, `/results`, and `/manifest`, verifies that the campaign is complete, caps each response at 2 MiB, persists a content-hashed `akash-workload-result://…` record, and returns a receipt without returning the bearer token.

## Exact provider campaign

The provider selection is part of the wallet-bound plan:

```json
{
  "mode": "exact",
  "provider_address": "akash1…",
  "selection": "only_qualified_bid_from_exact_provider"
}
```

Exact pinning has no marketplace fallback. The daemon also enforces the approved `uact` denomination and ceiling against that provider’s bid. No bid means refusal, automatic close, and provider-native settlement reconciliation.

The owner must review the immutable image digest, exact provider, SDL hash, resources, campaign ID, deposit, `uact` ceiling, connector references, and teardown policy in the dry challenge before minting the one-shot grant. Each of the two campaigns gets a fresh proposal, admission nonce, challenge, grant, and explicit approval.

The initial review envelope in `u1-campaign.example.json` is a $1 deposit and a `1000 uact` bid ceiling. This is deliberately the same hard deposit bound as C7; the known provider's tiny C7 workload bid was `0.726898 uact`, so the larger resource request still has a generous ceiling without raising maximum escrow exposure. The dry challenge is authoritative: if the exact provider does not bid within that bound, the daemon closes and reconciles rather than widening it automatically.

## Result claim

Same-provider pinning does not prove bare metal. Record the provider qualification evidence separately and use [provider-placement-attestation-request.md](provider-placement-attestation-request.md) for the tenant-specific placement statement. Use `Class C — measured on attested pinned bare metal` only if the runner/host allocation is independently attested and verified. Otherwise publish a measured-container or variance-caveated result and leave the bare-metal residual explicit.

After results are retrieved, always delete, confirm closure, reconcile the deposit and final debit/refund, and verify zero open or unknown exposure before assembling the U1 certificate and updating `specs/p4_measured_costs.md`.

Each campaign gets a separate `ioi.hypervisor.u1-aft-campaign-certificate.v1`
chained to its verified C7/C8 lifecycle certificate. The U1 verifier checks the
complete 14-row matrix, five-pass statistics, provider response hashes,
artifact manifest, exact provider, and terminal settlement; its 27-mutation
self-test also refuses unsupported bare-metal elevation:

```bash
npm --prefix apps/hypervisor run assemble:u1-campaign-certificate -- \
  --artifacts <CAMPAIGN_ARTIFACTS> \
  --lifecycle-certificate <C8_CERTIFICATE> \
  --lifecycle-verification <C8_VERIFICATION> \
  --output <U1_CERTIFICATE>
npm --prefix apps/hypervisor run check:u1-campaign-certificate -- \
  --certificate <U1_CERTIFICATE> --mutation-test
```

After both separately authorized campaigns are certified, compare their medians without dropping any metric:

```bash
./result-tools.py compare \
  --campaign-a campaign-a/result.json \
  --campaign-b campaign-b/result.json \
  --environment-a campaign-a/environment.json \
  --environment-b campaign-b/environment.json \
  --output-json campaign-comparison.json \
  --output-markdown campaign-comparison.md
```

If the provider returns the requested two-campaign placement statement, resolve
its Ed25519 public key independently and verify it before assigning an elevated
honesty class:

```bash
npm --prefix apps/hypervisor run check:u1-placement-attestation -- \
  --attestation placement.json \
  --public-key provider-ed25519-public.pem \
  --campaign-a campaign-a/u1-campaign-certificate.json \
  --campaign-b campaign-b/u1-campaign-certificate.json \
  --output placement-verification.json
```
