# Governed-effect security baseline — 2026-08-22

Status: re-derived T0 baseline; spend-free; no provider mutation performed.
Canonical owner: this record for the 2026-08-22 governed-effect T0 audit basis.
Doctrine status: reference
Implementation status: partial
Implementation refs:
  - `internal-docs/implementation/program/governed-effect-security-and-publication-target-plan.md`
  - `docs/architecture/_meta/schemas/architecture-contract-registry.v1.json`
Last implementation audit: 2026-08-22 (T0 contracts complete; later target-plan workstreams remain open)

This audit is the reproducible source/contract basis for the governed-effect
security and publication target. It records what passed, what initially failed,
and what was repaired. It does not upgrade the claims of the 2026-08-21 C7/C8
certificate.

## Source basis

| Input | Observed value |
|---|---|
| IOI commit before this tranche | `900bc8ad640aaf18e091a13aae33204c104f51b6` |
| IOI branch | `hv/reference-ux-remediation` |
| IOI pre-existing unrelated state | untracked file `0`, preserved |
| Website commit | `cbf1b1f6658c1faab2cdeda6f55677587e0fc59b` |
| Website branch | `feat/governed-infrastructure-syscall` |
| Website pre-existing unrelated state | untracked `docs/brand-guidelines/`, preserved |
| Node / npm | `v22.22.0` / `10.9.4` |
| rustc / Cargo | `1.93.1` / `1.93.1` |
| `package-lock.json` | `sha256:f6e51260f8506a2c31a8219610ed3c0464edc7581459d5db00e555a71627d45b` |
| `Cargo.lock` | `sha256:f493d665970cfb18264ad982a149c08fada607f1db1c34ae8bdf7c752ea1ed2a` |
| rebuilt daemon | `sha256:f00b078bba76af9e7caafa2bab54d4cd6546593034936bc375425625c1808234` |
| C8 verifier source | `sha256:13d9037b98a95132a95d16742809e6201e8dae44ed418c3f1ef4f34c42e50793` |
| C8 structural validator source | `sha256:8382811ab1567d1c3cbb9321719bcc926d3a3bb12c814c0ce67309d882e63c46` |

The rebuilt daemon hash is a development-baseline build from the declared dirty
T0 worktree. It is not the daemon hash in the clean C7/C8 certificate and must
not be substituted into that certificate.

## Re-derived checks

Run from the IOI repository root unless noted otherwise.

| Surface | Command | Result |
|---|---|---|
| Architecture contracts | `npm run generate:architecture-contracts && npm run check:architecture-contracts` | passed; registered projections generated for TypeScript and Rust |
| Governed-effect claim discipline | `npm run check:governed-effect-claims --workspace=@ioi/hypervisor-app` | 14/14 passed |
| C8 structural mutations | `node apps/hypervisor/scripts/verify-c7-c8-capstone.mjs --self-test` | 22/22 passed |
| U1 JS instrument | `node --test apps/hypervisor/scripts/lib/certified-campaign-config.test.mjs apps/hypervisor/scripts/lib/u1-campaign-certificate.test.mjs apps/hypervisor/scripts/lib/u1-placement-attestation.test.mjs` | 16/16 passed |
| U1 result tools/channel | `python3 -m unittest internal-docs/architecture/protocols/aft/bench/akash/test_result_tools.py` | 11/11 passed |
| AFT formal census | `bash .github/scripts/run_aft_formal_checks.sh --census-only` | 35 modules accounted for: 22 executed, 13 manually discharged |
| AFT claim discipline | `bash .github/scripts/check_aft_claim_discipline.sh` | passed |
| AFT whitepaper claim ledger | `bash .github/scripts/check_aft_whitepaper_claims.sh` | passed |
| AFT theorem assumptions | `bash .github/scripts/check_aft_theorem_assumes.sh` | passed |
| AFT no-mock-proof floor | `bash .github/scripts/check_aft_no_mock_proof.sh` | passed |
| Ontology route/admission census | `npm run check:ontology-admission-census --workspace=@ioi/hypervisor-app` | initially 22/25 because committed source counts exceeded stale pins; pins were re-derived and the gate then passed 25/25 |
| Session authority | `npm run check:session-authority --workspace=@ioi/hypervisor-app` | after rebuilding the daemon, 24/24 passed |
| Model-route authority | `npm run check:model-route-authority --workspace=@ioi/hypervisor-app` | after rebuilding the daemon, 43/43 passed |
| Website article lint | `npm run lint:blog` in `internetofintelligence-com` | passed |
| Website production build | `npm run build` in `internetofintelligence-com` | Vite build, roadmap audit, SEO generation, and SEO audit passed |
| Website rendered article QA | `IOI_AUDIT_BASE_URL=http://127.0.0.1:4197 npm run qa:blog-governed-syscall` against a current preview | four viewport/theme profiles plus full-size SVG passed with zero failures |

The first website QA invocation accidentally targeted an unrelated process on
port 4173 and correctly failed with an empty article. The current preview was
then addressed explicitly and passed. The failed invocation is not evidence of
the article state.

## C7/C8 baseline retained, not inflated

The clean retained certificate at the time of this audit remains:

- source commit `6ef974a08a2117b898f8b7e875f848c1b8a12620`;
- certificate hash
  `sha256:1aee64bf6eab70771c0a81abac39f2911b72a6f753e3c561a15bcd8ef4266148`;
- dseq `1787349025409`, provider lease closed;
- terminal provider readback with `$0.000002` final debit and zero open or
  unknown exposure;
- one desired replica, zero ready replicas; no workload-readiness or result
  claim; and
- no bare-metal, provider-neutrality, or remote-worker secret-non-possession
  claim.

The new public-evidence builder was run against that retained certificate and
its two retained verifier reports. It emitted eight disclosure-safe artifacts,
including `claim-manifest.json`. The manifest classified only
`governed_infrastructure_lifecycle`, `logical_policy_mediation`, and
`separate_verifier` as demonstrated under `development_cooperative`. It kept
workload readiness/result binding, workload-bound isolation, worker secret
non-possession, independent reproduction, third-party verification, provider
neutrality, and bare-metal placement as explicit nonclaims.

## T0 repair record

T0 registered six target contracts and generated their Rust/TypeScript
projections before adding any corresponding effect route:

| Contract | Canonical owner | Implementation unit |
|---|---|---|
| `GovernedEffectClaimManifestV1` | verifiable bounded agency | C8/public evidence claim gate |
| `AuthorityTrajectoryStateV1` | authority and access | `M03.14` |
| `TrajectoryAdmissionDecisionV1` | authority and access | `M03.14` |
| `RelyingPartyAcceptancePolicyV1` | verifiable bounded agency | `M06.7` |
| `CertificateAcceptanceReceiptV1` | verifiable bounded agency | `M06.7` |
| `C8CertificateV3` | providers and environments | `M12.10` |

ADR 0027's executable hostile-guest boundary is split from the broad cTEE lane
as `M09.8`. The existing `ReceiptCheckpoint` and `ReceiptProofBundle` contracts
are sufficient for the initial external-witness composition, so no speculative
`ExternalWitnessCommitmentV1` was registered. A locally produced checkpoint is
explicitly not external witnessing.

The canonical trajectory ruling is a deterministic projection whose state hash
is an admission input; update, authority draw-down, and C2 intent are one atomic
logical transition. The minimum aggregate scope is owner, bounded System,
principal, and every envelope ancestor. Semantic evidence can force step-up or
denial and cannot admit or widen. The first relying party is the AFT measured-
results registry, whose only accepted mutation is one verified measured-row
promotion.

The ontology census initially found exact count drift already present in the
committed daemon source. The governed pin update records the newly derived
closed-world population:

- tokens: `108258`;
- unresolved constants: `foreign-qualified=3512`,
  `opaque-initialiser=1559`, `bare-undeclared=518`; and
- production writer calls: `family=72`, `non-ODK=211`,
  `runtime-parameter=293`.

The repair changes no admission policy. It restores the census's exact-count
ratchet so later source shrinkage or growth fails closed.
