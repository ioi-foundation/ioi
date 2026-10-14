# The per-dependency randomness review of the mint gate

BUILD-DELTA #36. This implements the Hypervisor Director's ruling "Batch-3 Codex r5 = FAIL, 3 MAJOR + 1 MINOR" (1)
and the IOI Director's amendment (2): "the reviewed list of dependency randomness APIs (e.g. uuid v4, anything
reaching getrandom) is PINNED, has a dependency-helper canary, and is RE-OPENED on any pin change."

The review covers exactly the dependency set, the features and the configurations in `deps.pin`. That file also
records the sha256 of `clippy.toml` confirmed for that set. The gate fails until this review is re-done, `clippy.toml`
is extended and `deps.pin` is regenerated when any of these happens:

- a direct normal dependency of ioi-node or ioi-services is added, removed or changes version;
- ioi-node or ioi-services gains or loses a feature;
- the deny list is edited.

## What counts as a randomness API

A public API that draws fresh randomness from an entropy source (the OS RNG, a thread CSPRNG seeded from it, or a
caller-supplied RNG) and hands the result, or a value derived from it, to the caller: random bytes or numbers, an id
(UUIDv4), a key or keypair, a salt, a nonce, a challenge, a random string; or a type that IS an RNG. One
credential-minting API without randomness is listed too, `jsonwebtoken::encode` (it signs a bearer credential).

Not listed, each with its reason:

- internal draws that never leave the dependency: TLS handshakes and ticket keys (rustls `Ticketer::new`,
  `SupportedKxGroup::start`, hpke), libp2p noise and gossipsub internals, tokio's `select!` fairness RNG
  (`tokio::macros::support::thread_rng_n`, doc-hidden), futures' `select!` shuffle (deterministic), reqwest's multipart
  boundary (feature off);
- hash-map seeds: `std::collections::hash_map::RandomState` (the only stable std randomness; `std::random` is unstable
  on 1.93.1), `ahash::RandomState` and its maps;
- randomized SIGNATURES (k256/ecdsa `RandomizedSigner`, rcgen's ECDSA signing, rustls `Signer::sign`): the hedged nonce
  never leaves the signature and the signature is not secret;
- non-cryptographic names: tempfile's random file names (fastrand, time-seeded), lettre's Message-ID and MIME boundary
  (fastrand, "not cryptographically random");
- APIs behind features this build does not enable: uuid v1/v6/v7 constructors, libp2p secp256k1/ecdsa keypairs, k256
  ecdh/schnorr, webauthn conditional-ui and resident-key starts, rcgen RSA (aws_lc_rs), reqwest multipart;
- crates the inventoried code cannot name: getrandom, rand_core, rand_chacha, ring, fastrand, rand 0.9, openssl::rand
  are not direct dependencies and no direct dependency re-exports them, EXCEPT rand_core 0.6 (re-exported by k256 as
  `k256::elliptic_curve::rand_core` and `k256::ecdsa::signature::rand_core`), which is the SAME crate rand 0.8
  re-exports, so the rand entries resolve to its items. getrandom 0.2/0.3/0.4 are listed anyway (the ruling names
  getrandom; clippy resolves every crate named `getrandom` in the graph; the canary uses 0.2.17 and 0.4.1);
- (WITHDRAWN 2026-10-14, Codex batch-3 r6 MAJOR 1: see "Re-opened 2026-10-14: the seal-signer surface, re-derived per
  configuration" below; the two key generators are LISTED.) ioi-validator's seal-signer keys
  (`SlhDsaSealKeyPair::generate`, `DurableSealSignerV2::provision`) exist only under ioi-validator's `consensus-aft`;
  this bullet held that ioi-node never enables it, which manifest text suggested and the resolved graph refutes;
- `ioi_validator::standard::orchestration::Orchestrator::execute_query_unanimity_effect`: generic over four heavily
  bounded parameters; it draws a protocol verifier nonce into a request, and whether the returned receipt carries it is
  unconfirmed; it is not a credential. Named here, not listed;
- dependency APIs that draw internally and return nothing drawn (ioi-consensus journal nonces, `SecurityChannel`,
  `Libp2pSync`, `BrowserDriver::launch`, `WasmRuntime::execute`'s WASI RNG, `save_encrypted_file`, `setup_workload`'s GC
  jitter, `run_provider_server`): their callers see no drawn value.

## Method (reproducible, read-only, offline)

1. **Features.** `cargo tree --locked --offline -p ioi-node -e normal,build -f '{p} [{f}]'` gave the enabled feature
   set of every dependency (Cargo.lock does not record features). The surfaces below are those of the features ON.
2. **External crates.** Each direct dependency's registry source (`~/.cargo/registry/src/*/<crate>-<version>/src`) was
   searched for `\brand\b|rand::|getrandom|OsRng|random|\bRng\b|RngCore|uuid|entropy|nonce|SystemRandom|RandomState|
   fastrand|thread_rng`, and every hit was read to decide whether it is reachable through the crate's public API and
   hands randomness out. A Rust crate can only name items of its DIRECT dependencies, so a transitive crate's API is
   reachable only through a direct dependency's re-export; clippy resolves a re-export to the same definition.
3. **Workspace crates** (the 23 ioi-node/ioi-services depend on): non-test code searched for the rand/getrandom/uuid
   patterns above and for key-generation calls into dependencies (`generate_ed25519`, `Keypair::generate`,
   `::generate(`, `SigningKey::random`, `::keypair(`, `::encapsulate(`, `rcgen::`, `PeerId::random`, `WasiCtxBuilder`,
   `slh_dsa::`, `keygen`); every hit traced to the public path an outside crate can name.
4. **The deny list is checked by clippy itself, in EVERY gate invocation.** The canary binary uses each external entry
   once on a marked line and the gate requires exactly one report there; an entry the inventoried code already calls
   is marked `[witness: its real call sites]` and must be reported at one of them instead. So each entry is proven to
   resolve and to fire on the pinned toolchain, in each configuration.

## Per dependency

| Dependency (direct of) | Randomness API (enabled features) | Disposition |
|---|---|---|
| rand 0.8.5 (node, services) | `thread_rng`, `random`, `seq::index::{sample, sample_weighted}`; the RNG types `rngs::{OsRng, ThreadRng, StdRng, SmallRng}`; every drawing method of `RngCore`, `Rng`, `Fill`, `SeedableRng::{from_entropy, from_rng}`, `distributions::{Distribution, DistString}`, `distributions::uniform::{UniformSampler, SampleRange}`, `seq::{SliceRandom, IteratorRandom}` (rand re-exports rand_core's `RngCore`, `CryptoRng`, `SeedableRng`; it does not re-export the rand_core crate, getrandom or rand_chacha). `adapter::{ReseedingRng, ReadRng}` draw only through `RngCore` (listed) from a reseeder or reader the caller supplies (a `/dev/urandom` path is a layer-2 primitive). `seed_from_u64`/`from_seed` and `mock::StepRng` are deterministic. | All drawing APIs listed (canary) |
| uuid 1.21.0 (node) `[std, rng, serde, v4]` | `Uuid::new_v4` (also reachable as `webauthn_rs::prelude::Uuid::new_v4`, the same item). v1/v6/v7 are off. `Builder::from_random_bytes` formats caller bytes (not a draw). | Listed (canary) |
| libc 0.2.182 (node) | `getrandom`, `getentropy`, `getauxval` (`AT_RANDOM`: 16 kernel random bytes), `syscall` (`SYS_getrandom` exists), the PRNG family `rand, srand, drand48, erand48, lrand48, nrand48, jrand48, srand48, mrand48, seed48, lcong48`. `random`, `arc4random*` are not bound for linux-gnu. | All listed (canary) |
| dcrypt 4.0.1 `[full]` (node, services) | dcrypt has no OS RNG and its RNG traits are its own (`dcrypt_internal::random::{RngCore, CryptoRng}`), distinct from rand_core's. Its only RNG is `ChaCha20Rng` (caller-seeded). Every randomized dcrypt API (signature and KEM keypairs, encapsulation, symmetric key/nonce generation, salts, ECIES, BLS keys, hybrid engines) takes one of its RNGs, so constructing `ChaCha20Rng` (a listed type) or calling a `dcrypt::internal::RngCore` method is a site; `Signature::keypair`, `Kem::keypair`, `Kem::encapsulate` are listed as the trait entry points. | Type, RngCore methods and the three trait methods listed (canary) |
| libp2p 0.53.2 (node, services) `identity [ed25519, peerid, rand]` | `libp2p_identity::Keypair::generate_ed25519`, `ed25519::{Keypair, SecretKey}::generate`, `PeerId::random`, `SwarmBuilder::with_new_identity`. secp256k1/ecdsa keypairs are off. gossipsub's `RandomAuthor`, noise and mdns draw internally. | Listed; `generate_ed25519` is witnessed at the node bins' calls |
| k256 0.13.4 (services) `[ecdsa, std]` | Generic over a caller RNG: `ecdsa::SigningKey::random`, `elliptic_curve::{SecretKey, NonZeroScalar}::random`, `ff::Field::random`, `group::Group::random`, `k256::Scalar::{generate_biased, generate_vartime}`; re-exports rand_core 0.6 (= rand's). Randomized signers not listed (above). ecdh/schnorr off. | Listed (canary, through k256's public paths) |
| webauthn-rs 0.5.5 (node) `[attestation, danger-allow-state-serialisation]` | Every `Webauthn::start_*` draws a challenge (webauthn-rs-core, rand 0.9) and returns it: `start_passkey_registration`, `start_passkey_authentication` (witnessed at device_custody_routes.rs), `start_securitykey_{registration, authentication}`, `start_attested_passkey_{registration, authentication}`; `fake::WebauthnFakeCredentialGenerator::new_hmac_key` returns 16 random bytes. The other starts need features that are off. | Listed |
| rcgen 0.13.2 (node) `[crypto, pem, ring]` | `KeyPair::generate`, `KeyPair::generate_for`, `generate_simple_self_signed` (returns a fresh keypair). RSA generation needs aws_lc_rs (off). Default serials are deterministic. | Listed (canary) |
| rustls 0.23.36 (node) `[ring, aws_lc_rs, ...]`; tokio-rustls 0.26.4 re-exports it | `crypto::SecureRandom::fill` (through `CryptoProvider::secure_random`). Ticketers, key exchange and hpke draw internally. | `SecureRandom::fill` listed (canary) |
| jsonwebtoken 8.3.0 (node) | `encode` signs a JWT (RS256 deterministic; ES*/PS* use ring's SystemRandom). Its crypto modules are private. | Listed as a credential-minting API, witnessed at lifecycle_routes.rs `mint_github_app_jwt` (`jwt_encode`) |
| tokio 1.42.0, futures 0.3.32 | Only macro-support internals (above). | None |
| tempfile 3.25.0 (services), lettre 0.11.19 (services), ahash 0.8.12 (node) | Names, MIME metadata, hash seeds (above). | None (reason above) |
| reqwest 0.11.27, native-tls 0.2.18, tonic 0.11.0, warp 0.3.7, axum 0.7.9, rust_decimal 1.42.1, time 0.3.37, imap 2.4.1, zip 0.6.6 | Nothing enabled (multipart, `rand` features off; native-tls's random password is macOS-only). | None |
| once_cell, parking_lot, regex, image, image_hasher, whisper-rs, symphonia, scraper, pdf-extract, tar, xz2, schemars, url, walkdir, bytes, dotenvy, fd-lock, mime_guess, rpassword, rust-embed, toml, serde, serde_json, serde_jcs, sha2, zeroize, hex, base64, bs58, bincode, parity-scale-codec, clap, env_logger, tracing, tracing-subscriber, log, anyhow, thiserror, async-trait, cfg-if, atty, unicode-normalization | No public randomness API (hits, where any, are test-only or entropy-coding). | None |

## The workspace dependencies

| Crate | Public randomness API | Disposition |
|---|---|---|
| ioi-crypto | `sign::eddsa::Ed25519KeyPair::generate`, `sign::bls::BlsKeyPair::generate`, `sign::dilithium::MldsaScheme::generate_keypair`; the KEMs through the trait `ioi_api::crypto::KeyEncapsulation::{generate_keypair, encapsulate}`; `key_store::{encrypt_key, hash_password}` (OS-random salt/nonce in the output); `transport::pq_authenticated_channel::{start_pq_channel, accept_pq_channel}`; `transport::hybrid_kem_tls::{client_post_handshake, server_post_handshake}` (generic over the stream). `rng::os_rng` is pub(crate). | Listed; `Ed25519KeyPair::generate`, `encrypt_key`, `hash_password` witnessed at their calls in node and services |
| ioi-api | Only the trait declarations above (and `commitment::CommitmentScheme`, randomized for two ioi-state schemes). | The KEM trait methods listed; the commitment schemes listed by TYPE (the trait also covers deterministic hash/KZG schemes) |
| ioi-client | `slicing::SlicePackager::package` (12-byte nonce per slice, returned in each slice's iv). | Listed (canary) |
| ioi-networking | `noop::NoOpBlockSync` (its `new` and `Default` draw a `PeerId`), `libp2p::pq_channel::PqChannelSessionManager::{start, accept}`. | `NoOpBlockSync` (type) and `::new` witnessed at ioi-local.rs; the session manager listed (canary) |
| ioi-state | `primitives::lattice::LatticeParams::new_insecure_for_testing` (not cfg(test)); the randomized `primitives::lattice::LatticeCommitmentScheme` and `primitives::pedersen::PedersenCommitmentScheme`. | Listed (canary) |
| ioi-drivers | The trait method `provisioning::CloudProvider::provision` (its implementors draw a UUIDv4 instance id). | Witnessed at services/src/market/router.rs |
| ioi-validator | `common::transparency_log::MemoryTransparencyLog::ephemeral`, `common::guardian::generate_certificates_if_needed`, `common::guardian::GuardianContainer::new` (conditional key generation), `standard::provider::ProviderController::{handle_provision_request, provision_with_domain}`. Seal-signer keys and the orchestrator's verifier nonce: above. | Listed; `generate_certificates_if_needed` and `GuardianContainer::new` witnessed at guardian.rs |
| agentgres, http-rpc-gateway, ioi-consensus, ioi-execution, ioi-ipc, ioi-memory, ioi-plugin-ibc-service, ioi-storage, ioi-telemetry, ioi-tx, ioi-types, ioi-vm-wasm, transport-verifier, zk-driver-succinct, ioi-macros, ioi-pii | No public API that hands randomness out (ioi-consensus and ioi-vm-wasm draw internally only). No workspace crate re-exports rand, rand_core, getrandom, uuid or ring, and none takes or returns an RNG. | None |

## The inventoried code's own hand-outs

A function of ioi-node or ioi-services whose RETURNED value is drawn makes every caller use a draw without naming a
deny-list entry. Each is listed in `hand-outs.tsv` and as an own entry in `clippy.toml`, so its callers are sites:
`lifecycle_routes::gen_opaque`, `lifecycle_routes::random_token`, `orchestration_routes::new_webhook_token`,
`google_auth::random_url_safe_token`. The survey of every draw site extends this list.

## Re-opened 2026-10-13: the every-feature build is two configurations

`--all-features` does not build ioi-node: its commitment features are mutually exclusive (orchestration.rs picks its
`DefaultVerifier` by `commitment-hash` or `commitment-kzg`; with both, the Verkle/KZG arm fails E0271, as S1-29E's run of
the identical file and feature graph showed for the wire gate). `deps.pin` therefore replaces the configuration
`all-features` with `all-hash` (every ioi-node feature whose closure does not enable `commitment-kzg`) and `all-kzg`
(every one whose closure does not enable `commitment-hash`), each with every ioi-services feature. The review is
re-confirmed for the new set with no change to it: the features and the direct dependencies (default and every feature)
are the same lines, the deny list and its sha256 are unchanged, and the two configurations together enable every
feature, so every optional dependency a feature enables is still compiled in some configuration. The gate checks that
every feature is enabled, and every production target checked, in some configuration.

## Re-opened 2026-10-13: the draw-site survey's hand-outs (ticket b3r-t1b)

Reviewing every draw site the survey printed found eleven more own functions whose RETURNED value is drawn and which have
a production caller. Each is now in `hand-outs.tsv` and an own entry of `clippy.toml` (deny list regenerated by
work/s1-security/b3r/bin/gen_denylist2.py; its new sha256 confirmed in `deps.pin`), so its callers are sites:
`authority_challenge_routes::process_nonce`, `justification_checkpoint_routes::fresh_interaction`,
`lifecycle_routes::standing_draw_nonce`, `machine_routes::mint_operation_ref`, `provider_routes::random_proposal_nonce`,
`workload_effect_boundary::{mint_guest_effect_capability, mint_guest_governed_provider_effect_capability}`, the signer's
`load_keypair`, and in ioi-services `firewall_receipt_keys::mint_key`,
`model_mount::capability_token_control::plan_capability_token_control` and `web::transport::selected_browser_http_user_agent`.
Not hand-outs, by the same review: randomized encryption and password hashing (`key_store::encrypt_key`,
`hash_password` and their wrappers: the draw is a salt or nonce inside a ciphertext or verifier, not a value the caller
uses), temporary-path uniqueness inside a function (`persist_key`, `HostileGuestRoundtripDir::create`,
`StandingAuthority::record`, the export and import staging names), and `IntentResolver::resolve_intent` (no caller). The
dependency set, the features and the external entries are unchanged.

## Re-opened 2026-10-14: the seal-signer surface, re-derived per configuration (Codex batch-3 r6 MAJOR 1)

Codex batch-3 r6 (MAJOR 1) found the seal-signer exclusion above false: crates/node/Cargo.toml:151 forwards
`ioi-validator/consensus-aft`, so the inventoried build CAN name `SlhDsaSealKeyPair::generate` and
`DurableSealSignerV2::provision` (both draw a seed and return a key). Re-derived from cargo metadata's RESOLVED graph of
EVERY configuration (the IOI Director's amendment (2): never manifest text), by the gate itself on each run:

- `feature-scopes.tsv` row `seal-signer`: ON in a configuration whose ioi-node or ioi-services resolves ioi-validator as a
  direct dependency with `consensus-aft`: 7 of 8 (node-profile, the four profiles, all-hash, all-kzg); OFF in `default`
  (there ioi-validator is no resolved dependency of either inventoried package). Where ON, the gate passes the canary
  feature `seal-signer` and the canary must report each `// deny-in seal-signer:` entry once; where OFF those canary
  lines are compiled out and must report 0. Passing the canary feature changes no production package's resolved
  features in any of the 7 (cargo tree of the three selected packages, with and without it).
- Both key generators are deny-list entries (clippy.toml) in every configuration. No inventoried function calls either
  today (a read-only survey of consensus-aft's public surface); a call would be a draw site.
- The rest of consensus-aft's drawing surface: the `common::seal_signer::*` glob re-export is the same two items;
  `DurableSealSignerV2::{sign, open}` and the ioi-consensus aft journal types draw internally only (the "draw
  internally" class above); `ioi_finality::portable_assurance::generate_portable_receipt_key` draws and returns a key,
  but ioi-finality is a direct dependency of neither inventoried package and nothing they depend on re-exports it, so it
  cannot be named; a new direct dependency re-opens this review through `deps.pin`'s `dep` lines.
- Every other conclusion of this review that rests on a dependency feature being OFF is a `-` row of
  `feature-scopes.tsv` (uuid v1/v6/v7, libp2p secp256k1/ecdsa, k256 ecdh/schnorr, webauthn conditional-ui and
  resident-key, rcgen aws_lc_rs, reqwest multipart): each resolves in 0 of 8 configurations, and resolving one FAILS
  the gate until the review is re-opened.

## Re-opened 2026-10-14: resolved feature selections and forwarding are pinned (Codex batch-3 r6 MAJOR 2)

Codex batch-3 r6 (MAJOR 2) found that `deps.pin` pinned dependency names, versions and feature NAMES only, so
`features = ["consensus-aft"]` on ioi-node's validator line would not re-open this review. `deps.pin` now also holds,
from cargo metadata (`--offline --locked`) of EVERY configuration, normalized and sorted, exactly the lines the gate
prints (`--plan --print`): 74 `forward` lines (each workspace package's feature forwarding the inventoried build
reaches), 656 `select` lines (each dependency feature SELECTION: kind, target, optional, default-features, features)
and 1235 `resolved` lines (the resolved features of every package reached over normal and build edges, per
configuration). Three verdicts name each changed line (`feature_forwarding_equals_the_reviewed_pin`,
`dependency_feature_selections_equal_the_reviewed_pin`, `resolved_features_equal_the_reviewed_pin`): Codex's
validator-line plant fails the selection verdict, and a new forward fails the forwarding and resolved verdicts, by name,
until the review is re-confirmed. No conclusion of this review changed when these lines were first pinned. cargo
metadata resolves the whole workspace, so a `resolved` line can only OVER-state a configuration's features.

## Re-opened 2026-10-14: the hand-out reconcile's reviewed exclusions (Codex batch-3 r6 MAJOR 3)

Every own function the reconcile (src/handouts.rs) derives as a CANDIDATE hand-out and that is not registered in
`hand-outs.tsv` is listed here with its exact sink kinds and the reason it is not a hand-out; the gate fails on a
candidate in neither place, on a row whose sinks changed, and on a row that is no longer a candidate. A `-` file is a
layer-2-only holder, by its expanded item path.

<!-- reconcile-exclusions begin -->
| file | item | sinks | reason |
|---|---|---|---|
| crates/node/src/bin/guardian.rs | fn main | closure capture | binary entry point: no own caller (a bin's main, or the async body its main runs); its draws stay draw-site rows |
| crates/node/src/bin/hypervisor-daemon.rs | fn async_main | closure capture | binary entry point: no own caller (a bin's main, or the async body its main runs); its draws stay draw-site rows |
| crates/node/src/bin/hypervisor-daemon.rs | fn authorize | closure capture | closure captures consumed in place: the closure or async block runs inside the call and its value is not handed out |
| crates/node/src/bin/hypervisor-daemon.rs | fn handle_token_create | return | HTTP handler referenced only by the route table (hypervisor-daemon.rs): its sink is the response to the client; its draws stay draw-site rows and its mints stay pinned |
| crates/node/src/bin/hypervisor-daemon.rs | fn handle_token_revoke | return | HTTP handler referenced only by the route table (hypervisor-daemon.rs): its sink is the response to the client; its draws stay draw-site rows and its mints stay pinned |
| crates/node/src/bin/hypervisor-daemon.rs | fn handle_tokens_list | return | HTTP handler referenced only by the route table (hypervisor-daemon.rs): its sink is the response to the client; its draws stay draw-site rows and its mints stay pinned |
| crates/node/src/bin/hypervisor_daemon_routes/authority_challenge_routes.rs | fn handle_challenge_decision | return | HTTP handler referenced only by the route table (hypervisor-daemon.rs): its sink is the response to the client; its draws stay draw-site rows and its mints stay pinned |
| crates/node/src/bin/hypervisor_daemon_routes/authority_challenge_routes.rs | fn marker_is_ours | return | a predicate over the drawn value: it returns a bool (whether a marker carries this process's nonce), never the value (outside the ruled classes: disclosed) |
| crates/node/src/bin/hypervisor_daemon_routes/connector_session_routes.rs | fn handle_session_open | return | HTTP handler referenced only by the route table (hypervisor-daemon.rs): its sink is the response to the client; its draws stay draw-site rows and its mints stay pinned |
| crates/node/src/bin/hypervisor_daemon_routes/device_custody_routes.rs | fn handle_authority_start | closure capture,return | HTTP handler referenced only by the route table (hypervisor-daemon.rs): its sink is the response to the client; its draws stay draw-site rows and its mints stay pinned |
| crates/node/src/bin/hypervisor_daemon_routes/device_custody_routes.rs | fn handle_login_finish | return | HTTP handler referenced only by the route table (hypervisor-daemon.rs): its sink is the response to the client; its draws stay draw-site rows and its mints stay pinned |
| crates/node/src/bin/hypervisor_daemon_routes/device_custody_routes.rs | fn handle_login_start | return | HTTP handler referenced only by the route table (hypervisor-daemon.rs): its sink is the response to the client; its draws stay draw-site rows and its mints stay pinned |
| crates/node/src/bin/hypervisor_daemon_routes/device_custody_routes.rs | fn handle_registration_start | return | HTTP handler referenced only by the route table (hypervisor-daemon.rs): its sink is the response to the client; its draws stay draw-site rows and its mints stay pinned |
| crates/node/src/bin/hypervisor_daemon_routes/editor_routes.rs | fn handle_editor_access_lease_create | return | HTTP handler referenced only by the route table (hypervisor-daemon.rs): its sink is the response to the client; its draws stay draw-site rows and its mints stay pinned |
| crates/node/src/bin/hypervisor_daemon_routes/editor_routes.rs | fn handle_editor_service_expose | closure capture,non-local write,return | HTTP handler referenced only by the route table (hypervisor-daemon.rs): its sink is the response to the client; its draws stay draw-site rows and its mints stay pinned |
| crates/node/src/bin/hypervisor_daemon_routes/editor_routes.rs | fn handle_editor_service_start | return | HTTP handler referenced only by the route table (hypervisor-daemon.rs): its sink is the response to the client; its draws stay draw-site rows and its mints stay pinned |
| crates/node/src/bin/hypervisor_daemon_routes/environment_routes.rs | fn handle_env_port_expose | non-local write,return | HTTP handler referenced only by the route table (hypervisor-daemon.rs): its sink is the response to the client; its draws stay draw-site rows and its mints stay pinned |
| crates/node/src/bin/hypervisor_daemon_routes/environment_routes.rs | fn handle_environment_create | return | HTTP handler referenced only by the route table (hypervisor-daemon.rs): its sink is the response to the client; its draws stay draw-site rows and its mints stay pinned |
| crates/node/src/bin/hypervisor_daemon_routes/health_check_routes.rs | fn handle_health_check_create | return | HTTP handler referenced only by the route table (hypervisor-daemon.rs): its sink is the response to the client; its draws stay draw-site rows and its mints stay pinned |
| crates/node/src/bin/hypervisor_daemon_routes/lifecycle_routes.rs | fn handle_agent_create | return | HTTP handler referenced only by the route table (hypervisor-daemon.rs): its sink is the response to the client; its draws stay draw-site rows and its mints stay pinned |
| crates/node/src/bin/hypervisor_daemon_routes/lifecycle_routes.rs | fn handle_agent_run_create | return | HTTP handler referenced only by the route table (hypervisor-daemon.rs): its sink is the response to the client; its draws stay draw-site rows and its mints stay pinned |
| crates/node/src/bin/hypervisor_daemon_routes/lifecycle_routes.rs | fn handle_api_token_create | return | HTTP handler referenced only by the route table (hypervisor-daemon.rs): its sink is the response to the client; its draws stay draw-site rows and its mints stay pinned |
| crates/node/src/bin/hypervisor_daemon_routes/lifecycle_routes.rs | fn handle_auth_bootstrap | return | HTTP handler referenced only by the route table (hypervisor-daemon.rs): its sink is the response to the client; its draws stay draw-site rows and its mints stay pinned |
| crates/node/src/bin/hypervisor_daemon_routes/lifecycle_routes.rs | fn handle_auth_login | return | HTTP handler referenced only by the route table (hypervisor-daemon.rs): its sink is the response to the client; its draws stay draw-site rows and its mints stay pinned |
| crates/node/src/bin/hypervisor_daemon_routes/lifecycle_routes.rs | fn handle_auth_oidc_callback | closure capture,return | HTTP handler referenced only by the route table (hypervisor-daemon.rs): its sink is the response to the client; its draws stay draw-site rows and its mints stay pinned |
| crates/node/src/bin/hypervisor_daemon_routes/lifecycle_routes.rs | fn handle_auth_oidc_start | return | HTTP handler referenced only by the route table (hypervisor-daemon.rs): its sink is the response to the client; its draws stay draw-site rows and its mints stay pinned |
| crates/node/src/bin/hypervisor_daemon_routes/lifecycle_routes.rs | fn handle_connector_invoke | closure capture,return | HTTP handler referenced by the route table and called only by other route handlers (outside the ruled class's 'only': disclosed): its reply reaches the client through them; registering it would make the route table a holder; its draws stay draw-site rows |
| crates/node/src/bin/hypervisor_daemon_routes/lifecycle_routes.rs | fn handle_connector_mcp_tools | return | HTTP handler referenced only by the route table (hypervisor-daemon.rs): its sink is the response to the client; its draws stay draw-site rows and its mints stay pinned |
| crates/node/src/bin/hypervisor_daemon_routes/lifecycle_routes.rs | fn handle_connector_oauth_start | return | HTTP handler referenced only by the route table (hypervisor-daemon.rs): its sink is the response to the client; its draws stay draw-site rows and its mints stay pinned |
| crates/node/src/bin/hypervisor_daemon_routes/lifecycle_routes.rs | fn handle_domain_verification_create | return | HTTP handler referenced only by the route table (hypervisor-daemon.rs): its sink is the response to the client; its draws stay draw-site rows and its mints stay pinned |
| crates/node/src/bin/hypervisor_daemon_routes/lifecycle_routes.rs | fn handle_github_app_installation | return | HTTP handler referenced only by the route table (hypervisor-daemon.rs): its sink is the response to the client; its draws stay draw-site rows and its mints stay pinned |
| crates/node/src/bin/hypervisor_daemon_routes/lifecycle_routes.rs | fn handle_org_invite_accept | return | HTTP handler referenced only by the route table (hypervisor-daemon.rs): its sink is the response to the client; its draws stay draw-site rows and its mints stay pinned |
| crates/node/src/bin/hypervisor_daemon_routes/lifecycle_routes.rs | fn handle_org_invite_get | return | HTTP handler referenced only by the route table (hypervisor-daemon.rs): its sink is the response to the client; its draws stay draw-site rows and its mints stay pinned |
| crates/node/src/bin/hypervisor_daemon_routes/lifecycle_routes.rs | fn handle_org_invite_reset | return | HTTP handler referenced only by the route table (hypervisor-daemon.rs): its sink is the response to the client; its draws stay draw-site rows and its mints stay pinned |
| crates/node/src/bin/hypervisor_daemon_routes/lifecycle_routes.rs | fn handle_scim_config_create | return | HTTP handler referenced only by the route table (hypervisor-daemon.rs): its sink is the response to the client; its draws stay draw-site rows and its mints stay pinned |
| crates/node/src/bin/hypervisor_daemon_routes/lifecycle_routes.rs | fn handle_scm_abandon_pull_request | return | HTTP handler referenced only by the route table (hypervisor-daemon.rs): its sink is the response to the client; its draws stay draw-site rows and its mints stay pinned |
| crates/node/src/bin/hypervisor_daemon_routes/lifecycle_routes.rs | fn handle_session_execute | return | HTTP handler referenced only by the route table (hypervisor-daemon.rs): its sink is the response to the client; its draws stay draw-site rows and its mints stay pinned |
| crates/node/src/bin/hypervisor_daemon_routes/lifecycle_routes.rs | fn handle_subagent_spawn | return | HTTP handler referenced only by the route table (hypervisor-daemon.rs): its sink is the response to the client; its draws stay draw-site rows and its mints stay pinned |
| crates/node/src/bin/hypervisor_daemon_routes/lifecycle_routes.rs | fn handle_thread_create | return | HTTP handler referenced only by the route table (hypervisor-daemon.rs): its sink is the response to the client; its draws stay draw-site rows and its mints stay pinned |
| crates/node/src/bin/hypervisor_daemon_routes/lifecycle_routes.rs | fn handle_turn_create | return | HTTP handler referenced only by the route table (hypervisor-daemon.rs): its sink is the response to the client; its draws stay draw-site rows and its mints stay pinned |
| crates/node/src/bin/hypervisor_daemon_routes/lifecycle_routes.rs | fn hash_password | return | randomized encryption or password-hashing wrapper: the draw is a salt or nonce inside the ciphertext or verifier, not a value the caller uses |
| crates/node/src/bin/hypervisor_daemon_routes/lifecycle_routes.rs | fn import_guest_workspace | closure capture,return | temporary-path uniqueness: the draw names a temporary file, directory or socket the call uses itself, not an id or a secret |
| crates/node/src/bin/hypervisor_daemon_routes/lifecycle_routes.rs | fn seal_scm_token | return | randomized encryption or password-hashing wrapper: the draw is a salt or nonce inside the ciphertext or verifier, not a value the caller uses |
| crates/node/src/bin/hypervisor_daemon_routes/lifecycle_routes.rs | mod runtime_host > fn handle_runtime_host_session | return | HTTP handler referenced by the route table and called only by other route handlers (outside the ruled class's 'only': disclosed): its reply reaches the client through them; registering it would make the route table a holder; its draws stay draw-site rows |
| crates/node/src/bin/hypervisor_daemon_routes/lifecycle_routes.rs | mod runtime_host > impl DaemonHostStateAccess > fn persist_key | closure capture | temporary-path uniqueness: the draw names a temporary file, directory or socket the call uses itself, not an id or a secret |
| crates/node/src/bin/hypervisor_daemon_routes/machine_routes.rs | fn handle_machine_operation_submit | return | HTTP handler referenced only by the route table (hypervisor-daemon.rs): its sink is the response to the client; its draws stay draw-site rows and its mints stay pinned |
| crates/node/src/bin/hypervisor_daemon_routes/managed_runtime_routes.rs | fn build_export_bundle | return | temporary-path uniqueness: the draw names a temporary file, directory or socket the call uses itself, not an id or a secret |
| crates/node/src/bin/hypervisor_daemon_routes/managed_runtime_routes.rs | fn handle_backup_export | return | HTTP handler referenced only by the route table (hypervisor-daemon.rs): its sink is the response to the client; its draws stay draw-site rows and its mints stay pinned |
| crates/node/src/bin/hypervisor_daemon_routes/managed_runtime_routes.rs | fn handle_backup_import | closure capture,return | temporary-path uniqueness: the draw names a temporary file, directory or socket the call uses itself, not an id or a secret |
| crates/node/src/bin/hypervisor_daemon_routes/materializing_run_routes.rs | fn handle_mrun_acquire_lease | return | HTTP handler referenced only by the route table (hypervisor-daemon.rs): its sink is the response to the client; its draws stay draw-site rows and its mints stay pinned |
| crates/node/src/bin/hypervisor_daemon_routes/microvm.rs | fn hostile_guest_proposal_roundtrip | closure capture,return | temporary-path uniqueness: the draw names a temporary file, directory or socket the call uses itself, not an id or a secret |
| crates/node/src/bin/hypervisor_daemon_routes/microvm.rs | fn stage_and_start_model_proxy | closure capture | temporary-path uniqueness: the draw names a temporary file, directory or socket the call uses itself, not an id or a secret |
| crates/node/src/bin/hypervisor_daemon_routes/microvm.rs | impl HostileGuestRoundtripDir > fn create | return | temporary-path uniqueness: the draw names a temporary file, directory or socket the call uses itself, not an id or a secret |
| crates/node/src/bin/hypervisor_daemon_routes/model_routes.rs | fn handle_model_route_credential_bind | return | HTTP handler referenced only by the route table (hypervisor-daemon.rs): its sink is the response to the client; its draws stay draw-site rows and its mints stay pinned |
| crates/node/src/bin/hypervisor_daemon_routes/operations_support_routes.rs | fn handle_incident_create | return | HTTP handler referenced only by the route table (hypervisor-daemon.rs): its sink is the response to the client; its draws stay draw-site rows and its mints stay pinned |
| crates/node/src/bin/hypervisor_daemon_routes/orchestration_routes.rs | fn handle_automation_create | return | HTTP handler referenced only by the route table (hypervisor-daemon.rs): its sink is the response to the client; its draws stay draw-site rows and its mints stay pinned |
| crates/node/src/bin/hypervisor_daemon_routes/orchestration_routes.rs | fn handle_automation_start | return | HTTP handler referenced only by the route table (hypervisor-daemon.rs): its sink is the response to the client; its draws stay draw-site rows and its mints stay pinned |
| crates/node/src/bin/hypervisor_daemon_routes/orchestration_routes.rs | fn handle_automation_webhook | closure capture,return | HTTP handler referenced only by the route table (hypervisor-daemon.rs): its sink is the response to the client; its draws stay draw-site rows and its mints stay pinned |
| crates/node/src/bin/hypervisor_daemon_routes/orchestration_routes.rs | fn handle_automation_webhook_rotate | return | HTTP handler referenced only by the route table (hypervisor-daemon.rs): its sink is the response to the client; its draws stay draw-site rows and its mints stay pinned |
| crates/node/src/bin/hypervisor_daemon_routes/portal_session_exchange_routes.rs | fn handle_portal_session_exchange | return | HTTP handler referenced only by the route table (hypervisor-daemon.rs): its sink is the response to the client; its draws stay draw-site rows and its mints stay pinned |
| crates/node/src/bin/hypervisor_daemon_routes/provider_connection_routes.rs | fn handle_connection_reauthorize | return | HTTP handler referenced only by the route table (hypervisor-daemon.rs): its sink is the response to the client; its draws stay draw-site rows and its mints stay pinned |
| crates/node/src/bin/hypervisor_daemon_routes/provider_connection_routes.rs | fn handle_connection_start | return | HTTP handler referenced only by the route table (hypervisor-daemon.rs): its sink is the response to the client; its draws stay draw-site rows and its mints stay pinned |
| crates/node/src/bin/hypervisor_daemon_routes/provider_routes.rs | fn handle_provider_operation_proposal_issue | return | HTTP handler referenced only by the route table (hypervisor-daemon.rs): its sink is the response to the client; its draws stay draw-site rows and its mints stay pinned |
| crates/node/src/bin/hypervisor_daemon_routes/scm_publication_routes.rs | fn handle_scm_publish | return | HTTP handler referenced by the route table and called only by other route handlers (outside the ruled class's 'only': disclosed): its reply reaches the client through them; registering it would make the route table a holder; its draws stay draw-site rows |
| crates/node/src/bin/hypervisor_daemon_routes/standing_envelope_routes.rs | fn handle_standing_envelope_create | return | HTTP handler referenced only by the route table (hypervisor-daemon.rs): its sink is the response to the client; its draws stay draw-site rows and its mints stay pinned |
| crates/node/src/bin/hypervisor_daemon_routes/standing_envelope_routes.rs | impl StandingAuthority > fn record | closure capture,return | temporary-path uniqueness: the draw names a temporary file, directory or socket the call uses itself, not an id or a secret |
| crates/node/src/bin/hypervisor_daemon_routes/storage_backend_routes.rs | fn seal_archive_bytes | return | randomized encryption or password-hashing wrapper: the draw is a salt or nonce inside the ciphertext or verifier, not a value the caller uses |
| crates/node/src/bin/hypervisor_daemon_routes/supervisor_routes.rs | fn handle_env_ops_lease | return | HTTP handler referenced only by the route table (hypervisor-daemon.rs): its sink is the response to the client; its draws stay draw-site rows and its mints stay pinned |
| crates/node/src/bin/hypervisor_daemon_routes/system_activation_routes.rs | fn handle_activate | return | HTTP handler referenced only by the route table (hypervisor-daemon.rs): its sink is the response to the client; its draws stay draw-site rows and its mints stay pinned |
| crates/node/src/bin/hypervisor_daemon_routes/system_activation_routes.rs | fn handle_initialize | return | HTTP handler referenced only by the route table (hypervisor-daemon.rs): its sink is the response to the client; its draws stay draw-site rows and its mints stay pinned |
| crates/node/src/bin/hypervisor_daemon_routes/system_continuity_routes.rs | fn handle_transition | closure capture,return | HTTP handler referenced only by the route table (hypervisor-daemon.rs): its sink is the response to the client; its draws stay draw-site rows and its mints stay pinned |
| crates/node/src/bin/hypervisor_daemon_routes/system_genesis_routes.rs | fn handle_admit | return | HTTP handler referenced only by the route table (hypervisor-daemon.rs): its sink is the response to the client; its draws stay draw-site rows and its mints stay pinned |
| crates/node/src/bin/hypervisor_daemon_routes/system_protected_transition_routes.rs | fn handle_transition | closure capture,return | HTTP handler referenced only by the route table (hypervisor-daemon.rs): its sink is the response to the client; its draws stay draw-site rows and its mints stay pinned |
| crates/node/src/bin/hypervisor_daemon_routes/system_sequence_zero_routes.rs | fn handle_materialize | closure capture,return | HTTP handler referenced only by the route table (hypervisor-daemon.rs): its sink is the response to the client; its draws stay draw-site rows and its mints stay pinned |
| crates/node/src/bin/hypervisor_daemon_routes/workload_effect_boundary.rs | fn handle_governed_capability_mint | return | HTTP handler referenced only by the route table (hypervisor-daemon.rs): its sink is the response to the client; its draws stay draw-site rows and its mints stay pinned |
| crates/node/src/bin/ioi-agent.rs | fn main | return | binary entry point: no own caller (a bin's main, or the async body its main runs); its draws stay draw-site rows |
| crates/node/src/bin/ioi-local.rs | fn async_main | closure capture | binary entry point: no own caller (a bin's main, or the async body its main runs); its draws stay draw-site rows |
| crates/node/src/bin/ioi-provider.rs | fn main | closure capture | binary entry point: no own caller (a bin's main, or the async body its main runs); its draws stay draw-site rows |
| crates/node/src/bin/orchestration.rs | fn main | return | binary entry point: no own caller (a bin's main, or the async body its main runs); its draws stay draw-site rows |
| crates/node/src/bin/signer.rs | fn main | closure capture | binary entry point: no own caller (a bin's main, or the async body its main runs); its draws stay draw-site rows |
| crates/services/src/agentic/intent.rs | impl IntentResolver > fn resolve_intent | closure capture,return | no production caller in the inventoried code: nothing is handed to an own caller, and an own deny-list entry with no reported caller fails the gate (outside the ruled classes: disclosed; a later caller is not a site until this row is re-reviewed) |
| crates/services/src/agentic/runtime/connectors/google_workspace/configure.rs | fn connector_configure | return | no production caller in the inventoried code: nothing is handed to an own caller, and an own deny-list entry with no reported caller fails the gate (outside the ruled classes: disclosed; a later caller is not a site until this row is re-reviewed) |
| crates/services/src/agentic/runtime/firewall_receipt_keys.rs | impl FirewallReceiptKeyStore > fn rotate | non-local write,return | no production caller in the inventoried code: nothing is handed to an own caller, and an own deny-list entry with no reported caller fails the gate (outside the ruled classes: disclosed; a later caller is not a site until this row is re-reviewed) |
| crates/services/src/agentic/runtime/kernel/mod.rs | impl RuntimeKernelService > fn plan_model_mount_capability_token_control | return | no production caller in the inventoried code: nothing is handed to an own caller, and an own deny-list entry with no reported caller fails the gate (outside the ruled classes: disclosed; a later caller is not a site until this row is re-reviewed) |
| crates/services/src/agentic/web/transport.rs | fn fetch_binary_http_fallback_browser_ua_with_final_url | return | User-Agent fetch wrapper: it returns the fetched page, not the User-Agent (the User-Agent draw is a selected_browser_http_user_agent hand-out row) |
| crates/services/src/agentic/web/transport.rs | fn fetch_html_http_fallback_browser_ua | return | User-Agent fetch wrapper: it returns the fetched page, not the User-Agent (the User-Agent draw is a selected_browser_http_user_agent hand-out row) |
| crates/services/src/agentic/web/transport.rs | fn fetch_html_http_fallback_browser_ua_with_final_url | return | User-Agent fetch wrapper: it returns the fetched page, not the User-Agent (the User-Agent draw is a selected_browser_http_user_agent hand-out row) |
| crates/services/src/agentic/web/transport.rs | fn fetch_structured_detail_http_fallback_browser_ua | return | User-Agent fetch wrapper: it returns the fetched page, not the User-Agent (the User-Agent draw is a selected_browser_http_user_agent hand-out row) |
| crates/services/src/agentic/web/transport.rs | fn fetch_structured_detail_http_fallback_browser_ua_with_final_url | return | User-Agent fetch wrapper: it returns the fetched page, not the User-Agent (the User-Agent draw is a selected_browser_http_user_agent hand-out row) |
| crates/services/src/market/router.rs | impl ProvisioningRouter > fn launch_agent | return | no production caller in the inventoried code: nothing is handed to an own caller, and an own deny-list entry with no reported caller fails the gate (outside the ruled classes: disclosed; a later caller is not a site until this row is re-reviewed) |
| crates/services/src/wallet_network/handlers/connectors/auth.rs | fn connector_auth_export | &mut parameter | randomized encryption or password-hashing wrapper: the draw is a salt or nonce inside the ciphertext or verifier, not a value the caller uses |
| crates/services/src/wallet_network/support.rs | fn encrypt_secret_payload | return | randomized encryption or password-hashing wrapper: the draw is a salt or nonce inside the ciphertext or verifier, not a value the caller uses |
<!-- reconcile-exclusions end -->
