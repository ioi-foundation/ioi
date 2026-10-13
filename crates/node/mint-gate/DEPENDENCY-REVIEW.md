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
- ioi-validator's seal-signer keys (`SlhDsaSealKeyPair::generate`, `DurableSealSignerV2::provision`): they exist only
  under ioi-validator's `consensus-aft`, which ioi-node's dependency on ioi-validator (default-features = false) does not
  request; the canary depends on ioi-validator the same way, so they cannot be named here. A change of that dependency
  line re-opens the review through `deps.pin`;
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
