//! The mint gate's canary BINARY (crates/node/mint-gate): checked in EVERY gate invocation, never
//! run. Every line marked `// deny: <path>` uses that external deny-list entry once, and the gate
//! requires exactly one report of it on that line; `// canary: production` is a planted production
//! mint (must be reported); `// canary: test-only` lines are compiled out of a non-test build (must
//! NOT be reported); `// canary: external macro` invokes the canary library's macro, an external
//! crate's macro to this binary (must be reported at the invocation). Keep one marked use per line.
#![allow(dead_code, unused, deprecated, clippy::all)]

use ioi_api::crypto::KeyEncapsulation;
use rand::distributions::uniform::{SampleRange, UniformInt, UniformSampler};
use rand::distributions::{Alphanumeric, DistString, Distribution, Standard};
use rand::seq::{IteratorRandom, SliceRandom};
use rand::{Fill, Rng, RngCore, SeedableRng};

fn main() {}

// ---- the plants ---------------------------------------------------------------------------------

/// A production credential mint: its draw is reported (layer 1) and its prefixed literal is seen
/// in the expansion (layer 2).
fn planted_production_mint() -> String {
    let mut secret = [0u8; 16];
    RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut secret); // canary: production
    let _ = [
        #[cfg(test)]
        {
            RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut secret); // canary: test-only
            0u8
        },
        0u8,
    ];
    format!("ioi_pat_{secret:?}")
}

/// A draw inside an EXTERNAL crate's macro (the canary library's).
fn external_macro_draw() -> [u8; 16] {
    let mut buf = [0u8; 16];
    ioi_node_mint_gate_canary::external_draw!(&mut buf); // canary: external macro
    buf
}

#[cfg(test)]
mod planted_test_only {
    pub fn mint() -> String {
        let mut secret = [0u8; 16];
        rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut secret); // canary: test-only
        format!("ioi_pat_{secret:?}")
    }
}

// ---- rand 0.8: types ----------------------------------------------------------------------------

fn ty_os(_: rand::rngs::OsRng) {} // deny: rand::rngs::OsRng
fn ty_thread(_: rand::rngs::ThreadRng) {} // deny: rand::rngs::ThreadRng
fn ty_std(_: rand::rngs::StdRng) {} // deny: rand::rngs::StdRng
fn ty_small(_: rand::rngs::SmallRng) {} // deny: rand::rngs::SmallRng

// ---- rand 0.8: functions and methods ------------------------------------------------------------

fn rand_surface() {
    let mut os = rand::rngs::OsRng;
    let mut buf = [0u8; 8];
    let mut items = vec![1u8, 2, 3];
    let _ = rand::thread_rng; // deny: rand::thread_rng
    let _ = rand::random::<u8>; // deny: rand::random
    let _ = rand::seq::index::sample(&mut os, 4, 2); // deny: rand::seq::index::sample
    let _ = rand::seq::index::sample_weighted(&mut os, 3, |_| 1.0f64, 2); // deny: rand::seq::index::sample_weighted
    let _ = os.next_u32(); // deny: rand::RngCore::next_u32
    let _ = os.next_u64(); // deny: rand::RngCore::next_u64
    os.fill_bytes(&mut buf); // deny: rand::RngCore::fill_bytes
    let _ = os.try_fill_bytes(&mut buf); // deny: rand::RngCore::try_fill_bytes
    let _: u8 = os.gen(); // deny: rand::Rng::gen
    let _: u8 = os.gen_range(0..4); // deny: rand::Rng::gen_range
    let _: u8 = os.sample(Standard); // deny: rand::Rng::sample
    let _ = os.sample_iter::<u8, _>(Standard); // deny: rand::Rng::sample_iter
    os.fill(&mut buf[..]); // deny: rand::Rng::fill
    let _ = os.try_fill(&mut buf[..]); // deny: rand::Rng::try_fill
    let _ = os.gen_bool(0.5); // deny: rand::Rng::gen_bool
    let _ = os.gen_ratio(1, 2); // deny: rand::Rng::gen_ratio
    let _ = Fill::try_fill(&mut buf[..], &mut os); // deny: rand::Fill::try_fill
    let _ = rand::rngs::SmallRng::from_entropy; // deny: rand::SeedableRng::from_entropy
    let _ = rand::rngs::SmallRng::from_rng(&mut os); // deny: rand::SeedableRng::from_rng
    let _: u8 = Distribution::sample(&Standard, &mut os); // deny: rand::distributions::Distribution::sample
    let _ = Distribution::<u8>::sample_iter(Standard, &mut os); // deny: rand::distributions::Distribution::sample_iter
    let _ = Alphanumeric.sample_string(&mut os, 4); // deny: rand::distributions::DistString::sample_string
    let mut text = String::new();
    Alphanumeric.append_string(&mut os, &mut text, 4); // deny: rand::distributions::DistString::append_string
    let uniform = UniformInt::<u32>::new(0u32, 9u32);
    let _ = UniformSampler::sample(&uniform, &mut os); // deny: rand::distributions::uniform::UniformSampler::sample
    let _ = UniformInt::<u32>::sample_single(0u32, 9u32, &mut os); // deny: rand::distributions::uniform::UniformSampler::sample_single
    let _ = UniformInt::<u32>::sample_single_inclusive(0u32, 9u32, &mut os); // deny: rand::distributions::uniform::UniformSampler::sample_single_inclusive
    let _ = SampleRange::sample_single(0u32..9, &mut os); // deny: rand::distributions::uniform::SampleRange::sample_single
    let _ = items.choose(&mut os); // deny: rand::seq::SliceRandom::choose
    let _ = items.choose_mut(&mut os); // deny: rand::seq::SliceRandom::choose_mut
    let _ = items.choose_multiple(&mut os, 1); // deny: rand::seq::SliceRandom::choose_multiple
    let _ = items.choose_weighted(&mut os, |_| 1.0f64); // deny: rand::seq::SliceRandom::choose_weighted
    let _ = items.choose_weighted_mut(&mut os, |_| 1.0f64); // deny: rand::seq::SliceRandom::choose_weighted_mut
    let _ = items.choose_multiple_weighted(&mut os, 1, |_| 1.0f64); // deny: rand::seq::SliceRandom::choose_multiple_weighted
    items.shuffle(&mut os); // deny: rand::seq::SliceRandom::shuffle
    let _ = items.partial_shuffle(&mut os, 1); // deny: rand::seq::SliceRandom::partial_shuffle
    let _ = items.iter().choose(&mut os); // deny: rand::seq::IteratorRandom::choose
    let _ = items.iter().choose_stable(&mut os); // deny: rand::seq::IteratorRandom::choose_stable
    let mut pick = [&0u8; 1];
    let _ = items.iter().choose_multiple_fill(&mut os, &mut pick); // deny: rand::seq::IteratorRandom::choose_multiple_fill
    let _ = items.iter().choose_multiple(&mut os, 1); // deny: rand::seq::IteratorRandom::choose_multiple
}

// ---- getrandom, uuid, libc ----------------------------------------------------------------------

fn os_entropy() {
    let mut buf = [0u8; 8];
    let mut uninit = [std::mem::MaybeUninit::<u8>::uninit(); 8];
    let _ = getrandom02::getrandom(&mut buf); // deny: getrandom::getrandom
    let _ = getrandom02::getrandom_uninit(&mut uninit); // deny: getrandom::getrandom_uninit
    let _ = getrandom04::fill(&mut buf); // deny: getrandom::fill
    let _ = getrandom04::fill_uninit(&mut uninit); // deny: getrandom::fill_uninit
    let _ = getrandom04::u32(); // deny: getrandom::u32
    let _ = getrandom04::u64(); // deny: getrandom::u64
    let _ = uuid::Uuid::new_v4; // deny: uuid::Uuid::new_v4
    let _ = libc::getrandom; // deny: libc::getrandom
    let _ = libc::getentropy; // deny: libc::getentropy
    let _ = libc::syscall; // deny: libc::syscall
    let _ = libc::getauxval; // deny: libc::getauxval
    let _ = libc::rand; // deny: libc::rand
    let _ = libc::srand; // deny: libc::srand
    let _ = libc::drand48; // deny: libc::drand48
    let _ = libc::erand48; // deny: libc::erand48
    let _ = libc::lrand48; // deny: libc::lrand48
    let _ = libc::nrand48; // deny: libc::nrand48
    let _ = libc::jrand48; // deny: libc::jrand48
    let _ = libc::srand48; // deny: libc::srand48
    let _ = libc::mrand48; // deny: libc::mrand48
    let _ = libc::seed48; // deny: libc::seed48
    let _ = libc::lcong48; // deny: libc::lcong48
}

// ---- the reviewed direct dependencies' randomness APIs (DEPENDENCY-REVIEW.md) --------------------

fn dependency_helpers() {
    // The fake-credential generator is generic over its ID distribution: name one explicitly.
    use webauthn_rs::fake::FakePasskeyDistribution as Passkeys;
    let mut os = rand::rngs::OsRng;
    let _ = libp2p::identity::ed25519::Keypair::generate; // deny: libp2p_identity::ed25519::Keypair::generate
    let _ = libp2p::identity::ed25519::SecretKey::generate; // deny: libp2p_identity::ed25519::SecretKey::generate
    let _ = libp2p::PeerId::random; // deny: libp2p_identity::PeerId::random
    let _ = libp2p::SwarmBuilder::with_new_identity; // deny: libp2p::SwarmBuilder::with_new_identity
    let _ = k256::ecdsa::SigningKey::random(&mut os); // deny: ecdsa::SigningKey::random
    let _ = k256::SecretKey::random(&mut os); // deny: elliptic_curve::SecretKey::random
    let _ = k256::NonZeroScalar::random(&mut os); // deny: elliptic_curve::NonZeroScalar::random
    let _ = <k256::Scalar as k256::elliptic_curve::Field>::random(&mut os); // deny: ff::Field::random
    let _ = <k256::ProjectivePoint as k256::elliptic_curve::Group>::random(&mut os); // deny: group::Group::random
    let _ = k256::Scalar::generate_biased(&mut os); // deny: k256::Scalar::generate_biased
    let _ = k256::Scalar::generate_vartime(&mut os); // deny: k256::Scalar::generate_vartime
    let _ = webauthn_rs::Webauthn::start_securitykey_registration; // deny: webauthn_rs::Webauthn::start_securitykey_registration
    let _ = webauthn_rs::Webauthn::start_securitykey_authentication; // deny: webauthn_rs::Webauthn::start_securitykey_authentication
    let _ = webauthn_rs::Webauthn::start_attested_passkey_registration; // deny: webauthn_rs::Webauthn::start_attested_passkey_registration
    let _ = webauthn_rs::Webauthn::start_attested_passkey_authentication; // deny: webauthn_rs::Webauthn::start_attested_passkey_authentication
    let _ = webauthn_rs::fake::WebauthnFakeCredentialGenerator::<Passkeys>::new_hmac_key; // deny: webauthn_rs_core::fake::WebauthnFakeCredentialGenerator::new_hmac_key
    let _ = rcgen::KeyPair::generate; // deny: rcgen::KeyPair::generate
    let _ = rcgen::KeyPair::generate_for; // deny: rcgen::KeyPair::generate_for
    let _ = rcgen::generate_simple_self_signed(vec![String::new()]); // deny: rcgen::generate_simple_self_signed
    let provider = rustls::crypto::ring::default_provider();
    let _ = provider.secure_random.fill(&mut [0u8; 4]); // deny: rustls::crypto::SecureRandom::fill
    let chacha = dcrypt::internal::ChaCha20Rng::from_seed; // deny: dcrypt_internal::random::ChaCha20Rng
    let mut rng = chacha([7u8; 32]);
    let _ = dcrypt::internal::RngCore::next_u32(&mut rng); // deny: dcrypt_internal::random::RngCore::next_u32
    let _ = dcrypt::internal::RngCore::next_u64(&mut rng); // deny: dcrypt_internal::random::RngCore::next_u64
    dcrypt::internal::RngCore::fill_bytes(&mut rng, &mut [0u8; 4]); // deny: dcrypt_internal::random::RngCore::fill_bytes
    let _ = dcrypt::internal::RngCore::try_fill_bytes(&mut rng, &mut [0u8; 4]); // deny: dcrypt_internal::random::RngCore::try_fill_bytes
    let _ = <dcrypt::sign::Ed25519 as dcrypt::api::Signature>::keypair(&mut rng); // deny: dcrypt_api::traits::signature::Signature::keypair
    let kem = <dcrypt::kem::MlKem512 as dcrypt::api::Kem>::keypair(&mut rng); // deny: dcrypt_api::traits::kem::Kem::keypair
}

fn dcrypt_encapsulate<K, R>(rng: &mut R, public: &K::PublicKey)
where
    K: dcrypt::api::Kem,
    R: dcrypt::internal::CryptoRng + dcrypt::internal::RngCore,
{
    let _ = K::encapsulate(rng, public); // deny: dcrypt_api::traits::kem::Kem::encapsulate
}

fn workspace_helpers() {
    use ioi_crypto::sign::dilithium::MldsaScheme;
    let _ = ioi_crypto::sign::bls::BlsKeyPair::generate; // deny: ioi_crypto::sign::bls::BlsKeyPair::generate
    let _ = MldsaScheme::generate_keypair; // deny: ioi_crypto::sign::dilithium::MldsaScheme::generate_keypair
    use ioi_crypto::kem::kyber::KyberKEM;
    let _ = <KyberKEM as KeyEncapsulation>::generate_keypair; // deny: ioi_api::crypto::KeyEncapsulation::generate_keypair
    let _ = <KyberKEM as KeyEncapsulation>::encapsulate; // deny: ioi_api::crypto::KeyEncapsulation::encapsulate
    use ioi_crypto::transport::pq_authenticated_channel as pq;
    let _ = pq::start_pq_channel; // deny: ioi_crypto::transport::pq_authenticated_channel::start_pq_channel
    let _ = pq::accept_pq_channel; // deny: ioi_crypto::transport::pq_authenticated_channel::accept_pq_channel
    use ioi_crypto::transport::hybrid_kem_tls as tls;
    let _ = tls::client_post_handshake::<tokio::io::DuplexStream>; // deny: ioi_crypto::transport::hybrid_kem_tls::client_post_handshake
    let _ = tls::server_post_handshake::<tokio::io::DuplexStream>; // deny: ioi_crypto::transport::hybrid_kem_tls::server_post_handshake
    let _ = ioi_client::slicing::SlicePackager::package; // deny: ioi_client::slicing::SlicePackager::package
    use ioi_networking::libp2p::pq_channel::PqChannelSessionManager as Pq;
    let _ = Pq::start; // deny: ioi_networking::libp2p::pq_channel::PqChannelSessionManager::start
    let _ = Pq::accept; // deny: ioi_networking::libp2p::pq_channel::PqChannelSessionManager::accept
    use ioi_state::primitives::lattice::LatticeParams;
    let _ = LatticeParams::new_insecure_for_testing; // deny: ioi_state::primitives::lattice::LatticeParams::new_insecure_for_testing
    use ioi_validator::common::transparency_log::MemoryTransparencyLog;
    let _ = MemoryTransparencyLog::ephemeral("canary"); // deny: ioi_validator::common::transparency_log::MemoryTransparencyLog::ephemeral
    use ioi_validator::standard::provider::ProviderController as Provider;
    let _ = Provider::handle_provision_request; // deny: ioi_validator::standard::provider::ProviderController::handle_provision_request
    let _ = Provider::provision_with_domain; // deny: ioi_validator::standard::provider::ProviderController::provision_with_domain
}

fn ty_lattice(_: &ioi_state::primitives::lattice::LatticeCommitmentScheme) {} // deny: ioi_state::primitives::lattice::LatticeCommitmentScheme
fn ty_pedersen(_: &ioi_state::primitives::pedersen::PedersenCommitmentScheme) {} // deny: ioi_state::primitives::pedersen::PedersenCommitmentScheme
