//! OS-seeded CSPRNG bridge for dcrypt v4's caller-owned randomness boundary.
//!
//! dcrypt v4 no longer accepts `rand`'s `OsRng`/`ThreadRng`: key generation and
//! encapsulation are generic over dcrypt's own `CryptoRng`. `ChaCha20Rng` is
//! dcrypt's supplied CSPRNG; we seed it with 32 bytes drawn from the operating
//! system's entropy source so every keygen still roots in OS randomness.

use rand::RngCore as _;

/// A ChaCha20 CSPRNG seeded from 32 bytes of OS entropy. Satisfies dcrypt v4's
/// `CryptoRng` bound for `keypair`/`encapsulate`.
pub(crate) fn os_rng() -> dcrypt::internal::ChaCha20Rng {
    let mut seed = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut seed);
    dcrypt::internal::ChaCha20Rng::from_seed(seed)
}
