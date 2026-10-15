#![forbid(unsafe_code)]
// cf09 PREMISE (the forbid(unsafe_code) lint; not an API RED mutant and not hash provenance): a
// crate that forbids unsafe code cannot transmute bytes into the digest. Paired control: the
// identical fixture without the forbid line compiles (metadata only; never executed).
use ioi_proxy_digest::Sha256Digest;

pub fn negative() -> Sha256Digest {
    unsafe { core::mem::transmute::<[u8; 32], Sha256Digest>([0u8; 32]) } //~ cf09
}
