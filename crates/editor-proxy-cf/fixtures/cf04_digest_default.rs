// cf04: Default for the outbound Sha256Digest (no such method).
// Weakening: add Default.
use ioi_proxy_digest::Sha256Digest;

pub fn negative() -> Sha256Digest {
    Sha256Digest::default() //~ cf04
}
