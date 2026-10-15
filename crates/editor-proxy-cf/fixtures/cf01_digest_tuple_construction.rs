// cf01: tuple construction of the outbound Sha256Digest (its field is private).
// Weakening: a public tuple field.
use ioi_proxy_digest::Sha256Digest;

pub fn negative() -> Sha256Digest {
    Sha256Digest([0u8; 32]) //~ cf01
}
