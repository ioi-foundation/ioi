// cf07: reading the outbound field `.0` (privacy; the read-only view is `as_bytes`).
// Weakening: expose that field.
use ioi_proxy_digest::Sha256Digest;

pub fn negative(digest: &Sha256Digest) -> [u8; 32] {
    digest.0 //~ cf07
}
