// cf02: a raw array `.into()` an outbound Sha256Digest (no From<[u8; 32]>).
// Weakening: add exactly From<[u8; 32]>.
use ioi_proxy_digest::Sha256Digest;

pub fn negative() -> Sha256Digest {
    let digest: Sha256Digest = [0u8; 32].into(); //~ cf02
    digest
}
