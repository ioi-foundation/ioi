// cf03: TryFrom<[u8; 32]> for the outbound Sha256Digest (no conversion).
// Weakening: add exactly TryFrom<[u8; 32]>.
use ioi_proxy_digest::Sha256Digest;

pub fn negative() -> bool {
    Sha256Digest::try_from([0u8; 32]).is_ok() //~ cf03
}
