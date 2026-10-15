// cf08 PREMISE (E0117, the Rust orphan rule; not an API RED mutant): a downstream crate cannot
// implement a foreign trait for the foreign digest. Paired control: the SAME fixture with a local
// target type compiles.
use ioi_proxy_digest::Sha256Digest;

pub struct LocalDigest;

impl From<[u8; 32]> for Sha256Digest { //~ cf08
    fn from(_bytes: [u8; 32]) -> Self {
        loop {}
    }
}
