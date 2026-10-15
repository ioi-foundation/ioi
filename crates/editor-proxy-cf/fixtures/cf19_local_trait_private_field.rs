// cf19 (T-API): a downstream LOCAL trait implemented for the foreign digest (legal: not excluded by
// the orphan premise) still cannot reach its private field.
// Weakening: expose the field.
use ioi_proxy_digest::Sha256Digest;

pub trait Peek {
    fn peek(&self) -> [u8; 32];
}

impl Peek for Sha256Digest {
    fn peek(&self) -> [u8; 32] {
        self.0 //~ cf19
    }
}
