// cf11: a byte accessor on the inbound CompareOnlyDigest (none exists).
// Weakening: add an accessor.
use ioi_editor_proxy_ipc::CompareOnlyDigest;

pub fn negative(digest: &CompareOnlyDigest) -> [u8; 32] {
    *digest.as_bytes() //~ cf11
}
