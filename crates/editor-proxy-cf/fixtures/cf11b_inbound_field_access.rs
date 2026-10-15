// cf11b: reading the inbound field `.0` (privacy).
// Weakening: expose the field.
use ioi_editor_proxy_ipc::CompareOnlyDigest;

pub fn negative(digest: &CompareOnlyDigest) -> [u8; 32] {
    digest.0 //~ cf11b
}
