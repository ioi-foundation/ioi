// cf14: direct tuple construction of the inbound CompareOnlyDigest (privacy).
// Weakening: expose the tuple field/constructor for this weakening only.
use ioi_editor_proxy_ipc::CompareOnlyDigest;

pub fn negative() -> CompareOnlyDigest {
    CompareOnlyDigest([0u8; 32]) //~ cf14
}
