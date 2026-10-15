// cf20 (T-API): a downstream LOCAL macro cannot reach the inbound digest's private field.
// Weakening: expose the field.
use ioi_editor_proxy_ipc::CompareOnlyDigest;

macro_rules! raw_field {
    ($digest:expr) => {
        $digest.0 //~ cf20
    };
}

pub fn negative(digest: &CompareOnlyDigest) -> [u8; 32] {
    raw_field!(digest)
}
