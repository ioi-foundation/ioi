// cf12: Debug-formatting the inbound CompareOnlyDigest (no Debug).
// Weakening: add Debug.
use ioi_editor_proxy_ipc::CompareOnlyDigest;

pub fn negative(digest: &CompareOnlyDigest) -> String {
    format!("{:?}", digest) //~ cf12
}
