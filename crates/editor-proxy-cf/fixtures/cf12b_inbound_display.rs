// cf12b: Display-formatting the inbound CompareOnlyDigest (no Display).
// Weakening: add Display.
use ioi_editor_proxy_ipc::CompareOnlyDigest;

pub fn negative(digest: &CompareOnlyDigest) -> String {
    format!("{}", digest) //~ cf12b
}
