// cf15: cloning a BORROWED inbound CompareOnlyDigest into an OWNED value (no Clone; cloning the
// reference cannot satisfy the owned type).
// Weakening: add Clone.
use ioi_editor_proxy_ipc::CompareOnlyDigest;

pub fn negative(digest: &CompareOnlyDigest) -> CompareOnlyDigest {
    let owned: CompareOnlyDigest = digest.clone(); //~ cf15
    owned
}
