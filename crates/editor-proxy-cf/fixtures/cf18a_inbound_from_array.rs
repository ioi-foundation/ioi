// cf18a: a raw array `.into()` an inbound CompareOnlyDigest (no From<[u8; 32]>).
// Weakening: add From<[u8; 32]>.
use ioi_editor_proxy_ipc::CompareOnlyDigest;

pub fn negative() -> CompareOnlyDigest {
    let digest: CompareOnlyDigest = [0u8; 32].into(); //~ cf18a
    digest
}
