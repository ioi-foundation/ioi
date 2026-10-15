// cf13: serializing the inbound CompareOnlyDigest (no Serialize: no export).
// Weakening: add Serialize.
use ioi_editor_proxy_ipc::CompareOnlyDigest;

pub fn negative<S: serde::Serializer>(digest: &CompareOnlyDigest, out: S) -> bool {
    serde::Serialize::serialize(digest, out).is_ok() //~ cf13
}
