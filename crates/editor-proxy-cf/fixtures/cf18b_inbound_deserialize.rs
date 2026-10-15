// cf18b: serde deserialization of an inbound CompareOnlyDigest (no Deserialize).
// Weakening: add Deserialize.
use ioi_editor_proxy_ipc::CompareOnlyDigest;

pub fn negative<'de, D: serde::Deserializer<'de>>(input: D) -> bool {
    <CompareOnlyDigest as serde::Deserialize<'de>>::deserialize(input).is_ok() //~ cf18b
}
