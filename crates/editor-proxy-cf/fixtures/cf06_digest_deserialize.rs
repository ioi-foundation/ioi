// cf06: serde deserialization of the outbound Sha256Digest (no Deserialize).
// Weakening: add Deserialize in the weakened defining crate.
use ioi_proxy_digest::Sha256Digest;

pub fn negative<'de, D: serde::Deserializer<'de>>(input: D) -> bool {
    <Sha256Digest as serde::Deserialize<'de>>::deserialize(input).is_ok() //~ cf06
}
