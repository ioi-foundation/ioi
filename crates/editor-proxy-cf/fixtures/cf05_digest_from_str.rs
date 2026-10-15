// cf05: parsing a string into the outbound Sha256Digest (no FromStr).
// Weakening: add FromStr.
use ioi_proxy_digest::Sha256Digest;

pub fn negative() -> bool {
    "00".parse::<Sha256Digest>().is_ok() //~ cf05
}
