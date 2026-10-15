// cf17: calling the decoder-private array constructor of CompareOnlyDigest (legitimate full-frame
// decoding stays allowed: cf00).
// Weakening: make that constructor public.
use ioi_editor_proxy_ipc::CompareOnlyDigest;

pub fn negative() -> CompareOnlyDigest {
    CompareOnlyDigest::from_wire([0u8; 32]) //~ cf17
}
