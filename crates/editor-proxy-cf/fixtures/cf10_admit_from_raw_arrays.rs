// cf10: a raw-array slice passed to the outbound ADMIT builder (it takes only hashed digests).
// Weakening: change only the weakened builder's input type to raw arrays.
use ioi_editor_proxy_ipc::{OutboundAdmit, Purpose};

pub fn negative() -> bool {
    OutboundAdmit::new(Purpose::Forward, &[[0u8; 32]]).is_ok() //~ cf10
}
