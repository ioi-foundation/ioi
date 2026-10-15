// cf16 (T-DIRECTION): the production encoder given a DECODED inbound P2D message (encode_p2d accepts
// only outbound messages).
// Weakening: add a production encoder accepting the inbound type.
use ioi_editor_proxy_ipc::{decode_p2d, encode_p2d, InboundP2d};

pub fn negative(bytes: &[u8]) -> usize {
    let decoded: InboundP2d = match decode_p2d(bytes) {
        Ok(decoded) => decoded,
        Err(_) => return 0,
    };
    encode_p2d(&decoded).as_bytes().len() //~ cf16
}
