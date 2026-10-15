// cf00 POSITIVE (DESIGN v2 (4)): hashing, outbound ADMIT construction, encoding, trusted decoding
// and comparison of a decoded inbound digest all compile against the production crates. If this
// fixture fails, every negative's evidence is invalid (a setup error), never a pass.
use ioi_editor_proxy_ipc::{
    decode_p2d, encode_p2d, AdmissionId, InboundP2d, OutboundAdmit, OutboundP2d, Purpose,
    Sha256Digest,
};

pub fn positive() -> bool {
    let digest = Sha256Digest::of(b"lease-token");
    let copy = digest;
    let admit = match OutboundAdmit::new(Purpose::Forward, &[digest, copy]) {
        Ok(admit) => admit,
        Err(_) => return false,
    };
    let frame = encode_p2d(&OutboundP2d::Admit(AdmissionId::from_raw(1), admit));
    match decode_p2d(frame.as_bytes()) {
        Ok(InboundP2d::Admit(inbound)) => inbound.any_matches_stored_hex("00"),
        _ => false,
    }
}
