//! The wire contract (DESIGN v2 (2), "Wire contract and transport"): frames, the stateless
//! decoders, the directional message types and the OUTBOUND-only P2D encoder.
//!
//! | Direction/kind | Body | Total |
//! |---|---|---|
//! | P2D 0x01 READY | empty | 8 |
//! | P2D 0x02 ADMIT | conn:u32, purpose:u8, n:u8 (0..=8; at most 1 for a lease exchange or in static mode), n x 32 bytes | 14+32n <= 270 |
//! | P2D 0x03 EVENT | conn:u32 (=0), code:u16 (1..=12), count:u32 (>=1) | 18 |
//! | D2P 0x81 WELCOME | mode:u8, upstream:u8, public_port:u16, host_label:[u8;16], has_token:u8, token:[u8;64] | 93, one listener fd |
//! | D2P 0x82 VERDICT | conn:u32, outcome:u8 | 13, one fd iff outcome=1 |
//! | D2P 0x83 SHUTDOWN | empty | 8 |

use crate::candidates::{LeaseCandidates, TooManyLeaseCandidates};
use crate::digest::CompareOnlyDigest;
use crate::fds::{FdBatch, ReceivedFd, SocketClass};
use crate::refusal::IpcRefusal;
use crate::types::{AdmissionId, EventCode, ModeKind, Outcome, Purpose};
use ioi_proxy_digest::Sha256Digest;

/// The frame magic, `"IP"`.
pub const MAGIC: [u8; 2] = *b"IP";
/// The protocol version every frame carries, both ways (no version-1 path).
pub const VERSION: u8 = 2;
/// The header's length.
pub const HEADER_LEN: usize = 8;
/// The longest frame either side accepts, INCLUDING the header.
pub const MAX_FRAME: usize = 512;
/// The fixed receive buffer: one byte more than [`MAX_FRAME`], so an over-long datagram is seen as
/// one (and refused) rather than silently cut to a valid length.
pub const RECV_BUF_LEN: usize = MAX_FRAME + 1;
/// The most digests one ADMIT carries.
pub const MAX_DIGESTS: usize = 8;
/// The proxy's bounded ancillary space, in descriptors (more arrive as MSG_CTRUNC).
pub const MAX_ANCILLARY_FDS: usize = 4;
/// A WELCOME's host label: 16 lowercase hex bytes (rendered locally as `p<label>.localhost`).
pub const HOST_LABEL_LEN: usize = 16;
/// A WELCOME's runtime token: 64 lowercase hex bytes, or 64 ZERO bytes when absent.
pub const RUNTIME_TOKEN_LEN: usize = 64;

/// P2D READY.
pub const KIND_READY: u8 = 0x01;
/// P2D ADMIT.
pub const KIND_ADMIT: u8 = 0x02;
/// P2D EVENT.
pub const KIND_EVENT: u8 = 0x03;
/// D2P WELCOME.
pub const KIND_WELCOME: u8 = 0x81;
/// D2P VERDICT.
pub const KIND_VERDICT: u8 = 0x82;
/// D2P SHUTDOWN.
pub const KIND_SHUTDOWN: u8 = 0x83;

/// ADMIT's fixed body bytes before its digests.
pub const ADMIT_MIN_BODY: usize = 6;
/// EVENT's body.
pub const EVENT_BODY: usize = 10;
/// WELCOME's body.
pub const WELCOME_BODY: usize = 85;
/// VERDICT's body.
pub const VERDICT_BODY: usize = 5;

// ------------------------------------------------------------------------------------------------
// Frames
// ------------------------------------------------------------------------------------------------

/// One encoded frame, ready to send as one SEQPACKET message. Only this crate's encoders build one.
pub struct Frame {
    buf: [u8; MAX_FRAME],
    len: usize,
}

impl Frame {
    /// A frame of `kind` with an empty body; the caller `put`s the body and `finish`es.
    pub(crate) fn start(kind: u8) -> Frame {
        let mut buf = [0u8; MAX_FRAME];
        buf[0] = MAGIC[0];
        buf[1] = MAGIC[1];
        buf[2] = VERSION;
        buf[3] = kind;
        Frame {
            buf,
            len: HEADER_LEN,
        }
    }

    /// Appends body bytes (callers never exceed MAX_FRAME: the largest body is 262 bytes).
    pub(crate) fn put(&mut self, bytes: &[u8]) {
        let end = self.len + bytes.len();
        self.buf[self.len..end].copy_from_slice(bytes);
        self.len = end;
    }

    /// Writes body_len; reserved stays zero.
    pub(crate) fn finish(mut self) -> Frame {
        let body_len = (self.len - HEADER_LEN) as u16;
        self.buf[4..6].copy_from_slice(&body_len.to_le_bytes());
        self
    }

    /// The frame's bytes.
    pub fn as_bytes(&self) -> &[u8] {
        &self.buf[..self.len]
    }
}

pub(crate) fn le_u16(bytes: &[u8]) -> u16 {
    u16::from_le_bytes([bytes[0], bytes[1]])
}

pub(crate) fn le_u32(bytes: &[u8]) -> u32 {
    u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]])
}

pub(crate) fn is_lower_hex(byte: &u8) -> bool {
    matches!(*byte, b'0'..=b'9' | b'a'..=b'f')
}

pub(crate) fn is_p2d_kind(kind: u8) -> bool {
    matches!(kind, KIND_READY | KIND_ADMIT | KIND_EVENT)
}

pub(crate) fn is_d2p_kind(kind: u8) -> bool {
    matches!(kind, KIND_WELCOME | KIND_VERDICT | KIND_SHUTDOWN)
}

/// Precedence rows 3 and 4: size, then the header in order (magic, version, kind for this
/// direction, reserved, body_len = received length - 8). Returns the kind and the body.
pub(crate) fn parse_header(
    bytes: &[u8],
    msg_trunc: bool,
    kind_known: fn(u8) -> bool,
) -> Result<(u8, &[u8]), IpcRefusal> {
    if msg_trunc {
        return Err(IpcRefusal::Truncated);
    }
    if bytes.len() > MAX_FRAME {
        return Err(IpcRefusal::Oversized);
    }
    if bytes.len() < HEADER_LEN {
        return Err(IpcRefusal::Truncated);
    }
    if bytes[0..2] != MAGIC {
        return Err(IpcRefusal::BadMagic);
    }
    if bytes[2] != VERSION {
        return Err(IpcRefusal::BadVersion);
    }
    if !kind_known(bytes[3]) {
        return Err(IpcRefusal::UnknownKind);
    }
    if bytes[6] != 0 || bytes[7] != 0 {
        return Err(IpcRefusal::ReservedNonzero);
    }
    if le_u16(&bytes[4..6]) as usize != bytes.len() - HEADER_LEN {
        return Err(IpcRefusal::LengthMismatch);
    }
    Ok((bytes[3], &bytes[HEADER_LEN..]))
}

// ------------------------------------------------------------------------------------------------
// Inbound (decoded) messages
// ------------------------------------------------------------------------------------------------

/// A decoded proxy -> daemon message.
// clippy::large_enum_variant is allowed ON PURPOSE (S1-85D ruling, option (b)): the crate is no_std
// WITHOUT alloc, so the large variant cannot be boxed; it is a fixed-size stack value (at most a few
// hundred bytes) moved once per step through the actor's single-threaded loop.
#[allow(clippy::large_enum_variant)]
pub enum InboundP2d {
    /// READY.
    Ready,
    /// ADMIT, with compare-only digests.
    Admit(InboundAdmit),
    /// EVENT (always conn 0).
    Event(InboundEvent),
}

/// A decoded ADMIT: an id, a purpose and 0..=8 compare-only digests (at most 1 for a lease
/// exchange or in static mode). No digest is retained after the lease comparison (the pending map
/// stores only the id, purpose and deadline).
pub struct InboundAdmit {
    pub(crate) id: AdmissionId,
    pub(crate) purpose: Purpose,
    pub(crate) n: u8,
    pub(crate) digests: [CompareOnlyDigest; MAX_DIGESTS],
}

impl InboundAdmit {
    /// The admission id.
    pub fn id(&self) -> AdmissionId {
        self.id
    }

    /// The purpose.
    pub fn purpose(&self) -> Purpose {
        self.purpose
    }

    /// The presented digests (0..=8).
    pub fn presented(&self) -> &[CompareOnlyDigest] {
        &self.digests[..self.n as usize]
    }

    /// True iff ANY presented digest matches `stored` (a lease's lowercase hex SHA-256). Every
    /// presented digest is compared, with no early exit on a match.
    pub fn any_matches_stored_hex(&self, stored: &str) -> bool {
        let mut any = false;
        for digest in self.presented() {
            any |= digest.matches_stored_hex(stored);
        }
        any
    }
}

/// A decoded EVENT: a code and a count (1..=u32::MAX). Its conn is always 0 on the wire.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct InboundEvent {
    pub(crate) code: EventCode,
    pub(crate) count: u32,
}

impl InboundEvent {
    /// The code.
    pub fn code(&self) -> EventCode {
        self.code
    }

    /// The count.
    pub fn count(&self) -> u32 {
        self.count
    }
}

/// A decoded daemon -> proxy message (the stateless decoder's view, without descriptors).
pub enum InboundD2p {
    /// WELCOME.
    Welcome(InboundWelcome),
    /// VERDICT.
    Verdict(AdmissionId, Outcome),
    /// SHUTDOWN.
    Shutdown,
}

/// A decoded WELCOME: one of the three admitted configurations, the public port, the host label
/// and (UNIX forwarding only) the runtime token.
pub struct InboundWelcome {
    pub(crate) mode: ModeKind,
    pub(crate) public_port: u16,
    pub(crate) host_label: [u8; HOST_LABEL_LEN],
    pub(crate) token: [u8; RUNTIME_TOKEN_LEN],
}

impl InboundWelcome {
    /// The serving mode.
    pub fn mode(&self) -> ModeKind {
        self.mode
    }

    /// The public port (1..=65535).
    pub fn public_port(&self) -> u16 {
        self.public_port
    }

    /// The 16 lowercase hex host-label bytes (the proxy renders `p<label>.localhost`).
    pub fn host_label(&self) -> &str {
        core::str::from_utf8(&self.host_label).unwrap_or("")
    }

    /// The runtime token, for UNIX editor forwarding only.
    pub fn runtime_token(&self) -> Option<&[u8; RUNTIME_TOKEN_LEN]> {
        match self.mode {
            ModeKind::ForwardUnix => Some(&self.token),
            _ => None,
        }
    }
}

/// Precedence row 6 for P2D: the kind's minimum body (else LengthMismatch without reading
/// fields), then the fields in wire order, then the exact body length. ADMIT's `n` is checked
/// against its purpose's limit in `mode` ([`Purpose::max_digests`]; without a mode, the stateless
/// decoder's [`Purpose::max_digests_any_mode`]: 8 forward, 1 lease exchange).
pub(crate) fn decode_p2d_body(
    kind: u8,
    body: &[u8],
    mode: Option<ModeKind>,
) -> Result<InboundP2d, IpcRefusal> {
    match kind {
        KIND_READY => {
            if !body.is_empty() {
                return Err(IpcRefusal::LengthMismatch);
            }
            Ok(InboundP2d::Ready)
        }
        KIND_ADMIT => {
            if body.len() < ADMIT_MIN_BODY {
                return Err(IpcRefusal::LengthMismatch);
            }
            let id = AdmissionId::from_raw(le_u32(&body[0..4]));
            let purpose = match Purpose::from_wire(body[4]) {
                Some(purpose) => purpose,
                None => return Err(IpcRefusal::BadPurpose),
            };
            let n = body[5] as usize;
            let limit = match mode {
                Some(mode) => purpose.max_digests(mode),
                None => purpose.max_digests_any_mode(),
            };
            if n > limit {
                return Err(IpcRefusal::TooManyDigests);
            }
            if body.len() != ADMIT_MIN_BODY + 32 * n {
                return Err(IpcRefusal::LengthMismatch);
            }
            let digests = core::array::from_fn(|i| {
                let mut bytes = [0u8; 32];
                if i < n {
                    let at = ADMIT_MIN_BODY + 32 * i;
                    bytes.copy_from_slice(&body[at..at + 32]);
                }
                CompareOnlyDigest::from_wire(bytes)
            });
            Ok(InboundP2d::Admit(InboundAdmit {
                id,
                purpose,
                n: n as u8,
                digests,
            }))
        }
        KIND_EVENT => {
            if body.len() < EVENT_BODY {
                return Err(IpcRefusal::LengthMismatch);
            }
            if le_u32(&body[0..4]) != 0 {
                return Err(IpcRefusal::BadEventConnection);
            }
            let code = match EventCode::from_wire(le_u16(&body[4..6])) {
                Some(code) => code,
                None => return Err(IpcRefusal::BadEventCode),
            };
            let count = le_u32(&body[6..10]);
            if count == 0 {
                return Err(IpcRefusal::BadEventCount);
            }
            if body.len() != EVENT_BODY {
                return Err(IpcRefusal::LengthMismatch);
            }
            Ok(InboundP2d::Event(InboundEvent { code, count }))
        }
        _ => Err(IpcRefusal::UnknownKind),
    }
}

/// Precedence row 6 for D2P (WELCOME: tuple, port, label, token in that order -> BadWelcome).
pub(crate) fn decode_d2p_body(kind: u8, body: &[u8]) -> Result<InboundD2p, IpcRefusal> {
    match kind {
        KIND_WELCOME => {
            if body.len() < WELCOME_BODY {
                return Err(IpcRefusal::LengthMismatch);
            }
            let mode = match (body[0], body[1], body[20]) {
                (1, 1, 0) => ModeKind::ForwardTcp,
                (1, 2, 1) => ModeKind::ForwardUnix,
                (2, 0, 0) => ModeKind::Static,
                _ => return Err(IpcRefusal::BadWelcome),
            };
            let public_port = le_u16(&body[2..4]);
            if public_port == 0 {
                return Err(IpcRefusal::BadWelcome);
            }
            let label = &body[4..4 + HOST_LABEL_LEN];
            if !label.iter().all(is_lower_hex) {
                return Err(IpcRefusal::BadWelcome);
            }
            let token = &body[21..21 + RUNTIME_TOKEN_LEN];
            let token_ok = match mode {
                ModeKind::ForwardUnix => token.iter().all(is_lower_hex),
                _ => token.iter().all(|b| *b == 0),
            };
            if !token_ok {
                return Err(IpcRefusal::BadWelcome);
            }
            if body.len() != WELCOME_BODY {
                return Err(IpcRefusal::LengthMismatch);
            }
            let mut host_label = [0u8; HOST_LABEL_LEN];
            host_label.copy_from_slice(label);
            let mut token_bytes = [0u8; RUNTIME_TOKEN_LEN];
            token_bytes.copy_from_slice(token);
            Ok(InboundD2p::Welcome(InboundWelcome {
                mode,
                public_port,
                host_label,
                token: token_bytes,
            }))
        }
        KIND_VERDICT => {
            if body.len() < VERDICT_BODY {
                return Err(IpcRefusal::LengthMismatch);
            }
            let id = AdmissionId::from_raw(le_u32(&body[0..4]));
            let outcome = match Outcome::from_wire(body[4]) {
                Some(outcome) => outcome,
                None => return Err(IpcRefusal::BadOutcome),
            };
            if body.len() != VERDICT_BODY {
                return Err(IpcRefusal::LengthMismatch);
            }
            Ok(InboundD2p::Verdict(id, outcome))
        }
        KIND_SHUTDOWN => {
            if !body.is_empty() {
                return Err(IpcRefusal::LengthMismatch);
            }
            Ok(InboundD2p::Shutdown)
        }
        _ => Err(IpcRefusal::UnknownKind),
    }
}

/// The STATELESS P2D decoder: precedence rows 3, 4 and 6 (no ancillary, phase or id rules, and
/// no serving mode: a lease exchange carries at most 1 digest, a forward admission at most 8; the
/// [`crate::DaemonSession`] applies all eight rows and its mode's limit).
pub fn decode_p2d(frame: &[u8]) -> Result<InboundP2d, IpcRefusal> {
    let (kind, body) = parse_header(frame, false, is_p2d_kind)?;
    decode_p2d_body(kind, body, None)
}

/// The STATELESS D2P decoder: precedence rows 3, 4 and 6 (no descriptors; the
/// [`crate::ProxySession`] applies all eight rows).
pub fn decode_d2p(frame: &[u8]) -> Result<InboundD2p, IpcRefusal> {
    let (kind, body) = parse_header(frame, false, is_d2p_kind)?;
    decode_d2p_body(kind, body)
}

/// Precedence row 7 for a WELCOME: exactly one descriptor (BadFdCount), AF_INET stream
/// (BadFdKind), listening on 127.0.0.1:public_port with no pending error (BadListener).
pub(crate) fn check_welcome_fds<H>(
    welcome: &InboundWelcome,
    fds: &FdBatch<H>,
) -> Result<(), IpcRefusal> {
    if fds.len() != 1 {
        return Err(IpcRefusal::BadFdCount);
    }
    let facts = match fds.first_facts() {
        Some(facts) => facts,
        None => return Err(IpcRefusal::BadFdCount),
    };
    if facts.class != SocketClass::InetStream {
        return Err(IpcRefusal::BadFdKind);
    }
    if !facts.accept_conn
        || facts.pending_error
        || facts.local_inet != Some(([127, 0, 0, 1], welcome.public_port))
    {
        return Err(IpcRefusal::BadListener);
    }
    Ok(())
}

/// Precedence row 7 for a VERDICT: one descriptor iff outcome 1 (BadFdCount); its class must be
/// the WELCOME's upstream (TCP -> AF_INET, UNIX -> AF_UNIX; static has none) (BadFdKind); it must
/// be connected, not listening, with no pending error (NotConnected); its peer must match the
/// trusted specification (EndpointMismatch).
pub(crate) fn check_verdict_fds<H>(
    outcome: Outcome,
    mode: ModeKind,
    fds: &FdBatch<H>,
) -> Result<(), IpcRefusal> {
    if outcome != Outcome::AdmittedUpstream {
        return if fds.is_empty() {
            Ok(())
        } else {
            Err(IpcRefusal::BadFdCount)
        };
    }
    if fds.len() != 1 {
        return Err(IpcRefusal::BadFdCount);
    }
    let facts = match fds.first_facts() {
        Some(facts) => facts,
        None => return Err(IpcRefusal::BadFdCount),
    };
    let wanted = match mode {
        ModeKind::ForwardTcp => SocketClass::InetStream,
        ModeKind::ForwardUnix => SocketClass::UnixStream,
        ModeKind::Static => return Err(IpcRefusal::BadFdKind),
    };
    if facts.class != wanted {
        return Err(IpcRefusal::BadFdKind);
    }
    if facts.accept_conn || !facts.connected || facts.pending_error {
        return Err(IpcRefusal::NotConnected);
    }
    if !facts.peer_matches_spec {
        return Err(IpcRefusal::EndpointMismatch);
    }
    Ok(())
}

// ------------------------------------------------------------------------------------------------
// Sends and receives
// ------------------------------------------------------------------------------------------------

/// The one prepared send: the adapter sends `bytes` as ONE SEQPACKET message (with `fd`, if any, as
/// SCM_RIGHTS) and reports the result for `op`. On WouldBlock the same frame and fd stay prepared.
pub struct Outgoing<'a, H> {
    /// The operation serial the result must name.
    pub op: crate::types::OpId,
    /// The frame.
    pub bytes: &'a [u8],
    /// The descriptor to pass (daemon WELCOME listener or admitted upstream), if any.
    pub fd: Option<&'a H>,
}

// ------------------------------------------------------------------------------------------------
// Receives
// ------------------------------------------------------------------------------------------------

/// One daemon-side receive of a proxy message. The daemon supplies NO ancillary buffer, so any
/// descriptors the proxy tried to send arrive as MSG_CTRUNC (the kernel closed them).
pub struct P2dRecv<'a> {
    /// The received bytes (from a [`RECV_BUF_LEN`]-byte buffer).
    pub bytes: &'a [u8],
    /// MSG_TRUNC was reported.
    pub msg_trunc: bool,
    /// MSG_CTRUNC was reported.
    pub msg_ctrunc: bool,
    /// Any other ancillary indication (a nonzero control length).
    pub control_present: bool,
}

impl<'a> P2dRecv<'a> {
    /// A receive with no flags and no ancillary data.
    pub fn clean(bytes: &'a [u8]) -> P2dRecv<'a> {
        P2dRecv {
            bytes,
            msg_trunc: false,
            msg_ctrunc: false,
            control_present: false,
        }
    }
}

/// One proxy-side receive of a daemon message, with its received descriptors (already `OwnedFd`s
/// in the adapter's `H`, received with MSG_CMSG_CLOEXEC). A refused receive drops every one.
pub struct D2pRecv<'a, H> {
    /// The received bytes (from a [`RECV_BUF_LEN`]-byte buffer).
    pub bytes: &'a [u8],
    /// MSG_TRUNC was reported.
    pub msg_trunc: bool,
    /// MSG_CTRUNC was reported.
    pub msg_ctrunc: bool,
    /// A control message other than SCM_RIGHTS arrived.
    pub unexpected_control: bool,
    /// The SCM_RIGHTS descriptors.
    pub fds: FdBatch<H>,
}

impl<'a, H> D2pRecv<'a, H> {
    /// A receive with no flags and no descriptors.
    pub fn clean(bytes: &'a [u8]) -> D2pRecv<'a, H> {
        D2pRecv {
            bytes,
            msg_trunc: false,
            msg_ctrunc: false,
            unexpected_control: false,
            fds: FdBatch::new(),
        }
    }

    /// A receive with no flags and one descriptor.
    pub fn with_fd(bytes: &'a [u8], fd: ReceivedFd<H>) -> D2pRecv<'a, H> {
        let mut recv = D2pRecv::clean(bytes);
        if let Err(fd) = recv.fds.push(fd) {
            drop(fd);
        }
        recv
    }
}

// ------------------------------------------------------------------------------------------------
// Outbound messages and the outbound-only encoder
// ------------------------------------------------------------------------------------------------

/// An ADMIT the proxy will send: a purpose and 0..=8 HASH-ONLY digests (built only from
/// [`Sha256Digest`]s; a lease exchange carries at most its one form token, on every construction
/// path). The admission id is assigned by the [`crate::ProxySession`] actor, whose prepare also
/// refuses a static-mode admission with more than one digest (TooManyDigests).
#[derive(Clone)]
pub struct OutboundAdmit {
    purpose: Purpose,
    n: u8,
    digests: [[u8; 32]; MAX_DIGESTS],
}

impl OutboundAdmit {
    /// An ADMIT of `purpose` carrying `digests`: at most 8 for a forward admission and at most 1
    /// (the form token) for a lease exchange, else it is refused here, before IPC.
    pub fn new(
        purpose: Purpose,
        digests: &[Sha256Digest],
    ) -> Result<OutboundAdmit, TooManyLeaseCandidates> {
        OutboundAdmit::build(purpose, digests.len(), |i| *digests[i].as_bytes())
    }

    /// A forward-mode ADMIT carrying the digest of every counted header/cookie candidate (a
    /// request that pushed a ninth candidate refuses here too).
    pub fn forward(candidates: &LeaseCandidates) -> Result<OutboundAdmit, TooManyLeaseCandidates> {
        if candidates.is_refused() {
            return Err(TooManyLeaseCandidates);
        }
        Ok(OutboundAdmit {
            purpose: Purpose::Forward,
            n: candidates.digests().len() as u8,
            digests: candidates.digest_array(),
        })
    }

    /// A lease-exchange ADMIT: ONLY the submitted form token (n = 0 or 1), never header or cookie
    /// hashes, so a valid existing cookie cannot authorize an invalid form token.
    pub fn lease_exchange(form_token: Option<&Sha256Digest>) -> OutboundAdmit {
        let mut digests = [[0u8; 32]; MAX_DIGESTS];
        let mut n = 0;
        if let Some(digest) = form_token {
            digests[0] = *digest.as_bytes();
            n = 1;
        }
        OutboundAdmit {
            purpose: Purpose::LeaseExchange,
            n,
            digests,
        }
    }

    fn build(
        purpose: Purpose,
        n: usize,
        digest: impl Fn(usize) -> [u8; 32],
    ) -> Result<OutboundAdmit, TooManyLeaseCandidates> {
        if n > purpose.max_digests_any_mode() {
            return Err(TooManyLeaseCandidates);
        }
        let mut digests = [[0u8; 32]; MAX_DIGESTS];
        for (i, slot) in digests.iter_mut().enumerate().take(n) {
            *slot = digest(i);
        }
        Ok(OutboundAdmit {
            purpose,
            n: n as u8,
            digests,
        })
    }

    /// The purpose.
    pub fn purpose(&self) -> Purpose {
        self.purpose
    }

    /// How many digests it carries.
    pub fn digest_count(&self) -> usize {
        self.n as usize
    }
}

/// An EVENT the proxy will send: one code's aggregated count (>= 1). Built by the proxy actor's
/// counters; its conn is always 0.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct OutboundEvent {
    code: EventCode,
    count: u32,
}

impl OutboundEvent {
    /// An EVENT of `count` (none if 0: zero counters are never sent).
    pub fn new(code: EventCode, count: u32) -> Option<OutboundEvent> {
        if count == 0 {
            None
        } else {
            Some(OutboundEvent { code, count })
        }
    }

    /// The code.
    pub fn code(&self) -> EventCode {
        self.code
    }

    /// The count.
    pub fn count(&self) -> u32 {
        self.count
    }
}

/// A proxy -> daemon message to encode: OUTBOUND values only.
#[derive(Clone)]
// clippy::large_enum_variant is allowed ON PURPOSE (S1-85D ruling, option (b)): the crate is no_std
// WITHOUT alloc, so the large variant cannot be boxed; it is a fixed-size stack value (at most a few
// hundred bytes) moved once per step through the actor's single-threaded loop.
#[allow(clippy::large_enum_variant)]
pub enum OutboundP2d {
    /// READY.
    Ready,
    /// ADMIT with its actor-assigned id.
    Admit(AdmissionId, OutboundAdmit),
    /// EVENT.
    Event(OutboundEvent),
}

mod sealed {
    /// Implemented only for outbound message types.
    pub trait Sealed {}
}

/// The message types [`encode_p2d`] accepts: SEALED, implemented only for [`OutboundP2d`]. No
/// trait, feature, conversion or generic implementation accepts an inbound (decoded) message.
pub trait EncodeP2d: sealed::Sealed {
    /// The frame (callers use [`encode_p2d`]).
    #[doc(hidden)]
    fn encode_frame(&self) -> Frame;
}

impl sealed::Sealed for OutboundP2d {}

impl EncodeP2d for OutboundP2d {
    fn encode_frame(&self) -> Frame {
        match self {
            OutboundP2d::Ready => Frame::start(KIND_READY).finish(),
            OutboundP2d::Admit(id, admit) => {
                let mut frame = Frame::start(KIND_ADMIT);
                frame.put(&id.get().to_le_bytes());
                frame.put(&[admit.purpose.wire(), admit.n]);
                for digest in &admit.digests[..admit.n as usize] {
                    frame.put(digest);
                }
                frame.finish()
            }
            OutboundP2d::Event(event) => {
                let mut frame = Frame::start(KIND_EVENT);
                frame.put(&0u32.to_le_bytes());
                frame.put(&event.code.wire().to_le_bytes());
                frame.put(&event.count.to_le_bytes());
                frame.finish()
            }
        }
    }
}

/// Encodes an OUTBOUND proxy -> daemon message (DESIGN v2 (1): `encode_p2d` accepts only outbound
/// messages; a decoded [`InboundP2d`] does not implement [`EncodeP2d`]: cf16).
pub fn encode_p2d<M: EncodeP2d>(message: &M) -> Frame {
    message.encode_frame()
}
