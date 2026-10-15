//! The protocol's small closed value types.

/// An ADMISSION OPERATION's id (not a TCP connection: one browser connection can perform several
/// admissions). The proxy actor allocates them from 1, strictly increasing, never reused or
/// wrapped; [`u32::MAX`] is usable once. Ids are not secrets: `from_raw` exists for adapters and
/// tests (the receiver checks monotonicity itself).
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug)]
pub struct AdmissionId(u32);

impl AdmissionId {
    /// An id from its wire value.
    pub const fn from_raw(raw: u32) -> AdmissionId {
        AdmissionId(raw)
    }

    /// The id's wire value.
    pub const fn get(self) -> u32 {
        self.0
    }
}

/// What an ADMIT asks for.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Purpose {
    /// Wire 1: authorize forwarding (or static serving) of this request.
    Forward,
    /// Wire 2: exchange a submitted form token for a lease cookie.
    LeaseExchange,
}

impl Purpose {
    /// The wire byte.
    pub const fn wire(self) -> u8 {
        match self {
            Purpose::Forward => 1,
            Purpose::LeaseExchange => 2,
        }
    }

    pub(crate) const fn from_wire(byte: u8) -> Option<Purpose> {
        match byte {
            1 => Some(Purpose::Forward),
            2 => Some(Purpose::LeaseExchange),
            _ => None,
        }
    }
}

/// The twelve proxy observations, numbered in source order (DESIGN v2 (3)). Observations, never
/// proof of process state: lifecycle truth comes from the spawner.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum EventCode {
    /// 1
    ProxyStarted,
    /// 2
    ProxyStopped,
    /// 3
    RequestHeadRefused,
    /// 4
    WebsocketIntercepted,
    /// 5
    HostRefused,
    /// 6
    AuthenticationDenied,
    /// 7
    AuthenticationSucceeded,
    /// 8
    LeaseCookieIssued,
    /// 9
    TargetVersionUnreachable,
    /// 10
    RawConnectionEstablished,
    /// 11
    ClientDisconnected,
    /// 12 (counted per dropped cookie pair)
    SessionCookieDropped,
}

impl EventCode {
    /// Every code, in wire order 1..=12.
    pub const ALL: [EventCode; 12] = [
        EventCode::ProxyStarted,
        EventCode::ProxyStopped,
        EventCode::RequestHeadRefused,
        EventCode::WebsocketIntercepted,
        EventCode::HostRefused,
        EventCode::AuthenticationDenied,
        EventCode::AuthenticationSucceeded,
        EventCode::LeaseCookieIssued,
        EventCode::TargetVersionUnreachable,
        EventCode::RawConnectionEstablished,
        EventCode::ClientDisconnected,
        EventCode::SessionCookieDropped,
    ];

    /// The wire value, 1..=12.
    pub const fn wire(self) -> u16 {
        self.index() as u16 + 1
    }

    /// The code for a wire value, if it is 1..=12.
    pub fn from_wire(code: u16) -> Option<EventCode> {
        if (1..=12).contains(&code) {
            Some(EventCode::ALL[code as usize - 1])
        } else {
            None
        }
    }

    /// The code's fixed record name.
    pub const fn name(self) -> &'static str {
        match self {
            EventCode::ProxyStarted => "proxy_started",
            EventCode::ProxyStopped => "proxy_stopped",
            EventCode::RequestHeadRefused => "request_head_refused",
            EventCode::WebsocketIntercepted => "websocket_intercepted",
            EventCode::HostRefused => "host_refused",
            EventCode::AuthenticationDenied => "authentication_denied",
            EventCode::AuthenticationSucceeded => "authentication_succeeded",
            EventCode::LeaseCookieIssued => "lease_cookie_issued",
            EventCode::TargetVersionUnreachable => "target_version_unreachable",
            EventCode::RawConnectionEstablished => "raw_connection_established",
            EventCode::ClientDisconnected => "client_disconnected",
            EventCode::SessionCookieDropped => "session_cookie_dropped",
        }
    }

    pub(crate) const fn index(self) -> usize {
        match self {
            EventCode::ProxyStarted => 0,
            EventCode::ProxyStopped => 1,
            EventCode::RequestHeadRefused => 2,
            EventCode::WebsocketIntercepted => 3,
            EventCode::HostRefused => 4,
            EventCode::AuthenticationDenied => 5,
            EventCode::AuthenticationSucceeded => 6,
            EventCode::LeaseCookieIssued => 7,
            EventCode::TargetVersionUnreachable => 8,
            EventCode::RawConnectionEstablished => 9,
            EventCode::ClientDisconnected => 10,
            EventCode::SessionCookieDropped => 11,
        }
    }
}

/// The serving mode a WELCOME configures, with its runtime token for UNIX editor forwarding.
/// Exactly three configurations exist on the wire: `(mode=1, upstream=1, has_token=0)` TCP
/// forwarding, `(1, 2, 1)` editor UNIX forwarding, `(2, 0, 0)` workspace static serving.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum ServingMode {
    /// Forward to a TCP upstream (no runtime token).
    ForwardTcp,
    /// Forward to the editor runtime's UNIX socket; `token` must be 64 lowercase hex bytes.
    ForwardUnix {
        /// The runtime connection token (appears only in this IPC body).
        token: [u8; 64],
    },
    /// Serve the workspace statically (no upstream, no token).
    Static,
}

impl ServingMode {
    /// The mode without its token.
    pub const fn kind(&self) -> ModeKind {
        match self {
            ServingMode::ForwardTcp => ModeKind::ForwardTcp,
            ServingMode::ForwardUnix { .. } => ModeKind::ForwardUnix,
            ServingMode::Static => ModeKind::Static,
        }
    }
}

/// A serving mode without its token.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum ModeKind {
    /// `(1, 1, 0)`
    ForwardTcp,
    /// `(1, 2, 1)`
    ForwardUnix,
    /// `(2, 0, 0)`
    Static,
}

/// A VERDICT's outcome.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Outcome {
    /// Wire 0, no fd.
    Denied,
    /// Wire 1, exactly one verified upstream fd (forward purpose in a forward mode only).
    AdmittedUpstream,
    /// Wire 2, no fd (static serving, or a lease exchange).
    AdmittedNoUpstream,
    /// Wire 3, no fd (forward purpose in a forward mode only).
    UpstreamUnavailable,
}

impl Outcome {
    /// The wire byte.
    pub const fn wire(self) -> u8 {
        match self {
            Outcome::Denied => 0,
            Outcome::AdmittedUpstream => 1,
            Outcome::AdmittedNoUpstream => 2,
            Outcome::UpstreamUnavailable => 3,
        }
    }

    pub(crate) const fn from_wire(byte: u8) -> Option<Outcome> {
        match byte {
            0 => Some(Outcome::Denied),
            1 => Some(Outcome::AdmittedUpstream),
            2 => Some(Outcome::AdmittedNoUpstream),
            3 => Some(Outcome::UpstreamUnavailable),
            _ => None,
        }
    }

    /// The verdict legality table (DESIGN v2 (2)): forward purpose in a forward mode allows 0, 1,
    /// 3; forward purpose in static mode allows 0, 2; lease exchange in any mode allows 0, 2.
    pub const fn legal_for(self, mode: ModeKind, purpose: Purpose) -> bool {
        match (purpose, mode, self) {
            (_, _, Outcome::Denied) => true,
            (Purpose::Forward, ModeKind::ForwardTcp | ModeKind::ForwardUnix, o) => {
                matches!(o, Outcome::AdmittedUpstream | Outcome::UpstreamUnavailable)
            }
            (Purpose::Forward, ModeKind::Static, o) => matches!(o, Outcome::AdmittedNoUpstream),
            (Purpose::LeaseExchange, _, o) => matches!(o, Outcome::AdmittedNoUpstream),
        }
    }
}

/// A local operation serial: each actor numbers its prepared sends so a duplicate or stale send
/// completion cannot commit a different operation. Not a secret.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct OpId(u64);

impl OpId {
    /// An op id from its value (adapters and tests; a stale or forged one refuses).
    pub const fn from_raw(raw: u64) -> OpId {
        OpId(raw)
    }

    /// The op id's value.
    pub const fn get(self) -> u64 {
        self.0
    }
}

/// The transport's result for one attempt to send the prepared frame (one SEQPACKET message).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum SendOutcome {
    /// The whole message was sent: commits the prepared operation.
    SentWhole,
    /// EAGAIN: the same frame and fd stay prepared; nothing changes.
    WouldBlock,
    /// A permanent or indeterminate error: latches SendFailed, never retried.
    Fatal,
    /// A partial send (never accepted for SEQPACKET): latches SendFailed.
    Short,
}

/// Why a local actor terminates (no bytes, no text).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum StopReason {
    /// The lease or its authority was revoked.
    Revoked,
    /// The lease expired.
    Expired,
    /// The owning process is shutting down.
    Shutdown,
    /// The proxy used admission id `u32::MAX` and its pending results completed.
    IdsExhausted,
}

/// The trusted F0 boundary check's result for the pinned proxy identity (the checks themselves
/// are the spawner's, U4).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum F0Result {
    /// Every F0 check passed for the pinned identity.
    Pass,
    /// A check failed: latches BoundaryUnverified (the spawner records which check).
    Fail,
}
