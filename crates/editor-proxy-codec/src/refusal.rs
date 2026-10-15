//! The closed, fieldless refusal set and its fixed precedence (DESIGN v2 (2), "Refusal precedence
//! and effects"). U1 pins the complete list here.

/// Why a session refused. Fieldless and closed: it carries no input byte, errno text, path or
/// dynamic formatting. The FIRST refusal latches; it yields no further values or side effects
/// except one cleanup request.
///
/// The variants are listed in PRECEDENCE order: when one input has several defects, the session
/// reports the earliest applicable one ([`IpcRefusal::precedence`] gives its row).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum IpcRefusal {
    // ---- row 1: transport, send, deadline, F0, clock ----
    /// EOF on the IPC socket.
    TransportClosed,
    /// A permanent I/O error on the IPC socket.
    TransportFailed,
    /// A prepared send failed or was short.
    SendFailed,
    /// A send, startup, verdict or other operation deadline expired.
    OperationTimeout,
    /// The trusted F0 check failed.
    BoundaryUnverified,
    /// The monotonic clock went backwards.
    ClockRegression,
    // ---- row 2: ancillary data ----
    /// P2D: the proxy sent ancillary data (an indication, or MSG_CTRUNC on a receive with no
    /// control buffer).
    AncillaryFromProxy,
    /// D2P: MSG_CTRUNC (more ancillary data than the bounded control space).
    AncillaryTruncated,
    /// D2P: a control message other than SCM_RIGHTS.
    UnexpectedAncillary,
    // ---- row 3: message size ----
    /// MSG_TRUNC, or fewer than the 8 header bytes.
    Truncated,
    /// More than 512 bytes received.
    Oversized,
    // ---- row 4: header, in this order ----
    /// The first two bytes are not "IP".
    BadMagic,
    /// The version byte is not 2.
    BadVersion,
    /// The kind byte is not a kind of this direction.
    UnknownKind,
    /// The reserved u16 is not zero.
    ReservedNonzero,
    /// body_len differs from the received length minus 8, or the body length is not exact for its
    /// kind.
    LengthMismatch,
    // ---- row 5: phase ----
    /// The message or operation is not legal in the current phase (incl. a stale or duplicate send
    /// result, a second prepared send, a forged F0 pass).
    OutOfOrder,
    // ---- row 6: body fields, in wire order ----
    /// ADMIT purpose not 1 or 2.
    BadPurpose,
    /// ADMIT digest count above its purpose's limit in the session's mode: 8 for a forward
    /// admission in a forward mode; 1 for a lease exchange (its form token only) or a static-mode
    /// admission (its selected token only).
    TooManyDigests,
    /// EVENT conn not 0.
    BadEventConnection,
    /// EVENT code not 1..=12.
    BadEventCode,
    /// EVENT count 0.
    BadEventCount,
    /// WELCOME tuple, port, label or token illegal (checked in that order).
    BadWelcome,
    /// VERDICT outcome byte not 0..=3.
    BadOutcome,
    // ---- row 7: ancillary descriptors, in this order ----
    /// The wrong number of descriptors for the message.
    BadFdCount,
    /// A descriptor of the wrong socket domain/type.
    BadFdKind,
    /// An upstream descriptor that is listening, not connected, or has a pending error.
    NotConnected,
    /// A WELCOME listener that is not listening on 127.0.0.1:public_port or has a pending error.
    BadListener,
    /// An upstream descriptor whose peer does not match the trusted specification.
    EndpointMismatch,
    // ---- row 8: ids, verdict bookkeeping, capacity, rate ----
    /// ADMIT id zero or not strictly increasing.
    ConnNotIncreasing,
    /// ADMIT after id `u32::MAX` was used (or, locally, an ADMIT after exhaustion).
    ConnExhausted,
    /// VERDICT for an entry already being answered, or a recently completed id.
    DuplicateVerdict,
    /// VERDICT for an id neither pending nor recently completed.
    UnknownVerdict,
    /// VERDICT outcome not legal for its admission's purpose and the session's mode.
    BadOutcomeForPurpose,
    /// A 65th unanswered ADMIT.
    TooManyInFlight,
    /// A 2001st ADMIT in one ten-second window.
    RateExceeded,
}

impl IpcRefusal {
    /// Every refusal, in precedence order.
    pub const ALL: [IpcRefusal; 36] = [
        IpcRefusal::TransportClosed,
        IpcRefusal::TransportFailed,
        IpcRefusal::SendFailed,
        IpcRefusal::OperationTimeout,
        IpcRefusal::BoundaryUnverified,
        IpcRefusal::ClockRegression,
        IpcRefusal::AncillaryFromProxy,
        IpcRefusal::AncillaryTruncated,
        IpcRefusal::UnexpectedAncillary,
        IpcRefusal::Truncated,
        IpcRefusal::Oversized,
        IpcRefusal::BadMagic,
        IpcRefusal::BadVersion,
        IpcRefusal::UnknownKind,
        IpcRefusal::ReservedNonzero,
        IpcRefusal::LengthMismatch,
        IpcRefusal::OutOfOrder,
        IpcRefusal::BadPurpose,
        IpcRefusal::TooManyDigests,
        IpcRefusal::BadEventConnection,
        IpcRefusal::BadEventCode,
        IpcRefusal::BadEventCount,
        IpcRefusal::BadWelcome,
        IpcRefusal::BadOutcome,
        IpcRefusal::BadFdCount,
        IpcRefusal::BadFdKind,
        IpcRefusal::NotConnected,
        IpcRefusal::BadListener,
        IpcRefusal::EndpointMismatch,
        IpcRefusal::ConnNotIncreasing,
        IpcRefusal::ConnExhausted,
        IpcRefusal::DuplicateVerdict,
        IpcRefusal::UnknownVerdict,
        IpcRefusal::BadOutcomeForPurpose,
        IpcRefusal::TooManyInFlight,
        IpcRefusal::RateExceeded,
    ];

    /// The precedence row (1..=8) of DESIGN v2's refusal table.
    pub const fn precedence(self) -> u8 {
        use IpcRefusal::*;
        match self {
            TransportClosed | TransportFailed | SendFailed | OperationTimeout
            | BoundaryUnverified | ClockRegression => 1,
            AncillaryFromProxy | AncillaryTruncated | UnexpectedAncillary => 2,
            Truncated | Oversized => 3,
            BadMagic | BadVersion | UnknownKind | ReservedNonzero | LengthMismatch => 4,
            OutOfOrder => 5,
            BadPurpose | TooManyDigests | BadEventConnection | BadEventCode | BadEventCount
            | BadWelcome | BadOutcome => 6,
            BadFdCount | BadFdKind | NotConnected | BadListener | EndpointMismatch => 7,
            ConnNotIncreasing | ConnExhausted | DuplicateVerdict | UnknownVerdict
            | BadOutcomeForPurpose | TooManyInFlight | RateExceeded => 8,
        }
    }

    /// The refusal's fixed record name.
    pub const fn name(self) -> &'static str {
        use IpcRefusal::*;
        match self {
            TransportClosed => "transport_closed",
            TransportFailed => "transport_failed",
            SendFailed => "send_failed",
            OperationTimeout => "operation_timeout",
            BoundaryUnverified => "boundary_unverified",
            ClockRegression => "clock_regression",
            AncillaryFromProxy => "ancillary_from_proxy",
            AncillaryTruncated => "ancillary_truncated",
            UnexpectedAncillary => "unexpected_ancillary",
            Truncated => "truncated",
            Oversized => "oversized",
            BadMagic => "bad_magic",
            BadVersion => "bad_version",
            UnknownKind => "unknown_kind",
            ReservedNonzero => "reserved_nonzero",
            LengthMismatch => "length_mismatch",
            OutOfOrder => "out_of_order",
            BadPurpose => "bad_purpose",
            TooManyDigests => "too_many_digests",
            BadEventConnection => "bad_event_connection",
            BadEventCode => "bad_event_code",
            BadEventCount => "bad_event_count",
            BadWelcome => "bad_welcome",
            BadOutcome => "bad_outcome",
            BadFdCount => "bad_fd_count",
            BadFdKind => "bad_fd_kind",
            NotConnected => "not_connected",
            BadListener => "bad_listener",
            EndpointMismatch => "endpoint_mismatch",
            ConnNotIncreasing => "conn_not_increasing",
            ConnExhausted => "conn_exhausted",
            DuplicateVerdict => "duplicate_verdict",
            UnknownVerdict => "unknown_verdict",
            BadOutcomeForPurpose => "bad_outcome_for_purpose",
            TooManyInFlight => "too_many_in_flight",
            RateExceeded => "rate_exceeded",
        }
    }
}
