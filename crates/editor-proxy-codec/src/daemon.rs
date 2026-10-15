//! The DAEMON endpoint's state machine: RED (BUILD-DELTA #85 U1, DESIGN v2 (2), "RED and fuzz
//! proof").
//!
//! This is the runnable ACCEPTING machine. It decodes frames with the shared wire code (refusal
//! rows 2, 3, 4 and 6) but IGNORES phase legality, admission ids, the pending cap, the rate window,
//! the verdict bookkeeping, every deadline and the clock, and its refusals do NOT latch. It
//! persists one event record per EVENT frame. T-SESSION, T-LATCH, T-LIMITS, T-TIME, T-SEND,
//! T-VERDICT, T-EVENT and the named fuzz seeds fail against it at named assertions; the FIX
//! replaces it with the complete transition table.

use crate::events::{DaemonEventWindow, EventRecords};
use crate::refusal::IpcRefusal;
use crate::types::{
    AdmissionId, F0Result, ModeKind, OpId, Outcome, SendOutcome, ServingMode, StopReason,
};
use crate::wire::{
    self, is_lower_hex, Frame, InboundAdmit, InboundP2d, Outgoing, P2dRecv, HOST_LABEL_LEN,
    KIND_SHUTDOWN, KIND_VERDICT, KIND_WELCOME,
};

/// The daemon session's configuration.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct DaemonConfig {
    /// The total deadline from a committed ADMIT to its VERDICT's whole send (RED: ignored).
    pub verdict_deadline_ns: u64,
}

/// What the daemon sends in WELCOME (with the verified browser listener as the input's handle).
#[derive(Clone, Copy)]
pub struct WelcomeSpec {
    /// The serving mode (and, for UNIX forwarding, the runtime token).
    pub mode: ServingMode,
    /// 1..=65535.
    pub public_port: u16,
    /// 16 lowercase hex bytes.
    pub host_label: [u8; HOST_LABEL_LEN],
}

/// A VERDICT to prepare; only an admitted upstream carries a descriptor (by construction).
pub enum VerdictSpec<H> {
    /// Outcome 0.
    Denied,
    /// Outcome 1, with the verified, connected upstream descriptor.
    AdmittedUpstream(H),
    /// Outcome 2.
    AdmittedNoUpstream,
    /// Outcome 3.
    UpstreamUnavailable,
}

impl<H> VerdictSpec<H> {
    /// The outcome it encodes.
    pub fn outcome(&self) -> Outcome {
        match self {
            VerdictSpec::Denied => Outcome::Denied,
            VerdictSpec::AdmittedUpstream(_) => Outcome::AdmittedUpstream,
            VerdictSpec::AdmittedNoUpstream => Outcome::AdmittedNoUpstream,
            VerdictSpec::UpstreamUnavailable => Outcome::UpstreamUnavailable,
        }
    }

    fn into_fd(self) -> Option<H> {
        match self {
            VerdictSpec::AdmittedUpstream(fd) => Some(fd),
            _ => None,
        }
    }
}

/// The daemon session's phase.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum DaemonPhase {
    /// Spawned; waiting for READY.
    AwaitReady,
    /// READY received; the trusted F0 check runs.
    CheckingF0,
    /// F0 passed: one unconsumed per-spawn proof is held.
    WelcomeReady,
    /// WELCOME (with the listener) is prepared.
    WelcomePrepared,
    /// WELCOME was sent whole.
    Active,
    /// Terminating: SHUTDOWN (if READY was seen), then teardown.
    Stopping,
    /// Torn down.
    Closed,
    /// Refused (absorbing).
    Refused(IpcRefusal),
}

/// One input to the daemon actor.
pub enum DaemonInput<'a, H> {
    /// A trusted monotonic clock sample (nondecreasing).
    Tick(u64),
    /// One received proxy message.
    Recv(P2dRecv<'a>),
    /// The trusted F0 result for the pinned identity.
    F0(F0Result),
    /// Prepare WELCOME, consuming the F0 proof; the handle is the verified browser listener.
    PrepareWelcome(WelcomeSpec, H),
    /// Prepare the VERDICT for a pending admission.
    PrepareVerdict(AdmissionId, VerdictSpec<H>),
    /// Prepare SHUTDOWN (legal after READY; enters Stopping).
    PrepareShutdown,
    /// The transport's result for the prepared send.
    SendResult(OpId, SendOutcome),
    /// Local termination (revocation, expiry, shutdown).
    Terminate(StopReason),
    /// EOF on the IPC socket.
    TransportEof,
    /// A permanent IPC socket error.
    TransportError,
}

/// What the daemon adapter must do after one input.
pub enum DaemonStep {
    /// Nothing.
    Idle,
    /// READY arrived: run the trusted F0 check for the pinned identity (and nothing else).
    RunF0,
    /// A send is prepared: send [`DaemonSession::outgoing`] and report its result.
    Send(OpId),
    /// WELCOME was sent whole and the daemon's listener copy is closed: the URL may be published.
    WelcomeSent,
    /// A committed ADMIT: check the bound lease against every presented digest, then prepare its
    /// VERDICT.
    Admit(InboundAdmit),
    /// The VERDICT for this id was sent whole (its descriptor copy is closed).
    VerdictSent(AdmissionId),
    /// A local event window closed: persist these records (at most one per code).
    Persist(EventRecords),
    /// Terminating: cancel connector work and cease publication; SHUTDOWN may be prepared.
    Stopping,
    /// Execute the cgroup teardown now; the session is Closed.
    Teardown,
    /// The session refused (its one fixed-name record) and requests bounded teardown.
    Refused(IpcRefusal),
    /// Already terminal: nothing happens.
    Terminal,
}

/// A [`DaemonStep`] without its payload (for tests and records).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum DaemonStepKind {
    /// [`DaemonStep::Idle`]
    Idle,
    /// [`DaemonStep::RunF0`]
    RunF0,
    /// [`DaemonStep::Send`]
    Send,
    /// [`DaemonStep::WelcomeSent`]
    WelcomeSent,
    /// [`DaemonStep::Admit`]
    Admit,
    /// [`DaemonStep::VerdictSent`]
    VerdictSent,
    /// [`DaemonStep::Persist`]
    Persist,
    /// [`DaemonStep::Stopping`]
    Stopping,
    /// [`DaemonStep::Teardown`]
    Teardown,
    /// [`DaemonStep::Refused`]
    Refused(IpcRefusal),
    /// [`DaemonStep::Terminal`]
    Terminal,
}

impl DaemonStep {
    /// The step without its payload.
    pub fn kind(&self) -> DaemonStepKind {
        match self {
            DaemonStep::Idle => DaemonStepKind::Idle,
            DaemonStep::RunF0 => DaemonStepKind::RunF0,
            DaemonStep::Send(_) => DaemonStepKind::Send,
            DaemonStep::WelcomeSent => DaemonStepKind::WelcomeSent,
            DaemonStep::Admit(_) => DaemonStepKind::Admit,
            DaemonStep::VerdictSent(_) => DaemonStepKind::VerdictSent,
            DaemonStep::Persist(_) => DaemonStepKind::Persist,
            DaemonStep::Stopping => DaemonStepKind::Stopping,
            DaemonStep::Teardown => DaemonStepKind::Teardown,
            DaemonStep::Refused(code) => DaemonStepKind::Refused(*code),
            DaemonStep::Terminal => DaemonStepKind::Terminal,
        }
    }
}

enum Sending {
    Welcome,
    Verdict(AdmissionId),
    Shutdown,
}

struct Prepared<H> {
    op: OpId,
    frame: Frame,
    fd: Option<H>,
    kind: Sending,
}

/// The daemon endpoint of one proxy's IPC session (RED: the accepting machine).
#[allow(dead_code)]
pub struct DaemonSession<H> {
    phase: DaemonPhase,
    last_now: u64,
    mode: Option<ModeKind>,
    pending: usize,
    last_admitted: Option<AdmissionId>,
    last_completed: Option<AdmissionId>,
    next_op: u64,
    prepared: Option<Prepared<H>>,
    events: DaemonEventWindow,
}

/// WELCOME's typed builder: the tuple is valid by construction; port 1..=65535, a 16-byte
/// lowercase hex label and (UNIX) a 64-byte lowercase hex token are checked in that order.
pub(crate) fn encode_welcome(spec: &WelcomeSpec) -> Result<Frame, IpcRefusal> {
    if spec.public_port == 0 || !spec.host_label.iter().all(is_lower_hex) {
        return Err(IpcRefusal::BadWelcome);
    }
    let (mode, upstream, has_token, token) = match spec.mode {
        ServingMode::ForwardTcp => (1u8, 1u8, 0u8, [0u8; 64]),
        ServingMode::ForwardUnix { token } => {
            if !token.iter().all(is_lower_hex) {
                return Err(IpcRefusal::BadWelcome);
            }
            (1, 2, 1, token)
        }
        ServingMode::Static => (2, 0, 0, [0u8; 64]),
    };
    let mut frame = Frame::start(KIND_WELCOME);
    frame.put(&[mode, upstream]);
    frame.put(&spec.public_port.to_le_bytes());
    frame.put(&spec.host_label);
    frame.put(&[has_token]);
    frame.put(&token);
    Ok(frame.finish())
}

pub(crate) fn encode_verdict(id: AdmissionId, outcome: Outcome) -> Frame {
    let mut frame = Frame::start(KIND_VERDICT);
    frame.put(&id.get().to_le_bytes());
    frame.put(&[outcome.wire()]);
    frame.finish()
}

pub(crate) fn encode_shutdown() -> Frame {
    Frame::start(KIND_SHUTDOWN).finish()
}

impl<H> DaemonSession<H> {
    /// A session for a proxy spawned at `spawn_ns`.
    pub fn new(spawn_ns: u64, _config: DaemonConfig) -> DaemonSession<H> {
        DaemonSession {
            phase: DaemonPhase::AwaitReady,
            last_now: spawn_ns,
            mode: None,
            pending: 0,
            last_admitted: None,
            last_completed: None,
            next_op: 1,
            prepared: None,
            events: DaemonEventWindow::new(spawn_ns),
        }
    }

    /// The current phase.
    pub fn phase(&self) -> DaemonPhase {
        self.phase
    }

    /// The prepared send, if any.
    pub fn outgoing(&self) -> Option<Outgoing<'_, H>> {
        self.prepared.as_ref().map(|p| Outgoing {
            op: p.op,
            bytes: p.frame.as_bytes(),
            fd: p.fd.as_ref(),
        })
    }

    /// The one final bounded event summary, once, after the session is Closed or Refused.
    pub fn final_event_summary(&mut self) -> Option<EventRecords> {
        match self.phase {
            DaemonPhase::Closed | DaemonPhase::Refused(_) => self.events.final_summary(),
            _ => None,
        }
    }

    fn take_op(&mut self) -> OpId {
        let op = OpId::from_raw(self.next_op);
        self.next_op += 1;
        op
    }

    /// RED: accepts every well-formed input, whatever the phase, ids, limits or time.
    pub fn step(&mut self, input: DaemonInput<'_, H>) -> DaemonStep {
        match input {
            DaemonInput::Tick(now) => {
                self.last_now = now;
                match self.events.roll(now) {
                    Some(records) => DaemonStep::Persist(records),
                    None => DaemonStep::Idle,
                }
            }
            DaemonInput::Recv(recv) => {
                if recv.control_present || recv.msg_ctrunc {
                    return DaemonStep::Refused(IpcRefusal::AncillaryFromProxy);
                }
                let (kind, body) =
                    match wire::parse_header(recv.bytes, recv.msg_trunc, wire::is_p2d_kind) {
                        Ok(parsed) => parsed,
                        Err(code) => return DaemonStep::Refused(code),
                    };
                match wire::decode_p2d_body(kind, body) {
                    Err(code) => DaemonStep::Refused(code),
                    Ok(InboundP2d::Ready) => {
                        self.phase = DaemonPhase::CheckingF0;
                        DaemonStep::RunF0
                    }
                    Ok(InboundP2d::Admit(admit)) => {
                        self.pending += 1;
                        self.last_admitted = Some(admit.id());
                        DaemonStep::Admit(admit)
                    }
                    Ok(InboundP2d::Event(event)) => {
                        self.events.add(event.code(), event.count());
                        DaemonStep::Persist(EventRecords::single(
                            self.last_now,
                            event.code(),
                            event.count(),
                        ))
                    }
                }
            }
            DaemonInput::F0(F0Result::Pass) => {
                self.phase = DaemonPhase::WelcomeReady;
                DaemonStep::Idle
            }
            DaemonInput::F0(F0Result::Fail) => DaemonStep::Refused(IpcRefusal::BoundaryUnverified),
            DaemonInput::PrepareWelcome(spec, listener) => match encode_welcome(&spec) {
                Err(code) => DaemonStep::Refused(code),
                Ok(frame) => {
                    self.mode = Some(spec.mode.kind());
                    let op = self.take_op();
                    self.prepared = Some(Prepared {
                        op,
                        frame,
                        fd: Some(listener),
                        kind: Sending::Welcome,
                    });
                    self.phase = DaemonPhase::WelcomePrepared;
                    DaemonStep::Send(op)
                }
            },
            DaemonInput::PrepareVerdict(id, verdict) => {
                let outcome = verdict.outcome();
                let op = self.take_op();
                self.prepared = Some(Prepared {
                    op,
                    frame: encode_verdict(id, outcome),
                    fd: verdict.into_fd(),
                    kind: Sending::Verdict(id),
                });
                DaemonStep::Send(op)
            }
            DaemonInput::PrepareShutdown => {
                let op = self.take_op();
                self.prepared = Some(Prepared {
                    op,
                    frame: encode_shutdown(),
                    fd: None,
                    kind: Sending::Shutdown,
                });
                self.phase = DaemonPhase::Stopping;
                DaemonStep::Send(op)
            }
            DaemonInput::SendResult(_op, outcome) => match outcome {
                SendOutcome::Fatal | SendOutcome::Short => {
                    DaemonStep::Refused(IpcRefusal::SendFailed)
                }
                SendOutcome::WouldBlock => DaemonStep::Idle,
                SendOutcome::SentWhole => match self.prepared.take() {
                    None => DaemonStep::Idle,
                    Some(prepared) => match prepared.kind {
                        Sending::Welcome => {
                            self.phase = DaemonPhase::Active;
                            DaemonStep::WelcomeSent
                        }
                        Sending::Verdict(id) => {
                            self.pending = self.pending.saturating_sub(1);
                            self.last_completed = Some(id);
                            DaemonStep::VerdictSent(id)
                        }
                        Sending::Shutdown => {
                            self.phase = DaemonPhase::Closed;
                            DaemonStep::Teardown
                        }
                    },
                },
            },
            DaemonInput::Terminate(_reason) => {
                self.phase = DaemonPhase::Stopping;
                DaemonStep::Stopping
            }
            DaemonInput::TransportEof => DaemonStep::Refused(IpcRefusal::TransportClosed),
            DaemonInput::TransportError => DaemonStep::Refused(IpcRefusal::TransportFailed),
        }
    }
}

/// Test and fuzz accessors (never in a shipped build).
#[cfg(any(test, fuzzing))]
impl<H> DaemonSession<H> {
    /// Unanswered admissions (RED: admits minus verdicts).
    pub fn test_only_pending_len(&self) -> usize {
        self.pending.min(crate::limits::MAX_PENDING)
    }

    /// Admissions committed in the current rate window (RED: not tracked).
    pub fn test_only_window_admissions(&self) -> u32 {
        0
    }

    /// The most recently admitted id.
    pub fn test_only_answerable(&self) -> Option<AdmissionId> {
        self.last_admitted
    }

    /// The most recently completed id.
    pub fn test_only_last_completed(&self) -> Option<AdmissionId> {
        self.last_completed
    }

    /// The WELCOME mode, once prepared.
    pub fn test_only_mode(&self) -> Option<ModeKind> {
        self.mode
    }
}
