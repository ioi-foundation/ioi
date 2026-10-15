//! The PROXY endpoint's state machine: RED (BUILD-DELTA #85 U1, DESIGN v2 (2), "RED and fuzz
//! proof").
//!
//! This is the runnable ACCEPTING machine. It decodes frames and checks descriptors with the
//! shared wire code (refusal rows 2, 3, 4, 6 and 7) but IGNORES phase legality, the pending cap,
//! the rate mirror, id exhaustion, the verdict bookkeeping, every deadline and the clock, offers an
//! EVENT on every tick, and its refusals do NOT latch. The FIX replaces it with the complete
//! transition table.

use core::marker::PhantomData;

use crate::events::ProxyEventCounters;
use crate::refusal::IpcRefusal;
use crate::types::{AdmissionId, EventCode, ModeKind, OpId, Outcome, SendOutcome, StopReason};
use crate::wire::{
    self, encode_p2d, D2pRecv, Frame, InboundD2p, InboundWelcome, OutboundAdmit, OutboundEvent,
    OutboundP2d, Outgoing,
};

/// The proxy session's configuration.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct ProxyConfig {
    /// How long a sent ADMIT may wait for its VERDICT (RED: ignored).
    pub verdict_deadline_ns: u64,
}

/// The proxy session's phase.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum ProxyPhase {
    /// Single-threaded bootstrap, before READY is prepared.
    Bootstrap,
    /// READY is prepared.
    ReadyPrepared,
    /// READY was sent; waiting for WELCOME.
    AwaitWelcome,
    /// WELCOME (with the listener) was received: workers run.
    Active,
    /// Terminating: a bounded final EVENT flush, then Closed.
    Stopping,
    /// Closed.
    Closed,
    /// Refused (absorbing).
    Refused(IpcRefusal),
}

/// One input to the proxy actor.
pub enum ProxyInput<'a, H> {
    /// A trusted monotonic clock sample (nondecreasing).
    Tick(u64),
    /// One received daemon message with its descriptors.
    Recv(D2pRecv<'a, H>),
    /// Prepare READY (Bootstrap only).
    PrepareReady,
    /// Prepare an ADMIT; the actor assigns its id.
    PrepareAdmit(OutboundAdmit),
    /// Count `n` occurrences of an observation (saturating; sent as aggregated EVENTs).
    Observe(EventCode, u32),
    /// The transport's result for the prepared send.
    SendResult(OpId, SendOutcome),
    /// Local termination.
    Terminate(StopReason),
    /// EOF on the IPC socket.
    TransportEof,
    /// A permanent IPC socket error.
    TransportError,
}

/// What the proxy adapter must do after one input.
pub enum ProxyStep<H> {
    /// Nothing.
    Idle,
    /// A send is prepared: send [`ProxySession::outgoing`] and report its result.
    Send(OpId),
    /// The ADMIT for this id was sent whole and is pending.
    AdmitSent(AdmissionId),
    /// A validated WELCOME and its verified listener: start the HTTP workers.
    Welcome(InboundWelcome, H),
    /// A validated VERDICT (with its verified upstream iff outcome 1).
    Verdict(AdmissionId, Outcome, Option<H>),
    /// Terminating: cancel work; the final flush runs on Ticks.
    Stopping,
    /// Close owned connections and the IPC socket; the session is Closed.
    Close,
    /// The session refused (its one record) and requests bounded teardown.
    Refused(IpcRefusal),
    /// Already terminal: nothing happens.
    Terminal,
}

/// A [`ProxyStep`] without its payload (for tests and records).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum ProxyStepKind {
    /// [`ProxyStep::Idle`]
    Idle,
    /// [`ProxyStep::Send`]
    Send,
    /// [`ProxyStep::AdmitSent`]
    AdmitSent,
    /// [`ProxyStep::Welcome`]
    Welcome,
    /// [`ProxyStep::Verdict`]
    Verdict,
    /// [`ProxyStep::Stopping`]
    Stopping,
    /// [`ProxyStep::Close`]
    Close,
    /// [`ProxyStep::Refused`]
    Refused(IpcRefusal),
    /// [`ProxyStep::Terminal`]
    Terminal,
}

impl<H> ProxyStep<H> {
    /// The step without its payload.
    pub fn kind(&self) -> ProxyStepKind {
        match self {
            ProxyStep::Idle => ProxyStepKind::Idle,
            ProxyStep::Send(_) => ProxyStepKind::Send,
            ProxyStep::AdmitSent(_) => ProxyStepKind::AdmitSent,
            ProxyStep::Welcome(..) => ProxyStepKind::Welcome,
            ProxyStep::Verdict(..) => ProxyStepKind::Verdict,
            ProxyStep::Stopping => ProxyStepKind::Stopping,
            ProxyStep::Close => ProxyStepKind::Close,
            ProxyStep::Refused(code) => ProxyStepKind::Refused(*code),
            ProxyStep::Terminal => ProxyStepKind::Terminal,
        }
    }
}

/// Why an ADMIT cannot be prepared now (honest flow control).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum AdmitBlocked {
    /// Not Active (OutOfOrder).
    NotActive,
    /// Another send is prepared (OutOfOrder).
    SendInProgress,
    /// Id `u32::MAX` was used (ConnExhausted).
    Exhausted,
    /// 64 admissions are pending (TooManyInFlight).
    InFlightFull,
    /// 2000 admissions in this window (RateExceeded).
    RateLimited,
}

enum Sending {
    Ready,
    Admit(AdmissionId),
    Event(OutboundEvent),
}

struct Prepared {
    op: OpId,
    frame: Frame,
    kind: Sending,
}

/// The proxy endpoint of its IPC session (RED: the accepting machine).
#[allow(dead_code)]
pub struct ProxySession<H> {
    phase: ProxyPhase,
    mode: Option<ModeKind>,
    next_id: u32,
    pending: usize,
    last_sent: Option<AdmissionId>,
    last_completed: Option<AdmissionId>,
    next_op: u64,
    prepared: Option<Prepared>,
    counters: ProxyEventCounters,
    handles: PhantomData<fn(H)>,
}

impl<H> ProxySession<H> {
    /// A session for a proxy that started at `start_ns`.
    pub fn new(start_ns: u64, _config: ProxyConfig) -> ProxySession<H> {
        ProxySession {
            phase: ProxyPhase::Bootstrap,
            mode: None,
            next_id: 1,
            pending: 0,
            last_sent: None,
            last_completed: None,
            next_op: 1,
            prepared: None,
            counters: ProxyEventCounters::new(start_ns),
            handles: PhantomData,
        }
    }

    /// The current phase.
    pub fn phase(&self) -> ProxyPhase {
        self.phase
    }

    /// The prepared send, if any (the proxy never passes descriptors).
    pub fn outgoing(&self) -> Option<Outgoing<'_, H>> {
        self.prepared.as_ref().map(|p| Outgoing {
            op: p.op,
            bytes: p.frame.as_bytes(),
            fd: None,
        })
    }

    /// RED: never blocks.
    pub fn can_prepare_admit(&self) -> Result<(), AdmitBlocked> {
        Ok(())
    }

    fn take_op(&mut self) -> OpId {
        let op = OpId::from_raw(self.next_op);
        self.next_op += 1;
        op
    }

    /// RED: accepts every well-formed input, whatever the phase, limits or time.
    pub fn step(&mut self, input: ProxyInput<'_, H>) -> ProxyStep<H> {
        match input {
            ProxyInput::Tick(now) => match self.counters.next_offer(now, false) {
                Some(event) => {
                    let op = self.take_op();
                    self.prepared = Some(Prepared {
                        op,
                        frame: encode_p2d(&OutboundP2d::Event(event)),
                        kind: Sending::Event(event),
                    });
                    ProxyStep::Send(op)
                }
                None => ProxyStep::Idle,
            },
            ProxyInput::Recv(recv) => {
                if recv.msg_ctrunc {
                    return ProxyStep::Refused(IpcRefusal::AncillaryTruncated);
                }
                if recv.unexpected_control {
                    return ProxyStep::Refused(IpcRefusal::UnexpectedAncillary);
                }
                let (kind, body) =
                    match wire::parse_header(recv.bytes, recv.msg_trunc, wire::is_d2p_kind) {
                        Ok(parsed) => parsed,
                        Err(code) => return ProxyStep::Refused(code),
                    };
                let message = match wire::decode_d2p_body(kind, body) {
                    Ok(message) => message,
                    Err(code) => return ProxyStep::Refused(code),
                };
                let fds = recv.fds;
                match message {
                    InboundD2p::Welcome(welcome) => {
                        if let Err(code) = wire::check_welcome_fds(&welcome, &fds) {
                            return ProxyStep::Refused(code);
                        }
                        match fds.into_first() {
                            Some(listener) => {
                                self.phase = ProxyPhase::Active;
                                self.mode = Some(welcome.mode());
                                ProxyStep::Welcome(welcome, listener)
                            }
                            None => ProxyStep::Refused(IpcRefusal::BadFdCount),
                        }
                    }
                    InboundD2p::Verdict(id, outcome) => {
                        let mode = self.mode.unwrap_or(ModeKind::Static);
                        if let Err(code) = wire::check_verdict_fds(outcome, mode, &fds) {
                            return ProxyStep::Refused(code);
                        }
                        self.pending = self.pending.saturating_sub(1);
                        self.last_completed = Some(id);
                        let upstream = if outcome == Outcome::AdmittedUpstream {
                            fds.into_first()
                        } else {
                            None
                        };
                        ProxyStep::Verdict(id, outcome, upstream)
                    }
                    InboundD2p::Shutdown => {
                        self.phase = ProxyPhase::Closed;
                        ProxyStep::Close
                    }
                }
            }
            ProxyInput::PrepareReady => {
                let op = self.take_op();
                self.prepared = Some(Prepared {
                    op,
                    frame: encode_p2d(&OutboundP2d::Ready),
                    kind: Sending::Ready,
                });
                self.phase = ProxyPhase::ReadyPrepared;
                ProxyStep::Send(op)
            }
            ProxyInput::PrepareAdmit(admit) => {
                let id = AdmissionId::from_raw(self.next_id);
                self.next_id = self.next_id.wrapping_add(1);
                let op = self.take_op();
                self.prepared = Some(Prepared {
                    op,
                    frame: encode_p2d(&OutboundP2d::Admit(id, admit)),
                    kind: Sending::Admit(id),
                });
                ProxyStep::Send(op)
            }
            ProxyInput::Observe(code, count) => {
                self.counters.observe(code, count);
                ProxyStep::Idle
            }
            ProxyInput::SendResult(_op, outcome) => match outcome {
                SendOutcome::Fatal | SendOutcome::Short => {
                    ProxyStep::Refused(IpcRefusal::SendFailed)
                }
                SendOutcome::WouldBlock => ProxyStep::Idle,
                SendOutcome::SentWhole => match self.prepared.take() {
                    None => ProxyStep::Idle,
                    Some(prepared) => match prepared.kind {
                        Sending::Ready => {
                            self.phase = ProxyPhase::AwaitWelcome;
                            ProxyStep::Idle
                        }
                        Sending::Admit(id) => {
                            self.pending += 1;
                            self.last_sent = Some(id);
                            ProxyStep::AdmitSent(id)
                        }
                        Sending::Event(event) => {
                            self.counters.commit(&event);
                            ProxyStep::Idle
                        }
                    },
                },
            },
            ProxyInput::Terminate(_reason) => {
                self.phase = ProxyPhase::Stopping;
                ProxyStep::Stopping
            }
            ProxyInput::TransportEof => ProxyStep::Refused(IpcRefusal::TransportClosed),
            ProxyInput::TransportError => ProxyStep::Refused(IpcRefusal::TransportFailed),
        }
    }
}

/// Test and fuzz accessors and the test-only state builder (never in a shipped build).
#[cfg(any(test, fuzzing))]
impl<H> ProxySession<H> {
    /// Positions the allocator at `next_id` (RED: always applies).
    pub fn test_only_set_next_id(&mut self, next_id: u32) -> bool {
        self.next_id = next_id;
        true
    }

    /// Unanswered admissions (RED: sent minus verdicts).
    pub fn test_only_pending_len(&self) -> usize {
        self.pending.min(crate::limits::MAX_PENDING)
    }

    /// Admissions committed in the current rate window (RED: not tracked).
    pub fn test_only_window_admissions(&self) -> u32 {
        0
    }

    /// The most recently sent admission.
    pub fn test_only_answerable(&self) -> Option<AdmissionId> {
        self.last_sent
    }

    /// The most recently completed id.
    pub fn test_only_last_completed(&self) -> Option<AdmissionId> {
        self.last_completed
    }

    /// The current count for `code`.
    pub fn test_only_counter(&self, code: EventCode) -> u32 {
        self.counters.current(code)
    }

    /// Whether any counter is nonzero.
    pub fn test_only_counters_nonzero(&self) -> bool {
        self.counters.any_nonzero()
    }
}
