//! The PROXY endpoint's state machine (DESIGN v2 (2)): one actor's complete transition table.
//!
//! Phases: Bootstrap -> ReadyPrepared -> AwaitWelcome -> Active -> Stopping -> Closed, with
//! Refused(code) absorbing. READY is emitted after exec, bootstrap fd closure and final filter
//! installation (no listener exists in this process before WELCOME). The actor ALLOCATES admission
//! ids (from 1, strictly increasing, never reused or wrapped). The first refusal latches exactly as
//! the daemon's does.

use core::marker::PhantomData;

use crate::events::ProxyEventCounters;
use crate::limits::{RATE_MAX_ADMITS, RATE_WINDOW_NS, SEND_DEADLINE_NS, STARTUP_DEADLINE_NS};
use crate::pending::{CompletedFifo, Entry, PendingMap};
use crate::refusal::IpcRefusal;
use crate::types::{
    AdmissionId, EventCode, ModeKind, OpId, Outcome, Purpose, SendOutcome, StopReason,
};
use crate::wire::{
    self, encode_p2d, D2pRecv, Frame, InboundD2p, InboundWelcome, OutboundAdmit, OutboundEvent,
    OutboundP2d, Outgoing, KIND_SHUTDOWN, KIND_VERDICT, KIND_WELCOME,
};

/// The proxy session's configuration.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct ProxyConfig {
    /// How long a sent ADMIT may wait for its VERDICT (the daemon's verdict deadline); an expired
    /// pending admission latches OperationTimeout.
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

/// Why an ADMIT cannot be prepared now (honest flow control: check before preparing; preparing
/// anyway latches the matching refusal).
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
    Admit(AdmissionId, Purpose),
    Event(OutboundEvent),
}

struct Prepared {
    op: OpId,
    frame: Frame,
    kind: Sending,
    deadline: u64,
}

/// The proxy endpoint of its IPC session (pure: the adapter owns the socket).
pub struct ProxySession<H> {
    phase: ProxyPhase,
    config: ProxyConfig,
    last_now: u64,
    startup_deadline: u64,
    stop_deadline: u64,
    mode: Option<ModeKind>,
    epoch: u64,
    window_index: u64,
    window_admissions: u32,
    next_id: u32,
    any_admit: bool,
    exhausted: bool,
    pending: PendingMap,
    completed: CompletedFifo,
    next_op: u64,
    prepared: Option<Prepared>,
    counters: ProxyEventCounters,
    handles: PhantomData<fn(H)>,
}

impl<H> ProxySession<H> {
    /// A session for a proxy that started at `start_ns` (the 5-second startup deadline starts here).
    pub fn new(start_ns: u64, config: ProxyConfig) -> ProxySession<H> {
        ProxySession {
            phase: ProxyPhase::Bootstrap,
            config,
            last_now: start_ns,
            startup_deadline: start_ns.saturating_add(STARTUP_DEADLINE_NS),
            stop_deadline: u64::MAX,
            mode: None,
            epoch: start_ns,
            window_index: 0,
            window_admissions: 0,
            next_id: 1,
            any_admit: false,
            exhausted: false,
            pending: PendingMap::new(),
            completed: CompletedFifo::new(),
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

    /// Whether an ADMIT may be prepared now (no side effect).
    pub fn can_prepare_admit(&self) -> Result<(), AdmitBlocked> {
        if self.phase != ProxyPhase::Active {
            return Err(AdmitBlocked::NotActive);
        }
        if self.prepared.is_some() {
            return Err(AdmitBlocked::SendInProgress);
        }
        if self.exhausted {
            return Err(AdmitBlocked::Exhausted);
        }
        if self.pending.is_full() {
            return Err(AdmitBlocked::InFlightFull);
        }
        let (_, count) = self.window_count();
        if count >= RATE_MAX_ADMITS {
            return Err(AdmitBlocked::RateLimited);
        }
        Ok(())
    }

    /// Applies one input: the complete transition table.
    pub fn step(&mut self, input: ProxyInput<'_, H>) -> ProxyStep<H> {
        if matches!(self.phase, ProxyPhase::Closed | ProxyPhase::Refused(_)) {
            drop(input);
            return ProxyStep::Terminal;
        }
        match input {
            ProxyInput::Tick(now) => self.on_tick(now),
            ProxyInput::Recv(recv) => self.on_recv(recv),
            ProxyInput::PrepareReady => self.on_prepare_ready(),
            ProxyInput::PrepareAdmit(admit) => self.on_prepare_admit(admit),
            ProxyInput::Observe(code, count) => {
                self.counters.observe(code, count);
                ProxyStep::Idle
            }
            ProxyInput::SendResult(op, outcome) => self.on_send_result(op, outcome),
            ProxyInput::Terminate(_reason) => self.on_terminate(),
            ProxyInput::TransportEof => self.refuse(IpcRefusal::TransportClosed),
            ProxyInput::TransportError => self.refuse(IpcRefusal::TransportFailed),
        }
    }

    fn refuse(&mut self, code: IpcRefusal) -> ProxyStep<H> {
        self.phase = ProxyPhase::Refused(code);
        self.prepared = None;
        self.pending.clear();
        ProxyStep::Refused(code)
    }

    fn close(&mut self) -> ProxyStep<H> {
        self.phase = ProxyPhase::Closed;
        self.prepared = None;
        self.pending.clear();
        ProxyStep::Close
    }

    fn enter_stopping(&mut self) {
        self.phase = ProxyPhase::Stopping;
        self.stop_deadline = self.last_now.saturating_add(SEND_DEADLINE_NS);
        self.prepared = None;
        self.pending.clear();
    }

    fn take_op(&mut self) -> OpId {
        let op = OpId::from_raw(self.next_op);
        self.next_op += 1;
        op
    }

    /// The current rate window's index and committed count.
    fn window_count(&self) -> (u64, u32) {
        let index = self.last_now.saturating_sub(self.epoch) / RATE_WINDOW_NS;
        if index > self.window_index {
            (index, 0)
        } else {
            (self.window_index, self.window_admissions)
        }
    }

    fn on_tick(&mut self, now: u64) -> ProxyStep<H> {
        if now < self.last_now {
            return self.refuse(IpcRefusal::ClockRegression);
        }
        self.last_now = now;
        match self.phase {
            ProxyPhase::Bootstrap | ProxyPhase::ReadyPrepared | ProxyPhase::AwaitWelcome => {
                if now >= self.startup_deadline {
                    return self.refuse(IpcRefusal::OperationTimeout);
                }
            }
            ProxyPhase::Stopping => {
                if now >= self.stop_deadline {
                    return self.close();
                }
            }
            _ => {}
        }
        if let Some(prepared) = &self.prepared {
            if now >= prepared.deadline {
                return if self.phase == ProxyPhase::Stopping {
                    self.close()
                } else {
                    self.refuse(IpcRefusal::OperationTimeout)
                };
            }
        }
        if self.phase == ProxyPhase::Active {
            if self.pending.any_expired(now) {
                return self.refuse(IpcRefusal::OperationTimeout);
            }
            if self.exhausted && self.pending.len() == 0 && self.prepared.is_none() {
                self.enter_stopping();
                return ProxyStep::Stopping;
            }
        }
        if matches!(self.phase, ProxyPhase::Active | ProxyPhase::Stopping)
            && self.prepared.is_none()
        {
            let stopping = self.phase == ProxyPhase::Stopping;
            if let Some(event) = self.counters.next_offer(now, stopping) {
                let op = self.take_op();
                let deadline = if stopping {
                    self.stop_deadline
                } else {
                    now.saturating_add(SEND_DEADLINE_NS)
                };
                self.prepared = Some(Prepared {
                    op,
                    frame: encode_p2d(&OutboundP2d::Event(event)),
                    kind: Sending::Event(event),
                    deadline,
                });
                return ProxyStep::Send(op);
            }
            if stopping {
                return self.close();
            }
        }
        ProxyStep::Idle
    }

    fn on_recv(&mut self, recv: D2pRecv<'_, H>) -> ProxyStep<H> {
        // Row 2.
        if recv.msg_ctrunc {
            return self.refuse(IpcRefusal::AncillaryTruncated);
        }
        if recv.unexpected_control {
            return self.refuse(IpcRefusal::UnexpectedAncillary);
        }
        // Rows 3-4.
        let (kind, body) = match wire::parse_header(recv.bytes, recv.msg_trunc, wire::is_d2p_kind) {
            Ok(parsed) => parsed,
            Err(code) => return self.refuse(code),
        };
        // Row 5: inbound is suspended while a send is prepared.
        let legal = self.prepared.is_none()
            && match (self.phase, kind) {
                (ProxyPhase::AwaitWelcome, KIND_WELCOME | KIND_SHUTDOWN) => true,
                (ProxyPhase::Active, KIND_VERDICT | KIND_SHUTDOWN) => true,
                (ProxyPhase::Stopping, KIND_SHUTDOWN) => true,
                _ => false,
            };
        if !legal {
            return self.refuse(IpcRefusal::OutOfOrder);
        }
        // Row 6.
        let message = match wire::decode_d2p_body(kind, body) {
            Ok(message) => message,
            Err(code) => return self.refuse(code),
        };
        let fds = recv.fds;
        match message {
            InboundD2p::Welcome(welcome) => {
                // Row 7.
                if let Err(code) = wire::check_welcome_fds(&welcome, &fds) {
                    return self.refuse(code);
                }
                let listener = match fds.into_first() {
                    Some(listener) => listener,
                    None => return self.refuse(IpcRefusal::BadFdCount),
                };
                self.phase = ProxyPhase::Active;
                self.mode = Some(welcome.mode());
                self.epoch = self.last_now;
                self.window_index = 0;
                self.window_admissions = 0;
                ProxyStep::Welcome(welcome, listener)
            }
            InboundD2p::Verdict(id, outcome) => {
                let mode = self.mode.unwrap_or(ModeKind::Static);
                // Row 7.
                if let Err(code) = wire::check_verdict_fds(outcome, mode, &fds) {
                    return self.refuse(code);
                }
                // Row 8.
                let checked = match self.pending.get_mut(id) {
                    None => Err(if self.completed.contains(id) {
                        IpcRefusal::DuplicateVerdict
                    } else {
                        IpcRefusal::UnknownVerdict
                    }),
                    Some(entry) if !outcome.legal_for(mode, entry.purpose) => {
                        Err(IpcRefusal::BadOutcomeForPurpose)
                    }
                    Some(_) => Ok(()),
                };
                if let Err(code) = checked {
                    return self.refuse(code);
                }
                self.pending.remove(id);
                self.completed.push(id);
                let upstream = if outcome == Outcome::AdmittedUpstream {
                    fds.into_first()
                } else {
                    None
                };
                ProxyStep::Verdict(id, outcome, upstream)
            }
            InboundD2p::Shutdown => {
                if !fds.is_empty() {
                    return self.refuse(IpcRefusal::BadFdCount);
                }
                self.close()
            }
        }
    }

    fn on_prepare_ready(&mut self) -> ProxyStep<H> {
        if self.phase != ProxyPhase::Bootstrap || self.prepared.is_some() {
            return self.refuse(IpcRefusal::OutOfOrder);
        }
        let op = self.take_op();
        let deadline = self
            .last_now
            .saturating_add(SEND_DEADLINE_NS)
            .min(self.startup_deadline);
        self.prepared = Some(Prepared {
            op,
            frame: encode_p2d(&OutboundP2d::Ready),
            kind: Sending::Ready,
            deadline,
        });
        self.phase = ProxyPhase::ReadyPrepared;
        ProxyStep::Send(op)
    }

    fn on_prepare_admit(&mut self, admit: OutboundAdmit) -> ProxyStep<H> {
        if let Err(blocked) = self.can_prepare_admit() {
            return self.refuse(match blocked {
                AdmitBlocked::NotActive | AdmitBlocked::SendInProgress => IpcRefusal::OutOfOrder,
                AdmitBlocked::Exhausted => IpcRefusal::ConnExhausted,
                AdmitBlocked::InFlightFull => IpcRefusal::TooManyInFlight,
                AdmitBlocked::RateLimited => IpcRefusal::RateExceeded,
            });
        }
        let id = AdmissionId::from_raw(self.next_id);
        let purpose = admit.purpose();
        let op = self.take_op();
        self.any_admit = true;
        self.prepared = Some(Prepared {
            op,
            frame: encode_p2d(&OutboundP2d::Admit(id, admit)),
            kind: Sending::Admit(id, purpose),
            deadline: self.last_now.saturating_add(SEND_DEADLINE_NS),
        });
        ProxyStep::Send(op)
    }

    fn on_send_result(&mut self, op: OpId, outcome: SendOutcome) -> ProxyStep<H> {
        if matches!(outcome, SendOutcome::Fatal | SendOutcome::Short) {
            return self.refuse(IpcRefusal::SendFailed);
        }
        if !matches!(&self.prepared, Some(prepared) if prepared.op == op) {
            return self.refuse(IpcRefusal::OutOfOrder);
        }
        if outcome == SendOutcome::WouldBlock {
            return ProxyStep::Idle;
        }
        let prepared = match self.prepared.take() {
            Some(prepared) => prepared,
            None => return self.refuse(IpcRefusal::OutOfOrder),
        };
        match prepared.kind {
            Sending::Ready => {
                self.phase = ProxyPhase::AwaitWelcome;
                ProxyStep::Idle
            }
            Sending::Admit(id, purpose) => {
                let (index, count) = self.window_count();
                let entry = Entry {
                    id,
                    purpose,
                    sending: false,
                    deadline: self
                        .last_now
                        .saturating_add(self.config.verdict_deadline_ns),
                };
                if !self.pending.insert(entry) {
                    return self.refuse(IpcRefusal::TooManyInFlight);
                }
                self.window_index = index;
                self.window_admissions = count + 1;
                if id.get() == u32::MAX {
                    self.exhausted = true;
                } else {
                    self.next_id = id.get() + 1;
                }
                ProxyStep::AdmitSent(id)
            }
            Sending::Event(event) => {
                self.counters.commit(&event);
                ProxyStep::Idle
            }
        }
    }

    fn on_terminate(&mut self) -> ProxyStep<H> {
        match self.phase {
            ProxyPhase::Bootstrap | ProxyPhase::ReadyPrepared | ProxyPhase::AwaitWelcome => {
                self.close()
            }
            ProxyPhase::Stopping => ProxyStep::Idle,
            _ => {
                self.enter_stopping();
                ProxyStep::Stopping
            }
        }
    }
}

/// Test and fuzz accessors and the test-only state builder (never in a shipped build).
#[cfg(any(test, fuzzing))]
impl<H> ProxySession<H> {
    /// Positions the honest allocator at `next_id` (only before any ADMIT was prepared; 0 is
    /// refused). Returns whether it applied.
    pub fn test_only_set_next_id(&mut self, next_id: u32) -> bool {
        if self.any_admit || next_id == 0 {
            return false;
        }
        self.next_id = next_id;
        true
    }

    /// Unanswered admissions.
    pub fn test_only_pending_len(&self) -> usize {
        self.pending.len()
    }

    /// Admissions committed in the current rate window.
    pub fn test_only_window_admissions(&self) -> u32 {
        self.window_admissions
    }

    /// The oldest pending admission.
    pub fn test_only_answerable(&self) -> Option<AdmissionId> {
        self.pending.any_answerable()
    }

    /// The most recently completed id.
    pub fn test_only_last_completed(&self) -> Option<AdmissionId> {
        self.completed.last()
    }

    /// The current saturating count for `code`.
    pub fn test_only_counter(&self, code: EventCode) -> u32 {
        self.counters.current(code)
    }

    /// Whether any counter is nonzero.
    pub fn test_only_counters_nonzero(&self) -> bool {
        self.counters.any_nonzero()
    }
}
