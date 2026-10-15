//! The DAEMON endpoint's state machine (DESIGN v2 (2)): one actor's complete transition table.
//!
//! Phases: AwaitReady -> CheckingF0 -> WelcomeReady -> WelcomePrepared -> Active -> Stopping ->
//! Closed, with Refused(code) absorbing. Every input not legal in its phase refuses (OutOfOrder
//! unless an earlier precedence row applies); the first refusal latches: the session drops its
//! prepared frame and descriptor and every pending admission, returns [`DaemonStep::Refused`] ONCE
//! (the one cleanup request), and from then on returns [`DaemonStep::Terminal`] for every input,
//! dropping any descriptor the input carried.

use crate::events::{DaemonEventWindow, EventRecords};
use crate::limits::{RATE_MAX_ADMITS, RATE_WINDOW_NS, SEND_DEADLINE_NS, STARTUP_DEADLINE_NS};
use crate::pending::{CompletedFifo, Entry, PendingMap};
use crate::refusal::IpcRefusal;
use crate::types::{
    AdmissionId, F0Result, ModeKind, OpId, Outcome, SendOutcome, ServingMode, StopReason,
};
use crate::wire::{
    self, is_lower_hex, Frame, InboundAdmit, InboundP2d, Outgoing, P2dRecv, HOST_LABEL_LEN,
    KIND_ADMIT, KIND_EVENT, KIND_READY, KIND_SHUTDOWN, KIND_VERDICT, KIND_WELCOME,
};

/// The daemon session's configuration.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct DaemonConfig {
    /// The total deadline from a committed ADMIT to its VERDICT's whole send (the connector's
    /// bounded handover, DESIGN v2 (11), U4); an expired pending admission latches
    /// OperationTimeout.
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
// clippy::large_enum_variant is allowed ON PURPOSE (S1-85D ruling, option (b)): the crate is no_std
// WITHOUT alloc, so the large variant cannot be boxed; it is a fixed-size stack value (at most a few
// hundred bytes) moved once per step through the actor's single-threaded loop.
#[allow(clippy::large_enum_variant)]
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
    deadline: u64,
}

/// The daemon endpoint of one proxy's IPC session (pure: the adapter owns the socket).
pub struct DaemonSession<H> {
    phase: DaemonPhase,
    config: DaemonConfig,
    last_now: u64,
    startup_deadline: u64,
    stop_deadline: u64,
    f0_proof: bool,
    shutdown_prepared: bool,
    mode: Option<ModeKind>,
    epoch: u64,
    window_index: u64,
    window_admissions: u32,
    last_id: u32,
    pending: PendingMap,
    completed: CompletedFifo,
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
    /// A session for a proxy spawned at `spawn_ns` (the 5-second startup deadline starts here).
    pub fn new(spawn_ns: u64, config: DaemonConfig) -> DaemonSession<H> {
        DaemonSession {
            phase: DaemonPhase::AwaitReady,
            config,
            last_now: spawn_ns,
            startup_deadline: spawn_ns.saturating_add(STARTUP_DEADLINE_NS),
            stop_deadline: u64::MAX,
            f0_proof: false,
            shutdown_prepared: false,
            mode: None,
            epoch: spawn_ns,
            window_index: 0,
            window_admissions: 0,
            last_id: 0,
            pending: PendingMap::new(),
            completed: CompletedFifo::new(),
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

    /// Applies one input: the complete transition table.
    pub fn step(&mut self, input: DaemonInput<'_, H>) -> DaemonStep {
        if matches!(self.phase, DaemonPhase::Closed | DaemonPhase::Refused(_)) {
            drop(input);
            return DaemonStep::Terminal;
        }
        match input {
            DaemonInput::Tick(now) => self.on_tick(now),
            DaemonInput::Recv(recv) => self.on_recv(recv),
            DaemonInput::F0(result) => self.on_f0(result),
            DaemonInput::PrepareWelcome(spec, listener) => self.on_prepare_welcome(spec, listener),
            DaemonInput::PrepareVerdict(id, verdict) => self.on_prepare_verdict(id, verdict),
            DaemonInput::PrepareShutdown => self.on_prepare_shutdown(),
            DaemonInput::SendResult(op, outcome) => self.on_send_result(op, outcome),
            DaemonInput::Terminate(_reason) => self.on_terminate(),
            DaemonInput::TransportEof => self.refuse(IpcRefusal::TransportClosed),
            DaemonInput::TransportError => self.refuse(IpcRefusal::TransportFailed),
        }
    }

    fn refuse(&mut self, code: IpcRefusal) -> DaemonStep {
        self.phase = DaemonPhase::Refused(code);
        self.prepared = None;
        self.pending.clear();
        self.f0_proof = false;
        DaemonStep::Refused(code)
    }

    fn teardown(&mut self) -> DaemonStep {
        self.phase = DaemonPhase::Closed;
        self.prepared = None;
        self.pending.clear();
        self.f0_proof = false;
        DaemonStep::Teardown
    }

    fn enter_stopping(&mut self) {
        self.phase = DaemonPhase::Stopping;
        self.stop_deadline = self.last_now.saturating_add(SEND_DEADLINE_NS);
        self.prepared = None;
        self.pending.clear();
        self.f0_proof = false;
    }

    fn take_op(&mut self) -> OpId {
        let op = OpId::from_raw(self.next_op);
        self.next_op += 1;
        op
    }

    fn on_tick(&mut self, now: u64) -> DaemonStep {
        if now < self.last_now {
            return self.refuse(IpcRefusal::ClockRegression);
        }
        self.last_now = now;
        match self.phase {
            DaemonPhase::AwaitReady
            | DaemonPhase::CheckingF0
            | DaemonPhase::WelcomeReady
            | DaemonPhase::WelcomePrepared => {
                if now >= self.startup_deadline {
                    return self.refuse(IpcRefusal::OperationTimeout);
                }
            }
            DaemonPhase::Stopping => {
                if now >= self.stop_deadline {
                    return self.teardown();
                }
            }
            _ => {}
        }
        if let Some(prepared) = &self.prepared {
            if now >= prepared.deadline {
                return if self.phase == DaemonPhase::Stopping {
                    self.teardown()
                } else {
                    self.refuse(IpcRefusal::OperationTimeout)
                };
            }
        }
        if self.phase == DaemonPhase::Active && self.pending.any_expired(now) {
            return self.refuse(IpcRefusal::OperationTimeout);
        }
        match self.events.roll(now) {
            Some(records) => DaemonStep::Persist(records),
            None => DaemonStep::Idle,
        }
    }

    fn on_recv(&mut self, recv: P2dRecv<'_>) -> DaemonStep {
        // Row 2: the daemon supplies no ancillary buffer.
        if recv.control_present || recv.msg_ctrunc {
            return self.refuse(IpcRefusal::AncillaryFromProxy);
        }
        // Rows 3-4.
        let (kind, body) = match wire::parse_header(recv.bytes, recv.msg_trunc, wire::is_p2d_kind) {
            Ok(parsed) => parsed,
            Err(code) => return self.refuse(code),
        };
        // Row 5: inbound is suspended while a send is prepared.
        let legal = match (self.phase, kind) {
            (DaemonPhase::AwaitReady, KIND_READY) => true,
            (DaemonPhase::Active, KIND_ADMIT | KIND_EVENT) => self.prepared.is_none(),
            _ => false,
        };
        if !legal {
            return self.refuse(IpcRefusal::OutOfOrder);
        }
        // Row 6 (an ADMIT's digest count against its purpose's limit in this session's mode).
        let message = match wire::decode_p2d_body(kind, body, self.mode) {
            Ok(message) => message,
            Err(code) => return self.refuse(code),
        };
        match message {
            InboundP2d::Ready => {
                self.phase = DaemonPhase::CheckingF0;
                DaemonStep::RunF0
            }
            InboundP2d::Admit(admit) => self.on_admit(admit),
            InboundP2d::Event(event) => {
                self.events.add(event.code(), event.count());
                DaemonStep::Idle
            }
        }
    }

    /// Row 8 for ADMIT: id, then pending < 64, then the window count < 2000; all commit together.
    fn on_admit(&mut self, admit: InboundAdmit) -> DaemonStep {
        let id = admit.id().get();
        if self.last_id == u32::MAX {
            return self.refuse(IpcRefusal::ConnExhausted);
        }
        if id <= self.last_id {
            return self.refuse(IpcRefusal::ConnNotIncreasing);
        }
        if self.pending.is_full() {
            return self.refuse(IpcRefusal::TooManyInFlight);
        }
        let index = self.last_now.saturating_sub(self.epoch) / RATE_WINDOW_NS;
        let count = if index > self.window_index {
            0
        } else {
            self.window_admissions
        };
        if count >= RATE_MAX_ADMITS {
            return self.refuse(IpcRefusal::RateExceeded);
        }
        let entry = Entry {
            id: admit.id(),
            purpose: admit.purpose(),
            sending: false,
            deadline: self
                .last_now
                .saturating_add(self.config.verdict_deadline_ns),
        };
        if !self.pending.insert(entry) {
            return self.refuse(IpcRefusal::TooManyInFlight);
        }
        self.window_index = index.max(self.window_index);
        self.window_admissions = count + 1;
        self.last_id = id;
        DaemonStep::Admit(admit)
    }

    fn on_f0(&mut self, result: F0Result) -> DaemonStep {
        if result == F0Result::Fail {
            return self.refuse(IpcRefusal::BoundaryUnverified);
        }
        if self.phase != DaemonPhase::CheckingF0 {
            return self.refuse(IpcRefusal::OutOfOrder);
        }
        self.f0_proof = true;
        self.phase = DaemonPhase::WelcomeReady;
        DaemonStep::Idle
    }

    fn on_prepare_welcome(&mut self, spec: WelcomeSpec, listener: H) -> DaemonStep {
        if self.phase != DaemonPhase::WelcomeReady || !self.f0_proof || self.prepared.is_some() {
            drop(listener);
            return self.refuse(IpcRefusal::OutOfOrder);
        }
        let frame = match encode_welcome(&spec) {
            Ok(frame) => frame,
            Err(code) => {
                drop(listener);
                return self.refuse(code);
            }
        };
        self.f0_proof = false;
        self.mode = Some(spec.mode.kind());
        let op = self.take_op();
        let deadline = self
            .last_now
            .saturating_add(SEND_DEADLINE_NS)
            .min(self.startup_deadline);
        self.prepared = Some(Prepared {
            op,
            frame,
            fd: Some(listener),
            kind: Sending::Welcome,
            deadline,
        });
        self.phase = DaemonPhase::WelcomePrepared;
        DaemonStep::Send(op)
    }

    fn on_prepare_verdict(&mut self, id: AdmissionId, verdict: VerdictSpec<H>) -> DaemonStep {
        if self.phase != DaemonPhase::Active || self.prepared.is_some() {
            drop(verdict);
            return self.refuse(IpcRefusal::OutOfOrder);
        }
        let outcome = verdict.outcome();
        let mode = self.mode.unwrap_or(ModeKind::Static);
        let checked = match self.pending.get_mut(id) {
            None => Err(if self.completed.contains(id) {
                IpcRefusal::DuplicateVerdict
            } else {
                IpcRefusal::UnknownVerdict
            }),
            Some(entry) if entry.sending => Err(IpcRefusal::DuplicateVerdict),
            Some(entry) if !outcome.legal_for(mode, entry.purpose) => {
                Err(IpcRefusal::BadOutcomeForPurpose)
            }
            Some(entry) => {
                entry.sending = true;
                Ok(entry.deadline)
            }
        };
        let deadline = match checked {
            Ok(deadline) => deadline,
            Err(code) => {
                drop(verdict);
                return self.refuse(code);
            }
        };
        let op = self.take_op();
        self.prepared = Some(Prepared {
            op,
            frame: encode_verdict(id, outcome),
            fd: verdict.into_fd(),
            kind: Sending::Verdict(id),
            deadline,
        });
        DaemonStep::Send(op)
    }

    fn on_prepare_shutdown(&mut self) -> DaemonStep {
        let after_ready = matches!(
            self.phase,
            DaemonPhase::CheckingF0
                | DaemonPhase::WelcomeReady
                | DaemonPhase::Active
                | DaemonPhase::Stopping
        );
        if !after_ready || self.prepared.is_some() || self.shutdown_prepared {
            return self.refuse(IpcRefusal::OutOfOrder);
        }
        if self.phase != DaemonPhase::Stopping {
            self.enter_stopping();
        }
        self.shutdown_prepared = true;
        let op = self.take_op();
        self.prepared = Some(Prepared {
            op,
            frame: encode_shutdown(),
            fd: None,
            kind: Sending::Shutdown,
            deadline: self.stop_deadline,
        });
        DaemonStep::Send(op)
    }

    fn on_send_result(&mut self, op: OpId, outcome: SendOutcome) -> DaemonStep {
        if matches!(outcome, SendOutcome::Fatal | SendOutcome::Short) {
            return self.refuse(IpcRefusal::SendFailed);
        }
        if !matches!(&self.prepared, Some(prepared) if prepared.op == op) {
            return self.refuse(IpcRefusal::OutOfOrder);
        }
        if outcome == SendOutcome::WouldBlock {
            return DaemonStep::Idle;
        }
        let prepared = match self.prepared.take() {
            Some(prepared) => prepared,
            None => return self.refuse(IpcRefusal::OutOfOrder),
        };
        let Prepared { fd, kind, .. } = prepared;
        drop(fd);
        match kind {
            Sending::Welcome => {
                self.phase = DaemonPhase::Active;
                self.epoch = self.last_now;
                self.window_index = 0;
                self.window_admissions = 0;
                DaemonStep::WelcomeSent
            }
            Sending::Verdict(id) => {
                self.pending.remove(id);
                self.completed.push(id);
                DaemonStep::VerdictSent(id)
            }
            Sending::Shutdown => self.teardown(),
        }
    }

    fn on_terminate(&mut self) -> DaemonStep {
        match self.phase {
            DaemonPhase::AwaitReady => self.teardown(),
            DaemonPhase::Stopping => DaemonStep::Idle,
            _ => {
                self.enter_stopping();
                DaemonStep::Stopping
            }
        }
    }
}

/// Test and fuzz accessors (never in a shipped build).
#[cfg(any(test, fuzzing))]
impl<H> DaemonSession<H> {
    /// Unanswered admissions.
    pub fn test_only_pending_len(&self) -> usize {
        self.pending.len()
    }

    /// Admissions committed in the current rate window.
    pub fn test_only_window_admissions(&self) -> u32 {
        self.window_admissions
    }

    /// The oldest pending admission not yet being answered.
    pub fn test_only_answerable(&self) -> Option<AdmissionId> {
        self.pending.any_answerable()
    }

    /// The most recently completed id.
    pub fn test_only_last_completed(&self) -> Option<AdmissionId> {
        self.completed.last()
    }

    /// The WELCOME mode, once prepared.
    pub fn test_only_mode(&self) -> Option<ModeKind> {
        self.mode
    }
}
