//! The session limits and deadlines (DESIGN v2 (2)). All times are a trusted monotonic clock in
//! nanoseconds, supplied by the actor's own `Tick`s, never by the peer.

/// The most unanswered admissions per session (the 65th refuses TooManyInFlight).
pub const MAX_PENDING: usize = 64;
/// How many completed ids classify a repeated VERDICT as DuplicateVerdict.
pub const COMPLETED_FIFO: usize = 64;
/// The admission rate window (fixed windows from each actor's own WELCOME epoch).
pub const RATE_WINDOW_NS: u64 = 10_000_000_000;
/// Valid admissions per window (the 2001st refuses RateExceeded). Fixed windows permit a
/// 4000-admission boundary burst; U6 sizes this against editor load.
pub const RATE_MAX_ADMITS: u32 = 2000;
/// The total startup deadline from spawn (until WELCOME completes).
pub const STARTUP_DEADLINE_NS: u64 = 5_000_000_000;
/// The deadline of a READY / WELCOME / SHUTDOWN / ADMIT / EVENT send (also bounding Stopping);
/// VERDICT uses the configured verdict deadline instead.
pub const SEND_DEADLINE_NS: u64 = 1_000_000_000;
/// Per-session IPC work is serviced in batches of at most this many frames before yielding (an
/// adapter rule, U3/U4).
pub const MAX_FRAMES_PER_BATCH: usize = 64;
