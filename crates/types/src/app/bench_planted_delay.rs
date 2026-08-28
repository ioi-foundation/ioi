// Path: crates/types/src/app/bench_planted_delay.rs
//
// The M04.9 planted-phase-delay seam.
//
// ADR 0039 will not accept a numeric latency tripwire until a planted delay
// has been shown to land in the phase the artifact attributes it to. A profile
// that reports plausible numbers against the WRONG phase is indistinguishable
// from a correct one by reading it, so the only way to bind attribution is to
// inject a known delay at a known seam and require exactly the named phase to
// move.
//
// THIS IS OBSERVATION INSTRUMENTATION, NEVER A PRODUCTION DEFAULT.
//
// Two independent things must both be true before any delay is planted:
//
//   1. `IOI_AFT_BENCH_TRACE` is set -- the estate's existing, explicit,
//      test-only benchmark-trace arming; and
//   2. `IOI_TESTING_M049_PLANTED_PHASE_DELAY` names a phase and a delay.
//
// One without the other is an ERROR, not a silent no-op. A spec set without
// the trace arming means an operator believed a delay was active when it was
// not, and quietly running full speed would let them read an unplanted profile
// as a planted one. Symmetrically, an unparseable spec, an unknown phase name,
// a zero delay, or a delay beyond the ceiling all refuse: a mutation that
// silently did nothing would make the mutation test pass for the wrong reason.
//
// The refusal is returned, not panicked and not logged-and-ignored. Every call
// site is on a fallible path, so a malformed spec fails the run that armed it.

use std::fmt;
use std::time::Duration;

/// The explicit, test-only benchmark-trace arming this seam requires.
///
/// Deliberately the estate's EXISTING trace gate rather than a new one: a
/// planted delay must never be reachable on any path that the ordinary,
/// untraced runtime walks.
pub const BENCH_TRACE_ENV: &str = "IOI_AFT_BENCH_TRACE";

/// The planted-delay specification variable.
pub const PLANTED_PHASE_DELAY_ENV: &str = "IOI_TESTING_M049_PLANTED_PHASE_DELAY";

/// The largest delay this seam will plant, in milliseconds.
///
/// A ceiling exists because an implausible value is far more likely to be a
/// typo (`60000` meant as ms, `600000` typed) than an intent, and a delay that
/// dwarfs the fixture's own commit timeout turns an attribution mutation into
/// an unattributable timeout. Refusing is recoverable; a run that silently
/// hung for ten minutes is not.
pub const MAX_PLANTED_DELAY_MS: u64 = 60_000;

/// A phase this seam can plant a delay in.
///
/// EXACTLY the phases that have a wired call site. A name accepted here that
/// no call site honours would be a lie the parser could not detect: the spec
/// would parse, nothing would happen, and the mutation would "pass". So the
/// known set and the wired set are the same set by construction, and every
/// other phase name is refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PlantedPhase {
    /// Inside the producer's transaction-selection span, after the mempool has
    /// been read and after the proposal-wait observation has been sampled.
    ///
    /// Moves `select_ms`, and therefore the inclusive `ordering_finalization`
    /// phase. It deliberately does NOT move the per-transaction proposal wait:
    /// that observation is sampled before this seam runs.
    ProposalSelection,
    /// Between the durable finalized-header update and the publication of
    /// `Committed` plus the per-transaction completion event.
    ///
    /// Moves the server-side durable-ACK publication interval, and therefore
    /// every phase that contains it.
    DurableAckPublication,
}

impl PlantedPhase {
    /// Every phase with a wired call site.
    pub const ALL: [PlantedPhase; 2] = [
        PlantedPhase::ProposalSelection,
        PlantedPhase::DurableAckPublication,
    ];

    /// The exact spec token for this phase.
    pub fn as_str(self) -> &'static str {
        match self {
            PlantedPhase::ProposalSelection => "proposal_selection",
            PlantedPhase::DurableAckPublication => "durable_ack_publication",
        }
    }

    /// Resolves a spec token, with no case folding and no aliases.
    ///
    /// A near-miss is refused rather than corrected: a delay planted in a
    /// phase other than the one the operator named would attribute the
    /// mutation to the wrong seam, which is worse than not planting one.
    pub fn from_name(name: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|phase| phase.as_str() == name)
    }
}

impl fmt::Display for PlantedPhase {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// A parsed, armed planted delay.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PlantedPhaseDelay {
    /// The phase whose call site sleeps.
    pub phase: PlantedPhase,
    /// How long that call site sleeps.
    pub delay: Duration,
}

/// Every way this seam refuses.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PlantedPhaseDelayError {
    /// A spec was supplied without the benchmark-trace arming.
    NotArmed {
        /// The trimmed spec that was supplied.
        spec: String,
    },
    /// The spec was not exactly one `phase=delay_ms` pair.
    Malformed {
        /// The trimmed spec that was supplied.
        spec: String,
        /// Which rule the spec broke.
        reason: String,
    },
    /// The phase named has no wired call site.
    UnknownPhase {
        /// The phase token that was supplied.
        phase: String,
    },
    /// The delay was zero, non-numeric, or beyond the ceiling.
    DelayOutOfRange {
        /// The phase token the delay was requested for.
        phase: String,
        /// The delay token that was supplied.
        delay: String,
    },
}

impl fmt::Display for PlantedPhaseDelayError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PlantedPhaseDelayError::NotArmed { spec } => write!(
                f,
                "{PLANTED_PHASE_DELAY_ENV}={spec:?} was set without {BENCH_TRACE_ENV}; a planted \
                 delay is benchmark-trace instrumentation and refuses to arm on an untraced run \
                 rather than silently running at full speed"
            ),
            PlantedPhaseDelayError::Malformed { spec, reason } => write!(
                f,
                "{PLANTED_PHASE_DELAY_ENV}={spec:?} is malformed ({reason}); the exact accepted \
                 form is a single \"<phase>=<delay_ms>\" pair"
            ),
            PlantedPhaseDelayError::UnknownPhase { phase } => write!(
                f,
                "{PLANTED_PHASE_DELAY_ENV} names phase {phase:?}, which has no wired call site; \
                 known phases are {}",
                known_phase_list()
            ),
            PlantedPhaseDelayError::DelayOutOfRange { phase, delay } => write!(
                f,
                "{PLANTED_PHASE_DELAY_ENV} requests delay {delay:?} for phase {phase:?}; the \
                 delay must be an integer millisecond count in 1..={MAX_PLANTED_DELAY_MS} (0 is \
                 refused because an armed no-op reads as a planted delay that did nothing)"
            ),
        }
    }
}

impl std::error::Error for PlantedPhaseDelayError {}

fn known_phase_list() -> String {
    PlantedPhase::ALL
        .iter()
        .map(|phase| phase.as_str())
        .collect::<Vec<_>>()
        .join(", ")
}

/// Parses a planted-delay spec against the supplied arming.
///
/// Pure over its inputs so the refusal set can be proven without touching
/// process environment. `Ok(None)` means "nothing was requested"; it is
/// returned only for an absent or blank spec, never for one this parser could
/// not understand.
pub fn parse_planted_phase_delay(
    spec: Option<&str>,
    bench_trace_armed: bool,
) -> Result<Option<PlantedPhaseDelay>, PlantedPhaseDelayError> {
    let Some(raw) = spec else {
        return Ok(None);
    };
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Ok(None);
    }
    if !bench_trace_armed {
        return Err(PlantedPhaseDelayError::NotArmed {
            spec: trimmed.to_string(),
        });
    }

    // Exactly one pair. A list is refused rather than partially honoured:
    // two simultaneous planted delays make "exactly one phase moved"
    // unprovable, which is the whole claim this seam exists to support.
    let equals_count = trimmed.matches('=').count();
    if trimmed.contains(',')
        || trimmed.contains(';')
        || (equals_count > 1 && trimmed.chars().any(char::is_whitespace))
    {
        return Err(PlantedPhaseDelayError::Malformed {
            spec: trimmed.to_string(),
            reason: "exactly one phase may be planted at a time".to_string(),
        });
    }
    if equals_count != 1 {
        return Err(PlantedPhaseDelayError::Malformed {
            spec: trimmed.to_string(),
            reason: "expected exactly one '=' separating the phase from the delay".to_string(),
        });
    }
    let mut parts = trimmed.split('=');
    let (Some(phase_token), Some(delay_token), None) = (parts.next(), parts.next(), parts.next())
    else {
        return Err(PlantedPhaseDelayError::Malformed {
            spec: trimmed.to_string(),
            reason: "expected exactly one '=' separating the phase from the delay".to_string(),
        });
    };
    let phase_token = phase_token.trim();
    let delay_token = delay_token.trim();
    if phase_token.is_empty() || delay_token.is_empty() {
        return Err(PlantedPhaseDelayError::Malformed {
            spec: trimmed.to_string(),
            reason: "both the phase and the delay must be non-empty".to_string(),
        });
    }

    let Some(phase) = PlantedPhase::from_name(phase_token) else {
        return Err(PlantedPhaseDelayError::UnknownPhase {
            phase: phase_token.to_string(),
        });
    };

    // Digits only. `parse::<u64>` alone would accept `+5`, and a signed-looking
    // token in a delay spec is a strong signal the operator meant something
    // this seam does not do.
    let numeric = !delay_token.is_empty() && delay_token.bytes().all(|b| b.is_ascii_digit());
    let delay_ms = numeric.then(|| delay_token.parse::<u64>().ok()).flatten();
    let Some(delay_ms) = delay_ms.filter(|ms| (1..=MAX_PLANTED_DELAY_MS).contains(ms)) else {
        return Err(PlantedPhaseDelayError::DelayOutOfRange {
            phase: phase_token.to_string(),
            delay: delay_token.to_string(),
        });
    };

    Ok(Some(PlantedPhaseDelay {
        phase,
        delay: Duration::from_millis(delay_ms),
    }))
}

/// Reads the process environment and resolves the delay for one phase.
///
/// Returns `Ok(None)` both when nothing is armed and when a delay is armed for
/// a DIFFERENT phase, so a call site never has to know which phase was
/// selected. A malformed or unarmed spec is an error for every call site, not
/// just the one that was named -- otherwise a typo in the phase name would
/// leave the run looking healthy while planting nothing.
pub fn planted_delay_for(phase: PlantedPhase) -> Result<Option<Duration>, PlantedPhaseDelayError> {
    let spec = std::env::var(PLANTED_PHASE_DELAY_ENV).ok();
    let armed = std::env::var_os(BENCH_TRACE_ENV).is_some();
    Ok(parse_planted_phase_delay(spec.as_deref(), armed)?
        .filter(|planted| planted.phase == phase)
        .map(|planted| planted.delay))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn absent_or_blank_spec_plants_nothing() {
        assert_eq!(parse_planted_phase_delay(None, false), Ok(None));
        assert_eq!(parse_planted_phase_delay(None, true), Ok(None));
        assert_eq!(parse_planted_phase_delay(Some(""), true), Ok(None));
        assert_eq!(parse_planted_phase_delay(Some("   "), true), Ok(None));
        // Blank without arming is still "nothing requested", not a refusal:
        // an unset variable and an empty one mean the same thing to a shell.
        assert_eq!(parse_planted_phase_delay(Some(""), false), Ok(None));
    }

    #[test]
    fn an_armed_spec_parses_to_exactly_the_named_phase_and_delay() {
        assert_eq!(
            parse_planted_phase_delay(Some("proposal_selection=25"), true),
            Ok(Some(PlantedPhaseDelay {
                phase: PlantedPhase::ProposalSelection,
                delay: Duration::from_millis(25),
            }))
        );
        assert_eq!(
            parse_planted_phase_delay(Some("  durable_ack_publication = 40  "), true),
            Ok(Some(PlantedPhaseDelay {
                phase: PlantedPhase::DurableAckPublication,
                delay: Duration::from_millis(40),
            }))
        );
    }

    #[test]
    fn a_spec_without_the_bench_trace_arming_refuses() {
        // The defect this prevents: an operator sets the spec, the run does
        // not arm the trace, no delay is planted, and the resulting profile
        // is read as a planted one.
        let error = parse_planted_phase_delay(Some("proposal_selection=25"), false)
            .expect_err("an unarmed spec must refuse");
        assert_eq!(
            error,
            PlantedPhaseDelayError::NotArmed {
                spec: "proposal_selection=25".to_string()
            }
        );
        assert!(error.to_string().contains(BENCH_TRACE_ENV));
    }

    #[test]
    fn an_unknown_phase_refuses_rather_than_planting_nothing() {
        for unknown in [
            "durable_persistence=10",
            "state_commitment_materialization=10",
            "execution_commit=10",
            "ProposalSelection=10",
            "proposal-selection=10",
            "proposal_selection_=10",
        ] {
            let error = parse_planted_phase_delay(Some(unknown), true)
                .expect_err("an unwired phase name must refuse");
            assert!(
                matches!(error, PlantedPhaseDelayError::UnknownPhase { .. }),
                "{unknown} should be refused as an unknown phase, got {error:?}"
            );
        }
        // Not vacuous: the known names really are accepted.
        for phase in PlantedPhase::ALL {
            assert!(
                parse_planted_phase_delay(Some(&format!("{}=5", phase.as_str())), true)
                    .expect("a wired phase parses")
                    .is_some()
            );
        }
    }

    #[test]
    fn a_malformed_spec_refuses() {
        for (spec, fragment) in [
            ("proposal_selection", "exactly one '='"),
            ("proposal_selection=5=6", "exactly one '='"),
            ("=5", "non-empty"),
            ("proposal_selection=", "non-empty"),
            (
                "proposal_selection=5,durable_ack_publication=5",
                "one phase",
            ),
            (
                "proposal_selection=5;durable_ack_publication=5",
                "one phase",
            ),
            (
                "proposal_selection=5 durable_ack_publication=5",
                "one phase",
            ),
        ] {
            let error =
                parse_planted_phase_delay(Some(spec), true).expect_err("malformed must refuse");
            assert!(
                matches!(error, PlantedPhaseDelayError::Malformed { .. }),
                "{spec:?} should be malformed, got {error:?}"
            );
            assert!(
                error.to_string().contains(fragment),
                "{spec:?} should explain {fragment:?}, got {error}"
            );
        }
    }

    #[test]
    fn a_zero_negative_or_excessive_delay_refuses() {
        for delay in [
            "0",
            "-5",
            "+5",
            "5.5",
            "abc",
            "1e3",
            &(MAX_PLANTED_DELAY_MS + 1).to_string(),
            "18446744073709551616",
        ] {
            let spec = format!("proposal_selection={delay}");
            let error = parse_planted_phase_delay(Some(&spec), true)
                .expect_err("an out-of-range delay must refuse");
            assert!(
                matches!(error, PlantedPhaseDelayError::DelayOutOfRange { .. }),
                "{spec:?} should be out of range, got {error:?}"
            );
        }
        // The boundary itself is accepted, so the ceiling is a ceiling and not
        // an off-by-one refusal.
        assert_eq!(
            parse_planted_phase_delay(
                Some(&format!("proposal_selection={MAX_PLANTED_DELAY_MS}")),
                true
            ),
            Ok(Some(PlantedPhaseDelay {
                phase: PlantedPhase::ProposalSelection,
                delay: Duration::from_millis(MAX_PLANTED_DELAY_MS),
            }))
        );
    }

    #[test]
    fn every_declared_phase_round_trips_and_the_set_is_exactly_the_wired_set() {
        for phase in PlantedPhase::ALL {
            assert_eq!(PlantedPhase::from_name(phase.as_str()), Some(phase));
        }
        // Pinned so adding a name without wiring a call site is a deliberate,
        // visible edit rather than an accident.
        assert_eq!(
            PlantedPhase::ALL
                .iter()
                .map(|phase| phase.as_str())
                .collect::<Vec<_>>(),
            vec!["proposal_selection", "durable_ack_publication"]
        );
    }
}
