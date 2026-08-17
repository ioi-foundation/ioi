//! AFT-CB R13 — boundary-ring trace emission (C4a).
//!
//! This estate's own history (Q1–Q5) is proven-spec-beside-divergent-code;
//! the trace-conformance lane exists to make that defect class structurally
//! red.  A driver executes boundary-ring steps under the SAME guards the
//! formal kernel (`formal/common_boundary/BoundaryRing.tla`) imposes and
//! emits every APPLIED step as one JSON line; refused attempts emit
//! nothing, because a refusal is not a step of the behavior.  CI replays
//! the committed trace against the TLA model with TLC (deadlock checking
//! ON: a mid-trace disabled action deadlocks — that IS the divergence
//! signal), and a cargo test byte-compares this driver's emission against
//! the committed trace.  Code ↔ committed trace ↔ model closes end to end.
//!
//! FIRST CUT (honest label): the emitter is this REFERENCE DRIVER, not a
//! production code path — the n-of-n ring runtime does not exist yet.  The
//! lane's production binding extends as R1/R2/R5 land their ring runtime
//! and multi-member simulator; the machinery (schema, generation, replay,
//! CI wiring) is what this leg lands.

use std::collections::{BTreeMap, BTreeSet};

/// The constant sets of one boundary-ring configuration, mirroring the
/// CONSTANTS block of `BoundaryRing.tla`.  Identifiers must be TLA model
/// values (`[A-Za-z][A-Za-z0-9]*`); construction refuses anything else so
/// the emitted JSON and the generated TLA module never need escaping.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TraceConstants {
    /// The signer configuration C_v.
    pub ring: Vec<String>,
    /// The honest subset (MHA: nonempty).
    pub honest: Vec<String>,
    /// Seal slots.
    pub slots: Vec<String>,
    /// Candidate boundary roots.
    pub roots: Vec<String>,
    /// Submittable artifacts.
    pub artifacts: Vec<String>,
}

/// One applied step of a boundary-ring behavior.  Variant and field names
/// mirror the model's actions one to one — the generator maps them to TLA
/// action applications without interpretation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TraceEvent {
    /// The adversary delivered an artifact to a member (`Deliver`).
    Deliver {
        /// The delivered artifact.
        artifact: String,
        /// The receiving member.
        member: String,
    },
    /// An honest member declared a set drawn from what it received
    /// (`HonestDeclare`).
    HonestDeclare {
        /// The declaring member.
        member: String,
        /// The slot declared for.
        slot: String,
        /// The declared artifact set.
        artifacts: Vec<String>,
    },
    /// A corrupt member declared an arbitrary set (`ByzantineDeclare`).
    ByzantineDeclare {
        /// The declaring member.
        member: String,
        /// The slot declared for.
        slot: String,
        /// The declared artifact set.
        artifacts: Vec<String>,
    },
    /// An honest member journaled and released its final-ack share
    /// (`HonestFinalAck`) — journal-guarded single final-ack (A3).
    HonestFinalAck {
        /// The acking member.
        member: String,
        /// The slot acked.
        slot: String,
        /// The root acked.
        root: String,
    },
    /// A corrupt member emitted an arbitrary well-signed share
    /// (`ByzantineEmit`).
    ByzantineEmit {
        /// The emitting member.
        member: String,
        /// The slot named.
        slot: String,
        /// The root named.
        root: String,
    },
    /// Anyone assembled a UBC from every member's share (`CloseAct`).
    Close {
        /// The closed slot.
        slot: String,
        /// The closed root.
        root: String,
    },
}

/// Why a step was refused.  A refusal mutates nothing and emits nothing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TraceRefusal {
    /// An identifier is not a declared constant of this configuration,
    /// or is not a legal TLA model-value identifier.
    UnknownIdentifier(String),
    /// The member is not in the honest subset.
    NotHonest(String),
    /// The member is not corrupt (honest members cannot take Byzantine
    /// actions — that would forge A1).
    NotByzantine(String),
    /// An honest declaration named an artifact never delivered to the
    /// declaring member.
    UndeliveredArtifact {
        /// The declaring member.
        member: String,
        /// The undelivered artifact it named.
        artifact: String,
    },
    /// The journal already holds a root for this (member, slot): the
    /// single-final-ack discipline (A3) refuses a second share.
    JournalOccupied {
        /// The acking member.
        member: String,
        /// The slot.
        slot: String,
        /// The root already journaled.
        journaled: String,
    },
    /// A close named a (slot, root) some member never acked — n-of-n
    /// admits no smaller quorum.
    MissingShare {
        /// The first member (in ring order) whose share is missing.
        member: String,
        /// The slot.
        slot: String,
        /// The root.
        root: String,
    },
}

fn is_model_value(s: &str) -> bool {
    let mut chars = s.chars();
    match chars.next() {
        Some(c) if c.is_ascii_alphabetic() => chars.all(|c| c.is_ascii_alphanumeric()),
        _ => false,
    }
}

/// The reference boundary-ring state machine.  State variables mirror the
/// model's; every public step method imposes exactly the model action's
/// guard and appends the applied event to the trace.
#[derive(Debug, Clone)]
pub struct BoundaryRingDriver {
    constants: TraceConstants,
    delivered: BTreeSet<(String, String)>,
    declared: BTreeMap<(String, String), BTreeSet<String>>,
    journal: BTreeMap<(String, String), String>,
    acks: BTreeSet<(String, String, String)>,
    closes: BTreeSet<(String, String)>,
    trace: Vec<TraceEvent>,
}

impl BoundaryRingDriver {
    /// Builds a driver over the given constants.  Refuses non-model-value
    /// identifiers, honest members outside the ring, and the reserved
    /// journal sentinel name `NoRoot`.
    pub fn new(constants: TraceConstants) -> Result<Self, TraceRefusal> {
        let all = constants
            .ring
            .iter()
            .chain(constants.honest.iter())
            .chain(constants.slots.iter())
            .chain(constants.roots.iter())
            .chain(constants.artifacts.iter());
        for id in all {
            if !is_model_value(id) || id == "NoRoot" {
                return Err(TraceRefusal::UnknownIdentifier(id.clone()));
            }
        }
        for m in &constants.honest {
            if !constants.ring.contains(m) {
                return Err(TraceRefusal::UnknownIdentifier(m.clone()));
            }
        }
        Ok(BoundaryRingDriver {
            constants,
            delivered: BTreeSet::new(),
            declared: BTreeMap::new(),
            journal: BTreeMap::new(),
            acks: BTreeSet::new(),
            closes: BTreeSet::new(),
            trace: Vec::new(),
        })
    }

    fn require(list: &[String], id: &str) -> Result<(), TraceRefusal> {
        if list.iter().any(|x| x == id) {
            Ok(())
        } else {
            Err(TraceRefusal::UnknownIdentifier(id.to_string()))
        }
    }

    fn require_byzantine(&self, member: &str) -> Result<(), TraceRefusal> {
        Self::require(&self.constants.ring, member)?;
        if self.constants.honest.iter().any(|m| m == member) {
            return Err(TraceRefusal::NotByzantine(member.to_string()));
        }
        Ok(())
    }

    /// `Deliver(a, m)`: the adversary schedules delivery — always enabled
    /// for declared identifiers.
    pub fn deliver(&mut self, artifact: &str, member: &str) -> Result<(), TraceRefusal> {
        Self::require(&self.constants.artifacts, artifact)?;
        Self::require(&self.constants.ring, member)?;
        self.delivered
            .insert((artifact.to_string(), member.to_string()));
        self.trace.push(TraceEvent::Deliver {
            artifact: artifact.to_string(),
            member: member.to_string(),
        });
        Ok(())
    }

    /// `HonestDeclare(m, s, A)`: A must be drawn from what m actually
    /// received.
    pub fn honest_declare(
        &mut self,
        member: &str,
        slot: &str,
        artifacts: &[&str],
    ) -> Result<(), TraceRefusal> {
        Self::require(&self.constants.slots, slot)?;
        if !self.constants.honest.iter().any(|m| m == member) {
            return Err(TraceRefusal::NotHonest(member.to_string()));
        }
        for a in artifacts {
            Self::require(&self.constants.artifacts, a)?;
            if !self
                .delivered
                .contains(&((*a).to_string(), member.to_string()))
            {
                return Err(TraceRefusal::UndeliveredArtifact {
                    member: member.to_string(),
                    artifact: (*a).to_string(),
                });
            }
        }
        let set: BTreeSet<String> = artifacts.iter().map(|a| (*a).to_string()).collect();
        self.declared
            .insert((member.to_string(), slot.to_string()), set.clone());
        self.trace.push(TraceEvent::HonestDeclare {
            member: member.to_string(),
            slot: slot.to_string(),
            artifacts: set.into_iter().collect(),
        });
        Ok(())
    }

    /// `ByzantineDeclare(m, s, A)`: a corrupt member declares anything.
    pub fn byzantine_declare(
        &mut self,
        member: &str,
        slot: &str,
        artifacts: &[&str],
    ) -> Result<(), TraceRefusal> {
        Self::require(&self.constants.slots, slot)?;
        self.require_byzantine(member)?;
        for a in artifacts {
            Self::require(&self.constants.artifacts, a)?;
        }
        let set: BTreeSet<String> = artifacts.iter().map(|a| (*a).to_string()).collect();
        self.declared
            .insert((member.to_string(), slot.to_string()), set.clone());
        self.trace.push(TraceEvent::ByzantineDeclare {
            member: member.to_string(),
            slot: slot.to_string(),
            artifacts: set.into_iter().collect(),
        });
        Ok(())
    }

    /// `HonestFinalAck(m, s, r)` — THE journal guard (A3): the journal
    /// entry is written in the same atomic step that lets the share
    /// exist, and an occupied entry refuses a second share forever.
    pub fn honest_final_ack(
        &mut self,
        member: &str,
        slot: &str,
        root: &str,
    ) -> Result<(), TraceRefusal> {
        Self::require(&self.constants.slots, slot)?;
        Self::require(&self.constants.roots, root)?;
        if !self.constants.honest.iter().any(|m| m == member) {
            return Err(TraceRefusal::NotHonest(member.to_string()));
        }
        let key = (member.to_string(), slot.to_string());
        if let Some(journaled) = self.journal.get(&key) {
            return Err(TraceRefusal::JournalOccupied {
                member: member.to_string(),
                slot: slot.to_string(),
                journaled: journaled.clone(),
            });
        }
        self.journal.insert(key, root.to_string());
        self.acks
            .insert((member.to_string(), slot.to_string(), root.to_string()));
        self.trace.push(TraceEvent::HonestFinalAck {
            member: member.to_string(),
            slot: slot.to_string(),
            root: root.to_string(),
        });
        Ok(())
    }

    /// `ByzantineEmit(m, s, r)`: a corrupt member emits any share, any
    /// number of times.  No journal binds corrupt members.
    pub fn byzantine_emit(
        &mut self,
        member: &str,
        slot: &str,
        root: &str,
    ) -> Result<(), TraceRefusal> {
        Self::require(&self.constants.slots, slot)?;
        Self::require(&self.constants.roots, root)?;
        self.require_byzantine(member)?;
        self.acks
            .insert((member.to_string(), slot.to_string(), root.to_string()));
        self.trace.push(TraceEvent::ByzantineEmit {
            member: member.to_string(),
            slot: slot.to_string(),
            root: root.to_string(),
        });
        Ok(())
    }

    /// `CloseAct(s, r)`: n-of-n — EVERY ring member's share over this
    /// exact (slot, root) must exist.  No smaller quorum exists here.
    pub fn close(&mut self, slot: &str, root: &str) -> Result<(), TraceRefusal> {
        Self::require(&self.constants.slots, slot)?;
        Self::require(&self.constants.roots, root)?;
        for m in &self.constants.ring {
            if !self
                .acks
                .contains(&(m.clone(), slot.to_string(), root.to_string()))
            {
                return Err(TraceRefusal::MissingShare {
                    member: m.clone(),
                    slot: slot.to_string(),
                    root: root.to_string(),
                });
            }
        }
        self.closes.insert((slot.to_string(), root.to_string()));
        self.trace.push(TraceEvent::Close {
            slot: slot.to_string(),
            root: root.to_string(),
        });
        Ok(())
    }

    /// The applied-step trace so far.
    pub fn trace(&self) -> &[TraceEvent] {
        &self.trace
    }

    /// Serializes the behavior as JSON lines: one header line carrying
    /// the constants, then one line per applied event.  Emission is
    /// deterministic; identifiers were validated at construction, so no
    /// escaping is ever needed.
    pub fn trace_jsonl(&self) -> String {
        fn arr(items: &[String]) -> String {
            let quoted: Vec<String> = items.iter().map(|i| format!("\"{i}\"")).collect();
            format!("[{}]", quoted.join(","))
        }
        let c = &self.constants;
        let mut out = format!(
            "{{\"constants\":{{\"ring\":{},\"honest\":{},\"slots\":{},\"roots\":{},\"artifacts\":{},\"no_root\":\"NoRoot\"}}}}\n",
            arr(&c.ring),
            arr(&c.honest),
            arr(&c.slots),
            arr(&c.roots),
            arr(&c.artifacts),
        );
        for ev in &self.trace {
            let line = match ev {
                TraceEvent::Deliver { artifact, member } => format!(
                    "{{\"action\":\"Deliver\",\"artifact\":\"{artifact}\",\"member\":\"{member}\"}}"
                ),
                TraceEvent::HonestDeclare {
                    member,
                    slot,
                    artifacts,
                } => format!(
                    "{{\"action\":\"HonestDeclare\",\"member\":\"{member}\",\"slot\":\"{slot}\",\"artifacts\":{}}}",
                    arr(artifacts)
                ),
                TraceEvent::ByzantineDeclare {
                    member,
                    slot,
                    artifacts,
                } => format!(
                    "{{\"action\":\"ByzantineDeclare\",\"member\":\"{member}\",\"slot\":\"{slot}\",\"artifacts\":{}}}",
                    arr(artifacts)
                ),
                TraceEvent::HonestFinalAck { member, slot, root } => format!(
                    "{{\"action\":\"HonestFinalAck\",\"member\":\"{member}\",\"slot\":\"{slot}\",\"root\":\"{root}\"}}"
                ),
                TraceEvent::ByzantineEmit { member, slot, root } => format!(
                    "{{\"action\":\"ByzantineEmit\",\"member\":\"{member}\",\"slot\":\"{slot}\",\"root\":\"{root}\"}}"
                ),
                TraceEvent::Close { slot, root } => format!(
                    "{{\"action\":\"Close\",\"slot\":\"{slot}\",\"root\":\"{root}\"}}"
                ),
            };
            out.push_str(&line);
            out.push('\n');
        }
        out
    }
}

/// The committed reference behavior: the MHA corner from
/// `BoundaryRing.cfg` (n = 3, one honest member), one slot closed on one
/// root through the full ladder, a Byzantine equivocation attempt that
/// cannot assemble a second close, and the two refusals the guards exist
/// for (a double honest final-ack and an n−1 close).  Returns the driver
/// and the refusals encountered, in order.
pub fn reference_scenario() -> Result<(BoundaryRingDriver, Vec<TraceRefusal>), TraceRefusal> {
    let mut d = BoundaryRingDriver::new(TraceConstants {
        ring: vec!["m1".into(), "m2".into(), "m3".into()],
        honest: vec!["m1".into()],
        slots: vec!["s1".into(), "s2".into()],
        roots: vec!["rX".into(), "rY".into()],
        artifacts: vec!["a1".into()],
    })?;
    let mut refusals = Vec::new();

    d.deliver("a1", "m1")?;
    d.deliver("a1", "m2")?;
    d.honest_declare("m1", "s1", &["a1"])?;
    d.byzantine_declare("m2", "s1", &["a1"])?;
    d.honest_final_ack("m1", "s1", "rX")?;

    // The double-final-ack attempt: the journal guard must refuse it.
    // If a mutation removes the guard, this APPLIES, the trace grows,
    // and the TLC replay deadlocks at the disabled HonestFinalAck.
    if let Err(r) = d.honest_final_ack("m1", "s1", "rY") {
        refusals.push(r);
    }

    d.byzantine_emit("m2", "s1", "rX")?;
    d.byzantine_emit("m3", "s1", "rX")?;
    // Byzantine equivocation on a second root — legal for corrupt
    // members, and exactly what uniqueness must survive.
    d.byzantine_emit("m2", "s1", "rY")?;
    d.byzantine_emit("m3", "s1", "rY")?;

    // The n−1 close attempt on the equivocated root: m1's share for rY
    // does not exist (its journal holds rX), so n-of-n refuses.
    if let Err(r) = d.close("s1", "rY") {
        refusals.push(r);
    }

    d.close("s1", "rX")?;
    // A second slot exercises the per-slot journal independence.
    d.honest_final_ack("m1", "s2", "rY")?;

    Ok((d, refusals))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn golden_path() -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(
            "../../internal-docs/architecture/protocols/aft/formal/common_boundary/traces/boundary_ring_reference.trace.jsonl",
        )
    }

    /// R13 lane, cargo side: the reference driver's emission byte-matches
    /// the committed trace the formal floor replays against BoundaryRing,
    /// and the guards refuse exactly the two staged illegal attempts.
    /// Set AFT_TRACE_REGEN=1 to re-mint the golden after an INTENDED
    /// driver change (the TLC replay then judges the new behavior).
    #[test]
    fn boundary_ring_reference_trace_matches_committed_golden() {
        let (driver, refusals) = reference_scenario().expect("reference scenario applies");

        assert_eq!(refusals.len(), 2, "exactly the two staged refusals");
        assert_eq!(
            refusals[0],
            TraceRefusal::JournalOccupied {
                member: "m1".into(),
                slot: "s1".into(),
                journaled: "rX".into(),
            },
            "the journal guard refuses the double final-ack"
        );
        assert_eq!(
            refusals[1],
            TraceRefusal::MissingShare {
                member: "m1".into(),
                slot: "s1".into(),
                root: "rY".into(),
            },
            "n-of-n refuses the n-1 close"
        );

        let emitted = driver.trace_jsonl();
        assert_eq!(driver.trace().len(), 11, "eleven applied steps");

        if std::env::var("AFT_TRACE_REGEN").as_deref() == Ok("1") {
            std::fs::write(golden_path(), &emitted).expect("write golden");
            return;
        }
        let committed = std::fs::read_to_string(golden_path())
            .expect("committed golden trace exists (run with AFT_TRACE_REGEN=1 to mint)");
        assert_eq!(
            emitted, committed,
            "driver emission diverged from the committed trace; if the \
             driver change is intended, regenerate with AFT_TRACE_REGEN=1 \
             and let the formal floor's TLC replay judge the new behavior"
        );
    }
}
