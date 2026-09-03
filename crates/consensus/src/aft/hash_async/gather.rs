use super::{RaAction, ReliableAgreementState};
use ioi_types::app::{
    validate_index_set, AftAsyncGatherMessageV1, AftAsyncGeometryV1, AftAsyncRaPhaseV1,
    AftAsyncRaPurposeV1,
};
use std::collections::{BTreeMap, BTreeSet};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IndexGatherAction {
    Broadcast(AftAsyncGatherMessageV1),
    Send {
        recipient: u16,
        message: AftAsyncGatherMessageV1,
    },
    Output(Vec<u16>),
}

/// Event-driven Algorithm 3 index gather. Validation inputs are monotonic and
/// all emitted sets are sorted and duplicate-free.
#[derive(Debug, Clone)]
pub struct IndexGatherState {
    geometry: AftAsyncGeometryV1,
    local: u16,
    valid: BTreeSet<u16>,
    inform_sent: Option<Vec<u16>>,
    informs: BTreeMap<u16, Vec<u16>>,
    ack_sent: BTreeSet<u16>,
    own_acks: BTreeSet<u16>,
    prepare_sent: Option<Vec<u16>>,
    prepares: BTreeMap<u16, Vec<u16>>,
    validated_prepares: BTreeSet<u16>,
    output: Option<Vec<u16>>,
}

impl IndexGatherState {
    pub fn new(geometry: AftAsyncGeometryV1, local: u16) -> Result<Self, String> {
        geometry.validate()?;
        if !geometry.contains(local) {
            return Err("index gather local member is outside the configuration".into());
        }
        Ok(Self {
            geometry,
            local,
            valid: BTreeSet::new(),
            inform_sent: None,
            informs: BTreeMap::new(),
            ack_sent: BTreeSet::new(),
            own_acks: BTreeSet::new(),
            prepare_sent: None,
            prepares: BTreeMap::new(),
            validated_prepares: BTreeSet::new(),
            output: None,
        })
    }

    pub fn add_valid(&mut self, candidate: u16) -> Result<Vec<IndexGatherAction>, String> {
        if !self.geometry.contains(candidate) {
            return Err("index gather validation names an out-of-range member".into());
        }
        self.valid.insert(candidate);
        self.progress()
    }

    pub fn handle(
        &mut self,
        sender: u16,
        message: AftAsyncGatherMessageV1,
    ) -> Result<Vec<IndexGatherAction>, String> {
        if !self.geometry.contains(sender) {
            return Err("index gather message sender is outside the configuration".into());
        }
        match message {
            AftAsyncGatherMessageV1::Inform { indices } => {
                validate_index_set(&indices, self.geometry.n, self.geometry.quorum)?;
                insert_immutable(&mut self.informs, sender, indices, "INFORM")?;
            }
            AftAsyncGatherMessageV1::Ack { inform_sender } => {
                if inform_sender != self.local || self.inform_sent.is_none() {
                    return Err("index gather ACK does not acknowledge the local INFORM".into());
                }
                self.own_acks.insert(sender);
            }
            AftAsyncGatherMessageV1::Prepare { indices } => {
                validate_index_set(&indices, self.geometry.n, self.geometry.quorum)?;
                insert_immutable(&mut self.prepares, sender, indices, "PREPARE")?;
            }
            AftAsyncGatherMessageV1::Withdraw => {
                return Err("WITHDRAW belongs to index cover gather, not index gather".into());
            }
        }
        self.progress()
    }

    fn progress(&mut self) -> Result<Vec<IndexGatherAction>, String> {
        let mut actions = Vec::new();
        if self.inform_sent.is_none() && self.valid.len() >= self.geometry.quorum as usize {
            let indices = self
                .valid
                .iter()
                .copied()
                .take(self.geometry.quorum as usize)
                .collect::<Vec<_>>();
            self.inform_sent = Some(indices.clone());
            actions.push(IndexGatherAction::Broadcast(
                AftAsyncGatherMessageV1::Inform { indices },
            ));
        }

        for (sender, indices) in &self.informs {
            if !self.ack_sent.contains(sender) && is_subset(indices, &self.valid) {
                self.ack_sent.insert(*sender);
                actions.push(IndexGatherAction::Send {
                    recipient: *sender,
                    message: AftAsyncGatherMessageV1::Ack {
                        inform_sender: *sender,
                    },
                });
            }
        }

        if self.prepare_sent.is_none() && self.own_acks.len() >= self.geometry.quorum as usize {
            let indices = self.valid.iter().copied().collect::<Vec<_>>();
            validate_index_set(&indices, self.geometry.n, self.geometry.quorum)?;
            self.prepare_sent = Some(indices.clone());
            actions.push(IndexGatherAction::Broadcast(
                AftAsyncGatherMessageV1::Prepare { indices },
            ));
        }

        for (sender, indices) in &self.prepares {
            if is_subset(indices, &self.valid) {
                self.validated_prepares.insert(*sender);
            }
        }
        if self.output.is_none() && self.validated_prepares.len() >= self.geometry.quorum as usize {
            let mut union = BTreeSet::new();
            for sender in self
                .validated_prepares
                .iter()
                .take(self.geometry.quorum as usize)
            {
                let prepare = self.prepares.get(sender).ok_or_else(|| {
                    "validated index-gather PREPARE disappeared from state".to_string()
                })?;
                union.extend(prepare.iter().copied());
            }
            let output = union.into_iter().collect::<Vec<_>>();
            validate_index_set(&output, self.geometry.n, self.geometry.quorum)?;
            self.output = Some(output.clone());
            actions.push(IndexGatherAction::Output(output));
        }
        Ok(actions)
    }

    pub fn output(&self) -> Option<&[u16]> {
        self.output.as_deref()
    }
}

fn insert_immutable(
    map: &mut BTreeMap<u16, Vec<u16>>,
    sender: u16,
    value: Vec<u16>,
    label: &str,
) -> Result<(), String> {
    match map.insert(sender, value.clone()) {
        Some(previous) if previous != value => {
            map.insert(sender, previous);
            Err(format!("index gather sender equivocated on {label}"))
        }
        _ => Ok(()),
    }
}

fn is_subset(indices: &[u16], valid: &BTreeSet<u16>) -> bool {
    indices.iter().all(|index| valid.contains(index))
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IndexCoverGatherAction {
    RaBroadcast {
        purpose: AftAsyncRaPurposeV1,
        phase: AftAsyncRaPhaseV1,
        value_hash: [u8; 32],
        value: Vec<u8>,
    },
    GatherBroadcast(AftAsyncGatherMessageV1),
    GatherSend {
        recipient: u16,
        message: AftAsyncGatherMessageV1,
    },
    Output(Vec<u16>),
}

/// Algorithm 4 index cover gather. One RA instance gates each index before it
/// becomes input to Algorithm 3; `n-f` withdrawals bind the cover before any
/// output is released.
#[derive(Debug, Clone)]
pub struct IndexCoverGatherState {
    geometry: AftAsyncGeometryV1,
    view: u64,
    raw_valid: BTreeSet<u16>,
    validation_ra: BTreeMap<u16, ReliableAgreementState>,
    validation_input: BTreeSet<u16>,
    gather: IndexGatherState,
    withdrawn: bool,
    withdrawals: BTreeSet<u16>,
    gather_output: Option<Vec<u16>>,
    output: Option<Vec<u16>>,
}

impl IndexCoverGatherState {
    pub fn new(geometry: AftAsyncGeometryV1, local: u16, view: u64) -> Result<Self, String> {
        geometry.validate()?;
        let gather = IndexGatherState::new(geometry, local)?;
        Ok(Self {
            geometry,
            view,
            raw_valid: BTreeSet::new(),
            validation_ra: BTreeMap::new(),
            validation_input: BTreeSet::new(),
            gather,
            withdrawn: false,
            withdrawals: BTreeSet::new(),
            gather_output: None,
            output: None,
        })
    }

    pub fn add_valid(&mut self, candidate: u16) -> Result<Vec<IndexCoverGatherAction>, String> {
        if !self.geometry.contains(candidate) {
            return Err("ICG validation names an out-of-range member".into());
        }
        self.raw_valid.insert(candidate);
        if self.withdrawn || !self.validation_input.insert(candidate) {
            return Ok(Vec::new());
        }
        let ra = self.validation_ra(candidate)?;
        let action = ra.input(vec![1])?;
        Ok(map_ra_action(
            AftAsyncRaPurposeV1::CoverValidation {
                view: self.view,
                candidate,
            },
            action,
        )
        .into_iter()
        .collect())
    }

    pub fn handle_ra(
        &mut self,
        sender: u16,
        candidate: u16,
        phase: AftAsyncRaPhaseV1,
        value_hash: [u8; 32],
        value: Vec<u8>,
    ) -> Result<Vec<IndexCoverGatherAction>, String> {
        if value != [1] {
            return Err("ICG reliable agreement accepts only the value one".into());
        }
        let actions = self
            .validation_ra(candidate)?
            .handle(sender, phase, value_hash, value)?;
        let mut output = Vec::new();
        for action in actions {
            match action {
                RaAction::Output(value) => {
                    if value != [1] {
                        return Err("ICG RA output was not one".into());
                    }
                    output.extend(self.observe_ra_output(candidate)?);
                }
                other => output.extend(map_ra_action(
                    AftAsyncRaPurposeV1::CoverValidation {
                        view: self.view,
                        candidate,
                    },
                    other,
                )),
            }
        }
        Ok(output)
    }

    fn validation_ra(&mut self, candidate: u16) -> Result<&mut ReliableAgreementState, String> {
        if !self.geometry.contains(candidate) {
            return Err("ICG RA candidate is outside the configuration".into());
        }
        if !self.validation_ra.contains_key(&candidate) {
            self.validation_ra.insert(
                candidate,
                ReliableAgreementState::new(
                    self.geometry,
                    AftAsyncRaPurposeV1::CoverValidation {
                        view: self.view,
                        candidate,
                    },
                )?,
            );
        }
        self.validation_ra
            .get_mut(&candidate)
            .ok_or_else(|| "ICG RA state insertion failed".into())
    }

    fn observe_ra_output(&mut self, candidate: u16) -> Result<Vec<IndexCoverGatherAction>, String> {
        let actions = self.gather.add_valid(candidate)?;
        let mut mapped = self.map_gather_actions(actions);
        if !self.withdrawn && self.gather.valid.len() >= self.geometry.quorum as usize {
            self.withdrawn = true;
            mapped.push(IndexCoverGatherAction::GatherBroadcast(
                AftAsyncGatherMessageV1::Withdraw,
            ));
        }
        mapped.extend(self.maybe_output());
        Ok(mapped)
    }

    pub fn handle_gather(
        &mut self,
        sender: u16,
        message: AftAsyncGatherMessageV1,
    ) -> Result<Vec<IndexCoverGatherAction>, String> {
        if message == AftAsyncGatherMessageV1::Withdraw {
            if !self.geometry.contains(sender) {
                return Err("ICG withdrawal sender is outside the configuration".into());
            }
            self.withdrawals.insert(sender);
            return Ok(self.maybe_output());
        }
        let actions = self.gather.handle(sender, message)?;
        let mut mapped = self.map_gather_actions(actions);
        mapped.extend(self.maybe_output());
        Ok(mapped)
    }

    fn map_gather_actions(
        &mut self,
        actions: Vec<IndexGatherAction>,
    ) -> Vec<IndexCoverGatherAction> {
        let mut mapped = Vec::new();
        for action in actions {
            match action {
                IndexGatherAction::Broadcast(message) => {
                    mapped.push(IndexCoverGatherAction::GatherBroadcast(message));
                }
                IndexGatherAction::Send { recipient, message } => {
                    mapped.push(IndexCoverGatherAction::GatherSend { recipient, message });
                }
                IndexGatherAction::Output(indices) => self.gather_output = Some(indices),
            }
        }
        mapped
    }

    fn maybe_output(&mut self) -> Vec<IndexCoverGatherAction> {
        if self.output.is_none()
            && self.withdrawals.len() >= self.geometry.quorum as usize
            && self.gather_output.is_some()
        {
            let Some(output) = self.gather_output.clone() else {
                return Vec::new();
            };
            self.output = Some(output.clone());
            vec![IndexCoverGatherAction::Output(output)]
        } else {
            Vec::new()
        }
    }

    pub fn output(&self) -> Option<&[u16]> {
        self.output.as_deref()
    }
}

fn map_ra_action(purpose: AftAsyncRaPurposeV1, action: RaAction) -> Vec<IndexCoverGatherAction> {
    match action {
        RaAction::Broadcast {
            phase,
            value_hash,
            value,
        } => vec![IndexCoverGatherAction::RaBroadcast {
            purpose,
            phase,
            value_hash,
            value,
        }],
        RaAction::Output(_) => Vec::new(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn index_gather_waits_for_validated_informs_and_prepares() {
        let geometry = AftAsyncGeometryV1::exact(4).unwrap();
        let mut gather = IndexGatherState::new(geometry, 0).unwrap();
        for candidate in 0..3 {
            let actions = gather.add_valid(candidate).unwrap();
            if candidate == 2 {
                assert!(actions.iter().any(|action| matches!(
                    action,
                    IndexGatherAction::Broadcast(AftAsyncGatherMessageV1::Inform { .. })
                )));
            }
        }
        for sender in 0..3 {
            let actions = gather
                .handle(sender, AftAsyncGatherMessageV1::Ack { inform_sender: 0 })
                .unwrap();
            if sender == 2 {
                assert!(actions.iter().any(|action| matches!(
                    action,
                    IndexGatherAction::Broadcast(AftAsyncGatherMessageV1::Prepare { .. })
                )));
            }
        }
        let mut output = None;
        for sender in 0..3 {
            for action in gather
                .handle(
                    sender,
                    AftAsyncGatherMessageV1::Prepare {
                        indices: vec![0, 1, 2],
                    },
                )
                .unwrap()
            {
                if let IndexGatherAction::Output(indices) = action {
                    output = Some(indices);
                }
            }
        }
        assert_eq!(output, Some(vec![0, 1, 2]));
    }

    #[test]
    fn index_gather_refuses_noncanonical_and_equivocating_sets() {
        let geometry = AftAsyncGeometryV1::exact(4).unwrap();
        let mut gather = IndexGatherState::new(geometry, 0).unwrap();
        assert!(gather
            .handle(
                1,
                AftAsyncGatherMessageV1::Inform {
                    indices: vec![1, 0, 2],
                },
            )
            .is_err());
        gather
            .handle(
                1,
                AftAsyncGatherMessageV1::Inform {
                    indices: vec![0, 1, 2],
                },
            )
            .unwrap();
        assert!(gather
            .handle(
                1,
                AftAsyncGatherMessageV1::Inform {
                    indices: vec![0, 1, 3],
                },
            )
            .is_err());
    }
}
