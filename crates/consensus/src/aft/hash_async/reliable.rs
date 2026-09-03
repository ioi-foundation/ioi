use super::MAX_ASYNC_CONTROL_VALUE_BYTES;
use ioi_types::app::{
    aft_async_ra_value_hash, aft_async_rbc_value_hash, AftAsyncGeometryV1, AftAsyncRaPhaseV1,
    AftAsyncRaPurposeV1, AftAsyncRbcPhaseV1, AftAsyncRbcPurposeV1,
};
use std::collections::{BTreeMap, BTreeSet};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RbcAction {
    Broadcast {
        phase: AftAsyncRbcPhaseV1,
        value_hash: [u8; 32],
        value: Vec<u8>,
    },
    Deliver(Vec<u8>),
}

/// Bracha-style authenticated reliable broadcast. Every phase carries the
/// bounded value to avoid a digest-only liveness dependency.
#[derive(Debug, Clone)]
pub struct ReliableBroadcastState {
    geometry: AftAsyncGeometryV1,
    purpose: AftAsyncRbcPurposeV1,
    dealer: u16,
    observed: BTreeMap<(u16, u8), [u8; 32]>,
    values: BTreeMap<[u8; 32], Vec<u8>>,
    echo: BTreeMap<[u8; 32], BTreeSet<u16>>,
    ready: BTreeMap<[u8; 32], BTreeSet<u16>>,
    sent_echo: Option<[u8; 32]>,
    sent_ready: Option<[u8; 32]>,
    delivered: Option<[u8; 32]>,
}

impl ReliableBroadcastState {
    pub fn new(
        geometry: AftAsyncGeometryV1,
        purpose: AftAsyncRbcPurposeV1,
        dealer: u16,
    ) -> Result<Self, String> {
        geometry.validate()?;
        if !geometry.contains(dealer) {
            return Err("RBC dealer is outside the asynchronous configuration".into());
        }
        Ok(Self {
            geometry,
            purpose,
            dealer,
            observed: BTreeMap::new(),
            values: BTreeMap::new(),
            echo: BTreeMap::new(),
            ready: BTreeMap::new(),
            sent_echo: None,
            sent_ready: None,
            delivered: None,
        })
    }

    pub fn purpose(&self) -> &AftAsyncRbcPurposeV1 {
        &self.purpose
    }

    pub fn dealer(&self) -> u16 {
        self.dealer
    }

    pub fn dealer_value(value: Vec<u8>) -> Result<RbcAction, String> {
        let value_hash = checked_rbc_value(&value)?;
        Ok(RbcAction::Broadcast {
            phase: AftAsyncRbcPhaseV1::Value,
            value_hash,
            value,
        })
    }

    pub fn handle(
        &mut self,
        sender: u16,
        phase: AftAsyncRbcPhaseV1,
        value_hash: [u8; 32],
        value: Vec<u8>,
    ) -> Result<Vec<RbcAction>, String> {
        if !self.geometry.contains(sender) {
            return Err("RBC message sender is outside the configuration".into());
        }
        if phase == AftAsyncRbcPhaseV1::Value && sender != self.dealer {
            return Err("RBC VALUE was not sent by the designated dealer".into());
        }
        let computed = checked_rbc_value(&value)?;
        if computed != value_hash {
            return Err("RBC value digest mismatch".into());
        }
        let phase_tag = match phase {
            AftAsyncRbcPhaseV1::Value => 0,
            AftAsyncRbcPhaseV1::Echo => 1,
            AftAsyncRbcPhaseV1::Ready => 2,
        };
        match self.observed.insert((sender, phase_tag), value_hash) {
            Some(previous) if previous != value_hash => {
                self.observed.insert((sender, phase_tag), previous);
                return Err("RBC sender equivocated within one phase".into());
            }
            Some(_) => return Ok(Vec::new()),
            None => {}
        }
        self.values.entry(value_hash).or_insert(value.clone());
        match phase {
            AftAsyncRbcPhaseV1::Value => {}
            AftAsyncRbcPhaseV1::Echo => {
                self.echo.entry(value_hash).or_default().insert(sender);
            }
            AftAsyncRbcPhaseV1::Ready => {
                self.ready.entry(value_hash).or_default().insert(sender);
            }
        }

        let mut actions = Vec::new();
        if phase == AftAsyncRbcPhaseV1::Value && self.sent_echo.is_none() {
            self.sent_echo = Some(value_hash);
            actions.push(RbcAction::Broadcast {
                phase: AftAsyncRbcPhaseV1::Echo,
                value_hash,
                value: value.clone(),
            });
        }
        let echo_count = self.echo.get(&value_hash).map_or(0, BTreeSet::len);
        let ready_count = self.ready.get(&value_hash).map_or(0, BTreeSet::len);
        if self.sent_ready.is_none()
            && (echo_count >= self.geometry.quorum as usize
                || ready_count > self.geometry.f as usize)
        {
            self.sent_ready = Some(value_hash);
            actions.push(RbcAction::Broadcast {
                phase: AftAsyncRbcPhaseV1::Ready,
                value_hash,
                value: value.clone(),
            });
        }
        if ready_count >= self.geometry.quorum as usize {
            match self.delivered {
                Some(previous) if previous != value_hash => {
                    return Err("RBC attempted to deliver conflicting values".into());
                }
                Some(_) => {}
                None => {
                    self.delivered = Some(value_hash);
                    actions.push(RbcAction::Deliver(value));
                }
            }
        }
        Ok(actions)
    }

    pub fn delivered(&self) -> Option<&[u8]> {
        self.delivered
            .and_then(|digest| self.values.get(&digest))
            .map(Vec::as_slice)
    }
}

fn checked_rbc_value(value: &[u8]) -> Result<[u8; 32], String> {
    if value.is_empty() || value.len() > MAX_ASYNC_CONTROL_VALUE_BYTES {
        return Err("RBC value is empty or exceeds the control-plane bound".into());
    }
    aft_async_rbc_value_hash(value)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RaAction {
    Broadcast {
        phase: AftAsyncRaPhaseV1,
        value_hash: [u8; 32],
        value: Vec<u8>,
    },
    Output(Vec<u8>),
}

/// Authenticated reliable agreement (Algorithm 1 in the selected
/// construction). The caller is responsible for its primitive-specific
/// admissibility rule, which ensures honest inputs agree.
#[derive(Debug, Clone)]
pub struct ReliableAgreementState {
    geometry: AftAsyncGeometryV1,
    purpose: AftAsyncRaPurposeV1,
    observed: BTreeMap<(u16, u8), [u8; 32]>,
    values: BTreeMap<[u8; 32], Vec<u8>>,
    echo: BTreeMap<[u8; 32], BTreeSet<u16>>,
    ready: BTreeMap<[u8; 32], BTreeSet<u16>>,
    input: Option<[u8; 32]>,
    sent_ready: Option<[u8; 32]>,
    output: Option<[u8; 32]>,
}

impl ReliableAgreementState {
    pub fn new(geometry: AftAsyncGeometryV1, purpose: AftAsyncRaPurposeV1) -> Result<Self, String> {
        geometry.validate()?;
        Ok(Self {
            geometry,
            purpose,
            observed: BTreeMap::new(),
            values: BTreeMap::new(),
            echo: BTreeMap::new(),
            ready: BTreeMap::new(),
            input: None,
            sent_ready: None,
            output: None,
        })
    }

    pub fn purpose(&self) -> &AftAsyncRaPurposeV1 {
        &self.purpose
    }

    pub fn input(&mut self, value: Vec<u8>) -> Result<RaAction, String> {
        let value_hash = checked_ra_value(&value)?;
        match self.input {
            Some(previous) if previous != value_hash => {
                return Err("reliable agreement local input was rebound".into());
            }
            Some(_) => return Err("reliable agreement local input was duplicated".into()),
            None => self.input = Some(value_hash),
        }
        Ok(RaAction::Broadcast {
            phase: AftAsyncRaPhaseV1::Echo,
            value_hash,
            value,
        })
    }

    pub fn handle(
        &mut self,
        sender: u16,
        phase: AftAsyncRaPhaseV1,
        value_hash: [u8; 32],
        value: Vec<u8>,
    ) -> Result<Vec<RaAction>, String> {
        if !self.geometry.contains(sender) {
            return Err("RA message sender is outside the configuration".into());
        }
        let computed = checked_ra_value(&value)?;
        if computed != value_hash {
            return Err("RA value digest mismatch".into());
        }
        let phase_tag = match phase {
            AftAsyncRaPhaseV1::Echo => 0,
            AftAsyncRaPhaseV1::Ready => 1,
        };
        match self.observed.insert((sender, phase_tag), value_hash) {
            Some(previous) if previous != value_hash => {
                self.observed.insert((sender, phase_tag), previous);
                return Err("RA sender equivocated within one phase".into());
            }
            Some(_) => return Ok(Vec::new()),
            None => {}
        }
        self.values.entry(value_hash).or_insert(value.clone());
        match phase {
            AftAsyncRaPhaseV1::Echo => {
                self.echo.entry(value_hash).or_default().insert(sender);
            }
            AftAsyncRaPhaseV1::Ready => {
                self.ready.entry(value_hash).or_default().insert(sender);
            }
        }
        let echo_count = self.echo.get(&value_hash).map_or(0, BTreeSet::len);
        let ready_count = self.ready.get(&value_hash).map_or(0, BTreeSet::len);
        let mut actions = Vec::new();
        if self.sent_ready.is_none()
            && (echo_count >= self.geometry.quorum as usize
                || ready_count > self.geometry.f as usize)
        {
            self.sent_ready = Some(value_hash);
            actions.push(RaAction::Broadcast {
                phase: AftAsyncRaPhaseV1::Ready,
                value_hash,
                value: value.clone(),
            });
        }
        if ready_count >= self.geometry.quorum as usize {
            match self.output {
                Some(previous) if previous != value_hash => {
                    return Err("RA attempted to output conflicting values".into());
                }
                Some(_) => {}
                None => {
                    self.output = Some(value_hash);
                    actions.push(RaAction::Output(value));
                }
            }
        }
        Ok(actions)
    }

    pub fn output(&self) -> Option<&[u8]> {
        self.output
            .and_then(|digest| self.values.get(&digest))
            .map(Vec::as_slice)
    }
}

fn checked_ra_value(value: &[u8]) -> Result<[u8; 32], String> {
    if value.is_empty() || value.len() > MAX_ASYNC_CONTROL_VALUE_BYTES {
        return Err("RA value is empty or exceeds the control-plane bound".into());
    }
    aft_async_ra_value_hash(value)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rbc_delivers_after_quorum_ready_and_refuses_equivocation() {
        let geometry = AftAsyncGeometryV1::exact(4).unwrap();
        let mut rbc =
            ReliableBroadcastState::new(geometry, AftAsyncRbcPurposeV1::Proposal, 0).unwrap();
        let value = vec![7, 8, 9];
        let digest = aft_async_rbc_value_hash(&value).unwrap();
        assert!(matches!(
            rbc.handle(0, AftAsyncRbcPhaseV1::Value, digest, value.clone())
                .unwrap()[0],
            RbcAction::Broadcast {
                phase: AftAsyncRbcPhaseV1::Echo,
                ..
            }
        ));
        for sender in 0..3 {
            let _ = rbc
                .handle(sender, AftAsyncRbcPhaseV1::Echo, digest, value.clone())
                .unwrap();
        }
        let mut delivered = false;
        for sender in 0..3 {
            delivered |= rbc
                .handle(sender, AftAsyncRbcPhaseV1::Ready, digest, value.clone())
                .unwrap()
                .iter()
                .any(|action| matches!(action, RbcAction::Deliver(_)));
        }
        assert!(delivered);
        assert!(rbc
            .handle(0, AftAsyncRbcPhaseV1::Ready, [4; 32], vec![1])
            .is_err());
    }

    #[test]
    fn ra_outputs_after_quorum_and_never_rebinds_local_input() {
        let geometry = AftAsyncGeometryV1::exact(4).unwrap();
        let mut ra =
            ReliableAgreementState::new(geometry, AftAsyncRaPurposeV1::VabaDecision).unwrap();
        let value = vec![1];
        let digest = aft_async_ra_value_hash(&value).unwrap();
        ra.input(value.clone()).unwrap();
        assert!(ra.input(vec![2]).is_err());
        for sender in 0..3 {
            let _ = ra
                .handle(sender, AftAsyncRaPhaseV1::Echo, digest, value.clone())
                .unwrap();
        }
        let mut output = false;
        for sender in 0..3 {
            output |= ra
                .handle(sender, AftAsyncRaPhaseV1::Ready, digest, value.clone())
                .unwrap()
                .iter()
                .any(|action| matches!(action, RaAction::Output(_)));
        }
        assert!(output);
    }

    #[test]
    fn early_ready_amplification_needs_f_plus_one() {
        let geometry = AftAsyncGeometryV1::exact(4).unwrap();
        let mut ra =
            ReliableAgreementState::new(geometry, AftAsyncRaPurposeV1::VabaDecision).unwrap();
        let value = vec![1];
        let digest = aft_async_ra_value_hash(&value).unwrap();
        assert!(ra
            .handle(0, AftAsyncRaPhaseV1::Ready, digest, value.clone())
            .unwrap()
            .is_empty());
        assert!(ra
            .handle(1, AftAsyncRaPhaseV1::Ready, digest, value)
            .unwrap()
            .iter()
            .any(|action| matches!(action, RaAction::Broadcast { .. })));
    }
}
