use ioi_types::app::{
    validate_index_set, AftAsyncInstanceV1, AftAsyncOrderingDecisionV1, AftAsyncProposalRefV1,
    AftAsyncTranscriptSummaryV1,
};
use std::collections::BTreeMap;

/// Converts a common index-ACS output into AFT's canonical batch and ordering
/// roots. Availability verification must populate the proposal map before this
/// adapter is invoked.
#[derive(Debug, Clone, Copy, Default)]
pub struct HashAsyncOrderingAdapter;

impl HashAsyncOrderingAdapter {
    pub fn decide(
        instance: AftAsyncInstanceV1,
        acs_winner: u16,
        selected_indices: &[u16],
        available: &BTreeMap<u16, AftAsyncProposalRefV1>,
    ) -> Result<(AftAsyncOrderingDecisionV1, AftAsyncTranscriptSummaryV1), String> {
        validate_index_set(
            selected_indices,
            instance.geometry.n,
            instance.geometry.quorum,
        )?;
        let selected = selected_indices
            .iter()
            .map(|index| {
                let proposal = available.get(index).ok_or_else(|| {
                    format!("ACS selected proposal {index} before availability delivery")
                })?;
                if proposal.proposer != *index {
                    return Err("availability map key does not match proposal index".into());
                }
                proposal.validate_for(&instance)?;
                Ok(proposal.clone())
            })
            .collect::<Result<Vec<_>, String>>()?;
        let transcript = AftAsyncTranscriptSummaryV1::new(&instance, acs_winner, selected.clone())?;
        let transcript_root = transcript.transcript_root(&instance)?;
        let decision = AftAsyncOrderingDecisionV1::new(instance, selected, transcript_root)?;
        Ok((decision, transcript))
    }
}

/// One local height decision authorized by the shared optimistic/fallback
/// fence. This is signer discipline, not a network certificate.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CrossPathDecision {
    Optimistic([u8; 32]),
    HashAsync([u8; 32]),
}

impl CrossPathDecision {
    fn root(self) -> [u8; 32] {
        match self {
            Self::Optimistic(root) | Self::HashAsync(root) => root,
        }
    }
}

/// Fail-closed per-height signer fence used by both paths. Exact replay is
/// idempotent; a second root is never authorized, regardless of path label.
/// With two exact `2f+1` certificates in `3f+1`, their intersection contains
/// at least `f+1` members, hence at least one honest member running this fence.
#[derive(Debug, Clone)]
pub struct CrossPathDecisionFence {
    height: u64,
    decision: Option<CrossPathDecision>,
}

impl CrossPathDecisionFence {
    pub fn new(height: u64) -> Result<Self, String> {
        if height == 0 {
            return Err("cross-path decision fence cannot target genesis".into());
        }
        Ok(Self {
            height,
            decision: None,
        })
    }

    pub fn authorize(&mut self, height: u64, decision: CrossPathDecision) -> Result<bool, String> {
        if height != self.height || decision.root() == [0; 32] {
            return Err("cross-path decision has an invalid height or root".into());
        }
        match self.decision {
            None => {
                self.decision = Some(decision);
                Ok(true)
            }
            Some(previous) if previous.root() == decision.root() => Ok(false),
            Some(_) => Err("cross-path signer fence refuses a conflicting root".into()),
        }
    }

    pub fn decision(&self) -> Option<CrossPathDecision> {
        self.decision
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ioi_types::app::{
        AccountId, AftAsyncGeometryV1, AftFallbackScopeV1, AftFallbackTriggerCertificateV1,
        AftTimeoutCertificateV1, AftTimeoutVoteV1, FallbackStartCertificateV1, QuorumCertificate,
        AFT_TIMEOUT_PROTOCOL_VERSION_V1, AFT_TIMEOUT_SCHEMA_VERSION_V1,
    };

    fn instance() -> AftAsyncInstanceV1 {
        let scope = AftFallbackScopeV1 {
            network_id: [1; 32],
            configuration_hash: [2; 32],
            epoch: 1,
        };
        let tc = |view| AftTimeoutCertificateV1 {
            protocol_version: AFT_TIMEOUT_PROTOCOL_VERSION_V1,
            schema_version: AFT_TIMEOUT_SCHEMA_VERSION_V1,
            scope,
            height: 4,
            view,
            votes: vec![AftTimeoutVoteV1 {
                protocol_version: AFT_TIMEOUT_PROTOCOL_VERSION_V1,
                schema_version: AFT_TIMEOUT_SCHEMA_VERSION_V1,
                scope,
                height: 4,
                view,
                highest_qc: QuorumCertificate::default(),
                highest_qc_async_parent_proof_hash: None,
                locked_qc: QuorumCertificate::default(),
                locked_qc_async_parent_proof_hash: None,
                voter: AccountId([view as u8; 32]),
                signature: vec![1],
            }],
        };
        let start = FallbackStartCertificateV1::new(
            scope,
            4,
            AftFallbackTriggerCertificateV1 {
                height: 4,
                consecutive_timeout_certificates: vec![tc(1), tc(2), tc(3)],
            },
        )
        .unwrap();
        AftAsyncInstanceV1::from_fallback_start(&start, AftAsyncGeometryV1::exact(4).unwrap())
            .unwrap()
    }

    #[test]
    fn adapter_requires_every_acs_index_to_be_available_and_lock_bound() {
        let instance = instance();
        let available = (0..3)
            .map(|index| {
                (
                    index,
                    AftAsyncProposalRefV1 {
                        proposer: index,
                        proposal_hash: [index as u8 + 10; 32],
                        payload_len: 1,
                        availability_certificate_hash: [index as u8 + 20; 32],
                        parent_root: instance.locked_root,
                    },
                )
            })
            .collect::<BTreeMap<_, _>>();
        let (decision, transcript) =
            HashAsyncOrderingAdapter::decide(instance.clone(), 2, &[0, 1, 2], &available).unwrap();
        assert_eq!(
            decision.transcript_root,
            transcript.transcript_root(&instance).unwrap()
        );
        assert!(HashAsyncOrderingAdapter::decide(instance, 2, &[0, 1, 3], &available).is_err());
    }

    #[test]
    fn signer_fence_is_path_agnostic_and_root_specific() {
        let mut fence = CrossPathDecisionFence::new(7).unwrap();
        assert!(fence
            .authorize(7, CrossPathDecision::Optimistic([1; 32]))
            .unwrap());
        assert!(!fence
            .authorize(7, CrossPathDecision::HashAsync([1; 32]))
            .unwrap());
        assert!(fence
            .authorize(7, CrossPathDecision::HashAsync([2; 32]))
            .is_err());
    }
}
