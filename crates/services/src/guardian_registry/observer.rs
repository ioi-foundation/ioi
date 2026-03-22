use super::*;

impl GuardianRegistry {
    pub fn load_observer_challenges(
        state: &dyn StateAccess,
        epoch: u64,
        height: u64,
        view: u64,
    ) -> Result<Vec<AsymptoteObserverChallenge>, StateError> {
        let prefix = [
            GUARDIAN_REGISTRY_OBSERVER_CHALLENGE_PREFIX,
            &epoch.to_be_bytes(),
            &height.to_be_bytes(),
            &view.to_be_bytes(),
        ]
        .concat();
        let mut challenges = Vec::new();
        for item in state.prefix_scan(&prefix)? {
            let (_, value) = item?;
            let challenge: AsymptoteObserverChallenge = codec::from_bytes_canonical(&value)
                .map_err(|e| StateError::InvalidValue(e.to_string()))?;
            challenges.push(challenge);
        }
        challenges.sort_unstable_by_key(|challenge| challenge.challenge_id);
        Ok(challenges)
    }

    pub fn load_effect_proof_verifier(
        state: &dyn StateAccess,
        verifier_id: &str,
    ) -> Result<Option<EffectProofVerifierDescriptor>, StateError> {
        match state.get(&guardian_registry_effect_verifier_key(verifier_id))? {
            Some(bytes) => codec::from_bytes_canonical(&bytes)
                .map(Some)
                .map_err(|e| StateError::InvalidValue(e.to_string())),
            None => Ok(None),
        }
    }

    pub fn load_asymptote_observer_transcript_commitment(
        state: &dyn StateAccess,
        epoch: u64,
        height: u64,
        view: u64,
    ) -> Result<Option<AsymptoteObserverTranscriptCommitment>, StateError> {
        match state.get(&guardian_registry_observer_transcript_commitment_key(
            epoch, height, view,
        ))? {
            Some(bytes) => codec::from_bytes_canonical(&bytes)
                .map(Some)
                .map_err(|e| StateError::InvalidValue(e.to_string())),
            None => Ok(None),
        }
    }

    pub fn load_asymptote_observer_challenge_commitment(
        state: &dyn StateAccess,
        epoch: u64,
        height: u64,
        view: u64,
    ) -> Result<Option<AsymptoteObserverChallengeCommitment>, StateError> {
        match state.get(&guardian_registry_observer_challenge_commitment_key(
            epoch, height, view,
        ))? {
            Some(bytes) => codec::from_bytes_canonical(&bytes)
                .map(Some)
                .map_err(|e| StateError::InvalidValue(e.to_string())),
            None => Ok(None),
        }
    }

    pub fn load_asymptote_observer_canonical_close(
        state: &dyn StateAccess,
        epoch: u64,
        height: u64,
        view: u64,
    ) -> Result<Option<AsymptoteObserverCanonicalClose>, StateError> {
        match state.get(&guardian_registry_observer_canonical_close_key(
            epoch, height, view,
        ))? {
            Some(bytes) => codec::from_bytes_canonical(&bytes)
                .map(Some)
                .map_err(|e| StateError::InvalidValue(e.to_string())),
            None => Ok(None),
        }
    }

    pub fn load_asymptote_observer_canonical_abort(
        state: &dyn StateAccess,
        epoch: u64,
        height: u64,
        view: u64,
    ) -> Result<Option<AsymptoteObserverCanonicalAbort>, StateError> {
        match state.get(&guardian_registry_observer_canonical_abort_key(
            epoch, height, view,
        ))? {
            Some(bytes) => codec::from_bytes_canonical(&bytes)
                .map(Some)
                .map_err(|e| StateError::InvalidValue(e.to_string())),
            None => Ok(None),
        }
    }

    pub fn load_sealed_effect_record(
        state: &dyn StateAccess,
        intent_hash: &[u8; 32],
    ) -> Result<Option<SealedEffectRecord>, StateError> {
        match state.get(&guardian_registry_sealed_effect_key(intent_hash))? {
            Some(bytes) => codec::from_bytes_canonical(&bytes)
                .map(Some)
                .map_err(|e| StateError::InvalidValue(e.to_string())),
            None => Ok(None),
        }
    }
}
