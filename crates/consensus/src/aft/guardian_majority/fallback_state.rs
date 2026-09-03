use super::*;
use fs2::FileExt;
use parity_scale_codec::{Decode, Encode};
use std::fs::{File, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex as StdMutex};

const FALLBACK_JOURNAL_PROTOCOL_VERSION: u16 = 1;
const FALLBACK_JOURNAL_SCHEMA_VERSION: u16 = 1;
const FALLBACK_JOURNAL_MAX_BYTES: u64 = 64 * 1024 * 1024;
const FALLBACK_JOURNAL_MAX_ENTRIES: usize = 4_096;

#[derive(Clone, Debug, PartialEq, Eq, Encode, Decode)]
struct FallbackJournalStateV1 {
    protocol_version: u16,
    schema_version: u16,
    scope: AftFallbackScopeV1,
    starts: Vec<FallbackStartCertificateV1>,
}

struct FallbackJournalInner {
    path: PathBuf,
    _lock: File,
    state: FallbackJournalStateV1,
}

/// Clone-safe handle to one process-owned transition journal. Engine clones
/// share both the lock and state rather than opening parallel writers.
#[derive(Clone)]
pub(super) struct FallbackJournal(Arc<StdMutex<FallbackJournalInner>>);

impl std::fmt::Debug for FallbackJournal {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_tuple("FallbackJournal")
            .field(&"<durable state redacted>")
            .finish()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum JournalInsert {
    Inserted,
    Idempotent,
}

fn lock_path(path: &Path) -> PathBuf {
    let mut value = path.as_os_str().to_os_string();
    value.push(".lock");
    PathBuf::from(value)
}

fn temp_path(path: &Path) -> PathBuf {
    let mut value = path.as_os_str().to_os_string();
    value.push(".tmp");
    PathBuf::from(value)
}

fn open_private_file(path: &Path) -> Result<File, ConsensusError> {
    let mut options = OpenOptions::new();
    options.create(true).read(true).write(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    options.open(path).map_err(|error| {
        ConsensusError::BlockVerificationFailed(format!(
            "failed to open AFT fallback journal {}: {error}",
            path.display()
        ))
    })
}

fn persist(path: &Path, state: &FallbackJournalStateV1) -> Result<(), ConsensusError> {
    let bytes = codec::to_bytes_canonical(state).map_err(|error| {
        ConsensusError::BlockVerificationFailed(format!(
            "failed to encode AFT fallback journal: {error}"
        ))
    })?;
    let staged = temp_path(path);
    let mut options = OpenOptions::new();
    options.create(true).truncate(true).write(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(&staged).map_err(|error| {
        ConsensusError::BlockVerificationFailed(format!(
            "failed to stage AFT fallback journal {}: {error}",
            staged.display()
        ))
    })?;
    file.write_all(&bytes).map_err(|error| {
        ConsensusError::BlockVerificationFailed(format!(
            "failed to write AFT fallback journal {}: {error}",
            staged.display()
        ))
    })?;
    file.sync_all().map_err(|error| {
        ConsensusError::BlockVerificationFailed(format!(
            "failed to sync AFT fallback journal {}: {error}",
            staged.display()
        ))
    })?;
    std::fs::rename(&staged, path).map_err(|error| {
        ConsensusError::BlockVerificationFailed(format!(
            "failed to commit AFT fallback journal {}: {error}",
            path.display()
        ))
    })?;
    if let Some(parent) = path.parent() {
        File::open(parent)
            .and_then(|directory| directory.sync_all())
            .map_err(|error| {
                ConsensusError::BlockVerificationFailed(format!(
                    "failed to sync AFT fallback journal directory {}: {error}",
                    parent.display()
                ))
            })?;
    }
    Ok(())
}

impl FallbackJournal {
    pub(super) fn open(path: &Path, scope: AftFallbackScopeV1) -> Result<Self, ConsensusError> {
        scope
            .validate()
            .map_err(ConsensusError::BlockVerificationFailed)?;
        let parent = path.parent().ok_or_else(|| {
            ConsensusError::BlockVerificationFailed(
                "AFT fallback journal requires a durable parent directory".into(),
            )
        })?;
        std::fs::create_dir_all(parent).map_err(|error| {
            ConsensusError::BlockVerificationFailed(format!(
                "failed to create AFT fallback journal directory {}: {error}",
                parent.display()
            ))
        })?;
        let lock = open_private_file(&lock_path(path))?;
        lock.try_lock_exclusive().map_err(|error| {
            ConsensusError::BlockVerificationFailed(format!(
                "AFT fallback journal {} is already owned by another process: {error}",
                path.display()
            ))
        })?;
        let expected = FallbackJournalStateV1 {
            protocol_version: FALLBACK_JOURNAL_PROTOCOL_VERSION,
            schema_version: FALLBACK_JOURNAL_SCHEMA_VERSION,
            scope,
            starts: Vec::new(),
        };
        let state = if path.exists() {
            let metadata = std::fs::metadata(path).map_err(|error| {
                ConsensusError::BlockVerificationFailed(format!(
                    "failed to inspect AFT fallback journal {}: {error}",
                    path.display()
                ))
            })?;
            if metadata.len() > FALLBACK_JOURNAL_MAX_BYTES {
                return Err(ConsensusError::BlockVerificationFailed(format!(
                    "AFT fallback journal {} exceeds the {} byte limit",
                    path.display(),
                    FALLBACK_JOURNAL_MAX_BYTES
                )));
            }
            let bytes = std::fs::read(path).map_err(|error| {
                ConsensusError::BlockVerificationFailed(format!(
                    "failed to read AFT fallback journal {}: {error}",
                    path.display()
                ))
            })?;
            codec::from_bytes_canonical::<FallbackJournalStateV1>(&bytes).map_err(|error| {
                ConsensusError::BlockVerificationFailed(format!(
                    "failed to decode AFT fallback journal {}: {error}",
                    path.display()
                ))
            })?
        } else {
            persist(path, &expected)?;
            expected.clone()
        };
        if state.protocol_version != expected.protocol_version
            || state.schema_version != expected.schema_version
            || state.scope != scope
        {
            return Err(ConsensusError::BlockVerificationFailed(
                "AFT fallback journal scope/version does not match the active configuration".into(),
            ));
        }
        if state.starts.len() > FALLBACK_JOURNAL_MAX_ENTRIES {
            return Err(ConsensusError::BlockVerificationFailed(
                "AFT fallback journal exceeds its entry limit".into(),
            ));
        }
        let mut heights = BTreeSet::new();
        for certificate in &state.starts {
            certificate
                .validate_shape()
                .map_err(ConsensusError::BlockVerificationFailed)?;
            if certificate.scope != scope {
                return Err(ConsensusError::BlockVerificationFailed(
                    "AFT fallback journal contains a cross-scope transition".into(),
                ));
            }
            if !heights.insert(certificate.height) {
                return Err(ConsensusError::BlockVerificationFailed(
                    "AFT fallback journal contains conflicting duplicate heights".into(),
                ));
            }
        }
        Ok(Self(Arc::new(StdMutex::new(FallbackJournalInner {
            path: path.to_path_buf(),
            _lock: lock,
            state,
        }))))
    }

    pub(super) fn starts(&self) -> Result<Vec<FallbackStartCertificateV1>, ConsensusError> {
        let guard = self.0.lock().map_err(|_| {
            ConsensusError::BlockVerificationFailed("AFT fallback journal lock was poisoned".into())
        })?;
        Ok(guard.state.starts.clone())
    }

    pub(super) fn matches(&self, path: &Path, scope: AftFallbackScopeV1) -> bool {
        self.0
            .lock()
            .map(|guard| guard.path == path && guard.state.scope == scope)
            .unwrap_or(false)
    }

    /// Transactionally appends one height. An exact replay is idempotent; a
    /// second byte-distinct certificate for that height is refused.
    pub(super) fn insert(
        &self,
        certificate: &FallbackStartCertificateV1,
    ) -> Result<JournalInsert, ConsensusError> {
        certificate
            .validate_shape()
            .map_err(ConsensusError::BlockVerificationFailed)?;
        let mut guard = self.0.lock().map_err(|_| {
            ConsensusError::BlockVerificationFailed("AFT fallback journal lock was poisoned".into())
        })?;
        if certificate.scope != guard.state.scope {
            return Err(ConsensusError::BlockVerificationFailed(
                "AFT fallback transition does not match the journal scope".into(),
            ));
        }
        if let Some(existing) = guard
            .state
            .starts
            .iter()
            .find(|existing| existing.height == certificate.height)
        {
            return if existing == certificate {
                Ok(JournalInsert::Idempotent)
            } else {
                Err(ConsensusError::BlockVerificationFailed(
                    "conflicting AFT fallback transition for an already persisted height".into(),
                ))
            };
        }
        if guard.state.starts.len() >= FALLBACK_JOURNAL_MAX_ENTRIES {
            return Err(ConsensusError::BlockVerificationFailed(
                "AFT fallback journal is exhausted".into(),
            ));
        }
        let mut next = guard.state.clone();
        next.starts.push(certificate.clone());
        next.starts.sort_by_key(|entry| entry.height);
        persist(&guard.path, &next)?;
        guard.state = next;
        Ok(JournalInsert::Inserted)
    }
}

impl GuardianMajorityEngine {
    fn validator_sets_for_fallback(&self, height: u64) -> Option<ValidatorSetsV1> {
        self.validator_sets_by_height
            .range(..=height)
            .next_back()
            .map(|(_, sets)| sets.clone())
    }

    fn validate_fallback_profile(
        &self,
        scope: AftFallbackScopeV1,
        height: u64,
    ) -> Result<ValidatorSetsV1, ConsensusError> {
        if !matches!(self.safety_mode, AftSafetyMode::ClassicBft) {
            return Err(ConsensusError::BlockVerificationFailed(
                "AFT asynchronous fallback is available only in the ClassicBft PQ profile".into(),
            ));
        }
        let sets = self.validator_sets_for_fallback(height).ok_or_else(|| {
            ConsensusError::BlockVerificationFailed(format!(
                "no observed validator set for AFT fallback height {height}"
            ))
        })?;
        let set = effective_set_for_height(&sets, height);
        authenticated_quorum::pq_optimistic_quorum_geometry(set)?;
        let expected_hash = ioi_types::app::canonical_validator_set_hash(set)
            .map_err(ConsensusError::BlockVerificationFailed)?;
        if scope.configuration_hash != expected_hash || scope.epoch != set.effective_from_height {
            return Err(ConsensusError::BlockVerificationFailed(
                "AFT fallback scope does not match the rooted effective validator set".into(),
            ));
        }
        Ok(sets)
    }

    pub(super) fn validate_safe_state_qc(
        &self,
        qc: &QuorumCertificate,
        async_parent_proof_hash: Option<[u8; 32]>,
        label: &str,
    ) -> Result<(), ConsensusError> {
        if qc.height == 0 {
            if qc != &QuorumCertificate::default() || async_parent_proof_hash.is_some() {
                return Err(ConsensusError::BlockVerificationFailed(format!(
                    "AFT fallback {label} uses a non-canonical genesis sentinel"
                )));
            }
            return Ok(());
        }
        if let Some(expected) = self.async_parent_proof_hash(qc) {
            return if async_parent_proof_hash == Some(expected) {
                Ok(())
            } else {
                Err(ConsensusError::BlockVerificationFailed(format!(
                    "AFT fallback {label} does not bind its verified async-parent proof"
                )))
            };
        }
        if async_parent_proof_hash.is_some() {
            return Err(ConsensusError::BlockVerificationFailed(format!(
                "AFT fallback {label} names an unavailable or mismatched async-parent proof"
            )));
        }
        self.authenticated_quorum(qc).map(|_| ()).map_err(|error| {
            ConsensusError::BlockVerificationFailed(format!(
                "AFT fallback {label} is not an authenticated quorum certificate: {error}"
            ))
        })
    }

    pub(super) fn validate_fallback_start(
        &self,
        certificate: &FallbackStartCertificateV1,
    ) -> Result<(), ConsensusError> {
        certificate
            .validate_shape()
            .map_err(ConsensusError::BlockVerificationFailed)?;
        let configured = self.fallback_scope.ok_or_else(|| {
            ConsensusError::BlockVerificationFailed(
                "AFT fallback scope and durable journal are not configured".into(),
            )
        })?;
        if certificate.scope != configured {
            return Err(ConsensusError::BlockVerificationFailed(
                "AFT fallback certificate is replayed across configuration scope".into(),
            ));
        }
        let sets = self.validate_fallback_profile(certificate.scope, certificate.height)?;
        for timeout_certificate in &certificate
            .trigger_certificate
            .consecutive_timeout_certificates
        {
            self.verify_aft_timeout_certificate(timeout_certificate, &sets)?;
        }
        self.validate_safe_state_qc(
            &certificate.highest_qc,
            certificate.highest_qc_async_parent_proof_hash,
            "high QC",
        )?;
        self.validate_safe_state_qc(
            &certificate.locked_qc,
            certificate.locked_qc_async_parent_proof_hash,
            "locked QC",
        )?;
        let local_lock = self.safety.locked_qc.clone().unwrap_or_default();
        let rank = |qc: &QuorumCertificate| (qc.height, qc.view, qc.block_hash);
        if rank(&certificate.highest_qc) < rank(&self.highest_qc)
            || rank(&certificate.locked_qc) < rank(&local_lock)
        {
            return Err(ConsensusError::BlockVerificationFailed(
                "AFT fallback trigger omits newer locally authenticated high-QC or lock state"
                    .into(),
            ));
        }
        Ok(())
    }

    pub(super) fn configure_fallback_transition_journal(
        &mut self,
        scope: AftFallbackScopeV1,
        path: &Path,
    ) -> Result<(), ConsensusError> {
        scope
            .validate()
            .map_err(ConsensusError::BlockVerificationFailed)?;
        if self
            .fallback_journal
            .as_ref()
            .is_some_and(|journal| journal.matches(path, scope))
        {
            return Ok(());
        }
        // The rooted set and the declared scope must agree before any existing
        // bytes are admitted from disk.
        let observation_height = self
            .validator_sets_by_height
            .keys()
            .next_back()
            .copied()
            .ok_or_else(|| {
                ConsensusError::BlockVerificationFailed(
                    "AFT fallback journal cannot be configured before validator-set hydration"
                        .into(),
                )
            })?;
        self.validate_fallback_profile(scope, observation_height)?;

        let journal = FallbackJournal::open(path, scope)?;
        let starts = journal.starts()?;
        for certificate in &starts {
            self.validate_fallback_start_against_scope(certificate, scope)?;
        }

        self.fallback_scope = Some(scope);
        self.fallback_starts = starts
            .iter()
            .cloned()
            .map(|certificate| (certificate.height, certificate))
            .collect();
        self.pending_fallback_broadcasts = starts.into_iter().collect();
        self.announced_fallback_instances.clear();
        self.fallback_journal = Some(journal);
        Ok(())
    }

    fn validate_fallback_start_against_scope(
        &self,
        certificate: &FallbackStartCertificateV1,
        scope: AftFallbackScopeV1,
    ) -> Result<(), ConsensusError> {
        certificate
            .validate_shape()
            .map_err(ConsensusError::BlockVerificationFailed)?;
        if certificate.scope != scope {
            return Err(ConsensusError::BlockVerificationFailed(
                "AFT fallback certificate is replayed across configuration scope".into(),
            ));
        }
        let sets = self.validate_fallback_profile(scope, certificate.height)?;
        for timeout_certificate in &certificate
            .trigger_certificate
            .consecutive_timeout_certificates
        {
            self.verify_aft_timeout_certificate(timeout_certificate, &sets)?;
        }
        self.validate_safe_state_qc(
            &certificate.highest_qc,
            certificate.highest_qc_async_parent_proof_hash,
            "high QC",
        )?;
        self.validate_safe_state_qc(
            &certificate.locked_qc,
            certificate.locked_qc_async_parent_proof_hash,
            "locked QC",
        )?;
        Ok(())
    }

    fn persist_fallback_start(
        &mut self,
        certificate: FallbackStartCertificateV1,
    ) -> Result<bool, ConsensusError> {
        self.validate_fallback_start(&certificate)?;
        if let Some(existing) = self.fallback_starts.get(&certificate.height) {
            return if existing
                .consensus_equivalent(&certificate)
                .map_err(ConsensusError::BlockVerificationFailed)?
            {
                Ok(false)
            } else {
                Err(ConsensusError::BlockVerificationFailed(
                    "conflicting AFT fallback trigger for an active height".into(),
                ))
            };
        }
        let journal = self.fallback_journal.as_ref().ok_or_else(|| {
            ConsensusError::BlockVerificationFailed(
                "AFT fallback transition refused because its durable journal is unavailable".into(),
            )
        })?;
        match journal.insert(&certificate)? {
            JournalInsert::Inserted => {
                self.fallback_starts
                    .insert(certificate.height, certificate.clone());
                if self
                    .announced_fallback_instances
                    .insert(certificate.fallback_instance_id)
                {
                    self.pending_fallback_broadcasts.push_back(certificate);
                }
                Ok(true)
            }
            JournalInsert::Idempotent => {
                self.fallback_starts.insert(certificate.height, certificate);
                Ok(false)
            }
        }
    }

    fn maybe_start_fallback(&mut self, height: u64) -> Result<bool, ConsensusError> {
        let Some(sets) = self.validator_sets_for_fallback(height) else {
            return Ok(false);
        };
        let set = effective_set_for_height(&sets, height);
        if !matches!(self.safety_mode, AftSafetyMode::ClassicBft)
            || !set.validators.iter().all(|validator| {
                validator.consensus_key.suite == ioi_types::app::SignatureSuite::ML_DSA_44
            })
        {
            return Ok(false);
        }
        // A malformed nominal PQ set is not a compatibility profile. Its
        // exact 3f+1/unit-weight geometry must pass or transition refuses.
        authenticated_quorum::pq_optimistic_quorum_geometry(set)?;
        if self.fallback_starts.contains_key(&height) {
            return Ok(false);
        }
        let mut consecutive_timeout_certificates =
            Vec::with_capacity(AFT_FALLBACK_TRIGGER_VIEW_V1 as usize);
        for view in 1..=AFT_FALLBACK_TRIGGER_VIEW_V1 {
            if !self.tc_formed.contains(&(height, view)) {
                return Ok(false);
            }
            let Some(certificate) = self.check_aft_timeout_quorum(height, view, &sets)? else {
                return Ok(false);
            };
            consecutive_timeout_certificates.push(certificate);
        }
        let scope = self.fallback_scope.ok_or_else(|| {
            ConsensusError::BlockVerificationFailed(
                "canonical fallback trigger formed without a configured durable journal".into(),
            )
        })?;
        // An authenticated QC at this height wins the optimistic/fallback race;
        // M3 will consume the persisted transition only when no such QC exists.
        if self.highest_qc.height >= height {
            return Ok(false);
        }
        let certificate = FallbackStartCertificateV1::new(
            scope,
            height,
            AftFallbackTriggerCertificateV1 {
                height,
                consecutive_timeout_certificates,
            },
        )
        .map_err(ConsensusError::BlockVerificationFailed)?;
        self.persist_fallback_start(certificate)
    }

    fn queue_timeout_relay(&mut self, certificate: &TimeoutCertificate) {
        if self
            .announced_tcs
            .insert((certificate.height, certificate.view))
        {
            self.pending_tc_broadcasts.push_back(certificate.clone());
        }
    }

    fn queue_aft_timeout_relay(&mut self, certificate: &AftTimeoutCertificateV1) {
        if self
            .announced_aft_tcs
            .insert((certificate.scope, certificate.height, certificate.view))
        {
            self.pending_aft_tc_broadcasts
                .push_back(certificate.clone());
        }
    }

    pub(super) async fn adopt_timeout_certificate(
        &mut self,
        certificate: TimeoutCertificate,
        relayed: bool,
    ) -> Result<bool, ConsensusError> {
        if certificate.height == 0 {
            return Err(ConsensusError::BlockVerificationFailed(
                "timeout certificate cannot target genesis height zero".into(),
            ));
        }
        if self.pacemaker_height > 0 && certificate.height < self.pacemaker_height {
            return Err(ConsensusError::BlockVerificationFailed(format!(
                "stale timeout certificate for height {} below active height {}",
                certificate.height, self.pacemaker_height
            )));
        }
        if certificate.height > self.pacemaker_height.saturating_add(1) {
            return Err(ConsensusError::BlockVerificationFailed(format!(
                "future timeout certificate for height {} exceeds active height {}",
                certificate.height, self.pacemaker_height
            )));
        }
        let sets = self
            .validator_sets_for_fallback(certificate.height)
            .ok_or_else(|| {
                ConsensusError::BlockVerificationFailed(format!(
                    "no observed validator set for timeout certificate height {}",
                    certificate.height
                ))
            })?;
        self.verify_timeout_certificate(&certificate, &sets)?;

        let is_new = self
            .tc_formed
            .insert((certificate.height, certificate.view));
        let view_map = self
            .view_votes
            .entry(certificate.height)
            .or_default()
            .entry(certificate.view)
            .or_default();
        for vote in &certificate.votes {
            view_map.insert(vote.voter, vote.clone());
        }
        self.queue_timeout_relay(&certificate);
        self.maybe_start_fallback(certificate.height)?;
        if relayed && certificate.height == self.pacemaker_height {
            self.pacemaker
                .lock()
                .await
                .adopt_relayed_view(certificate.view);
        }
        Ok(is_new)
    }

    pub(super) async fn adopt_aft_timeout_certificate(
        &mut self,
        certificate: AftTimeoutCertificateV1,
        relayed: bool,
    ) -> Result<bool, ConsensusError> {
        let configured_scope = self.fallback_scope.ok_or_else(|| {
            ConsensusError::BlockVerificationFailed(
                "AFT timeout transition refused before durable scope configuration".into(),
            )
        })?;
        if certificate.scope != configured_scope {
            return Err(ConsensusError::BlockVerificationFailed(
                "AFT timeout certificate is replayed across configuration scope".into(),
            ));
        }
        if certificate.height == 0 {
            return Err(ConsensusError::BlockVerificationFailed(
                "AFT timeout certificate cannot target genesis height zero".into(),
            ));
        }
        if self.pacemaker_height > 0 && certificate.height < self.pacemaker_height {
            return Err(ConsensusError::BlockVerificationFailed(format!(
                "stale AFT timeout certificate for height {} below active height {}",
                certificate.height, self.pacemaker_height
            )));
        }
        if certificate.height > self.pacemaker_height.saturating_add(1) {
            return Err(ConsensusError::BlockVerificationFailed(format!(
                "future AFT timeout certificate for height {} exceeds active height {}",
                certificate.height, self.pacemaker_height
            )));
        }
        let sets = self
            .validator_sets_for_fallback(certificate.height)
            .ok_or_else(|| {
                ConsensusError::BlockVerificationFailed(format!(
                    "no observed validator set for AFT timeout certificate height {}",
                    certificate.height
                ))
            })?;
        self.verify_aft_timeout_certificate(&certificate, &sets)?;

        let is_new = self
            .tc_formed
            .insert((certificate.height, certificate.view));
        let view_map = self
            .aft_timeout_votes
            .entry(certificate.height)
            .or_default()
            .entry(certificate.view)
            .or_default();
        for vote in &certificate.votes {
            view_map.insert(vote.voter, vote.clone());
        }
        self.queue_aft_timeout_relay(&certificate);
        self.maybe_start_fallback(certificate.height)?;
        if relayed && certificate.height == self.pacemaker_height {
            self.pacemaker
                .lock()
                .await
                .adopt_relayed_view(certificate.view);
        }
        Ok(is_new)
    }

    pub(super) fn adopt_fallback_start(
        &mut self,
        certificate: FallbackStartCertificateV1,
    ) -> Result<bool, ConsensusError> {
        if self.pacemaker_height > 0 && certificate.height < self.pacemaker_height {
            return Err(ConsensusError::BlockVerificationFailed(format!(
                "stale AFT fallback transition for height {} below active height {}",
                certificate.height, self.pacemaker_height
            )));
        }
        if certificate.height > self.pacemaker_height.saturating_add(1) {
            return Err(ConsensusError::BlockVerificationFailed(format!(
                "future AFT fallback transition for height {} exceeds active height {}",
                certificate.height, self.pacemaker_height
            )));
        }
        let local_lock = self.safety.locked_qc.clone().unwrap_or_default();
        let rank = |qc: &QuorumCertificate| (qc.height, qc.view, qc.block_hash);
        if rank(&certificate.highest_qc) < rank(&self.highest_qc)
            || rank(&certificate.locked_qc) < rank(&local_lock)
        {
            return Err(ConsensusError::BlockVerificationFailed(
                "relayed AFT fallback omits newer locally authenticated high-QC or lock state"
                    .into(),
            ));
        }
        self.persist_fallback_start(certificate)
    }

    pub(super) fn drain_pending_timeout_certificates(&mut self) -> Vec<TimeoutCertificate> {
        self.pending_tc_broadcasts.drain(..).collect()
    }

    pub(super) fn drain_pending_aft_timeout_certificates(
        &mut self,
    ) -> Vec<AftTimeoutCertificateV1> {
        self.pending_aft_tc_broadcasts.drain(..).collect()
    }

    pub(super) fn drain_pending_fallback_starts(&mut self) -> Vec<FallbackStartCertificateV1> {
        self.pending_fallback_broadcasts.drain(..).collect()
    }
}
