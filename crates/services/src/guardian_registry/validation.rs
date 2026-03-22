use super::*;

impl GuardianRegistry {
    pub(super) fn validate_diversity(
        labels: impl Iterator<Item = Option<String>>,
        minimum: u16,
        field: &str,
    ) -> Result<(), TransactionError> {
        if minimum == 0 {
            return Ok(());
        }

        let distinct = labels
            .flatten()
            .filter(|value| !value.trim().is_empty())
            .collect::<BTreeSet<_>>();

        if distinct.len() < usize::from(minimum) {
            return Err(TransactionError::Invalid(format!(
                "guardian registry policy requires at least {} distinct {} labels, got {}",
                minimum,
                field,
                distinct.len()
            )));
        }
        Ok(())
    }

    pub(super) fn validate_committee_manifest(
        &self,
        manifest: &GuardianCommitteeManifest,
    ) -> Result<(), TransactionError> {
        let member_count = manifest.members.len();
        if member_count < usize::from(self.config.minimum_committee_size) {
            return Err(TransactionError::Invalid(format!(
                "guardian committee size {} is below minimum {}",
                member_count, self.config.minimum_committee_size
            )));
        }
        if member_count == 0 {
            return Err(TransactionError::Invalid(
                "guardian committee must contain at least one member".into(),
            ));
        }
        if manifest.threshold == 0 || usize::from(manifest.threshold) > member_count {
            return Err(TransactionError::Invalid(format!(
                "guardian committee threshold {} is invalid for size {}",
                manifest.threshold, member_count
            )));
        }
        if usize::from(manifest.threshold) <= member_count / 2 {
            return Err(TransactionError::Invalid(
                "guardian committee threshold must be a strict majority".into(),
            ));
        }
        if self.config.require_even_committee_sizes && member_count % 2 != 0 {
            return Err(TransactionError::Invalid(
                "production guardian committees must be even-sized in registry policy".into(),
            ));
        }
        if self.config.require_checkpoint_anchoring
            && manifest.transparency_log_id.trim().is_empty()
        {
            return Err(TransactionError::Invalid(
                "guardian committee must declare a transparency log id".into(),
            ));
        }

        Self::validate_diversity(
            manifest
                .members
                .iter()
                .map(|member| member.provider.clone()),
            self.config.minimum_provider_diversity,
            "provider",
        )?;
        Self::validate_diversity(
            manifest.members.iter().map(|member| member.region.clone()),
            self.config.minimum_region_diversity,
            "region",
        )?;
        Self::validate_diversity(
            manifest
                .members
                .iter()
                .map(|member| member.host_class.clone()),
            self.config.minimum_host_class_diversity,
            "host class",
        )?;
        Self::validate_diversity(
            manifest
                .members
                .iter()
                .map(|member| member.key_authority_kind.map(|kind| format!("{kind:?}"))),
            self.config.minimum_backend_diversity,
            "key authority",
        )?;

        Ok(())
    }

    pub(super) fn validate_witness_manifest(
        &self,
        manifest: &GuardianWitnessCommitteeManifest,
    ) -> Result<(), TransactionError> {
        let member_count = manifest.members.len();
        if member_count < usize::from(self.config.minimum_witness_committee_size) {
            return Err(TransactionError::Invalid(format!(
                "witness committee size {} is below minimum {}",
                member_count, self.config.minimum_witness_committee_size
            )));
        }
        if manifest.threshold == 0 || usize::from(manifest.threshold) > member_count {
            return Err(TransactionError::Invalid(format!(
                "witness committee threshold {} is invalid for size {}",
                manifest.threshold, member_count
            )));
        }
        if usize::from(manifest.threshold) <= member_count / 2 {
            return Err(TransactionError::Invalid(
                "witness committee threshold must be a strict majority".into(),
            ));
        }
        if self.config.require_even_committee_sizes && member_count % 2 != 0 {
            return Err(TransactionError::Invalid(
                "production witness committees must be even-sized in registry policy".into(),
            ));
        }
        if self.config.require_checkpoint_anchoring
            && manifest.transparency_log_id.trim().is_empty()
        {
            return Err(TransactionError::Invalid(
                "witness committee must declare a transparency log id".into(),
            ));
        }
        if manifest.stratum_id.trim().is_empty() {
            return Err(TransactionError::Invalid(
                "witness committee must declare a certification stratum".into(),
            ));
        }

        Self::validate_diversity(
            manifest
                .members
                .iter()
                .map(|member| member.provider.clone()),
            self.config.minimum_provider_diversity,
            "provider",
        )?;
        Self::validate_diversity(
            manifest.members.iter().map(|member| member.region.clone()),
            self.config.minimum_region_diversity,
            "region",
        )?;
        Self::validate_diversity(
            manifest
                .members
                .iter()
                .map(|member| member.host_class.clone()),
            self.config.minimum_host_class_diversity,
            "host class",
        )?;
        Self::validate_diversity(
            manifest
                .members
                .iter()
                .map(|member| member.key_authority_kind.map(|kind| format!("{kind:?}"))),
            self.config.minimum_backend_diversity,
            "key authority",
        )?;

        Ok(())
    }

    pub(super) fn validate_log_descriptor(
        &self,
        descriptor: &GuardianTransparencyLogDescriptor,
    ) -> Result<(), TransactionError> {
        if descriptor.log_id.trim().is_empty() {
            return Err(TransactionError::Invalid(
                "guardian transparency log id must not be empty".into(),
            ));
        }
        if descriptor.public_key.is_empty() {
            return Err(TransactionError::Invalid(
                "guardian transparency log public key must not be empty".into(),
            ));
        }
        Ok(())
    }
}
