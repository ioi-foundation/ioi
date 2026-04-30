fn bootstrap_restaurants_near_me_fixture_runtime(
    run_unique_num: &str,
) -> Result<RestaurantsNearMeFixtureRuntime> {
    let temp_dir = tempdir()?;
    let fixture_root = temp_dir.path().join(format!(
        "{}{}",
        RESTAURANTS_NEAR_ME_FIXTURE_DIR_PREFIX, run_unique_num
    ));
    std::fs::create_dir_all(&fixture_root)?;
    let manifest_path = fixture_root.join("fixture_manifest.txt");
    let observed_locality = std::env::var(RESTAURANTS_NEAR_ME_LOCALITY_ENV_KEY)
        .ok()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty());
    std::fs::write(
        &manifest_path,
        format!(
            "mode={}\nrun_unique_num={}\nlocality_env_key={}\nobserved_locality={}\n",
            RESTAURANTS_NEAR_ME_FIXTURE_MODE,
            run_unique_num,
            RESTAURANTS_NEAR_ME_LOCALITY_ENV_KEY,
            display_optional_env_value(observed_locality.as_deref())
        ),
    )?;

    Ok(RestaurantsNearMeFixtureRuntime {
        _temp_dir: temp_dir,
        fixture_root,
        manifest_path,
        observed_locality,
    })
}

fn restaurants_near_me_fixture_preflight_checks(
    fixture: &RestaurantsNearMeFixtureRuntime,
    run_unique_num: &str,
    run_timestamp_ms: u64,
) -> EnvironmentEvidenceBatch {
    let probe_source = format!("{}.preflight", RESTAURANTS_NEAR_ME_FIXTURE_PROBE_SOURCE);
    let fixture_root = fixture.fixture_root.to_string_lossy().to_string();
    let locality_observed = std::env::var(RESTAURANTS_NEAR_ME_LOCALITY_ENV_KEY)
        .ok()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty());
    let run_unique_satisfied = fixture_root.contains(run_unique_num);
    let manifest_seeded_satisfied = fixture.manifest_path.is_file();
    let locality_observation_satisfied =
        locality_observed.as_deref() == fixture.observed_locality.as_deref();
    let fixture_satisfied =
        run_unique_satisfied && manifest_seeded_satisfied && locality_observation_satisfied;

    let mut batch = EnvironmentEvidenceBatch::default();
    push_environment_receipt(
        &mut batch,
        "restaurants_near_me_fixture_mode",
        RESTAURANTS_NEAR_ME_FIXTURE_MODE,
        Some(RESTAURANTS_NEAR_ME_FIXTURE_PROBE_SOURCE.to_string()),
        Some(run_timestamp_ms),
        Some(true),
    );
    push_environment_receipt(
        &mut batch,
        "restaurants_near_me_fixture_root",
        fixture.fixture_root.to_string_lossy().to_string(),
        Some(RESTAURANTS_NEAR_ME_FIXTURE_PROBE_SOURCE.to_string()),
        Some(run_timestamp_ms),
        Some(fixture_satisfied),
    );
    push_environment_receipt(
        &mut batch,
        "restaurants_near_me_fixture_manifest_path",
        fixture.manifest_path.to_string_lossy().to_string(),
        Some(RESTAURANTS_NEAR_ME_FIXTURE_PROBE_SOURCE.to_string()),
        Some(run_timestamp_ms),
        Some(manifest_seeded_satisfied),
    );
    push_environment_receipt(
        &mut batch,
        "restaurants_near_me_run_unique_num",
        run_unique_num.to_string(),
        Some(RESTAURANTS_NEAR_ME_FIXTURE_PROBE_SOURCE.to_string()),
        Some(run_timestamp_ms),
        Some(run_unique_satisfied),
    );
    push_environment_receipt(
        &mut batch,
        "restaurants_near_me_locality_env_key",
        RESTAURANTS_NEAR_ME_LOCALITY_ENV_KEY,
        Some(probe_source.clone()),
        Some(run_timestamp_ms),
        Some(true),
    );
    push_environment_receipt(
        &mut batch,
        "restaurants_near_me_locality_observed_value",
        display_optional_env_value(locality_observed.as_deref()),
        Some(probe_source.clone()),
        Some(run_timestamp_ms),
        Some(locality_observation_satisfied),
    );
    push_environment_receipt(
        &mut batch,
        "restaurants_near_me_locality_initial_value",
        display_optional_env_value(fixture.observed_locality.as_deref()),
        Some(probe_source.clone()),
        Some(run_timestamp_ms),
        Some(locality_observation_satisfied),
    );
    push_environment_receipt(
        &mut batch,
        "restaurants_near_me_locality",
        display_optional_env_value(locality_observed.as_deref()),
        Some(probe_source.clone()),
        Some(run_timestamp_ms),
        Some(locality_observation_satisfied),
    );
    push_environment_receipt(
        &mut batch,
        "restaurants_near_me_locality_observation",
        locality_observation_satisfied.to_string(),
        Some(probe_source.clone()),
        Some(run_timestamp_ms),
        Some(locality_observation_satisfied),
    );
    push_environment_receipt(
        &mut batch,
        "restaurants_near_me_manifest_seeded",
        manifest_seeded_satisfied.to_string(),
        Some(RESTAURANTS_NEAR_ME_FIXTURE_PROBE_SOURCE.to_string()),
        Some(run_timestamp_ms),
        Some(manifest_seeded_satisfied),
    );
    push_environment_receipt(
        &mut batch,
        "restaurants_near_me_fixture",
        fixture_satisfied.to_string(),
        Some(RESTAURANTS_NEAR_ME_FIXTURE_PROBE_SOURCE.to_string()),
        Some(run_timestamp_ms),
        Some(fixture_satisfied),
    );
    batch
}

fn restaurants_near_me_fixture_post_run_checks(
    fixture: &RestaurantsNearMeFixtureRuntime,
) -> EnvironmentEvidenceBatch {
    let root_exists_satisfied = fixture.fixture_root.is_dir();
    let manifest_exists_satisfied = fixture.manifest_path.is_file();
    let locality_post_run = std::env::var(RESTAURANTS_NEAR_ME_LOCALITY_ENV_KEY)
        .ok()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty());
    let locality_unchanged_satisfied = std::env::var(RESTAURANTS_NEAR_ME_LOCALITY_ENV_KEY)
        .ok()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
        .as_deref()
        == fixture.observed_locality.as_deref();
    let scope_satisfied = root_exists_satisfied && manifest_exists_satisfied;

    let timestamp_ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64;
    let probe_source = format!("{}.post_run", RESTAURANTS_NEAR_ME_FIXTURE_PROBE_SOURCE);
    let mut batch = EnvironmentEvidenceBatch::default();
    push_environment_receipt(
        &mut batch,
        "restaurants_near_me_fixture_root_exists",
        root_exists_satisfied.to_string(),
        Some(probe_source.clone()),
        Some(timestamp_ms),
        Some(root_exists_satisfied),
    );
    push_environment_receipt(
        &mut batch,
        "restaurants_near_me_manifest_exists",
        manifest_exists_satisfied.to_string(),
        Some(probe_source.clone()),
        Some(timestamp_ms),
        Some(manifest_exists_satisfied),
    );
    push_environment_receipt(
        &mut batch,
        "restaurants_near_me_locality_unchanged_post_run",
        locality_unchanged_satisfied.to_string(),
        Some(probe_source.clone()),
        Some(timestamp_ms),
        Some(locality_unchanged_satisfied),
    );
    push_environment_receipt(
        &mut batch,
        "restaurants_near_me_locality_post_run_value",
        display_optional_env_value(locality_post_run.as_deref()),
        Some(probe_source.clone()),
        Some(timestamp_ms),
        Some(locality_unchanged_satisfied),
    );
    push_environment_receipt(
        &mut batch,
        "restaurants_near_me_scope",
        scope_satisfied.to_string(),
        Some(probe_source),
        Some(timestamp_ms),
        Some(scope_satisfied),
    );
    batch
}

fn restaurants_near_me_fixture_cleanup_checks(
    fixture: &RestaurantsNearMeFixtureRuntime,
) -> EnvironmentEvidenceBatch {
    let timestamp_ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64;
    let probe_source = format!("{}.cleanup_probe", RESTAURANTS_NEAR_ME_FIXTURE_PROBE_SOURCE);

    let observed_locality = std::env::var(RESTAURANTS_NEAR_ME_LOCALITY_ENV_KEY)
        .ok()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty());
    restore_optional_env_value(
        RESTAURANTS_NEAR_ME_LOCALITY_ENV_KEY,
        fixture.observed_locality.as_deref(),
    );
    let restored_locality = std::env::var(RESTAURANTS_NEAR_ME_LOCALITY_ENV_KEY)
        .ok()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty());
    let locality_unchanged_satisfied =
        restored_locality.as_deref() == fixture.observed_locality.as_deref();

    let _ = std::fs::remove_file(&fixture.manifest_path);
    let _ = std::fs::remove_dir_all(&fixture.fixture_root);
    let fixture_root_exists_after_cleanup = fixture.fixture_root.exists();
    let manifest_exists_after_cleanup = fixture.manifest_path.exists();
    let cleanup_satisfied = !fixture_root_exists_after_cleanup
        && !manifest_exists_after_cleanup
        && locality_unchanged_satisfied;

    let mut batch = EnvironmentEvidenceBatch::default();
    push_environment_receipt(
        &mut batch,
        "restaurants_near_me_cleanup_root_exists",
        fixture_root_exists_after_cleanup.to_string(),
        Some(probe_source.clone()),
        Some(timestamp_ms),
        Some(!fixture_root_exists_after_cleanup),
    );
    push_environment_receipt(
        &mut batch,
        "restaurants_near_me_cleanup_manifest_exists",
        manifest_exists_after_cleanup.to_string(),
        Some(probe_source.clone()),
        Some(timestamp_ms),
        Some(!manifest_exists_after_cleanup),
    );
    push_environment_receipt(
        &mut batch,
        "restaurants_near_me_cleanup_locality_observed_value",
        display_optional_env_value(restored_locality.as_deref()),
        Some(probe_source.clone()),
        Some(timestamp_ms),
        Some(locality_unchanged_satisfied),
    );
    push_environment_receipt(
        &mut batch,
        "restaurants_near_me_cleanup_locality_pre_restore_value",
        display_optional_env_value(observed_locality.as_deref()),
        Some(probe_source.clone()),
        Some(timestamp_ms),
        Some(true),
    );
    push_environment_receipt(
        &mut batch,
        "restaurants_near_me_cleanup_locality_unchanged",
        locality_unchanged_satisfied.to_string(),
        Some(probe_source.clone()),
        Some(timestamp_ms),
        Some(locality_unchanged_satisfied),
    );
    push_environment_receipt(
        &mut batch,
        "restaurants_near_me_cleanup",
        cleanup_satisfied.to_string(),
        Some(probe_source),
        Some(timestamp_ms),
        Some(cleanup_satisfied),
    );
    batch
}

fn bootstrap_latest_nist_pqc_briefing_fixture_runtime(
    run_unique_num: &str,
) -> Result<LatestNistPqcBriefingFixtureRuntime> {
    let temp_dir = tempdir()?;
    let fixture_root = temp_dir.path().join(format!(
        "{}{}",
        LATEST_NIST_PQC_BRIEFING_FIXTURE_DIR_PREFIX, run_unique_num
    ));
    std::fs::create_dir_all(&fixture_root)?;

    let observed_utc_timestamp_ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64;
    let observed_utc_date = iso_datetime_from_unix_ms(observed_utc_timestamp_ms)
        .chars()
        .take(10)
        .collect::<String>();
    let manifest_path = fixture_root.join("latest_nist_pqc_briefing_fixture_manifest.txt");
    std::fs::write(
        &manifest_path,
        format!(
            "mode={}\nrun_unique_num={}\nobserved_utc_date={}\nobserved_utc_timestamp_ms={}\n",
            LATEST_NIST_PQC_BRIEFING_FIXTURE_MODE,
            run_unique_num,
            observed_utc_date,
            observed_utc_timestamp_ms
        ),
    )?;

    Ok(LatestNistPqcBriefingFixtureRuntime {
        _temp_dir: temp_dir,
        fixture_root,
        manifest_path,
        observed_utc_date,
        observed_utc_timestamp_ms,
    })
}

fn latest_nist_pqc_briefing_fixture_preflight_checks(
    fixture: &LatestNistPqcBriefingFixtureRuntime,
    run_unique_num: &str,
    run_timestamp_ms: u64,
) -> EnvironmentEvidenceBatch {
    let fixture_root = fixture.fixture_root.to_string_lossy().to_string();
    let run_unique_satisfied = fixture_root.contains(run_unique_num);
    let manifest_seeded_satisfied = fixture.manifest_path.is_file();
    let fixture_satisfied =
        fixture.fixture_root.is_dir() && manifest_seeded_satisfied && run_unique_satisfied;
    let mut batch = EnvironmentEvidenceBatch::default();
    push_environment_receipt(
        &mut batch,
        "latest_nist_pqc_briefing_fixture_mode",
        LATEST_NIST_PQC_BRIEFING_FIXTURE_MODE,
        Some(LATEST_NIST_PQC_BRIEFING_FIXTURE_PROBE_SOURCE.to_string()),
        Some(run_timestamp_ms),
        Some(true),
    );
    push_environment_receipt(
        &mut batch,
        "latest_nist_pqc_briefing_fixture_root",
        fixture.fixture_root.to_string_lossy().to_string(),
        Some(LATEST_NIST_PQC_BRIEFING_FIXTURE_PROBE_SOURCE.to_string()),
        Some(run_timestamp_ms),
        Some(fixture_satisfied),
    );
    push_environment_receipt(
        &mut batch,
        "latest_nist_pqc_briefing_fixture_manifest_path",
        fixture.manifest_path.to_string_lossy().to_string(),
        Some(LATEST_NIST_PQC_BRIEFING_FIXTURE_PROBE_SOURCE.to_string()),
        Some(run_timestamp_ms),
        Some(manifest_seeded_satisfied),
    );
    push_environment_receipt(
        &mut batch,
        "latest_nist_pqc_briefing_run_unique_num",
        run_unique_num.to_string(),
        Some(LATEST_NIST_PQC_BRIEFING_FIXTURE_PROBE_SOURCE.to_string()),
        Some(run_timestamp_ms),
        Some(run_unique_satisfied),
    );
    push_environment_receipt(
        &mut batch,
        "latest_nist_pqc_briefing_current_utc_date",
        fixture.observed_utc_date.clone(),
        Some(format!(
            "{}.preflight",
            LATEST_NIST_PQC_BRIEFING_FIXTURE_PROBE_SOURCE
        )),
        Some(run_timestamp_ms),
        Some(!fixture.observed_utc_date.trim().is_empty()),
    );
    push_environment_receipt(
        &mut batch,
        "latest_nist_pqc_briefing_current_utc_timestamp_ms",
        fixture.observed_utc_timestamp_ms.to_string(),
        Some(format!(
            "{}.preflight",
            LATEST_NIST_PQC_BRIEFING_FIXTURE_PROBE_SOURCE
        )),
        Some(run_timestamp_ms),
        Some(fixture.observed_utc_timestamp_ms > 0),
    );
    push_environment_receipt(
        &mut batch,
        "latest_nist_pqc_briefing_fixture",
        fixture_satisfied.to_string(),
        Some(LATEST_NIST_PQC_BRIEFING_FIXTURE_PROBE_SOURCE.to_string()),
        Some(run_timestamp_ms),
        Some(fixture_satisfied),
    );
    batch
}

fn latest_nist_pqc_briefing_fixture_post_run_checks(
    fixture: &LatestNistPqcBriefingFixtureRuntime,
) -> EnvironmentEvidenceBatch {
    let timestamp_ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64;
    let probe_source = format!("{}.post_run", LATEST_NIST_PQC_BRIEFING_FIXTURE_PROBE_SOURCE);
    let fixture_root_exists = fixture.fixture_root.is_dir();
    let manifest_exists = fixture.manifest_path.is_file();
    let current_utc_date = iso_datetime_from_unix_ms(timestamp_ms)
        .chars()
        .take(10)
        .collect::<String>();
    let scope_satisfied = fixture_root_exists && manifest_exists;

    let mut batch = EnvironmentEvidenceBatch::default();
    push_environment_receipt(
        &mut batch,
        "latest_nist_pqc_briefing_fixture_root_exists",
        fixture_root_exists.to_string(),
        Some(probe_source.clone()),
        Some(timestamp_ms),
        Some(fixture_root_exists),
    );
    push_environment_receipt(
        &mut batch,
        "latest_nist_pqc_briefing_manifest_exists",
        manifest_exists.to_string(),
        Some(probe_source.clone()),
        Some(timestamp_ms),
        Some(manifest_exists),
    );
    push_environment_receipt(
        &mut batch,
        "latest_nist_pqc_briefing_current_utc_date_post_run",
        current_utc_date.clone(),
        Some(probe_source.clone()),
        Some(timestamp_ms),
        Some(!current_utc_date.trim().is_empty()),
    );
    push_environment_receipt(
        &mut batch,
        "latest_nist_pqc_briefing_scope",
        scope_satisfied.to_string(),
        Some(probe_source),
        Some(timestamp_ms),
        Some(scope_satisfied),
    );
    batch
}

fn latest_nist_pqc_briefing_fixture_cleanup_checks(
    fixture: &LatestNistPqcBriefingFixtureRuntime,
) -> EnvironmentEvidenceBatch {
    let timestamp_ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64;
    let probe_source = format!(
        "{}.cleanup_probe",
        LATEST_NIST_PQC_BRIEFING_FIXTURE_PROBE_SOURCE
    );

    let _ = std::fs::remove_file(&fixture.manifest_path);
    let _ = std::fs::remove_dir_all(&fixture.fixture_root);
    let fixture_root_exists_after_cleanup = fixture.fixture_root.exists();
    let manifest_exists_after_cleanup = fixture.manifest_path.exists();
    let cleanup_satisfied = !fixture_root_exists_after_cleanup && !manifest_exists_after_cleanup;

    let mut batch = EnvironmentEvidenceBatch::default();
    push_environment_receipt(
        &mut batch,
        "latest_nist_pqc_briefing_cleanup_root_exists",
        fixture_root_exists_after_cleanup.to_string(),
        Some(probe_source.clone()),
        Some(timestamp_ms),
        Some(!fixture_root_exists_after_cleanup),
    );
    push_environment_receipt(
        &mut batch,
        "latest_nist_pqc_briefing_cleanup_manifest_exists",
        manifest_exists_after_cleanup.to_string(),
        Some(probe_source.clone()),
        Some(timestamp_ms),
        Some(!manifest_exists_after_cleanup),
    );
    push_environment_receipt(
        &mut batch,
        "latest_nist_pqc_briefing_cleanup",
        cleanup_satisfied.to_string(),
        Some(probe_source),
        Some(timestamp_ms),
        Some(cleanup_satisfied),
    );
    batch
}

async fn bootstrap_mailbox_runtime_state(
    state: &mut IAVLTree<HashCommitmentScheme>,
    ctx: &mut TxContext<'_>,
    wallet_service: &WalletNetworkService,
    run_index: usize,
    run_timestamp_ms: u64,
    requested_capability: Option<&str>,
) -> Result<EnvironmentEvidenceBatch> {
    fn read_wallet_receipt<T: parity_scale_codec::Decode>(
        state: &IAVLTree<HashCommitmentScheme>,
        key: &[u8],
        label: &str,
    ) -> Result<T> {
        let bytes = state
            .get(key)?
            .ok_or_else(|| anyhow!("missing wallet receipt '{}'", label))?;
        codec::from_bytes_canonical(&bytes)
            .map_err(|e| anyhow!("failed to decode wallet receipt '{}': {}", label, e))
    }

    fn wallet_mail_connector_get_receipt_key(request_id: &[u8; 32]) -> Vec<u8> {
        [
            b"mail_connector_get_evidence::".as_slice(),
            request_id.as_slice(),
        ]
        .concat()
    }

    fn wallet_mail_binding_receipt_key(request_id: &[u8; 32]) -> Vec<u8> {
        [
            b"mail_connector_binding_evidence::".as_slice(),
            request_id.as_slice(),
        ]
        .concat()
    }

    #[derive(Debug, Clone)]
    struct WalletHarnessIdentity {
        account_id: [u8; 32],
        public_key: Vec<u8>,
        signature_suite: SignatureSuite,
    }

    fn build_wallet_harness_identity(
        run_index: usize,
        primary_salt: u8,
        secondary_salt: u8,
    ) -> Result<WalletHarnessIdentity> {
        let mut public_key = deterministic_id(run_index, primary_salt).to_vec();
        public_key.extend_from_slice(&deterministic_id(run_index, secondary_salt));
        let signature_suite = SignatureSuite::HYBRID_ED25519_ML_DSA_44;
        let account_id = ioi_types::app::account_id_from_key_material(signature_suite, &public_key)
            .map_err(|error| anyhow!("failed to derive wallet harness account id: {}", error))?;
        Ok(WalletHarnessIdentity {
            account_id,
            public_key,
            signature_suite,
        })
    }

    fn build_mail_connector_config(config: &MailRuntimeBootstrapConfig) -> MailConnectorConfig {
        MailConnectorConfig {
            provider: MailConnectorProvider::ImapSmtp,
            auth_mode: config.auth_mode,
            account_email: config.account_email.clone(),
            sender_display_name: None,
            imap: MailConnectorEndpoint {
                host: config.imap_host.clone(),
                port: config.imap_port,
                tls_mode: config.imap_tls_mode,
            },
            smtp: MailConnectorEndpoint {
                host: config.smtp_host.clone(),
                port: config.smtp_port,
                tls_mode: config.smtp_tls_mode,
            },
            secret_aliases: MailConnectorSecretAliases {
                imap_username_alias: config.imap_username_alias.clone(),
                imap_password_alias: config.imap_secret_alias.clone(),
                smtp_username_alias: config.smtp_username_alias.clone(),
                smtp_password_alias: config.smtp_secret_alias.clone(),
            },
            metadata: BTreeMap::new(),
        }
    }

    fn build_connector_auth_record(
        config: &MailRuntimeBootstrapConfig,
        requested_capability: Option<&str>,
        timestamp_ms: u64,
    ) -> ioi_types::app::ConnectorAuthRecord {
        let mut credential_aliases = BTreeMap::new();
        credential_aliases.insert(
            "imap_username".to_string(),
            config.imap_username_alias.clone(),
        );
        credential_aliases.insert("imap_secret".to_string(), config.imap_secret_alias.clone());
        credential_aliases.insert(
            "smtp_username".to_string(),
            config.smtp_username_alias.clone(),
        );
        credential_aliases.insert("smtp_secret".to_string(), config.smtp_secret_alias.clone());

        ioi_types::app::ConnectorAuthRecord {
            connector_id: format!("mail.{}", config.mailbox),
            provider_family: "mail.wallet_network".to_string(),
            auth_protocol: match config.auth_mode {
                MailConnectorAuthMode::Password => {
                    ioi_types::app::ConnectorAuthProtocol::StaticPassword
                }
                MailConnectorAuthMode::Oauth2 => {
                    ioi_types::app::ConnectorAuthProtocol::OAuth2Bearer
                }
            },
            state: ioi_types::app::ConnectorAuthState::Connected,
            account_label: Some(config.account_email.clone()),
            mailbox: Some(config.mailbox.clone()),
            granted_scopes: requested_capability
                .map(|value| value.trim().to_string())
                .filter(|value| !value.is_empty())
                .into_iter()
                .collect(),
            credential_aliases,
            metadata: BTreeMap::new(),
            created_at_ms: timestamp_ms,
            updated_at_ms: timestamp_ms,
            expires_at_ms: None,
            last_validated_at_ms: Some(timestamp_ms),
        }
    }

    let (config, bootstrap_source) = resolve_mail_runtime_bootstrap_config()?;
    upsert_wallet_network_service_meta(state)?;

    let root = build_wallet_harness_identity(run_index, 0xC1, 0xC2)?;
    let capability_client = build_wallet_harness_identity(run_index, 0xC3, 0xC4)?;
    ctx.signer_account_id = ioi_types::app::AccountId(root.account_id);

    let root_record = ioi_types::app::WalletControlPlaneRootRecord {
        account_id: root.account_id,
        signature_suite: root.signature_suite,
        public_key: root.public_key.clone(),
        registered_at_ms: run_timestamp_ms,
        updated_at_ms: run_timestamp_ms,
        metadata: BTreeMap::from([("bootstrap_source".to_string(), bootstrap_source.to_string())]),
    };
    invoke_wallet_method(
        wallet_service,
        state,
        ctx,
        "configure_control_root@v1",
        &ioi_types::app::WalletConfigureControlRootParams { root: root_record },
    )
    .await?;

    let client_record = ioi_types::app::WalletRegisteredClientRecord {
        client_id: capability_client.account_id,
        label: format!("capabilities-suite-client-{}", run_index),
        surface: ioi_types::app::VaultSurface::Desktop,
        signature_suite: capability_client.signature_suite,
        public_key: capability_client.public_key.clone(),
        role: ioi_types::app::WalletClientRole::Capability,
        state: ioi_types::app::WalletClientState::Active,
        registered_at_ms: run_timestamp_ms,
        updated_at_ms: run_timestamp_ms,
        expires_at_ms: None,
        allowed_provider_families: vec!["mail.wallet_network".to_string()],
        metadata: BTreeMap::from([("bootstrap_source".to_string(), bootstrap_source.to_string())]),
    };
    invoke_wallet_method(
        wallet_service,
        state,
        ctx,
        "register_client@v1",
        &ioi_types::app::WalletRegisterClientParams {
            client: client_record,
        },
    )
    .await?;

    let secret_specs = build_mail_runtime_secret_specs(&config);
    for spec in secret_specs {
        let record = VaultSecretRecord {
            secret_id: spec.secret_id,
            alias: spec.alias,
            kind: spec.kind,
            ciphertext: spec.value.as_bytes().to_vec(),
            metadata: BTreeMap::new(),
            created_at_ms: run_timestamp_ms,
            rotated_at_ms: None,
        };
        invoke_wallet_method(
            wallet_service,
            state,
            ctx,
            "store_secret_record@v1",
            &record,
        )
        .await?;
    }

    let upsert = MailConnectorUpsertParams {
        mailbox: config.mailbox.clone(),
        config: build_mail_connector_config(&config),
    };
    invoke_wallet_method(
        wallet_service,
        state,
        ctx,
        "mail_connector_upsert@v1",
        &upsert,
    )
    .await?;

    let connector_auth = build_connector_auth_record(
        &config,
        requested_capability,
        run_timestamp_ms,
    );
    invoke_wallet_method(
        wallet_service,
        state,
        ctx,
        "connector_auth_upsert@v1",
        &ioi_types::app::ConnectorAuthUpsertParams {
            record: connector_auth,
        },
    )
    .await?;

    let connector_get_request_id = deterministic_id(run_index, 0xB1);
    invoke_wallet_method(
        wallet_service,
        state,
        ctx,
        "mail_connector_get@v1",
        &ioi_types::app::MailConnectorGetParams {
            request_id: connector_get_request_id,
            mailbox: config.mailbox.clone(),
        },
    )
    .await?;
    let connector_receipt: ioi_types::app::MailConnectorGetReceipt = read_wallet_receipt(
        state,
        &wallet_mail_connector_get_receipt_key(&connector_get_request_id),
        "mail_connector_get",
    )?;

    ctx.signer_account_id = ioi_types::app::AccountId(capability_client.account_id);

    let binding_request_id = deterministic_id(run_index, 0xB2);
    invoke_wallet_method(
        wallet_service,
        state,
        ctx,
        "mail_connector_ensure_binding@v1",
        &ioi_types::app::MailConnectorEnsureBindingParams {
            request_id: binding_request_id,
            mailbox: connector_receipt.mailbox.clone(),
            audience: Some(capability_client.account_id),
            lease_ttl_ms: None,
            requested_capability: requested_capability
                .map(str::trim)
                .filter(|value| !value.is_empty())
                .map(|value| value.to_string()),
        },
    )
    .await?;
    let binding_receipt: ioi_types::app::MailConnectorEnsureBindingReceipt = read_wallet_receipt(
        state,
        &wallet_mail_binding_receipt_key(&binding_request_id),
        "mail_connector_ensure_binding",
    )?;

    let mail_send_capability_bound = binding_receipt.capability_set.iter().any(|capability| {
        matches!(
            capability.trim().to_ascii_lowercase().as_str(),
            "mail.reply" | "mail.send" | "email:send"
        )
    });

    let auth_mode_label = match config.auth_mode {
        MailConnectorAuthMode::Password => "password",
        MailConnectorAuthMode::Oauth2 => "oauth2",
    };

    let probe_source = "harness.mail_runtime_wallet_bootstrap".to_string();
    let mut batch = EnvironmentEvidenceBatch::default();
    push_environment_receipt(
        &mut batch,
        "mail_wallet_control_root_configured",
        "true",
        Some(probe_source.clone()),
        Some(run_timestamp_ms),
        Some(true),
    );
    push_environment_receipt(
        &mut batch,
        "mail_wallet_capability_client_registered",
        "true",
        Some(probe_source.clone()),
        Some(run_timestamp_ms),
        Some(true),
    );
    push_environment_receipt(
        &mut batch,
        "mail_wallet_auth_source",
        bootstrap_source,
        Some(probe_source.clone()),
        Some(run_timestamp_ms),
        Some(true),
    );
    push_environment_receipt(
        &mut batch,
        "mail_service_meta_registered",
        "true",
        Some(probe_source.clone()),
        Some(run_timestamp_ms),
        Some(true),
    );
    push_environment_receipt(
        &mut batch,
        "mail_connector_bootstrap",
        "true",
        Some(probe_source.clone()),
        Some(run_timestamp_ms),
        Some(true),
    );
    push_environment_receipt(
        &mut batch,
        "mail_binding_ready",
        "true",
        Some(probe_source.clone()),
        Some(run_timestamp_ms),
        Some(true),
    );
    push_environment_receipt(
        &mut batch,
        "mail_binding_reused_existing",
        binding_receipt.reused_existing.to_string(),
        Some(probe_source.clone()),
        Some(run_timestamp_ms),
        Some(true),
    );
    push_environment_receipt(
        &mut batch,
        "mail_send_capability_bound",
        mail_send_capability_bound.to_string(),
        Some(probe_source.clone()),
        Some(run_timestamp_ms),
        Some(mail_send_capability_bound),
    );
    push_environment_receipt(
        &mut batch,
        "mail_binding_capabilities",
        binding_receipt.capability_set.join(","),
        Some(probe_source.clone()),
        Some(run_timestamp_ms),
        Some(true),
    );
    push_environment_receipt(
        &mut batch,
        "mail_requested_capability",
        requested_capability
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .unwrap_or("*"),
        Some(probe_source.clone()),
        Some(run_timestamp_ms),
        Some(true),
    );
    push_environment_receipt(
        &mut batch,
        "mail_auth_mode",
        auth_mode_label,
        Some(probe_source.clone()),
        Some(run_timestamp_ms),
        Some(true),
    );
    push_environment_receipt(
        &mut batch,
        "mail_mailbox",
        connector_receipt.mailbox,
        Some(probe_source.clone()),
        Some(run_timestamp_ms),
        Some(true),
    );
    push_environment_receipt(
        &mut batch,
        "mail_setup_timestamp_ms",
        run_timestamp_ms.to_string(),
        Some(probe_source),
        Some(run_timestamp_ms),
        Some(true),
    );
    Ok(batch)
}

