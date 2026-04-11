fn desktop_project_create_fixture_post_run_checks(
    fixture: &DesktopProjectCreateFixtureRuntime,
) -> EnvironmentEvidenceBatch {
    let timestamp_ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64;
    let probe_source = format!("{}.fs_probe", DESKTOP_PROJECT_CREATE_FIXTURE_PROBE_SOURCE);
    let desktop_entries = list_directory_entry_names(&fixture.desktop_dir);
    let expected_dir_name = fixture
        .expected_project_dir
        .file_name()
        .and_then(|value| value.to_str())
        .unwrap_or_default()
        .to_string();
    let created_satisfied = fixture.expected_project_dir.is_dir();
    let scope_satisfied = created_satisfied
        && desktop_entries.len() == 1
        && desktop_entries
            .first()
            .map(|entry| entry == &expected_dir_name)
            .unwrap_or(false);
    let mut batch = EnvironmentEvidenceBatch::default();
    push_environment_observation(
        &mut batch,
        "desktop_project_observed_path",
        fixture.expected_project_dir.to_string_lossy().to_string(),
    );
    push_environment_metadata(
        &mut batch,
        "desktop_project_created",
        Some(probe_source.clone()),
        Some(timestamp_ms),
        Some(created_satisfied),
    );
    push_environment_receipt(
        &mut batch,
        "desktop_project_desktop_entries",
        desktop_entries.join(","),
        Some(probe_source.clone()),
        Some(timestamp_ms),
        Some(scope_satisfied),
    );
    push_environment_metadata(
        &mut batch,
        "desktop_project_scope",
        Some(probe_source),
        Some(timestamp_ms),
        Some(scope_satisfied),
    );
    batch
}
