struct VlcInstallFixtureRuntime {
    _temp_dir: tempfile::TempDir,
    _env_path: ScopedEnvVar,
    _env_prefix: ScopedEnvVar,
    _env_mode: ScopedEnvVar,
    prefix: PathBuf,
    download_receipt_path: PathBuf,
    install_receipt_path: PathBuf,
    vlc_binary_path: PathBuf,
}

struct ProjectsZipFixtureRuntime {
    _temp_dir: tempfile::TempDir,
    _env_home: ScopedEnvVar,
    _env_userprofile: ScopedEnvVar,
    home_dir: PathBuf,
    projects_dir: PathBuf,
    desktop_dir: PathBuf,
    archive_path: PathBuf,
}

struct DesktopProjectCreateFixtureRuntime {
    _temp_dir: tempfile::TempDir,
    _env_home: ScopedEnvVar,
    _env_userprofile: ScopedEnvVar,
    home_dir: PathBuf,
    desktop_dir: PathBuf,
    expected_project_dir: PathBuf,
}

struct DownloadsLowercaseFixtureRuntime {
    _temp_dir: tempfile::TempDir,
    _env_home: ScopedEnvVar,
    _env_userprofile: ScopedEnvVar,
    home_dir: PathBuf,
    downloads_dir: PathBuf,
    target_dir: PathBuf,
}

struct DownloadsPngMoveFixtureRuntime {
    _temp_dir: tempfile::TempDir,
    _env_home: ScopedEnvVar,
    _env_userprofile: ScopedEnvVar,
    home_dir: PathBuf,
    downloads_dir: PathBuf,
    target_dir: PathBuf,
    images_dir: PathBuf,
}

struct DesktopDocumentsBackupFixtureRuntime {
    _temp_dir: tempfile::TempDir,
    _env_home: ScopedEnvVar,
    _env_userprofile: ScopedEnvVar,
    home_dir: PathBuf,
    desktop_dir: PathBuf,
    documents_dir: PathBuf,
    external_drive_path: PathBuf,
    backup_root: PathBuf,
    backup_desktop_path: PathBuf,
    backup_documents_path: PathBuf,
}

struct DocumentsSummaryFixtureRuntime {
    _temp_dir: tempfile::TempDir,
    _env_home: ScopedEnvVar,
    _env_userprofile: ScopedEnvVar,
    home_dir: PathBuf,
    documents_dir: PathBuf,
    fixture_dir: PathBuf,
    latest_document_path: PathBuf,
}

struct PdfLastWeekFixtureRuntime {
    _temp_dir: tempfile::TempDir,
    _env_home: ScopedEnvVar,
    _env_userprofile: ScopedEnvVar,
    home_dir: PathBuf,
    documents_dir: PathBuf,
    fixture_dir: PathBuf,
    expected_pdf_paths: Vec<PathBuf>,
    window_start_epoch_ms: u64,
}

struct SpotifyUninstallFixtureRuntime {
    _temp_dir: tempfile::TempDir,
    _env_home: ScopedEnvVar,
    _env_userprofile: ScopedEnvVar,
    _env_path: ScopedEnvVar,
    _env_fixture_root: ScopedEnvVar,
    _env_fixture_mode: ScopedEnvVar,
    _env_install_marker: ScopedEnvVar,
    _env_binary_path: ScopedEnvVar,
    _env_provider_receipt: ScopedEnvVar,
    home_dir: PathBuf,
    fixture_root: PathBuf,
    provider_receipt_path: PathBuf,
    install_marker_path: PathBuf,
    binary_path: PathBuf,
    config_paths: Vec<PathBuf>,
    sentinel_paths: Vec<PathBuf>,
}

struct TopMemoryAppsFixtureRuntime {
    _temp_dir: tempfile::TempDir,
    _env_path: ScopedEnvVar,
    _env_fixture_mode: ScopedEnvVar,
    _env_receipt_path: ScopedEnvVar,
    fixture_root: PathBuf,
    probe_script_path: PathBuf,
    receipt_path: PathBuf,
}

struct MediaTranscriptFixtureRuntime {
    _temp_dir: tempfile::TempDir,
    _env_media_tool_home: ScopedEnvVar,
    fixture_root: PathBuf,
    tool_home: PathBuf,
    receipt_path: PathBuf,
}

struct ShutdownScheduleFixtureRuntime {
    _temp_dir: tempfile::TempDir,
    _env_path: ScopedEnvVar,
    _env_fixture_mode: ScopedEnvVar,
    _env_receipt_path: ScopedEnvVar,
    _env_provider_receipt_path: ScopedEnvVar,
    _env_run_unique_num: ScopedEnvVar,
    fixture_root: PathBuf,
    probe_script_path: PathBuf,
    receipt_path: PathBuf,
    provider_receipt_path: PathBuf,
}

struct HackerNewsMonitorFixtureRuntime {
    _temp_dir: tempfile::TempDir,
    _env_automation_root: ScopedEnvVar,
    _env_fixture_mode: ScopedEnvVar,
    _env_run_unique_num: ScopedEnvVar,
    fixture_root: PathBuf,
    automation_root: PathBuf,
    manifest_path: PathBuf,
}

struct RestaurantsNearMeFixtureRuntime {
    _temp_dir: tempfile::TempDir,
    fixture_root: PathBuf,
    manifest_path: PathBuf,
    observed_locality: Option<String>,
}

struct LatestNistPqcBriefingFixtureRuntime {
    _temp_dir: tempfile::TempDir,
    fixture_root: PathBuf,
    manifest_path: PathBuf,
    observed_utc_date: String,
    observed_utc_timestamp_ms: u64,
}

struct CodingPathNormalizerFixtureRuntime {
    _temp_dir: tempfile::TempDir,
    _env_home: ScopedEnvVar,
    _env_userprofile: ScopedEnvVar,
    fixture_root: PathBuf,
    repo_root: PathBuf,
    source_file: PathBuf,
    test_file: PathBuf,
    expected_function_name: String,
    seeded_test_command: String,
    hidden_probe_command: String,
    baseline_test_contents: String,
}

#[derive(Debug, Clone)]
struct TopMemoryAppProbeRow {
    rank: usize,
    app: String,
    pid: u32,
    rss_kb: u64,
}

#[derive(Debug, Clone, Default)]
struct TopMemoryAppsProbeReceipt {
    provider: String,
    rows: Vec<TopMemoryAppProbeRow>,
}

#[derive(Debug, Clone, Default, Deserialize)]
struct MediaTranscriptFixtureReceipt {
    requested_url: String,
    canonical_url: String,
    title: Option<String>,
    duration_seconds: Option<u64>,
    requested_language: String,
    #[serde(default)]
    selected_modalities: Vec<String>,
    #[serde(default)]
    selected_provider_ids: Vec<String>,
    transcript_provider_id: Option<String>,
    transcript_provider_version: Option<String>,
    transcript_provider_binary_path: Option<String>,
    transcript_provider_model_id: Option<String>,
    transcript_provider_model_path: Option<String>,
    transcript_selected_audio_format_id: Option<String>,
    transcript_selected_audio_ext: Option<String>,
    transcript_selected_audio_acodec: Option<String>,
    transcript_language: Option<String>,
    transcript_source_kind: Option<String>,
    transcript_char_count: Option<u32>,
    transcript_segment_count: Option<u32>,
    transcript_hash: Option<String>,
    timeline_provider_id: Option<String>,
    timeline_provider_version: Option<String>,
    timeline_source_kind: Option<String>,
    timeline_cue_count: Option<u32>,
    timeline_char_count: Option<u32>,
    timeline_hash: Option<String>,
    visual_provider_id: Option<String>,
    visual_provider_version: Option<String>,
    visual_provider_binary_path: Option<String>,
    visual_ffprobe_path: Option<String>,
    visual_selected_video_format_id: Option<String>,
    visual_selected_video_ext: Option<String>,
    visual_selected_video_codec: Option<String>,
    visual_frame_count: Option<u32>,
    visual_char_count: Option<u32>,
    visual_hash: Option<String>,
    visual_summary_char_count: Option<u32>,
    retrieved_at_ms: u64,
}

#[derive(Debug, Clone, Default)]
struct ShutdownScheduleProbeReceipt {
    provider: String,
    target_local_time: String,
    target_local_date: String,
    now_epoch_sec: i64,
    target_epoch_sec: i64,
    delay_seconds: i64,
    rollover_to_next_day: bool,
    run_unique_num: String,
    scheduled: bool,
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(rename_all = "camelCase")]
struct HackerNewsMonitorRegistry {
    #[serde(default)]
    workflows: Vec<HackerNewsMonitorRegistryRecord>,
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(rename_all = "camelCase")]
struct HackerNewsMonitorRegistryRecord {
    #[serde(default)]
    workflow_id: String,
    #[serde(default)]
    status: String,
    #[serde(default)]
    spec_version: String,
    #[serde(default)]
    artifact_path: String,
    #[serde(default)]
    poll_interval_seconds: u64,
    #[serde(default)]
    source_label: String,
    #[serde(default)]
    keywords: Vec<String>,
    #[serde(default)]
    next_run_at_ms: Option<u64>,
    #[serde(default)]
    run_count: u64,
    #[serde(default)]
    failure_count: u64,
}

fn should_bootstrap_mailbox_runtime(case: &QueryCase) -> bool {
    case_requires_wallet_mail_runtime(case)
}

fn should_bootstrap_vlc_install_fixture(case_id: &str) -> bool {
    case_id.eq_ignore_ascii_case(VLC_INSTALL_CASE_ID)
        || case_id.eq_ignore_ascii_case(VLC_INSTALL_UNSEEDED_CASE_ID)
}

fn should_bootstrap_desktop_project_create_fixture(case_id: &str) -> bool {
    case_id.eq_ignore_ascii_case(DESKTOP_PROJECT_CREATE_CASE_ID)
}

fn should_bootstrap_projects_zip_fixture(case_id: &str) -> bool {
    case_id.eq_ignore_ascii_case(PROJECTS_ZIP_CASE_ID)
}

fn should_bootstrap_downloads_lowercase_fixture(case_id: &str) -> bool {
    case_id.eq_ignore_ascii_case(DOWNLOADS_LOWERCASE_CASE_ID)
}

fn should_bootstrap_downloads_png_move_fixture(case_id: &str) -> bool {
    case_id.eq_ignore_ascii_case(DOWNLOADS_PNG_MOVE_CASE_ID)
}

fn should_bootstrap_desktop_documents_backup_fixture(case_id: &str) -> bool {
    case_id.eq_ignore_ascii_case(DESKTOP_DOCUMENTS_BACKUP_CASE_ID)
}

fn should_bootstrap_documents_summary_fixture(case_id: &str) -> bool {
    case_id.eq_ignore_ascii_case(DOCUMENTS_SUMMARY_CASE_ID)
}

fn should_bootstrap_pdf_last_week_fixture(case_id: &str) -> bool {
    case_id.eq_ignore_ascii_case(PDF_LAST_WEEK_CASE_ID)
}

fn should_bootstrap_spotify_uninstall_fixture(case_id: &str) -> bool {
    case_id.eq_ignore_ascii_case(SPOTIFY_UNINSTALL_CASE_ID)
}

fn should_bootstrap_top_memory_apps_fixture(case_id: &str) -> bool {
    case_id.eq_ignore_ascii_case(TOP_MEMORY_APPS_CASE_ID)
}

fn should_bootstrap_media_transcript_fixture(case_id: &str) -> bool {
    case_id.eq_ignore_ascii_case(MEDIA_TRANSCRIPT_SUMMARY_CASE_ID)
}

fn should_bootstrap_shutdown_schedule_fixture(case_id: &str) -> bool {
    case_id.eq_ignore_ascii_case(SHUTDOWN_SCHEDULE_CASE_ID)
}

fn should_bootstrap_hacker_news_monitor_fixture(case_id: &str) -> bool {
    case_id.eq_ignore_ascii_case(HACKER_NEWS_MONITOR_CASE_ID)
}

fn should_bootstrap_restaurants_near_me_fixture(case_id: &str) -> bool {
    case_id.eq_ignore_ascii_case(RESTAURANTS_NEAR_ME_CASE_ID)
}

fn should_bootstrap_latest_nist_pqc_briefing_fixture(case_id: &str) -> bool {
    case_id.eq_ignore_ascii_case(LATEST_NIST_PQC_BRIEFING_CASE_ID)
        || case_id.eq_ignore_ascii_case(LATEST_NIST_PQC_BRIEFING_UNSEEDED_CASE_ID)
}

fn should_bootstrap_coding_path_normalizer_fixture(case_id: &str) -> bool {
    case_id.eq_ignore_ascii_case(CODING_PATH_NORMALIZER_CASE_ID)
}

fn bootstrap_vlc_install_fixture_runtime() -> Result<VlcInstallFixtureRuntime> {
    let temp_dir = tempdir()?;
    let fixture_bin = temp_dir.path().join("bin");
    let fixture_prefix = temp_dir.path().join("prefix");
    let fixture_prefix_bin = fixture_prefix.join("bin");
    let fixture_downloads = fixture_prefix.join("downloads");
    let fixture_receipts = fixture_prefix.join("install_receipts");
    std::fs::create_dir_all(&fixture_bin)?;
    std::fs::create_dir_all(&fixture_prefix_bin)?;
    std::fs::create_dir_all(&fixture_downloads)?;
    std::fs::create_dir_all(&fixture_receipts)?;

    let sudo_script = r#"#!/usr/bin/env bash
set -euo pipefail
if [ "$#" -eq 0 ]; then
  exit 0
fi
args=()
for arg in "$@"; do
  case "$arg" in
    -n|-S|-k|--) ;;
    *) args+=("$arg") ;;
  esac
done
if [ "${#args[@]}" -eq 0 ]; then
  exit 0
fi
exec "${args[@]}"
"#;
    write_executable_script(&fixture_bin.join("sudo"), sudo_script)?;

    let apt_script = r#"#!/usr/bin/env bash
set -euo pipefail
prefix="${IOI_VLC_FIXTURE_PREFIX:-}"
if [ -z "$prefix" ]; then
  echo "apt-get fixture: IOI_VLC_FIXTURE_PREFIX missing" >&2
  exit 2
fi
command_name="${1:-}"
if [ -z "$command_name" ]; then
  echo "apt-get fixture: missing command" >&2
  exit 2
fi
shift
case "$command_name" in
  update)
    echo "Hit:1 http://fixture.example stable InRelease"
    echo "Reading package lists... Done"
    exit 0
    ;;
  install)
    package=""
    for arg in "$@"; do
      case "$arg" in
        -*) ;;
        *) package="$arg" ;;
      esac
    done
    if [ -z "$package" ]; then
      echo "E: Unable to locate package" >&2
      exit 100
    fi
    if [ "$package" != "vlc" ]; then
      echo "E: Unable to locate package $package" >&2
      exit 100
    fi

    mkdir -p "$prefix/bin" "$prefix/downloads" "$prefix/install_receipts"
    cat > "$prefix/bin/vlc" <<'EOS'
#!/usr/bin/env bash
set -euo pipefail
if [ "${1:-}" = "--version" ]; then
  echo "VLC media player 3.0.20 Vetinari (fixture)"
else
  echo "VLC fixture executable"
fi
EOS
    chmod +x "$prefix/bin/vlc"
    printf 'fixture-vlc-package\n' > "$prefix/downloads/vlc-fixture.deb"
    printf 'vlc\n' > "$prefix/install_receipts/vlc.installed"
    echo "Get:1 http://fixture.example/vlc vlc 3.0.20-fixture amd64"
    echo "Fetched 42.0 MB in 1s (42.0 MB/s)"
    echo "Selecting previously unselected package vlc."
    echo "Setting up vlc (3.0.20-fixture) ..."
    exit 0
    ;;
  *)
    echo "apt-get fixture: unsupported command '$command_name'" >&2
    exit 2
    ;;
esac
"#;
    write_executable_script(&fixture_bin.join("apt-get"), apt_script)?;
    write_executable_script(
        &fixture_bin.join("apt"),
        "#!/usr/bin/env bash\nset -euo pipefail\nexec apt-get \"$@\"\n",
    )?;

    let inherited_path = std::env::var("PATH").unwrap_or_default();
    let fixture_path = format!(
        "{}:{}:{}",
        fixture_bin.to_string_lossy(),
        fixture_prefix_bin.to_string_lossy(),
        inherited_path
    );
    let env_path = ScopedEnvVar::set("PATH", fixture_path);
    let env_prefix = ScopedEnvVar::set(
        "IOI_VLC_FIXTURE_PREFIX",
        fixture_prefix.to_string_lossy().to_string(),
    );
    let env_mode = ScopedEnvVar::set("IOI_VLC_FIXTURE_MODE", VLC_INSTALL_FIXTURE_MODE);

    Ok(VlcInstallFixtureRuntime {
        _temp_dir: temp_dir,
        _env_path: env_path,
        _env_prefix: env_prefix,
        _env_mode: env_mode,
        prefix: fixture_prefix.clone(),
        download_receipt_path: fixture_downloads.join("vlc-fixture.deb"),
        install_receipt_path: fixture_receipts.join("vlc.installed"),
        vlc_binary_path: fixture_prefix_bin.join("vlc"),
    })
}

fn vlc_install_fixture_preflight_checks(
    fixture: &VlcInstallFixtureRuntime,
    run_timestamp_ms: u64,
) -> EnvironmentEvidenceBatch {
    let mut batch = EnvironmentEvidenceBatch::default();
    push_environment_observation(&mut batch, "vlc_fixture_mode", VLC_INSTALL_FIXTURE_MODE);
    push_environment_observation(
        &mut batch,
        "vlc_fixture_prefix",
        fixture.prefix.to_string_lossy().to_string(),
    );
    push_environment_metadata(
        &mut batch,
        "vlc_fixture",
        Some(VLC_INSTALL_FIXTURE_PROBE_SOURCE.to_string()),
        Some(run_timestamp_ms),
        Some(true),
    );
    batch
}

fn vlc_install_fixture_post_run_checks(
    fixture: &VlcInstallFixtureRuntime,
) -> EnvironmentEvidenceBatch {
    let timestamp_ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64;
    let download_exists = fixture.download_receipt_path.is_file();
    let install_exists = fixture.install_receipt_path.is_file();
    let binary_exists = fixture.vlc_binary_path.is_file();
    let install_receipt_value = std::fs::read_to_string(&fixture.install_receipt_path)
        .ok()
        .map(|value| value.trim().to_string())
        .unwrap_or_default();
    let install_receipt_value_satisfied = install_receipt_value == "vlc";
    let probe_source = format!("{}.fs_probe", VLC_INSTALL_FIXTURE_PROBE_SOURCE);
    let mut batch = EnvironmentEvidenceBatch::default();
    push_environment_observation(
        &mut batch,
        "vlc_download_receipt_path",
        fixture.download_receipt_path.to_string_lossy().to_string(),
    );
    push_environment_metadata(
        &mut batch,
        "vlc_download_receipt",
        Some(probe_source.clone()),
        Some(timestamp_ms),
        Some(download_exists),
    );
    push_environment_observation(
        &mut batch,
        "vlc_install_receipt_path",
        fixture.install_receipt_path.to_string_lossy().to_string(),
    );
    push_environment_metadata(
        &mut batch,
        "vlc_install_receipt",
        Some(probe_source.clone()),
        Some(timestamp_ms),
        Some(install_exists),
    );
    push_environment_receipt(
        &mut batch,
        "vlc_install_receipt_value",
        install_receipt_value,
        Some(probe_source.clone()),
        Some(timestamp_ms),
        Some(install_receipt_value_satisfied),
    );
    push_environment_observation(
        &mut batch,
        "vlc_binary_path",
        fixture.vlc_binary_path.to_string_lossy().to_string(),
    );
    push_environment_metadata(
        &mut batch,
        "vlc_binary",
        Some(probe_source),
        Some(timestamp_ms),
        Some(binary_exists),
    );
    batch
}

fn bootstrap_projects_zip_fixture_runtime() -> Result<ProjectsZipFixtureRuntime> {
    let temp_dir = tempdir()?;
    let home_dir = temp_dir.path().join("home");
    let projects_dir = home_dir.join("Projects");
    let desktop_dir = home_dir.join("Desktop");
    let archive_path = desktop_dir.join("Projects.zip");
    std::fs::create_dir_all(projects_dir.join("src"))?;
    std::fs::create_dir_all(projects_dir.join("docs"))?;
    std::fs::create_dir_all(&desktop_dir)?;

    std::fs::write(projects_dir.join("README.md"), "# fixture project\n")?;
    std::fs::write(
        projects_dir.join("src").join("main.rs"),
        "fn main() { println!(\"fixture\"); }\n",
    )?;
    std::fs::write(
        projects_dir.join("docs").join("spec.txt"),
        "fixture spec document\n",
    )?;

    let env_home = ScopedEnvVar::set("HOME", home_dir.to_string_lossy().to_string());
    let env_userprofile = ScopedEnvVar::set("USERPROFILE", home_dir.to_string_lossy().to_string());

    Ok(ProjectsZipFixtureRuntime {
        _temp_dir: temp_dir,
        _env_home: env_home,
        _env_userprofile: env_userprofile,
        home_dir,
        projects_dir,
        desktop_dir,
        archive_path,
    })
}

fn bootstrap_desktop_project_create_fixture_runtime(
    run_unique_num: &str,
) -> Result<DesktopProjectCreateFixtureRuntime> {
    let temp_dir = tempdir()?;
    let home_dir = temp_dir.path().join("home");
    let desktop_dir = home_dir.join("Desktop");
    let expected_project_dir = desktop_dir.join(format!("Project_{}", run_unique_num));
    std::fs::create_dir_all(&desktop_dir)?;

    let env_home = ScopedEnvVar::set("HOME", home_dir.to_string_lossy().to_string());
    let env_userprofile = ScopedEnvVar::set("USERPROFILE", home_dir.to_string_lossy().to_string());

    Ok(DesktopProjectCreateFixtureRuntime {
        _temp_dir: temp_dir,
        _env_home: env_home,
        _env_userprofile: env_userprofile,
        home_dir,
        desktop_dir,
        expected_project_dir,
    })
}

fn projects_zip_fixture_preflight_checks(
    fixture: &ProjectsZipFixtureRuntime,
    run_timestamp_ms: u64,
) -> EnvironmentEvidenceBatch {
    let mut batch = EnvironmentEvidenceBatch::default();
    push_environment_observation(
        &mut batch,
        "projects_zip_fixture_mode",
        PROJECTS_ZIP_FIXTURE_MODE,
    );
    push_environment_observation(
        &mut batch,
        "projects_zip_home_dir",
        fixture.home_dir.to_string_lossy().to_string(),
    );
    push_environment_observation(
        &mut batch,
        "projects_zip_projects_dir",
        fixture.projects_dir.to_string_lossy().to_string(),
    );
    push_environment_observation(
        &mut batch,
        "projects_zip_desktop_dir",
        fixture.desktop_dir.to_string_lossy().to_string(),
    );
    push_environment_observation(
        &mut batch,
        "projects_zip_archive_path",
        fixture.archive_path.to_string_lossy().to_string(),
    );
    push_environment_observation(
        &mut batch,
        "projects_zip_expected_entries",
        PROJECTS_ZIP_EXPECTED_ENTRIES.join(","),
    );
    push_environment_metadata(
        &mut batch,
        "projects_zip_fixture",
        Some(PROJECTS_ZIP_FIXTURE_PROBE_SOURCE.to_string()),
        Some(run_timestamp_ms),
        Some(true),
    );
    batch
}

fn projects_zip_fixture_post_run_checks(
    fixture: &ProjectsZipFixtureRuntime,
) -> EnvironmentEvidenceBatch {
    let timestamp_ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64;
    let probe_source = format!("{}.fs_probe", PROJECTS_ZIP_FIXTURE_PROBE_SOURCE);
    let archive_exists = fixture.archive_path.is_file();
    let archive_entries = if archive_exists {
        zip_archive_entries(&fixture.archive_path).unwrap_or_default()
    } else {
        Vec::new()
    };
    let expected_entries_satisfied = PROJECTS_ZIP_EXPECTED_ENTRIES
        .iter()
        .all(|entry| archive_entries.iter().any(|observed| observed == entry));
    let source_preserved = PROJECTS_ZIP_EXPECTED_ENTRIES
        .iter()
        .all(|entry| fixture.projects_dir.join(entry).is_file());
    let mut batch = EnvironmentEvidenceBatch::default();
    push_environment_observation(
        &mut batch,
        "projects_zip_archive_path",
        fixture.archive_path.to_string_lossy().to_string(),
    );
    push_environment_metadata(
        &mut batch,
        "projects_zip_archive",
        Some(probe_source.clone()),
        Some(timestamp_ms),
        Some(archive_exists),
    );
    push_environment_receipt(
        &mut batch,
        "projects_zip_entries",
        archive_entries.join(","),
        Some(probe_source.clone()),
        Some(timestamp_ms),
        Some(expected_entries_satisfied),
    );
    push_environment_metadata(
        &mut batch,
        "projects_zip_source_preserved",
        Some(probe_source),
        Some(timestamp_ms),
        Some(source_preserved),
    );
    batch
}

fn projects_zip_fixture_cleanup_checks(
    fixture: &ProjectsZipFixtureRuntime,
) -> EnvironmentEvidenceBatch {
    let timestamp_ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64;
    let probe_source = format!("{}.cleanup_probe", PROJECTS_ZIP_FIXTURE_PROBE_SOURCE);

    let _ = std::fs::remove_file(&fixture.archive_path);
    let _ = std::fs::remove_dir_all(&fixture.projects_dir);
    let cleanup_satisfied = !fixture.archive_path.exists() && !fixture.projects_dir.exists();
    let mut batch = EnvironmentEvidenceBatch::default();
    push_environment_metadata(
        &mut batch,
        "projects_zip_cleanup",
        Some(probe_source),
        Some(timestamp_ms),
        Some(cleanup_satisfied),
    );
    batch
}

fn bootstrap_downloads_lowercase_fixture_runtime(
    run_unique_num: &str,
) -> Result<DownloadsLowercaseFixtureRuntime> {
    let temp_dir = tempdir()?;
    let home_dir = temp_dir.path().join("home");
    let downloads_dir = home_dir.join("Downloads");
    std::fs::create_dir_all(&downloads_dir)?;
    let target_dir = downloads_dir.join(format!(
        "{}{}",
        DOWNLOADS_LOWERCASE_TARGET_PREFIX, run_unique_num
    ));
    std::fs::create_dir_all(&target_dir)?;
    for file_name in DOWNLOADS_LOWERCASE_EXPECTED_ORIGINAL_FILES {
        std::fs::write(
            target_dir.join(file_name),
            format!("fixture content for {}", file_name),
        )?;
    }

    let env_home = ScopedEnvVar::set("HOME", home_dir.to_string_lossy().to_string());
    let env_userprofile = ScopedEnvVar::set("USERPROFILE", home_dir.to_string_lossy().to_string());

    Ok(DownloadsLowercaseFixtureRuntime {
        _temp_dir: temp_dir,
        _env_home: env_home,
        _env_userprofile: env_userprofile,
        home_dir,
        downloads_dir,
        target_dir,
    })
}

fn downloads_lowercase_fixture_preflight_checks(
    fixture: &DownloadsLowercaseFixtureRuntime,
    run_timestamp_ms: u64,
) -> EnvironmentEvidenceBatch {
    let seeded_files = list_directory_entry_names(&fixture.target_dir);
    let seeded_files_satisfied = DOWNLOADS_LOWERCASE_EXPECTED_ORIGINAL_FILES
        .iter()
        .all(|expected| seeded_files.iter().any(|observed| observed == expected));
    let mut batch = EnvironmentEvidenceBatch::default();
    push_environment_observation(
        &mut batch,
        "downloads_lowercase_fixture_mode",
        DOWNLOADS_LOWERCASE_FIXTURE_MODE,
    );
    push_environment_observation(
        &mut batch,
        "downloads_lowercase_home_dir",
        fixture.home_dir.to_string_lossy().to_string(),
    );
    push_environment_observation(
        &mut batch,
        "downloads_lowercase_downloads_dir",
        fixture.downloads_dir.to_string_lossy().to_string(),
    );
    push_environment_observation(
        &mut batch,
        "downloads_lowercase_target_dir",
        fixture.target_dir.to_string_lossy().to_string(),
    );
    push_environment_receipt(
        &mut batch,
        "downloads_lowercase_seeded_files",
        seeded_files.join(","),
        None,
        None,
        Some(seeded_files_satisfied),
    );
    push_environment_metadata(
        &mut batch,
        "downloads_lowercase_fixture",
        Some(DOWNLOADS_LOWERCASE_FIXTURE_PROBE_SOURCE.to_string()),
        Some(run_timestamp_ms),
        Some(true),
    );
    batch
}

fn downloads_lowercase_fixture_post_run_checks(
    fixture: &DownloadsLowercaseFixtureRuntime,
) -> EnvironmentEvidenceBatch {
    let timestamp_ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64;
    let probe_source = format!("{}.fs_probe", DOWNLOADS_LOWERCASE_FIXTURE_PROBE_SOURCE);
    let mut target_dirs_sorted = std::fs::read_dir(&fixture.downloads_dir)
        .ok()
        .into_iter()
        .flatten()
        .filter_map(|entry| entry.ok())
        .filter(|entry| entry.file_type().map(|kind| kind.is_dir()).unwrap_or(false))
        .filter_map(|entry| entry.file_name().to_str().map(str::to_string))
        .filter(|name| name.starts_with(DOWNLOADS_LOWERCASE_TARGET_PREFIX))
        .collect::<Vec<_>>();
    target_dirs_sorted.sort();
    let target_dir_count = target_dirs_sorted.len();
    let target_dir_name = target_dirs_sorted.first().cloned().unwrap_or_default();
    let target_dir_path = if target_dir_name.is_empty() {
        String::new()
    } else {
        fixture
            .downloads_dir
            .join(&target_dir_name)
            .to_string_lossy()
            .to_string()
    };
    let target_dir_satisfied = target_dir_count == 1 && !target_dir_path.is_empty();
    let target_entries = if target_dir_satisfied {
        list_directory_entry_names(&fixture.downloads_dir.join(&target_dir_name))
    } else {
        Vec::new()
    };
    let entries_satisfied = DOWNLOADS_LOWERCASE_EXPECTED_FINAL_FILES
        .iter()
        .all(|expected| target_entries.iter().any(|observed| observed == expected));
    let uppercase_absent = DOWNLOADS_LOWERCASE_EXPECTED_ORIGINAL_FILES
        .iter()
        .all(|original| !target_entries.iter().any(|observed| observed == original));
    let scope_satisfied = std::fs::read_dir(&fixture.downloads_dir)
        .ok()
        .into_iter()
        .flatten()
        .filter_map(|entry| entry.ok())
        .all(|entry| {
            entry
                .file_name()
                .to_str()
                .map(|name| name.starts_with(DOWNLOADS_LOWERCASE_TARGET_PREFIX))
                .unwrap_or(false)
        });
    let mut batch = EnvironmentEvidenceBatch::default();
    push_environment_observation(
        &mut batch,
        "downloads_lowercase_target_dir_count",
        target_dir_count.to_string(),
    );
    push_environment_observation(
        &mut batch,
        "downloads_lowercase_target_dir_path",
        target_dir_path,
    );
    push_environment_metadata(
        &mut batch,
        "downloads_lowercase_target_dir",
        Some(probe_source.clone()),
        Some(timestamp_ms),
        Some(target_dir_satisfied),
    );
    push_environment_receipt(
        &mut batch,
        "downloads_lowercase_entries",
        target_entries.join(","),
        None,
        None,
        Some(entries_satisfied),
    );
    push_environment_metadata(
        &mut batch,
        "downloads_lowercase_uppercase_absent",
        Some(probe_source.clone()),
        Some(timestamp_ms),
        Some(uppercase_absent),
    );
    push_environment_metadata(
        &mut batch,
        "downloads_lowercase_scope",
        Some(probe_source),
        Some(timestamp_ms),
        Some(scope_satisfied),
    );
    batch
}

fn downloads_lowercase_fixture_cleanup_checks(
    fixture: &DownloadsLowercaseFixtureRuntime,
) -> EnvironmentEvidenceBatch {
    let timestamp_ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64;
    let probe_source = format!("{}.cleanup_probe", DOWNLOADS_LOWERCASE_FIXTURE_PROBE_SOURCE);
    let _ = std::fs::remove_dir_all(&fixture.downloads_dir);
    let _ = std::fs::create_dir_all(&fixture.downloads_dir);
    let remaining_entries = list_directory_entry_names(&fixture.downloads_dir);
    let cleanup_satisfied = remaining_entries.is_empty();
    let mut batch = EnvironmentEvidenceBatch::default();
    push_environment_metadata(
        &mut batch,
        "downloads_lowercase_cleanup",
        Some(probe_source),
        Some(timestamp_ms),
        Some(cleanup_satisfied),
    );
    batch
}

fn bootstrap_downloads_png_move_fixture_runtime(
    run_unique_num: &str,
) -> Result<DownloadsPngMoveFixtureRuntime> {
    let temp_dir = tempdir()?;
    let home_dir = temp_dir.path().join("home");
    let downloads_dir = home_dir.join("Downloads");
    std::fs::create_dir_all(&downloads_dir)?;
    let target_dir = downloads_dir.join(format!(
        "{}{}",
        DOWNLOADS_PNG_MOVE_TARGET_PREFIX, run_unique_num
    ));
    std::fs::create_dir_all(&target_dir)?;
    for file_name in DOWNLOADS_PNG_MOVE_EXPECTED_PNG_FILES {
        std::fs::write(
            target_dir.join(file_name),
            format!("fixture png payload for {}", file_name),
        )?;
    }
    for file_name in DOWNLOADS_PNG_MOVE_EXPECTED_NON_PNG_FILES {
        std::fs::write(
            target_dir.join(file_name),
            format!("fixture non-png payload for {}", file_name),
        )?;
    }
    let images_dir = target_dir.join(DOWNLOADS_PNG_MOVE_IMAGES_DIR_NAME);

    let env_home = ScopedEnvVar::set("HOME", home_dir.to_string_lossy().to_string());
    let env_userprofile = ScopedEnvVar::set("USERPROFILE", home_dir.to_string_lossy().to_string());

    Ok(DownloadsPngMoveFixtureRuntime {
        _temp_dir: temp_dir,
        _env_home: env_home,
        _env_userprofile: env_userprofile,
        home_dir,
        downloads_dir,
        target_dir,
        images_dir,
    })
}

fn downloads_png_move_fixture_preflight_checks(
    fixture: &DownloadsPngMoveFixtureRuntime,
    run_unique_num: &str,
    run_timestamp_ms: u64,
) -> EnvironmentEvidenceBatch {
    let seeded_entries = list_directory_entry_names(&fixture.target_dir);
    let seeded_png_satisfied = DOWNLOADS_PNG_MOVE_EXPECTED_PNG_FILES
        .iter()
        .all(|expected| seeded_entries.iter().any(|observed| observed == expected));
    let seeded_non_png_satisfied = DOWNLOADS_PNG_MOVE_EXPECTED_NON_PNG_FILES
        .iter()
        .all(|expected| seeded_entries.iter().any(|observed| observed == expected));
    let images_dir_absent_satisfied = !fixture.images_dir.exists();
    let run_unique_satisfied = fixture
        .target_dir
        .file_name()
        .and_then(|name| name.to_str())
        .map(|name| name.ends_with(run_unique_num))
        .unwrap_or(false);
    let fixture_satisfied = seeded_png_satisfied
        && seeded_non_png_satisfied
        && images_dir_absent_satisfied
        && run_unique_satisfied;
    let mut batch = EnvironmentEvidenceBatch::default();
    push_environment_observation(
        &mut batch,
        "downloads_png_move_fixture_mode",
        DOWNLOADS_PNG_MOVE_FIXTURE_MODE,
    );
    push_environment_observation(
        &mut batch,
        "downloads_png_move_home_dir",
        fixture.home_dir.to_string_lossy().to_string(),
    );
    push_environment_observation(
        &mut batch,
        "downloads_png_move_downloads_dir",
        fixture.downloads_dir.to_string_lossy().to_string(),
    );
    push_environment_observation(
        &mut batch,
        "downloads_png_move_target_dir",
        fixture.target_dir.to_string_lossy().to_string(),
    );
    push_environment_observation(
        &mut batch,
        "downloads_png_move_images_dir",
        fixture.images_dir.to_string_lossy().to_string(),
    );
    push_environment_observation(
        &mut batch,
        "downloads_png_move_run_unique_num",
        run_unique_num.to_string(),
    );
    push_environment_observation(
        &mut batch,
        "downloads_png_move_seeded_entries",
        seeded_entries.join(","),
    );
    push_environment_observation(
        &mut batch,
        "downloads_png_move_seeded_png_files",
        DOWNLOADS_PNG_MOVE_EXPECTED_PNG_FILES.join(","),
    );
    push_environment_observation(
        &mut batch,
        "downloads_png_move_seeded_non_png_files",
        DOWNLOADS_PNG_MOVE_EXPECTED_NON_PNG_FILES.join(","),
    );
    push_environment_metadata(
        &mut batch,
        "downloads_png_move_seeded_png",
        Some(DOWNLOADS_PNG_MOVE_FIXTURE_PROBE_SOURCE.to_string()),
        Some(run_timestamp_ms),
        Some(seeded_png_satisfied),
    );
    push_environment_metadata(
        &mut batch,
        "downloads_png_move_seeded_non_png",
        Some(DOWNLOADS_PNG_MOVE_FIXTURE_PROBE_SOURCE.to_string()),
        Some(run_timestamp_ms),
        Some(seeded_non_png_satisfied),
    );
    push_environment_metadata(
        &mut batch,
        "downloads_png_move_images_dir_absent",
        Some(DOWNLOADS_PNG_MOVE_FIXTURE_PROBE_SOURCE.to_string()),
        Some(run_timestamp_ms),
        Some(images_dir_absent_satisfied),
    );
    push_environment_metadata(
        &mut batch,
        "downloads_png_move_run_unique",
        Some(DOWNLOADS_PNG_MOVE_FIXTURE_PROBE_SOURCE.to_string()),
        Some(run_timestamp_ms),
        Some(run_unique_satisfied),
    );
    push_environment_metadata(
        &mut batch,
        "downloads_png_move_fixture",
        Some(DOWNLOADS_PNG_MOVE_FIXTURE_PROBE_SOURCE.to_string()),
        Some(run_timestamp_ms),
        Some(fixture_satisfied),
    );
    batch
}

fn downloads_png_move_fixture_post_run_checks(
    fixture: &DownloadsPngMoveFixtureRuntime,
) -> EnvironmentEvidenceBatch {
    let timestamp_ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64;
    let probe_source = format!("{}.fs_probe", DOWNLOADS_PNG_MOVE_FIXTURE_PROBE_SOURCE);

    let expected_target_dir_name = fixture
        .target_dir
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or_default()
        .to_string();
    let mut target_dirs_sorted = std::fs::read_dir(&fixture.downloads_dir)
        .ok()
        .into_iter()
        .flatten()
        .filter_map(|entry| entry.ok())
        .filter(|entry| entry.file_type().map(|kind| kind.is_dir()).unwrap_or(false))
        .filter_map(|entry| entry.file_name().to_str().map(str::to_string))
        .filter(|name| name.starts_with(DOWNLOADS_PNG_MOVE_TARGET_PREFIX))
        .collect::<Vec<_>>();
    target_dirs_sorted.sort();
    let target_dir_count = target_dirs_sorted.len();
    let target_dir_name = target_dirs_sorted.first().cloned().unwrap_or_default();
    let target_dir_path = if target_dir_name.is_empty() {
        String::new()
    } else {
        fixture
            .downloads_dir
            .join(&target_dir_name)
            .to_string_lossy()
            .to_string()
    };
    let target_dir_satisfied = target_dir_count == 1
        && !target_dir_path.is_empty()
        && target_dir_name == expected_target_dir_name;

    let source_dir_path = fixture.downloads_dir.join(&target_dir_name);
    let source_entries = if target_dir_satisfied {
        list_directory_entry_names(&source_dir_path)
    } else {
        Vec::new()
    };
    let images_dir_path = if target_dir_satisfied {
        source_dir_path.join(DOWNLOADS_PNG_MOVE_IMAGES_DIR_NAME)
    } else {
        fixture.images_dir.clone()
    };
    let images_dir_exists = images_dir_path.is_dir();
    let images_entries = if images_dir_exists {
        list_directory_entry_names(&images_dir_path)
    } else {
        Vec::new()
    };
    let images_entries_satisfied = DOWNLOADS_PNG_MOVE_EXPECTED_PNG_FILES
        .iter()
        .all(|expected| images_entries.iter().any(|observed| observed == expected))
        && images_entries.len() == DOWNLOADS_PNG_MOVE_EXPECTED_PNG_FILES.len();
    let source_non_png_preserved = DOWNLOADS_PNG_MOVE_EXPECTED_NON_PNG_FILES
        .iter()
        .all(|expected| source_entries.iter().any(|observed| observed == expected));
    let source_png_absent = DOWNLOADS_PNG_MOVE_EXPECTED_PNG_FILES
        .iter()
        .all(|png_name| !source_entries.iter().any(|observed| observed == png_name));
    let source_entries_scope_satisfied = source_entries.iter().all(|entry| {
        entry == DOWNLOADS_PNG_MOVE_IMAGES_DIR_NAME
            || DOWNLOADS_PNG_MOVE_EXPECTED_NON_PNG_FILES
                .iter()
                .any(|expected| entry == expected)
    }) && source_entries.len()
        == DOWNLOADS_PNG_MOVE_EXPECTED_NON_PNG_FILES.len() + 1;
    let downloads_scope_satisfied = std::fs::read_dir(&fixture.downloads_dir)
        .ok()
        .into_iter()
        .flatten()
        .filter_map(|entry| entry.ok())
        .all(|entry| {
            entry
                .file_name()
                .to_str()
                .map(|name| name.starts_with(DOWNLOADS_PNG_MOVE_TARGET_PREFIX))
                .unwrap_or(false)
        });
    let scope_satisfied =
        target_dir_satisfied && source_entries_scope_satisfied && downloads_scope_satisfied;
    let mut batch = EnvironmentEvidenceBatch::default();
    push_environment_observation(
        &mut batch,
        "downloads_png_move_target_dir_count",
        target_dir_count.to_string(),
    );
    push_environment_observation(
        &mut batch,
        "downloads_png_move_target_dir_path",
        target_dir_path,
    );
    push_environment_metadata(
        &mut batch,
        "downloads_png_move_target_dir",
        Some(probe_source.clone()),
        Some(timestamp_ms),
        Some(target_dir_satisfied),
    );
    push_environment_observation(
        &mut batch,
        "downloads_png_move_images_dir_path",
        images_dir_path.to_string_lossy().to_string(),
    );
    push_environment_metadata(
        &mut batch,
        "downloads_png_move_images_dir",
        Some(probe_source.clone()),
        Some(timestamp_ms),
        Some(images_dir_exists),
    );
    push_environment_receipt(
        &mut batch,
        "downloads_png_move_images_entries",
        images_entries.join(","),
        None,
        None,
        Some(images_entries_satisfied),
    );
    push_environment_observation(
        &mut batch,
        "downloads_png_move_source_entries",
        source_entries.join(","),
    );
    push_environment_metadata(
        &mut batch,
        "downloads_png_move_source_non_png_preserved",
        Some(probe_source.clone()),
        Some(timestamp_ms),
        Some(source_non_png_preserved),
    );
    push_environment_metadata(
        &mut batch,
        "downloads_png_move_source_png_absent",
        Some(probe_source.clone()),
        Some(timestamp_ms),
        Some(source_png_absent),
    );
    push_environment_metadata(
        &mut batch,
        "downloads_png_move_scope",
        Some(probe_source),
        Some(timestamp_ms),
        Some(scope_satisfied),
    );
    batch
}

fn downloads_png_move_fixture_cleanup_checks(
    fixture: &DownloadsPngMoveFixtureRuntime,
) -> EnvironmentEvidenceBatch {
    let timestamp_ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64;
    let probe_source = format!("{}.cleanup_probe", DOWNLOADS_PNG_MOVE_FIXTURE_PROBE_SOURCE);
    let _ = std::fs::remove_dir_all(&fixture.downloads_dir);
    let _ = std::fs::create_dir_all(&fixture.downloads_dir);
    let remaining_entries = list_directory_entry_names(&fixture.downloads_dir);
    let cleanup_satisfied = remaining_entries.is_empty();
    let mut batch = EnvironmentEvidenceBatch::default();
    push_environment_metadata(
        &mut batch,
        "downloads_png_move_cleanup",
        Some(probe_source),
        Some(timestamp_ms),
        Some(cleanup_satisfied),
    );
    batch
}

fn bootstrap_desktop_documents_backup_fixture_runtime(
    run_unique_num: &str,
) -> Result<DesktopDocumentsBackupFixtureRuntime> {
    let temp_dir = tempdir()?;
    let home_dir = temp_dir.path().join("home");
    let desktop_dir = home_dir.join("Desktop");
    let documents_dir = home_dir.join("Documents");
    let external_drive_path = temp_dir.path().join("mnt").join("external_drive");
    let backup_root = external_drive_path.join(format!(
        "{}{}",
        DESKTOP_DOCUMENTS_BACKUP_TARGET_PREFIX, run_unique_num
    ));
    let backup_desktop_path = backup_root.join("Desktop");
    let backup_documents_path = backup_root.join("Documents");

    std::fs::create_dir_all(desktop_dir.join("Projects"))?;
    std::fs::create_dir_all(desktop_dir.join("Screenshots"))?;
    std::fs::create_dir_all(documents_dir.join("finance"))?;
    std::fs::create_dir_all(documents_dir.join("reference").join("ops"))?;
    std::fs::create_dir_all(&external_drive_path)?;

    std::fs::write(
        desktop_dir.join("todo.txt"),
        "Desktop todo list\n- ship backup flow\n",
    )?;
    std::fs::write(
        desktop_dir.join("Projects").join("roadmap.md"),
        "Q2 roadmap checkpoint\n",
    )?;
    std::fs::write(
        desktop_dir.join("Screenshots").join("sprint.png"),
        "fixture screenshot bytes\n",
    )?;

    std::fs::write(
        documents_dir.join("report.md"),
        "Weekly report\nStatus: green\n",
    )?;
    std::fs::write(
        documents_dir.join("finance").join("q1-budget.csv"),
        "category,amount\ninfra,1200\n",
    )?;
    std::fs::write(
        documents_dir
            .join("reference")
            .join("ops")
            .join("runbook.txt"),
        "Incident runbook v1\n",
    )?;

    let env_home = ScopedEnvVar::set("HOME", home_dir.to_string_lossy().to_string());
    let env_userprofile = ScopedEnvVar::set("USERPROFILE", home_dir.to_string_lossy().to_string());

    Ok(DesktopDocumentsBackupFixtureRuntime {
        _temp_dir: temp_dir,
        _env_home: env_home,
        _env_userprofile: env_userprofile,
        home_dir,
        desktop_dir,
        documents_dir,
        external_drive_path,
        backup_root,
        backup_desktop_path,
        backup_documents_path,
    })
}

fn desktop_documents_backup_fixture_preflight_checks(
    fixture: &DesktopDocumentsBackupFixtureRuntime,
    run_unique_num: &str,
    run_timestamp_ms: u64,
) -> EnvironmentEvidenceBatch {
    let seeded_desktop_files = list_relative_file_paths(&fixture.desktop_dir);
    let seeded_documents_files = list_relative_file_paths(&fixture.documents_dir);
    let seeded_desktop_satisfied =
        DESKTOP_DOCUMENTS_BACKUP_EXPECTED_DESKTOP_FILES
            .iter()
            .all(|expected| {
                seeded_desktop_files
                    .iter()
                    .any(|observed| observed == expected)
            })
            && seeded_desktop_files.len() == DESKTOP_DOCUMENTS_BACKUP_EXPECTED_DESKTOP_FILES.len();
    let seeded_documents_satisfied = DESKTOP_DOCUMENTS_BACKUP_EXPECTED_DOCUMENTS_FILES
        .iter()
        .all(|expected| {
            seeded_documents_files
                .iter()
                .any(|observed| observed == expected)
        })
        && seeded_documents_files.len() == DESKTOP_DOCUMENTS_BACKUP_EXPECTED_DOCUMENTS_FILES.len();
    let destination_absent_satisfied = !fixture.backup_root.exists();
    let run_unique_satisfied = fixture
        .backup_root
        .file_name()
        .and_then(|name| name.to_str())
        .map(|name| name.ends_with(run_unique_num))
        .unwrap_or(false);
    let fixture_satisfied = fixture.external_drive_path.is_dir()
        && seeded_desktop_satisfied
        && seeded_documents_satisfied
        && destination_absent_satisfied
        && run_unique_satisfied;
    let mut batch = EnvironmentEvidenceBatch::default();
    push_environment_observation(
        &mut batch,
        "desktop_documents_backup_fixture_mode",
        DESKTOP_DOCUMENTS_BACKUP_FIXTURE_MODE,
    );
    push_environment_observation(
        &mut batch,
        "desktop_documents_backup_home_dir",
        fixture.home_dir.to_string_lossy().to_string(),
    );
    push_environment_observation(
        &mut batch,
        "desktop_documents_backup_desktop_dir",
        fixture.desktop_dir.to_string_lossy().to_string(),
    );
    push_environment_observation(
        &mut batch,
        "desktop_documents_backup_documents_dir",
        fixture.documents_dir.to_string_lossy().to_string(),
    );
    push_environment_observation(
        &mut batch,
        "desktop_documents_backup_external_drive_path",
        fixture.external_drive_path.to_string_lossy().to_string(),
    );
    push_environment_observation(
        &mut batch,
        "desktop_documents_backup_destination_root",
        fixture.backup_root.to_string_lossy().to_string(),
    );
    push_environment_observation(
        &mut batch,
        "desktop_documents_backup_run_unique_num",
        run_unique_num.to_string(),
    );
    push_environment_receipt(
        &mut batch,
        "desktop_documents_backup_seeded_desktop_files",
        seeded_desktop_files.join(","),
        None,
        None,
        Some(seeded_desktop_satisfied),
    );
    push_environment_receipt(
        &mut batch,
        "desktop_documents_backup_seeded_documents_files",
        seeded_documents_files.join(","),
        None,
        None,
        Some(seeded_documents_satisfied),
    );
    push_environment_metadata(
        &mut batch,
        "desktop_documents_backup_destination_absent",
        Some(DESKTOP_DOCUMENTS_BACKUP_FIXTURE_PROBE_SOURCE.to_string()),
        Some(run_timestamp_ms),
        Some(destination_absent_satisfied),
    );
    push_environment_metadata(
        &mut batch,
        "desktop_documents_backup_run_unique",
        Some(DESKTOP_DOCUMENTS_BACKUP_FIXTURE_PROBE_SOURCE.to_string()),
        Some(run_timestamp_ms),
        Some(run_unique_satisfied),
    );
    push_environment_metadata(
        &mut batch,
        "desktop_documents_backup_fixture",
        Some(DESKTOP_DOCUMENTS_BACKUP_FIXTURE_PROBE_SOURCE.to_string()),
        Some(run_timestamp_ms),
        Some(fixture_satisfied),
    );
    batch
}

fn desktop_documents_backup_fixture_post_run_checks(
    fixture: &DesktopDocumentsBackupFixtureRuntime,
) -> EnvironmentEvidenceBatch {
    let timestamp_ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64;
    let probe_source = format!("{}.fs_probe", DESKTOP_DOCUMENTS_BACKUP_FIXTURE_PROBE_SOURCE);

    let backup_root_satisfied = fixture.backup_root.is_dir();
    let backup_desktop_satisfied = fixture.backup_desktop_path.is_dir();
    let backup_documents_satisfied = fixture.backup_documents_path.is_dir();

    let source_desktop_files = list_relative_file_paths(&fixture.desktop_dir);
    let source_documents_files = list_relative_file_paths(&fixture.documents_dir);
    let backup_desktop_files = list_relative_file_paths(&fixture.backup_desktop_path);
    let backup_documents_files = list_relative_file_paths(&fixture.backup_documents_path);

    let source_desktop_satisfied =
        DESKTOP_DOCUMENTS_BACKUP_EXPECTED_DESKTOP_FILES
            .iter()
            .all(|expected| {
                source_desktop_files
                    .iter()
                    .any(|observed| observed == expected)
            })
            && source_desktop_files.len() == DESKTOP_DOCUMENTS_BACKUP_EXPECTED_DESKTOP_FILES.len();
    let source_documents_satisfied = DESKTOP_DOCUMENTS_BACKUP_EXPECTED_DOCUMENTS_FILES
        .iter()
        .all(|expected| {
            source_documents_files
                .iter()
                .any(|observed| observed == expected)
        })
        && source_documents_files.len() == DESKTOP_DOCUMENTS_BACKUP_EXPECTED_DOCUMENTS_FILES.len();
    let backup_desktop_files_satisfied = DESKTOP_DOCUMENTS_BACKUP_EXPECTED_DESKTOP_FILES
        .iter()
        .all(|expected| {
            backup_desktop_files
                .iter()
                .any(|observed| observed == expected)
        })
        && backup_desktop_files.len() == DESKTOP_DOCUMENTS_BACKUP_EXPECTED_DESKTOP_FILES.len();
    let backup_documents_files_satisfied = DESKTOP_DOCUMENTS_BACKUP_EXPECTED_DOCUMENTS_FILES
        .iter()
        .all(|expected| {
            backup_documents_files
                .iter()
                .any(|observed| observed == expected)
        })
        && backup_documents_files.len() == DESKTOP_DOCUMENTS_BACKUP_EXPECTED_DOCUMENTS_FILES.len();
    let source_preserved_satisfied = source_desktop_satisfied && source_documents_satisfied;
    let content_match_satisfied = backup_desktop_files_satisfied
        && backup_documents_files_satisfied
        && file_sets_content_match(
            &fixture.desktop_dir,
            &fixture.backup_desktop_path,
            &backup_desktop_files,
        )
        && file_sets_content_match(
            &fixture.documents_dir,
            &fixture.backup_documents_path,
            &backup_documents_files,
        );

    let external_drive_entries = list_directory_entry_names(&fixture.external_drive_path);
    let expected_backup_dir_name = fixture
        .backup_root
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or_default()
        .to_string();
    let scope_satisfied = !expected_backup_dir_name.is_empty()
        && external_drive_entries.len() == 1
        && external_drive_entries
            .iter()
            .any(|entry| entry == &expected_backup_dir_name);
    let mut batch = EnvironmentEvidenceBatch::default();
    push_environment_observation(
        &mut batch,
        "desktop_documents_backup_backup_root_path",
        fixture.backup_root.to_string_lossy().to_string(),
    );
    push_environment_metadata(
        &mut batch,
        "desktop_documents_backup_backup",
        Some(probe_source.clone()),
        Some(timestamp_ms),
        Some(true),
    );
    push_environment_metadata(
        &mut batch,
        "desktop_documents_backup_backup_root",
        Some(probe_source.clone()),
        Some(timestamp_ms),
        Some(backup_root_satisfied),
    );
    push_environment_observation(
        &mut batch,
        "desktop_documents_backup_backup_desktop_path",
        fixture.backup_desktop_path.to_string_lossy().to_string(),
    );
    push_environment_metadata(
        &mut batch,
        "desktop_documents_backup_backup_desktop",
        Some(probe_source.clone()),
        Some(timestamp_ms),
        Some(backup_desktop_satisfied),
    );
    push_environment_receipt(
        &mut batch,
        "desktop_documents_backup_backup_desktop_files",
        backup_desktop_files.join(","),
        None,
        None,
        Some(backup_desktop_files_satisfied),
    );
    push_environment_observation(
        &mut batch,
        "desktop_documents_backup_backup_documents_path",
        fixture.backup_documents_path.to_string_lossy().to_string(),
    );
    push_environment_metadata(
        &mut batch,
        "desktop_documents_backup_backup_documents",
        Some(probe_source.clone()),
        Some(timestamp_ms),
        Some(backup_documents_satisfied),
    );
    push_environment_receipt(
        &mut batch,
        "desktop_documents_backup_backup_documents_files",
        backup_documents_files.join(","),
        None,
        None,
        Some(backup_documents_files_satisfied),
    );
    push_environment_observation(
        &mut batch,
        "desktop_documents_backup_source_desktop_files",
        source_desktop_files.join(","),
    );
    push_environment_observation(
        &mut batch,
        "desktop_documents_backup_source_documents_files",
        source_documents_files.join(","),
    );
    push_environment_metadata(
        &mut batch,
        "desktop_documents_backup_source_preserved",
        Some(probe_source.clone()),
        Some(timestamp_ms),
        Some(source_preserved_satisfied),
    );
    push_environment_metadata(
        &mut batch,
        "desktop_documents_backup_content_match",
        Some(probe_source.clone()),
        Some(timestamp_ms),
        Some(content_match_satisfied),
    );
    push_environment_metadata(
        &mut batch,
        "desktop_documents_backup_scope",
        Some(probe_source),
        Some(timestamp_ms),
        Some(scope_satisfied),
    );
    batch
}

fn desktop_documents_backup_fixture_cleanup_checks(
    fixture: &DesktopDocumentsBackupFixtureRuntime,
) -> EnvironmentEvidenceBatch {
    let timestamp_ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64;
    let probe_source = format!(
        "{}.cleanup_probe",
        DESKTOP_DOCUMENTS_BACKUP_FIXTURE_PROBE_SOURCE
    );

    let _ = std::fs::remove_dir_all(&fixture.backup_root);
    let _ = std::fs::remove_dir_all(&fixture.external_drive_path);
    let _ = std::fs::remove_dir_all(&fixture.desktop_dir);
    let _ = std::fs::remove_dir_all(&fixture.documents_dir);
    let cleanup_satisfied = !fixture.backup_root.exists()
        && !fixture.external_drive_path.exists()
        && !fixture.desktop_dir.exists()
        && !fixture.documents_dir.exists();
    let mut batch = EnvironmentEvidenceBatch::default();
    push_environment_metadata(
        &mut batch,
        "desktop_documents_backup_cleanup",
        Some(probe_source),
        Some(timestamp_ms),
        Some(cleanup_satisfied),
    );
    batch
}

fn bootstrap_documents_summary_fixture_runtime(
    run_unique_num: &str,
) -> Result<DocumentsSummaryFixtureRuntime> {
    let temp_dir = tempdir()?;
    let home_dir = temp_dir.path().join("home");
    let documents_dir = home_dir.join("Documents");
    let fixture_dir = documents_dir.join(format!(
        "{}{}",
        DOCUMENTS_SUMMARY_FIXTURE_DIR_PREFIX, run_unique_num
    ));
    std::fs::create_dir_all(&fixture_dir)?;

    let brief_path = fixture_dir.join(DOCUMENTS_SUMMARY_EXPECTED_FILE_NAMES[0]);
    let notes_path = fixture_dir.join(DOCUMENTS_SUMMARY_EXPECTED_FILE_NAMES[1]);
    let latest_path = fixture_dir.join(DOCUMENTS_SUMMARY_EXPECTED_FILE_NAMES[2]);

    std::fs::write(
        &brief_path,
        concat!(
            "Project brief\n",
            "Owner: Platform Ops\n",
            "Status: Planning\n",
        ),
    )?;
    std::thread::sleep(Duration::from_millis(1_100));
    std::fs::write(
        &notes_path,
        concat!(
            "Meeting notes\n",
            "Topic: ingestion backlog\n",
            "Action: investigate worker token expiry policy\n",
        ),
    )?;
    std::thread::sleep(Duration::from_millis(1_100));
    std::fs::write(
        &latest_path,
        concat!(
            "Incident update\n",
            "Root cause: expired API token on ingestion worker.\n",
            "Mitigation: rotated the token and restarted the worker.\n",
            "Next step: add a 30-day token expiry alert.\n",
        ),
    )?;

    let env_home = ScopedEnvVar::set("HOME", home_dir.to_string_lossy().to_string());
    let env_userprofile = ScopedEnvVar::set("USERPROFILE", home_dir.to_string_lossy().to_string());

    Ok(DocumentsSummaryFixtureRuntime {
        _temp_dir: temp_dir,
        _env_home: env_home,
        _env_userprofile: env_userprofile,
        home_dir,
        documents_dir,
        fixture_dir,
        latest_document_path: latest_path,
    })
}

fn documents_summary_fixture_preflight_checks(
    fixture: &DocumentsSummaryFixtureRuntime,
    run_unique_num: &str,
    run_timestamp_ms: u64,
) -> EnvironmentEvidenceBatch {
    let seeded_files = list_directory_entry_names(&fixture.fixture_dir);
    let seeded_files_satisfied = DOCUMENTS_SUMMARY_EXPECTED_FILE_NAMES
        .iter()
        .all(|expected| seeded_files.iter().any(|observed| observed == expected));
    let run_unique_satisfied = fixture
        .fixture_dir
        .file_name()
        .and_then(|name| name.to_str())
        .map(|name| name.ends_with(run_unique_num))
        .unwrap_or(false);
    let fixture_satisfied = seeded_files_satisfied && run_unique_satisfied;
    let mut batch = EnvironmentEvidenceBatch::default();
    push_environment_observation(
        &mut batch,
        "documents_summary_fixture_mode",
        DOCUMENTS_SUMMARY_FIXTURE_MODE,
    );
    push_environment_observation(
        &mut batch,
        "documents_summary_home_dir",
        fixture.home_dir.to_string_lossy().to_string(),
    );
    push_environment_observation(
        &mut batch,
        "documents_summary_documents_dir",
        fixture.documents_dir.to_string_lossy().to_string(),
    );
    push_environment_observation(
        &mut batch,
        "documents_summary_fixture_dir",
        fixture.fixture_dir.to_string_lossy().to_string(),
    );
    push_environment_observation(
        &mut batch,
        "documents_summary_run_unique_num",
        run_unique_num.to_string(),
    );
    push_environment_observation(
        &mut batch,
        "documents_summary_expected_latest_path",
        fixture.latest_document_path.to_string_lossy().to_string(),
    );
    push_environment_receipt(
        &mut batch,
        "documents_summary_seeded_files",
        seeded_files.join(","),
        None,
        None,
        Some(seeded_files_satisfied),
    );
    push_environment_metadata(
        &mut batch,
        "documents_summary_run_unique",
        Some(DOCUMENTS_SUMMARY_FIXTURE_PROBE_SOURCE.to_string()),
        Some(run_timestamp_ms),
        Some(run_unique_satisfied),
    );
    push_environment_metadata(
        &mut batch,
        "documents_summary_fixture",
        Some(DOCUMENTS_SUMMARY_FIXTURE_PROBE_SOURCE.to_string()),
        Some(run_timestamp_ms),
        Some(fixture_satisfied),
    );
    batch
}

fn documents_summary_fixture_post_run_checks(
    fixture: &DocumentsSummaryFixtureRuntime,
) -> EnvironmentEvidenceBatch {
    let timestamp_ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64;
    let probe_source = format!("{}.fs_probe", DOCUMENTS_SUMMARY_FIXTURE_PROBE_SOURCE);
    let observed_files = list_directory_entry_names(&fixture.fixture_dir);
    let observed_files_satisfied = DOCUMENTS_SUMMARY_EXPECTED_FILE_NAMES
        .iter()
        .all(|expected| observed_files.iter().any(|observed| observed == expected));
    let latest_observed = latest_file_path_and_mtime(&fixture.fixture_dir);
    let latest_observed_path = latest_observed
        .as_ref()
        .map(|(path, _)| path.to_string_lossy().to_string())
        .unwrap_or_default();
    let latest_observed_mtime_ms = latest_observed
        .as_ref()
        .map(|(_, mtime_ms)| *mtime_ms)
        .unwrap_or(0);
    let latest_expected_path = fixture.latest_document_path.to_string_lossy().to_string();
    let latest_path_satisfied = latest_observed
        .as_ref()
        .map(|(path, _)| path == &fixture.latest_document_path)
        .unwrap_or(false);
    let latest_content = std::fs::read_to_string(&fixture.latest_document_path).unwrap_or_default();
    let latest_content_lower = latest_content.to_ascii_lowercase();
    let latest_content_satisfied = DOCUMENTS_SUMMARY_EXPECTED_LATEST_MARKERS
        .iter()
        .all(|marker| latest_content_lower.contains(marker));
    let latest_content_probe_source = format!("{}.content_probe", probe_source);
    let latest_expected_mtime_ms =
        file_modified_epoch_ms(&fixture.latest_document_path).unwrap_or(0);
    let mut batch = EnvironmentEvidenceBatch::default();
    push_environment_receipt(
        &mut batch,
        "documents_summary_observed_files",
        observed_files.join(","),
        Some(probe_source.clone()),
        Some(timestamp_ms),
        Some(observed_files_satisfied),
    );
    push_environment_receipt(
        &mut batch,
        "documents_summary_latest_observed_path",
        latest_observed_path,
        Some(probe_source.clone()),
        Some(timestamp_ms),
        Some(latest_path_satisfied),
    );
    push_environment_observation(
        &mut batch,
        "documents_summary_latest_observed_modified_epoch_ms",
        latest_observed_mtime_ms.to_string(),
    );
    push_environment_observation(
        &mut batch,
        "documents_summary_latest_expected_modified_epoch_ms",
        latest_expected_mtime_ms.to_string(),
    );
    push_environment_observation(
        &mut batch,
        "documents_summary_latest_expected_path",
        latest_expected_path,
    );
    push_environment_receipt(
        &mut batch,
        "documents_summary_latest_content_excerpt",
        truncate_for_log(&latest_content, 240),
        Some(latest_content_probe_source),
        Some(timestamp_ms),
        Some(latest_content_satisfied),
    );
    batch
}

fn documents_summary_fixture_cleanup_checks(
    fixture: &DocumentsSummaryFixtureRuntime,
) -> EnvironmentEvidenceBatch {
    let timestamp_ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64;
    let probe_source = format!("{}.cleanup_probe", DOCUMENTS_SUMMARY_FIXTURE_PROBE_SOURCE);
    let _ = std::fs::remove_dir_all(&fixture.fixture_dir);
    let fixture_dir_exists_after_cleanup = fixture.fixture_dir.exists();
    let documents_dir_entries = list_directory_entry_names(&fixture.documents_dir);
    let cleanup_satisfied = !fixture_dir_exists_after_cleanup && documents_dir_entries.is_empty();
    let mut batch = EnvironmentEvidenceBatch::default();
    push_environment_observation(
        &mut batch,
        "documents_summary_cleanup_fixture_dir_exists",
        fixture_dir_exists_after_cleanup.to_string(),
    );
    push_environment_observation(
        &mut batch,
        "documents_summary_cleanup_documents_dir_entries",
        documents_dir_entries.join(","),
    );
    push_environment_metadata(
        &mut batch,
        "documents_summary_cleanup",
        Some(probe_source),
        Some(timestamp_ms),
        Some(cleanup_satisfied),
    );
    batch
}

fn bootstrap_pdf_last_week_fixture_runtime(
    run_unique_num: &str,
) -> Result<PdfLastWeekFixtureRuntime> {
    let temp_dir = tempdir()?;
    let home_dir = temp_dir.path().join("home");
    let documents_dir = home_dir.join("Documents");
    let fixture_dir = documents_dir.join(format!(
        "{}{}",
        PDF_LAST_WEEK_FIXTURE_DIR_PREFIX, run_unique_num
    ));
    std::fs::create_dir_all(&fixture_dir)?;

    let weekly_status = fixture_dir.join(PDF_LAST_WEEK_EXPECTED_PDF_FILES[0]);
    let incident_report = fixture_dir.join(PDF_LAST_WEEK_EXPECTED_PDF_FILES[1]);
    let notes = fixture_dir.join(PDF_LAST_WEEK_SUPPORTING_FILE);
    std::fs::write(
        &weekly_status,
        concat!(
            "Weekly status packet\n",
            "PDF fixture content for deterministic capabilities testing.\n",
        ),
    )?;
    std::thread::sleep(Duration::from_millis(1_100));
    std::fs::write(
        &incident_report,
        concat!(
            "Incident report packet\n",
            "PDF fixture content for deterministic capabilities testing.\n",
        ),
    )?;
    std::thread::sleep(Duration::from_millis(1_100));
    std::fs::write(
        &notes,
        concat!(
            "Supporting notes\n",
            "This file is intentionally non-PDF and must not appear in results.\n",
        ),
    )?;

    let env_home = ScopedEnvVar::set("HOME", home_dir.to_string_lossy().to_string());
    let env_userprofile = ScopedEnvVar::set("USERPROFILE", home_dir.to_string_lossy().to_string());
    let now_epoch_ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64;
    let seven_days_ms = 7 * 24 * 60 * 60 * 1_000;

    Ok(PdfLastWeekFixtureRuntime {
        _temp_dir: temp_dir,
        _env_home: env_home,
        _env_userprofile: env_userprofile,
        home_dir,
        documents_dir,
        fixture_dir,
        expected_pdf_paths: vec![incident_report, weekly_status],
        window_start_epoch_ms: now_epoch_ms.saturating_sub(seven_days_ms),
    })
}

fn pdf_last_week_fixture_preflight_checks(
    fixture: &PdfLastWeekFixtureRuntime,
    run_unique_num: &str,
    run_timestamp_ms: u64,
) -> EnvironmentEvidenceBatch {
    let seeded_files = list_directory_entry_names(&fixture.fixture_dir);
    let expected_seeded_files_present = PDF_LAST_WEEK_EXPECTED_PDF_FILES
        .iter()
        .all(|expected| seeded_files.iter().any(|observed| observed == expected))
        && seeded_files
            .iter()
            .any(|observed| observed.eq_ignore_ascii_case(PDF_LAST_WEEK_SUPPORTING_FILE));
    let expected_pdf_paths_satisfied = fixture.expected_pdf_paths.iter().all(|path| path.is_file());
    let run_unique_satisfied = fixture
        .fixture_dir
        .file_name()
        .and_then(|name| name.to_str())
        .map(|name| name.ends_with(run_unique_num))
        .unwrap_or(false);
    let fixture_satisfied =
        expected_seeded_files_present && expected_pdf_paths_satisfied && run_unique_satisfied;
    let mut batch = EnvironmentEvidenceBatch::default();
    push_environment_observation(
        &mut batch,
        "pdf_last_week_fixture_mode",
        PDF_LAST_WEEK_FIXTURE_MODE,
    );
    push_environment_observation(
        &mut batch,
        "pdf_last_week_home_dir",
        fixture.home_dir.to_string_lossy().to_string(),
    );
    push_environment_observation(
        &mut batch,
        "pdf_last_week_documents_dir",
        fixture.documents_dir.to_string_lossy().to_string(),
    );
    push_environment_observation(
        &mut batch,
        "pdf_last_week_fixture_dir",
        fixture.fixture_dir.to_string_lossy().to_string(),
    );
    push_environment_observation(
        &mut batch,
        "pdf_last_week_run_unique_num",
        run_unique_num.to_string(),
    );
    push_environment_receipt(
        &mut batch,
        "pdf_last_week_expected_paths",
        join_paths_csv(&fixture.expected_pdf_paths),
        None,
        None,
        Some(expected_pdf_paths_satisfied),
    );
    push_environment_observation(
        &mut batch,
        "pdf_last_week_expected_count",
        fixture.expected_pdf_paths.len().to_string(),
    );
    push_environment_observation(
        &mut batch,
        "pdf_last_week_expected_window_start_epoch_ms",
        fixture.window_start_epoch_ms.to_string(),
    );
    push_environment_receipt(
        &mut batch,
        "pdf_last_week_seeded_files",
        seeded_files.join(","),
        None,
        None,
        Some(expected_seeded_files_present),
    );
    push_environment_metadata(
        &mut batch,
        "pdf_last_week_run_unique",
        Some(PDF_LAST_WEEK_FIXTURE_PROBE_SOURCE.to_string()),
        Some(run_timestamp_ms),
        Some(run_unique_satisfied),
    );
    push_environment_metadata(
        &mut batch,
        "pdf_last_week_fixture",
        Some(PDF_LAST_WEEK_FIXTURE_PROBE_SOURCE.to_string()),
        Some(run_timestamp_ms),
        Some(fixture_satisfied),
    );
    batch
}

fn pdf_last_week_fixture_post_run_checks(
    fixture: &PdfLastWeekFixtureRuntime,
) -> EnvironmentEvidenceBatch {
    let timestamp_ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64;
    let probe_source = format!("{}.fs_probe", PDF_LAST_WEEK_FIXTURE_PROBE_SOURCE);
    let observed_files = list_directory_entry_names(&fixture.fixture_dir);
    let observed_pdf_paths = list_pdf_file_paths(&fixture.fixture_dir);
    let observed_pdf_paths_csv = join_paths_csv(&observed_pdf_paths);
    let expected_pdf_paths_csv = join_paths_csv(&fixture.expected_pdf_paths);
    let observed_files_satisfied = PDF_LAST_WEEK_EXPECTED_PDF_FILES
        .iter()
        .all(|expected| observed_files.iter().any(|observed| observed == expected))
        && observed_files
            .iter()
            .any(|observed| observed.eq_ignore_ascii_case(PDF_LAST_WEEK_SUPPORTING_FILE));
    let expected_pdf_paths_satisfied = observed_pdf_paths == fixture.expected_pdf_paths;
    let observed_within_window_count = observed_pdf_paths
        .iter()
        .filter_map(|path| file_modified_epoch_ms(path))
        .filter(|mtime_ms| *mtime_ms >= fixture.window_start_epoch_ms)
        .count();
    let observed_within_window_satisfied =
        observed_within_window_count == fixture.expected_pdf_paths.len();
    let mut batch = EnvironmentEvidenceBatch::default();
    push_environment_receipt(
        &mut batch,
        "pdf_last_week_observed_files",
        observed_files.join(","),
        Some(probe_source.clone()),
        Some(timestamp_ms),
        Some(observed_files_satisfied),
    );
    push_environment_observation(
        &mut batch,
        "pdf_last_week_expected_paths",
        expected_pdf_paths_csv,
    );
    push_environment_receipt(
        &mut batch,
        "pdf_last_week_observed_pdf_paths",
        observed_pdf_paths_csv,
        Some(probe_source.clone()),
        Some(timestamp_ms),
        Some(expected_pdf_paths_satisfied),
    );
    push_environment_observation(
        &mut batch,
        "pdf_last_week_observed_window_start_epoch_ms",
        fixture.window_start_epoch_ms.to_string(),
    );
    push_environment_metadata(
        &mut batch,
        "pdf_last_week_observed_window_start",
        Some(probe_source.clone()),
        Some(timestamp_ms),
        Some(true),
    );
    push_environment_observation(
        &mut batch,
        "pdf_last_week_observed_within_window_count",
        observed_within_window_count.to_string(),
    );
    push_environment_metadata(
        &mut batch,
        "pdf_last_week_observed_within_window",
        Some(probe_source),
        Some(timestamp_ms),
        Some(observed_within_window_satisfied),
    );
    batch
}

fn pdf_last_week_fixture_cleanup_checks(
    fixture: &PdfLastWeekFixtureRuntime,
) -> EnvironmentEvidenceBatch {
    let timestamp_ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64;
    let probe_source = format!("{}.cleanup_probe", PDF_LAST_WEEK_FIXTURE_PROBE_SOURCE);
    let _ = std::fs::remove_dir_all(&fixture.fixture_dir);
    let fixture_dir_exists_after_cleanup = fixture.fixture_dir.exists();
    let documents_dir_entries = list_directory_entry_names(&fixture.documents_dir);
    let cleanup_satisfied = !fixture_dir_exists_after_cleanup && documents_dir_entries.is_empty();
    let mut batch = EnvironmentEvidenceBatch::default();
    push_environment_observation(
        &mut batch,
        "pdf_last_week_cleanup_fixture_dir_exists",
        fixture_dir_exists_after_cleanup.to_string(),
    );
    push_environment_observation(
        &mut batch,
        "pdf_last_week_cleanup_documents_dir_entries",
        documents_dir_entries.join(","),
    );
    push_environment_metadata(
        &mut batch,
        "pdf_last_week_cleanup",
        Some(probe_source),
        Some(timestamp_ms),
        Some(cleanup_satisfied),
    );
    batch
}

fn bootstrap_spotify_uninstall_fixture_runtime(
    run_unique_num: &str,
) -> Result<SpotifyUninstallFixtureRuntime> {
    let temp_dir = tempdir()?;
    let home_dir = temp_dir.path().join("home");
    let fixture_root = temp_dir
        .path()
        .join(format!("spotify_uninstall_{}", run_unique_num));
    let fixture_bin = temp_dir.path().join("bin");
    let install_state_dir = fixture_root.join("install_state");
    let receipts_dir = fixture_root.join("receipts");
    let local_bin_dir = home_dir.join(".local").join("bin");

    std::fs::create_dir_all(&fixture_bin)?;
    std::fs::create_dir_all(&install_state_dir)?;
    std::fs::create_dir_all(&receipts_dir)?;
    std::fs::create_dir_all(&local_bin_dir)?;

    let config_paths = SPOTIFY_UNINSTALL_CONFIG_RELATIVE_PATHS
        .iter()
        .map(|relative| home_dir.join(relative))
        .collect::<Vec<_>>();
    for path in &config_paths {
        std::fs::create_dir_all(path)?;
        std::fs::write(
            path.join("prefs.json"),
            format!("fixture config payload for {}", path.to_string_lossy()),
        )?;
    }

    let sentinel_paths = vec![
        home_dir
            .join(".config")
            .join(SPOTIFY_UNINSTALL_SENTINEL_FILE_NAME),
        home_dir
            .join(".cache")
            .join(SPOTIFY_UNINSTALL_SENTINEL_FILE_NAME),
        home_dir
            .join(".local")
            .join("share")
            .join(SPOTIFY_UNINSTALL_SENTINEL_FILE_NAME),
    ];
    for path in &sentinel_paths {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        std::fs::write(path, "fixture sentinel must persist\n")?;
    }

    let install_marker_path = install_state_dir.join("spotify.installed");
    std::fs::write(&install_marker_path, "spotify\n")?;
    let binary_path = local_bin_dir.join("spotify");
    write_executable_script(
        &binary_path,
        "#!/usr/bin/env bash\nset -euo pipefail\necho \"Spotify fixture binary\"\n",
    )?;

    let provider_receipt_path = receipts_dir.join("provider.txt");
    let _ = std::fs::remove_file(&provider_receipt_path);

    let sudo_script = r#"#!/usr/bin/env bash
set -euo pipefail
if [ "$#" -eq 0 ]; then
  exit 0
fi
args=()
for arg in "$@"; do
  case "$arg" in
    -n|-S|-k|--) ;;
    *) args+=("$arg") ;;
  esac
done
if [ "${#args[@]}" -eq 0 ]; then
  exit 0
fi
exec "${args[@]}"
"#;
    write_executable_script(&fixture_bin.join("sudo"), sudo_script)?;

    let provider_script = r#"#!/usr/bin/env bash
set -euo pipefail
provider="${1:-}"
if [ -z "$provider" ]; then
  echo "spotify fixture provider: missing provider id" >&2
  exit 2
fi
shift || true

command_name="${1:-}"
if [ -z "$command_name" ]; then
  echo "spotify fixture provider: missing provider command" >&2
  exit 2
fi
shift || true

is_uninstall=0
case "$provider" in
  apt-get)
    case "$command_name" in
      update|--version|-v|help)
        echo "Hit:1 http://fixture.example stable InRelease"
        echo "Reading package lists... Done"
        exit 0
        ;;
      remove|purge|autoremove|uninstall)
        is_uninstall=1
        ;;
      *)
        echo "spotify fixture apt-get: unsupported command '$command_name'" >&2
        exit 2
        ;;
    esac
    ;;
  snap)
    case "$command_name" in
      --version|version|list|find|info)
        echo "snap    2.0-fixture"
        exit 0
        ;;
      remove|uninstall)
        is_uninstall=1
        ;;
      *)
        echo "spotify fixture snap: unsupported command '$command_name'" >&2
        exit 2
        ;;
    esac
    ;;
  flatpak)
    case "$command_name" in
      --version|--installations|list|info|remotes|search)
        echo "flatpak fixture discovery ok"
        exit 0
        ;;
      uninstall|remove)
        is_uninstall=1
        ;;
      *)
        echo "spotify fixture flatpak: unsupported command '$command_name'" >&2
        exit 2
        ;;
    esac
    ;;
  brew)
    case "$command_name" in
      --version|list|info|search)
        echo "Homebrew 4.0-fixture"
        exit 0
        ;;
      uninstall|remove)
        is_uninstall=1
        ;;
      *)
        echo "spotify fixture brew: unsupported command '$command_name'" >&2
        exit 2
        ;;
    esac
    ;;
  pacman)
    case "$command_name" in
      -V|-Q|-Qi|-Ss)
        echo "pacman fixture discovery ok"
        exit 0
        ;;
      -R|-Rs|-Rns|-Rnsc|--remove)
        is_uninstall=1
        ;;
      *)
        echo "spotify fixture pacman: unsupported command '$command_name'" >&2
        exit 2
        ;;
    esac
    ;;
  *)
    echo "spotify fixture provider: unsupported provider '$provider'" >&2
    exit 2
    ;;
esac

if [ "$is_uninstall" -ne 1 ]; then
  exit 0
fi

spotify_match=0
for arg in "$@"; do
  case "$arg" in
    -*) ;;
    spotify|spotify:*|spotify-client*|com.spotify.Client|com.spotify.Client//stable)
      spotify_match=1
      ;;
  esac
done
if [ "$spotify_match" -ne 1 ]; then
  echo "spotify fixture provider: spotify package id missing" >&2
  exit 100
fi

install_marker="${IOI_SPOTIFY_INSTALL_MARKER:-}"
binary_path="${IOI_SPOTIFY_BINARY_PATH:-}"
provider_receipt="${IOI_SPOTIFY_PROVIDER_RECEIPT:-}"
if [ -z "$install_marker" ] || [ -z "$provider_receipt" ]; then
  echo "spotify fixture provider: required env vars are missing" >&2
  exit 2
fi

rm -f "$install_marker"
if [ -n "$binary_path" ]; then
  rm -f "$binary_path"
fi
mkdir -p "$(dirname "$provider_receipt")"
printf '%s\n' "$provider" > "$provider_receipt"
echo "spotify fixture: removed spotify via provider '$provider'"
"#;
    write_executable_script(
        &fixture_bin.join("spotify_fixture_provider"),
        provider_script,
    )?;

    write_executable_script(
        &fixture_bin.join("apt-get"),
        "#!/usr/bin/env bash\nset -euo pipefail\nexec spotify_fixture_provider apt-get \"$@\"\n",
    )?;
    write_executable_script(
        &fixture_bin.join("apt"),
        "#!/usr/bin/env bash\nset -euo pipefail\nexec apt-get \"$@\"\n",
    )?;
    write_executable_script(
        &fixture_bin.join("snap"),
        "#!/usr/bin/env bash\nset -euo pipefail\nexec spotify_fixture_provider snap \"$@\"\n",
    )?;
    write_executable_script(
        &fixture_bin.join("flatpak"),
        "#!/usr/bin/env bash\nset -euo pipefail\nexec spotify_fixture_provider flatpak \"$@\"\n",
    )?;
    write_executable_script(
        &fixture_bin.join("brew"),
        "#!/usr/bin/env bash\nset -euo pipefail\nexec spotify_fixture_provider brew \"$@\"\n",
    )?;
    write_executable_script(
        &fixture_bin.join("pacman"),
        "#!/usr/bin/env bash\nset -euo pipefail\nexec spotify_fixture_provider pacman \"$@\"\n",
    )?;

    let inherited_path = std::env::var("PATH").unwrap_or_default();
    let fixture_path = format!(
        "{}:{}:{}",
        fixture_bin.to_string_lossy(),
        local_bin_dir.to_string_lossy(),
        inherited_path
    );
    let env_home = ScopedEnvVar::set("HOME", home_dir.to_string_lossy().to_string());
    let env_userprofile = ScopedEnvVar::set("USERPROFILE", home_dir.to_string_lossy().to_string());
    let env_path = ScopedEnvVar::set("PATH", fixture_path);
    let env_fixture_root = ScopedEnvVar::set(
        "IOI_SPOTIFY_FIXTURE_ROOT",
        fixture_root.to_string_lossy().to_string(),
    );
    let env_fixture_mode =
        ScopedEnvVar::set("IOI_SPOTIFY_FIXTURE_MODE", SPOTIFY_UNINSTALL_FIXTURE_MODE);
    let env_install_marker = ScopedEnvVar::set(
        "IOI_SPOTIFY_INSTALL_MARKER",
        install_marker_path.to_string_lossy().to_string(),
    );
    let env_binary_path = ScopedEnvVar::set(
        "IOI_SPOTIFY_BINARY_PATH",
        binary_path.to_string_lossy().to_string(),
    );
    let env_provider_receipt = ScopedEnvVar::set(
        "IOI_SPOTIFY_PROVIDER_RECEIPT",
        provider_receipt_path.to_string_lossy().to_string(),
    );

    Ok(SpotifyUninstallFixtureRuntime {
        _temp_dir: temp_dir,
        _env_home: env_home,
        _env_userprofile: env_userprofile,
        _env_path: env_path,
        _env_fixture_root: env_fixture_root,
        _env_fixture_mode: env_fixture_mode,
        _env_install_marker: env_install_marker,
        _env_binary_path: env_binary_path,
        _env_provider_receipt: env_provider_receipt,
        home_dir,
        fixture_root,
        provider_receipt_path,
        install_marker_path,
        binary_path,
        config_paths,
        sentinel_paths,
    })
}

fn spotify_uninstall_fixture_preflight_checks(
    fixture: &SpotifyUninstallFixtureRuntime,
    run_unique_num: &str,
    run_timestamp_ms: u64,
) -> EnvironmentEvidenceBatch {
    let config_paths_seeded = fixture.config_paths.iter().all(|path| path.is_dir());
    let sentinel_paths_seeded = fixture.sentinel_paths.iter().all(|path| path.is_file());
    let install_marker_seeded = fixture.install_marker_path.is_file();
    let binary_seeded = fixture.binary_path.is_file();
    let provider_receipt_absent = !fixture.provider_receipt_path.exists();
    let run_unique_satisfied = fixture
        .fixture_root
        .file_name()
        .and_then(|name| name.to_str())
        .map(|name| name.ends_with(run_unique_num))
        .unwrap_or(false);
    let fixture_satisfied = config_paths_seeded
        && sentinel_paths_seeded
        && install_marker_seeded
        && binary_seeded
        && provider_receipt_absent
        && run_unique_satisfied;
    let mut batch = EnvironmentEvidenceBatch::default();
    push_environment_observation(
        &mut batch,
        "spotify_uninstall_fixture_mode",
        SPOTIFY_UNINSTALL_FIXTURE_MODE,
    );
    push_environment_observation(
        &mut batch,
        "spotify_uninstall_fixture_home_dir",
        fixture.home_dir.to_string_lossy().to_string(),
    );
    push_environment_observation(
        &mut batch,
        "spotify_uninstall_fixture_root",
        fixture.fixture_root.to_string_lossy().to_string(),
    );
    push_environment_observation(
        &mut batch,
        "spotify_uninstall_run_unique_num",
        run_unique_num.to_string(),
    );
    push_environment_observation(
        &mut batch,
        "spotify_uninstall_provider_candidates",
        SPOTIFY_UNINSTALL_PROVIDER_IDS.join(","),
    );
    push_environment_observation(
        &mut batch,
        "spotify_uninstall_provider_receipt_path",
        fixture.provider_receipt_path.to_string_lossy().to_string(),
    );
    push_environment_observation(
        &mut batch,
        "spotify_uninstall_install_marker_path",
        fixture.install_marker_path.to_string_lossy().to_string(),
    );
    push_environment_observation(
        &mut batch,
        "spotify_uninstall_binary_path",
        fixture.binary_path.to_string_lossy().to_string(),
    );
    push_environment_observation(
        &mut batch,
        "spotify_uninstall_config_paths",
        join_paths_csv(&fixture.config_paths),
    );
    push_environment_observation(
        &mut batch,
        "spotify_uninstall_sentinel_paths",
        join_paths_csv(&fixture.sentinel_paths),
    );
    push_environment_metadata(
        &mut batch,
        "spotify_uninstall_config_paths_seeded",
        Some(SPOTIFY_UNINSTALL_FIXTURE_PROBE_SOURCE.to_string()),
        Some(run_timestamp_ms),
        Some(config_paths_seeded),
    );
    push_environment_metadata(
        &mut batch,
        "spotify_uninstall_sentinel_paths_seeded",
        Some(SPOTIFY_UNINSTALL_FIXTURE_PROBE_SOURCE.to_string()),
        Some(run_timestamp_ms),
        Some(sentinel_paths_seeded),
    );
    push_environment_metadata(
        &mut batch,
        "spotify_uninstall_install_marker_seeded",
        Some(SPOTIFY_UNINSTALL_FIXTURE_PROBE_SOURCE.to_string()),
        Some(run_timestamp_ms),
        Some(install_marker_seeded),
    );
    push_environment_metadata(
        &mut batch,
        "spotify_uninstall_binary_seeded",
        Some(SPOTIFY_UNINSTALL_FIXTURE_PROBE_SOURCE.to_string()),
        Some(run_timestamp_ms),
        Some(binary_seeded),
    );
    push_environment_metadata(
        &mut batch,
        "spotify_uninstall_provider_receipt_absent",
        Some(SPOTIFY_UNINSTALL_FIXTURE_PROBE_SOURCE.to_string()),
        Some(run_timestamp_ms),
        Some(provider_receipt_absent),
    );
    push_environment_metadata(
        &mut batch,
        "spotify_uninstall_run_unique",
        Some(SPOTIFY_UNINSTALL_FIXTURE_PROBE_SOURCE.to_string()),
        Some(run_timestamp_ms),
        Some(run_unique_satisfied),
    );
    push_environment_metadata(
        &mut batch,
        "spotify_uninstall_fixture",
        Some(SPOTIFY_UNINSTALL_FIXTURE_PROBE_SOURCE.to_string()),
        Some(run_timestamp_ms),
        Some(fixture_satisfied),
    );
    batch
}

fn spotify_uninstall_fixture_post_run_checks(
    fixture: &SpotifyUninstallFixtureRuntime,
) -> EnvironmentEvidenceBatch {
    let timestamp_ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64;
    let probe_source = format!("{}.fs_probe", SPOTIFY_UNINSTALL_FIXTURE_PROBE_SOURCE);

    let provider_selected = std::fs::read_to_string(&fixture.provider_receipt_path)
        .unwrap_or_default()
        .trim()
        .to_string();
    let provider_satisfied = SPOTIFY_UNINSTALL_PROVIDER_IDS
        .iter()
        .any(|provider| provider_selected.eq_ignore_ascii_case(provider));
    let install_marker_removed = !fixture.install_marker_path.exists();
    let binary_absent = !fixture.binary_path.exists();
    let config_paths_removed = fixture.config_paths.iter().all(|path| !path.exists());
    let sentinel_paths_preserved = fixture.sentinel_paths.iter().all(|path| path.is_file());
    let scope_satisfied = sentinel_paths_preserved;
    let mut batch = EnvironmentEvidenceBatch::default();
    push_environment_receipt(
        &mut batch,
        "spotify_uninstall_provider",
        provider_selected,
        Some(probe_source.clone()),
        Some(timestamp_ms),
        Some(provider_satisfied),
    );
    push_environment_observation(
        &mut batch,
        "spotify_uninstall_install_marker_path",
        fixture.install_marker_path.to_string_lossy().to_string(),
    );
    push_environment_metadata(
        &mut batch,
        "spotify_uninstall_install_marker_removed",
        Some(probe_source.clone()),
        Some(timestamp_ms),
        Some(install_marker_removed),
    );
    push_environment_observation(
        &mut batch,
        "spotify_uninstall_binary_path",
        fixture.binary_path.to_string_lossy().to_string(),
    );
    push_environment_metadata(
        &mut batch,
        "spotify_uninstall_binary_absent",
        Some(probe_source.clone()),
        Some(timestamp_ms),
        Some(binary_absent),
    );
    push_environment_observation(
        &mut batch,
        "spotify_uninstall_config_paths",
        join_paths_csv(&fixture.config_paths),
    );
    push_environment_metadata(
        &mut batch,
        "spotify_uninstall_config_paths_removed",
        Some(probe_source.clone()),
        Some(timestamp_ms),
        Some(config_paths_removed),
    );
    push_environment_observation(
        &mut batch,
        "spotify_uninstall_sentinel_paths",
        join_paths_csv(&fixture.sentinel_paths),
    );
    push_environment_metadata(
        &mut batch,
        "spotify_uninstall_scope",
        Some(probe_source),
        Some(timestamp_ms),
        Some(scope_satisfied),
    );
    batch
}

fn spotify_uninstall_fixture_cleanup_checks(
    fixture: &SpotifyUninstallFixtureRuntime,
) -> EnvironmentEvidenceBatch {
    let timestamp_ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64;
    let probe_source = format!("{}.cleanup_probe", SPOTIFY_UNINSTALL_FIXTURE_PROBE_SOURCE);

    let _ = std::fs::remove_file(&fixture.provider_receipt_path);
    let _ = std::fs::remove_dir_all(&fixture.home_dir);
    let _ = std::fs::create_dir_all(&fixture.home_dir);
    let _ = std::fs::remove_dir_all(&fixture.fixture_root);
    let _ = std::fs::create_dir_all(&fixture.fixture_root);
    let home_entries = list_directory_entry_names(&fixture.home_dir);
    let fixture_root_entries = list_directory_entry_names(&fixture.fixture_root);
    let cleanup_satisfied = home_entries.is_empty() && fixture_root_entries.is_empty();
    let mut batch = EnvironmentEvidenceBatch::default();
    push_environment_observation(
        &mut batch,
        "spotify_uninstall_cleanup_home_entries",
        home_entries.join(","),
    );
    push_environment_observation(
        &mut batch,
        "spotify_uninstall_cleanup_fixture_root_entries",
        fixture_root_entries.join(","),
    );
    push_environment_metadata(
        &mut batch,
        "spotify_uninstall_cleanup",
        Some(probe_source),
        Some(timestamp_ms),
        Some(cleanup_satisfied),
    );
    batch
}

fn bootstrap_top_memory_apps_fixture_runtime(
    run_unique_num: &str,
) -> Result<TopMemoryAppsFixtureRuntime> {
    let temp_dir = tempdir()?;
    let fixture_root = temp_dir
        .path()
        .join(format!("top_memory_apps_{}", run_unique_num));
    let fixture_bin = fixture_root.join("bin");
    let fixture_receipts = fixture_root.join("receipts");
    std::fs::create_dir_all(&fixture_bin)?;
    std::fs::create_dir_all(&fixture_receipts)?;

    let probe_script_path = fixture_bin.join(TOP_MEMORY_APPS_PROBE_SCRIPT_NAME);
    let receipt_path = fixture_receipts.join("latest_probe_receipt.txt");
    let _ = std::fs::remove_file(&receipt_path);

    let probe_script = r##"#!/usr/bin/env bash
set -euo pipefail

top_n="${1:-5}"
if ! [[ "$top_n" =~ ^[0-9]+$ ]] || [ "$top_n" -lt 1 ]; then
  echo "invalid top_n argument; expected positive integer" >&2
  exit 2
fi

for required in ps sort head awk; do
  if ! command -v "$required" >/dev/null 2>&1; then
    echo "missing required provider binary: $required" >&2
    exit 3
  fi
done

receipt_path="${IOI_TOP_MEMORY_APPS_RECEIPT_PATH:-}"
if [ -z "$receipt_path" ]; then
  echo "missing IOI_TOP_MEMORY_APPS_RECEIPT_PATH" >&2
  exit 4
fi

rows="$(
  ps -eo pid=,comm=,rss= 2>/dev/null \
    | awk '
      {
        pid=$1; app=$2; rss=$3;
        if (pid ~ /^[0-9]+$/ && rss ~ /^[0-9]+$/ && app != "") {
          print rss "\t" app "\t" pid;
        }
      }
    ' \
    | sort -t$'\t' -k1,1nr \
    | awk -v top_n="$top_n" 'NR <= top_n { print }'
)"

if [ -z "$rows" ]; then
  echo "no process rows were produced by ps provider" >&2
  exit 5
fi

mkdir -p "$(dirname "$receipt_path")"
{
  echo "provider=ps"
  rank=1
  while IFS=$'\t' read -r rss app pid; do
    if [ -z "${rss:-}" ] || [ -z "${app:-}" ] || [ -z "${pid:-}" ]; then
      continue
    fi
    echo "row|${rank}|${app}|${pid}|${rss}"
    rank=$((rank + 1))
  done <<< "$rows"
} > "$receipt_path"

cat "$receipt_path"
"##;
    write_executable_script(&probe_script_path, probe_script)?;

    let inherited_path = std::env::var("PATH").unwrap_or_default();
    let fixture_path = format!("{}:{}", fixture_bin.to_string_lossy(), inherited_path);
    let env_path = ScopedEnvVar::set("PATH", fixture_path);
    let env_fixture_mode = ScopedEnvVar::set(
        "IOI_TOP_MEMORY_APPS_FIXTURE_MODE",
        TOP_MEMORY_APPS_FIXTURE_MODE,
    );
    let env_receipt_path = ScopedEnvVar::set(
        "IOI_TOP_MEMORY_APPS_RECEIPT_PATH",
        receipt_path.to_string_lossy().to_string(),
    );

    Ok(TopMemoryAppsFixtureRuntime {
        _temp_dir: temp_dir,
        _env_path: env_path,
        _env_fixture_mode: env_fixture_mode,
        _env_receipt_path: env_receipt_path,
        fixture_root,
        probe_script_path,
        receipt_path,
    })
}

fn top_memory_apps_fixture_preflight_checks(
    fixture: &TopMemoryAppsFixtureRuntime,
    run_unique_num: &str,
    run_timestamp_ms: u64,
) -> EnvironmentEvidenceBatch {
    let run_unique_satisfied = fixture
        .fixture_root
        .file_name()
        .and_then(|name| name.to_str())
        .map(|name| name.ends_with(run_unique_num))
        .unwrap_or(false);
    let probe_script_seeded_satisfied = fixture.probe_script_path.is_file();
    let receipt_absent_satisfied = !fixture.receipt_path.exists();
    let fixture_satisfied =
        run_unique_satisfied && probe_script_seeded_satisfied && receipt_absent_satisfied;
    let mut batch = EnvironmentEvidenceBatch::default();
    push_environment_observation(
        &mut batch,
        "top_memory_apps_fixture_mode",
        TOP_MEMORY_APPS_FIXTURE_MODE,
    );
    push_environment_observation(
        &mut batch,
        "top_memory_apps_fixture_root",
        fixture.fixture_root.to_string_lossy().to_string(),
    );
    push_environment_observation(
        &mut batch,
        "top_memory_apps_probe_script_path",
        fixture.probe_script_path.to_string_lossy().to_string(),
    );
    push_environment_observation(
        &mut batch,
        "top_memory_apps_receipt_path",
        fixture.receipt_path.to_string_lossy().to_string(),
    );
    push_environment_observation(
        &mut batch,
        "top_memory_apps_run_unique_num",
        run_unique_num.to_string(),
    );
    push_environment_metadata(
        &mut batch,
        "top_memory_apps_run_unique",
        Some(TOP_MEMORY_APPS_FIXTURE_PROBE_SOURCE.to_string()),
        Some(run_timestamp_ms),
        Some(run_unique_satisfied),
    );
    push_environment_metadata(
        &mut batch,
        "top_memory_apps_probe_script_seeded",
        Some(TOP_MEMORY_APPS_FIXTURE_PROBE_SOURCE.to_string()),
        Some(run_timestamp_ms),
        Some(probe_script_seeded_satisfied),
    );
    push_environment_metadata(
        &mut batch,
        "top_memory_apps_receipt_absent",
        Some(TOP_MEMORY_APPS_FIXTURE_PROBE_SOURCE.to_string()),
        Some(run_timestamp_ms),
        Some(receipt_absent_satisfied),
    );
    push_environment_metadata(
        &mut batch,
        "top_memory_apps_fixture",
        Some(TOP_MEMORY_APPS_FIXTURE_PROBE_SOURCE.to_string()),
        Some(run_timestamp_ms),
        Some(fixture_satisfied),
    );
    batch
}

fn parse_top_memory_apps_probe_receipt(path: &Path) -> TopMemoryAppsProbeReceipt {
    let mut receipt = TopMemoryAppsProbeReceipt::default();
    let raw = std::fs::read_to_string(path).unwrap_or_default();
    for line in raw.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        if let Some(provider) = trimmed.strip_prefix("provider=") {
            receipt.provider = provider.trim().to_string();
            continue;
        }
        if let Some(payload) = trimmed.strip_prefix("row|") {
            let mut parts = payload.split('|').map(str::trim);
            let rank = parts.next().and_then(|value| value.parse::<usize>().ok());
            let app = parts.next().map(str::to_string);
            let pid = parts.next().and_then(|value| value.parse::<u32>().ok());
            let rss_kb = parts.next().and_then(|value| value.parse::<u64>().ok());
            if let (Some(rank), Some(app), Some(pid), Some(rss_kb)) = (rank, app, pid, rss_kb) {
                if !app.is_empty() && pid > 0 && rss_kb > 0 {
                    receipt.rows.push(TopMemoryAppProbeRow {
                        rank,
                        app,
                        pid,
                        rss_kb,
                    });
                }
            }
        }
    }
    receipt.rows.sort_by_key(|row| row.rank);
    receipt
}

fn top_memory_apps_rows_sorted_desc(rows: &[TopMemoryAppProbeRow]) -> bool {
    if rows.len() < 3 {
        return false;
    }

    let mut previous_rss: Option<u64> = None;
    for (index, row) in rows.iter().enumerate() {
        if row.rank != index + 1 || row.app.trim().is_empty() || row.pid == 0 || row.rss_kb == 0 {
            return false;
        }
        if let Some(previous) = previous_rss {
            if row.rss_kb > previous {
                return false;
            }
        }
        previous_rss = Some(row.rss_kb);
    }
    true
}

fn top_memory_apps_fixture_post_run_checks(
    fixture: &TopMemoryAppsFixtureRuntime,
) -> EnvironmentEvidenceBatch {
    let timestamp_ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64;
    let probe_source = format!("{}.receipt_probe", TOP_MEMORY_APPS_FIXTURE_PROBE_SOURCE);
    let receipt_present_satisfied = fixture.receipt_path.is_file();
    let receipt = if receipt_present_satisfied {
        parse_top_memory_apps_probe_receipt(&fixture.receipt_path)
    } else {
        TopMemoryAppsProbeReceipt::default()
    };
    let provider_satisfied = receipt.provider.eq_ignore_ascii_case("ps");
    let row_count = receipt.rows.len();
    let row_count_satisfied = row_count >= 3;
    let rows_sorted_desc_satisfied = top_memory_apps_rows_sorted_desc(&receipt.rows);
    let scope_satisfied = provider_satisfied && row_count_satisfied && rows_sorted_desc_satisfied;
    let mut batch = EnvironmentEvidenceBatch::default();
    push_environment_receipt(
        &mut batch,
        "top_memory_apps_provider",
        receipt.provider,
        Some(probe_source.clone()),
        Some(timestamp_ms),
        Some(provider_satisfied),
    );
    push_environment_receipt(
        &mut batch,
        "top_memory_apps_row_count",
        row_count.to_string(),
        Some(probe_source.clone()),
        Some(timestamp_ms),
        Some(row_count_satisfied),
    );
    push_environment_metadata(
        &mut batch,
        "top_memory_apps_rows_sorted_desc",
        Some(probe_source.clone()),
        Some(timestamp_ms),
        Some(rows_sorted_desc_satisfied),
    );
    push_environment_observation(
        &mut batch,
        "top_memory_apps_receipt_path",
        fixture.receipt_path.to_string_lossy().to_string(),
    );
    push_environment_metadata(
        &mut batch,
        "top_memory_apps_receipt",
        Some(probe_source.clone()),
        Some(timestamp_ms),
        Some(receipt_present_satisfied),
    );
    push_environment_metadata(
        &mut batch,
        "top_memory_apps_scope",
        Some(probe_source),
        Some(timestamp_ms),
        Some(scope_satisfied),
    );
    for row in receipt.rows {
        push_environment_observation(
            &mut batch,
            "top_memory_apps_row",
            format!("{}|{}|{}|{}", row.rank, row.app, row.pid, row.rss_kb),
        );
    }
    batch
}

fn top_memory_apps_fixture_cleanup_checks(
    fixture: &TopMemoryAppsFixtureRuntime,
) -> EnvironmentEvidenceBatch {
    let timestamp_ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64;
    let probe_source = format!("{}.cleanup_probe", TOP_MEMORY_APPS_FIXTURE_PROBE_SOURCE);
    let _ = std::fs::remove_file(&fixture.receipt_path);
    let _ = std::fs::remove_dir_all(&fixture.fixture_root);
    let fixture_root_exists_after_cleanup = fixture.fixture_root.exists();
    let receipt_exists_after_cleanup = fixture.receipt_path.exists();
    let cleanup_satisfied = !fixture_root_exists_after_cleanup && !receipt_exists_after_cleanup;
    let mut batch = EnvironmentEvidenceBatch::default();
    push_environment_observation(
        &mut batch,
        "top_memory_apps_cleanup_fixture_root_exists",
        fixture_root_exists_after_cleanup.to_string(),
    );
    push_environment_observation(
        &mut batch,
        "top_memory_apps_cleanup_receipt_exists",
        receipt_exists_after_cleanup.to_string(),
    );
    push_environment_metadata(
        &mut batch,
        "top_memory_apps_cleanup",
        Some(probe_source),
        Some(timestamp_ms),
        Some(cleanup_satisfied),
    );
    batch
}

fn bootstrap_media_transcript_fixture_runtime(
    run_unique_num: &str,
) -> Result<MediaTranscriptFixtureRuntime> {
    let temp_dir = tempdir()?;
    let fixture_root = temp_dir
        .path()
        .join(format!("media_multimodal_summary_{}", run_unique_num));
    let tool_home = fixture_root.join("tool_home");
    let receipt_path = tool_home.join("receipts").join("last_success.json");
    std::fs::create_dir_all(&tool_home)?;
    let env_media_tool_home = ScopedEnvVar::set(
        MEDIA_TRANSCRIPT_SUMMARY_TOOL_HOME_ENV_KEY,
        tool_home.to_string_lossy().to_string(),
    );

    Ok(MediaTranscriptFixtureRuntime {
        _temp_dir: temp_dir,
        _env_media_tool_home: env_media_tool_home,
        fixture_root,
        tool_home,
        receipt_path,
    })
}

fn media_transcript_fixture_preflight_checks(
    fixture: &MediaTranscriptFixtureRuntime,
    run_unique_num: &str,
    run_timestamp_ms: u64,
) -> EnvironmentEvidenceBatch {
    let run_unique_satisfied = fixture
        .fixture_root
        .file_name()
        .and_then(|name| name.to_str())
        .map(|name| name.ends_with(run_unique_num))
        .unwrap_or(false);
    let tool_home_seeded_satisfied = fixture.tool_home.is_dir();
    let receipt_absent_satisfied = !fixture.receipt_path.exists();
    let fixture_satisfied =
        run_unique_satisfied && tool_home_seeded_satisfied && receipt_absent_satisfied;
    let mut batch = EnvironmentEvidenceBatch::default();
    push_environment_receipt(
        &mut batch,
        "media_multimodal_fixture_mode",
        MEDIA_TRANSCRIPT_SUMMARY_FIXTURE_MODE,
        Some(MEDIA_TRANSCRIPT_SUMMARY_FIXTURE_PROBE_SOURCE.to_string()),
        Some(run_timestamp_ms),
        Some(true),
    );
    push_environment_receipt(
        &mut batch,
        "media_multimodal_fixture_root",
        fixture.fixture_root.to_string_lossy().to_string(),
        Some(MEDIA_TRANSCRIPT_SUMMARY_FIXTURE_PROBE_SOURCE.to_string()),
        Some(run_timestamp_ms),
        Some(run_unique_satisfied),
    );
    push_environment_receipt(
        &mut batch,
        "media_multimodal_tool_home",
        fixture.tool_home.to_string_lossy().to_string(),
        Some(MEDIA_TRANSCRIPT_SUMMARY_FIXTURE_PROBE_SOURCE.to_string()),
        Some(run_timestamp_ms),
        Some(tool_home_seeded_satisfied),
    );
    push_environment_receipt(
        &mut batch,
        "media_multimodal_receipt_path",
        fixture.receipt_path.to_string_lossy().to_string(),
        Some(MEDIA_TRANSCRIPT_SUMMARY_FIXTURE_PROBE_SOURCE.to_string()),
        Some(run_timestamp_ms),
        Some(receipt_absent_satisfied),
    );
    push_environment_receipt(
        &mut batch,
        "media_multimodal_run_unique_num",
        run_unique_num.to_string(),
        Some(MEDIA_TRANSCRIPT_SUMMARY_FIXTURE_PROBE_SOURCE.to_string()),
        Some(run_timestamp_ms),
        Some(run_unique_satisfied),
    );
    push_environment_metadata(
        &mut batch,
        "media_multimodal_run_unique",
        Some(MEDIA_TRANSCRIPT_SUMMARY_FIXTURE_PROBE_SOURCE.to_string()),
        Some(run_timestamp_ms),
        Some(run_unique_satisfied),
    );
    push_environment_metadata(
        &mut batch,
        "media_multimodal_tool_home_seeded",
        Some(MEDIA_TRANSCRIPT_SUMMARY_FIXTURE_PROBE_SOURCE.to_string()),
        Some(run_timestamp_ms),
        Some(tool_home_seeded_satisfied),
    );
    push_environment_metadata(
        &mut batch,
        "media_multimodal_receipt_absent",
        Some(MEDIA_TRANSCRIPT_SUMMARY_FIXTURE_PROBE_SOURCE.to_string()),
        Some(run_timestamp_ms),
        Some(receipt_absent_satisfied),
    );
    push_environment_metadata(
        &mut batch,
        "media_multimodal_fixture",
        Some(MEDIA_TRANSCRIPT_SUMMARY_FIXTURE_PROBE_SOURCE.to_string()),
        Some(run_timestamp_ms),
        Some(fixture_satisfied),
    );
    batch
}

fn parse_media_transcript_fixture_receipt(path: &Path) -> MediaTranscriptFixtureReceipt {
    std::fs::read_to_string(path)
        .ok()
        .and_then(|raw| serde_json::from_str::<MediaTranscriptFixtureReceipt>(&raw).ok())
        .unwrap_or_default()
}

fn media_transcript_fixture_post_run_checks(
    fixture: &MediaTranscriptFixtureRuntime,
) -> EnvironmentEvidenceBatch {
    let timestamp_ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64;
    let probe_source = format!(
        "{}.receipt_probe",
        MEDIA_TRANSCRIPT_SUMMARY_FIXTURE_PROBE_SOURCE
    );
    let receipt_present_satisfied = fixture.receipt_path.is_file();
    let receipt = if receipt_present_satisfied {
        parse_media_transcript_fixture_receipt(&fixture.receipt_path)
    } else {
        MediaTranscriptFixtureReceipt::default()
    };
    let selected_modalities_value = receipt.selected_modalities.join(",");
    let transcript_selected = receipt
        .selected_modalities
        .iter()
        .any(|value| value.eq_ignore_ascii_case("transcript"))
        || receipt
            .transcript_provider_id
            .as_deref()
            .is_some_and(|value| !value.trim().is_empty());
    let timeline_selected = receipt
        .selected_modalities
        .iter()
        .any(|value| value.eq_ignore_ascii_case("timeline"))
        || receipt
            .timeline_provider_id
            .as_deref()
            .is_some_and(|value| !value.trim().is_empty());
    let visual_selected = receipt
        .selected_modalities
        .iter()
        .any(|value| value.eq_ignore_ascii_case("visual"))
        || receipt
            .visual_provider_id
            .as_deref()
            .is_some_and(|value| !value.trim().is_empty());
    let selected_modalities_satisfied =
        visual_selected && (transcript_selected || timeline_selected);
    let transcript_provider_binary_path = receipt
        .transcript_provider_binary_path
        .clone()
        .unwrap_or_default();
    let transcript_provider_binary_path_buf = PathBuf::from(transcript_provider_binary_path.trim());
    let transcript_provider_id = receipt.transcript_provider_id.clone().unwrap_or_default();
    let transcript_provider_id_satisfied = if transcript_selected {
        matches!(
            transcript_provider_id.trim(),
            "yt_dlp.managed_subtitles" | "yt_dlp.whisper_rs_audio" | "youtube.watch_transcript"
        )
    } else {
        transcript_provider_id.trim().is_empty()
    };
    let transcript_provider_uses_managed_binary = matches!(
        transcript_provider_id.trim(),
        "yt_dlp.managed_subtitles" | "yt_dlp.whisper_rs_audio"
    );
    let transcript_provider_binary_satisfied = if !transcript_selected {
        transcript_provider_binary_path.trim().is_empty()
    } else if transcript_provider_uses_managed_binary {
        transcript_provider_binary_path_buf.is_file()
            && transcript_provider_binary_path_buf.starts_with(&fixture.tool_home)
    } else {
        transcript_provider_binary_path.trim().is_empty()
    };
    let transcript_provider_model_id = receipt
        .transcript_provider_model_id
        .clone()
        .unwrap_or_default();
    let transcript_provider_model_path = receipt
        .transcript_provider_model_path
        .clone()
        .unwrap_or_default();
    let transcript_provider_model_path_buf = PathBuf::from(transcript_provider_model_path.trim());
    let transcript_provider_model_satisfied = if !transcript_selected {
        transcript_provider_model_id.trim().is_empty()
            && transcript_provider_model_path.trim().is_empty()
    } else if transcript_provider_id.eq_ignore_ascii_case("yt_dlp.whisper_rs_audio") {
        !transcript_provider_model_id.trim().is_empty()
            && transcript_provider_model_path_buf.is_file()
            && transcript_provider_model_path_buf.starts_with(&fixture.tool_home)
    } else {
        transcript_provider_model_id.trim().is_empty()
            && transcript_provider_model_path.trim().is_empty()
    };
    let transcript_selected_audio_format_id = receipt
        .transcript_selected_audio_format_id
        .clone()
        .unwrap_or_default();
    let transcript_selected_audio_ext = receipt
        .transcript_selected_audio_ext
        .clone()
        .unwrap_or_default();
    let transcript_selected_audio_acodec = receipt
        .transcript_selected_audio_acodec
        .clone()
        .unwrap_or_default();
    let transcript_selected_audio_satisfied = if !transcript_selected {
        transcript_selected_audio_format_id.trim().is_empty()
            && transcript_selected_audio_ext.trim().is_empty()
            && transcript_selected_audio_acodec.trim().is_empty()
    } else if transcript_provider_id.eq_ignore_ascii_case("yt_dlp.whisper_rs_audio") {
        !transcript_selected_audio_format_id.trim().is_empty()
            && !transcript_selected_audio_ext.trim().is_empty()
            && !transcript_selected_audio_acodec.trim().is_empty()
    } else {
        transcript_selected_audio_format_id.trim().is_empty()
            && transcript_selected_audio_ext.trim().is_empty()
            && transcript_selected_audio_acodec.trim().is_empty()
    };
    let requested_url_satisfied = receipt
        .requested_url
        .trim()
        .eq_ignore_ascii_case(MEDIA_TRANSCRIPT_SUMMARY_EXPECTED_URL);
    let canonical_url_satisfied = receipt.canonical_url.contains("9Tm2c6NJH4Y");
    let title_satisfied = receipt
        .title
        .as_deref()
        .map(str::trim)
        .is_some_and(|value| !value.is_empty());
    let duration_seconds = receipt.duration_seconds.unwrap_or_default();
    let duration_satisfied = duration_seconds >= 2_400;
    let transcript_char_count = receipt.transcript_char_count.unwrap_or_default();
    let transcript_char_count_satisfied = if transcript_selected {
        transcript_char_count >= 3_000
    } else {
        transcript_char_count == 0
    };
    let transcript_segment_count = receipt.transcript_segment_count.unwrap_or_default();
    let transcript_segment_count_satisfied = if transcript_selected {
        transcript_segment_count >= 100
    } else {
        transcript_segment_count == 0
    };
    let transcript_language = receipt.transcript_language.clone().unwrap_or_default();
    let transcript_language_satisfied = if transcript_selected {
        transcript_language
            .trim()
            .to_ascii_lowercase()
            .starts_with("en")
    } else {
        transcript_language.trim().is_empty()
    };
    let transcript_source_kind = receipt.transcript_source_kind.clone().unwrap_or_default();
    let transcript_source_kind_satisfied = if transcript_selected {
        matches!(
            transcript_source_kind.trim(),
            "manual" | "automatic" | "stt" | "watch_transcript"
        )
    } else {
        transcript_source_kind.trim().is_empty()
    };
    let transcript_hash_satisfied = if transcript_selected {
        receipt
            .transcript_hash
            .as_deref()
            .map(str::trim)
            .is_some_and(|value| !value.is_empty())
    } else {
        receipt
            .transcript_hash
            .as_deref()
            .unwrap_or_default()
            .trim()
            .is_empty()
    };
    let timeline_provider_id = receipt.timeline_provider_id.clone().unwrap_or_default();
    let timeline_provider_id_satisfied = if timeline_selected {
        timeline_provider_id
            .trim()
            .eq_ignore_ascii_case("youtube.key_moments_timeline")
    } else {
        timeline_provider_id.trim().is_empty()
    };
    let timeline_provider_version = receipt
        .timeline_provider_version
        .clone()
        .unwrap_or_default();
    let timeline_provider_version_satisfied = if timeline_selected {
        !timeline_provider_version.trim().is_empty()
    } else {
        timeline_provider_version.trim().is_empty()
    };
    let timeline_source_kind = receipt.timeline_source_kind.clone().unwrap_or_default();
    let timeline_source_kind_satisfied = if timeline_selected {
        timeline_source_kind
            .trim()
            .eq_ignore_ascii_case("key_moments")
    } else {
        timeline_source_kind.trim().is_empty()
    };
    let timeline_cue_count = receipt.timeline_cue_count.unwrap_or_default();
    let timeline_cue_count_satisfied = if timeline_selected {
        timeline_cue_count >= 5
    } else {
        timeline_cue_count == 0
    };
    let timeline_char_count = receipt.timeline_char_count.unwrap_or_default();
    let timeline_char_count_satisfied = if timeline_selected {
        timeline_char_count >= 120
    } else {
        timeline_char_count == 0
    };
    let timeline_hash = receipt.timeline_hash.clone().unwrap_or_default();
    let timeline_hash_satisfied = if timeline_selected {
        !timeline_hash.trim().is_empty()
    } else {
        timeline_hash.trim().is_empty()
    };
    let visual_provider_id = receipt.visual_provider_id.clone().unwrap_or_default();
    let visual_provider_id_satisfied = matches!(
        visual_provider_id.trim(),
        "ffmpeg.managed_frames_vision" | "youtube.chapter_thumbnails_vision"
    );
    let visual_provider_uses_managed_binary =
        visual_provider_id.eq_ignore_ascii_case("ffmpeg.managed_frames_vision");
    let visual_frame_count = receipt.visual_frame_count.unwrap_or_default();
    let visual_frame_count_satisfied = visual_frame_count >= 4;
    let visual_char_count = receipt.visual_char_count.unwrap_or_default();
    let visual_char_count_satisfied = visual_char_count >= 100;
    let visual_hash = receipt.visual_hash.clone().unwrap_or_default();
    let visual_hash_satisfied = !visual_hash.trim().is_empty();
    let visual_provider_binary_path = receipt
        .visual_provider_binary_path
        .clone()
        .unwrap_or_default();
    let visual_provider_binary_path_buf = PathBuf::from(visual_provider_binary_path.trim());
    let visual_provider_binary_satisfied = if visual_provider_uses_managed_binary {
        visual_provider_binary_path_buf.is_file()
            && visual_provider_binary_path_buf.starts_with(&fixture.tool_home)
    } else {
        visual_provider_binary_path.trim().is_empty()
    };
    let visual_ffprobe_path = receipt.visual_ffprobe_path.clone().unwrap_or_default();
    let visual_ffprobe_path_buf = PathBuf::from(visual_ffprobe_path.trim());
    let visual_ffprobe_satisfied = if visual_provider_uses_managed_binary {
        visual_ffprobe_path_buf.is_file() && visual_ffprobe_path_buf.starts_with(&fixture.tool_home)
    } else {
        visual_ffprobe_path.trim().is_empty()
    };
    let scope_satisfied = fixture.tool_home.starts_with(&fixture.fixture_root)
        && fixture.receipt_path.starts_with(&fixture.tool_home)
        && (!transcript_provider_uses_managed_binary
            || transcript_provider_binary_path_buf.starts_with(&fixture.tool_home))
        && (!visual_provider_uses_managed_binary
            || visual_provider_binary_path_buf.starts_with(&fixture.tool_home))
        && (transcript_provider_model_path.trim().is_empty()
            || transcript_provider_model_path_buf.starts_with(&fixture.tool_home))
        && (!visual_provider_uses_managed_binary
            || visual_ffprobe_path_buf.starts_with(&fixture.tool_home));
    let transcript_provider_version_satisfied = if transcript_selected {
        receipt
            .transcript_provider_version
            .as_deref()
            .map(str::trim)
            .is_some_and(|value| !value.is_empty())
    } else {
        receipt
            .transcript_provider_version
            .as_deref()
            .unwrap_or_default()
            .trim()
            .is_empty()
    };
    let visual_provider_version_satisfied = receipt
        .visual_provider_version
        .as_deref()
        .map(str::trim)
        .is_some_and(|value| !value.is_empty());
    let mut batch = EnvironmentEvidenceBatch::default();
    push_environment_receipt(
        &mut batch,
        "media_multimodal_receipt_path",
        fixture.receipt_path.to_string_lossy().to_string(),
        Some(probe_source.clone()),
        Some(timestamp_ms),
        Some(receipt_present_satisfied),
    );
    push_environment_metadata(
        &mut batch,
        "media_multimodal_receipt",
        Some(probe_source.clone()),
        Some(timestamp_ms),
        Some(receipt_present_satisfied),
    );
    push_environment_receipt(
        &mut batch,
        "media_multimodal_transcript_provider_id",
        transcript_provider_id,
        Some(probe_source.clone()),
        Some(timestamp_ms),
        Some(transcript_provider_id_satisfied && transcript_provider_binary_satisfied),
    );
    push_environment_receipt(
        &mut batch,
        "media_multimodal_transcript_provider_version",
        receipt.transcript_provider_version.unwrap_or_default(),
        Some(probe_source.clone()),
        Some(timestamp_ms),
        Some(transcript_provider_version_satisfied),
    );
    push_environment_receipt(
        &mut batch,
        "media_multimodal_transcript_provider_binary_path",
        transcript_provider_binary_path,
        Some(probe_source.clone()),
        Some(timestamp_ms),
        Some(transcript_provider_binary_satisfied),
    );
    push_environment_receipt(
        &mut batch,
        "media_multimodal_transcript_provider_model_id",
        transcript_provider_model_id,
        Some(probe_source.clone()),
        Some(timestamp_ms),
        Some(transcript_provider_model_satisfied),
    );
    push_environment_receipt(
        &mut batch,
        "media_multimodal_transcript_provider_model_path",
        transcript_provider_model_path,
        Some(probe_source.clone()),
        Some(timestamp_ms),
        Some(transcript_provider_model_satisfied),
    );
    push_environment_receipt(
        &mut batch,
        "media_multimodal_transcript_selected_audio_format_id",
        transcript_selected_audio_format_id,
        Some(probe_source.clone()),
        Some(timestamp_ms),
        Some(transcript_selected_audio_satisfied),
    );
    push_environment_receipt(
        &mut batch,
        "media_multimodal_transcript_selected_audio_ext",
        transcript_selected_audio_ext,
        Some(probe_source.clone()),
        Some(timestamp_ms),
        Some(transcript_selected_audio_satisfied),
    );
    push_environment_receipt(
        &mut batch,
        "media_multimodal_transcript_selected_audio_acodec",
        transcript_selected_audio_acodec,
        Some(probe_source.clone()),
        Some(timestamp_ms),
        Some(transcript_selected_audio_satisfied),
    );
    push_environment_receipt(
        &mut batch,
        "media_multimodal_requested_url",
        receipt.requested_url,
        Some(probe_source.clone()),
        Some(timestamp_ms),
        Some(requested_url_satisfied),
    );
    push_environment_receipt(
        &mut batch,
        "media_multimodal_canonical_url",
        receipt.canonical_url,
        Some(probe_source.clone()),
        Some(timestamp_ms),
        Some(canonical_url_satisfied),
    );
    push_environment_receipt(
        &mut batch,
        "media_multimodal_title",
        receipt.title.unwrap_or_default(),
        Some(probe_source.clone()),
        Some(timestamp_ms),
        Some(title_satisfied),
    );
    push_environment_receipt(
        &mut batch,
        "media_multimodal_duration_seconds",
        duration_seconds.to_string(),
        Some(probe_source.clone()),
        Some(timestamp_ms),
        Some(duration_satisfied),
    );
    push_environment_receipt(
        &mut batch,
        "media_multimodal_transcript_char_count",
        transcript_char_count.to_string(),
        Some(probe_source.clone()),
        Some(timestamp_ms),
        Some(transcript_char_count_satisfied),
    );
    push_environment_receipt(
        &mut batch,
        "media_multimodal_transcript_segment_count",
        transcript_segment_count.to_string(),
        Some(probe_source.clone()),
        Some(timestamp_ms),
        Some(transcript_segment_count_satisfied),
    );
    push_environment_receipt(
        &mut batch,
        "media_multimodal_transcript_language",
        transcript_language,
        Some(probe_source.clone()),
        Some(timestamp_ms),
        Some(transcript_language_satisfied),
    );
    push_environment_receipt(
        &mut batch,
        "media_multimodal_transcript_source_kind",
        transcript_source_kind,
        Some(probe_source.clone()),
        Some(timestamp_ms),
        Some(transcript_source_kind_satisfied),
    );
    push_environment_receipt(
        &mut batch,
        "media_multimodal_transcript_hash",
        receipt.transcript_hash.unwrap_or_default(),
        Some(probe_source.clone()),
        Some(timestamp_ms),
        Some(transcript_hash_satisfied),
    );
    push_environment_receipt(
        &mut batch,
        "media_multimodal_timeline_provider_id",
        timeline_provider_id,
        Some(probe_source.clone()),
        Some(timestamp_ms),
        Some(timeline_provider_id_satisfied),
    );
    push_environment_receipt(
        &mut batch,
        "media_multimodal_timeline_provider_version",
        timeline_provider_version,
        Some(probe_source.clone()),
        Some(timestamp_ms),
        Some(timeline_provider_version_satisfied),
    );
    push_environment_receipt(
        &mut batch,
        "media_multimodal_timeline_source_kind",
        timeline_source_kind,
        Some(probe_source.clone()),
        Some(timestamp_ms),
        Some(timeline_source_kind_satisfied),
    );
    push_environment_receipt(
        &mut batch,
        "media_multimodal_timeline_cue_count",
        timeline_cue_count.to_string(),
        Some(probe_source.clone()),
        Some(timestamp_ms),
        Some(timeline_cue_count_satisfied),
    );
    push_environment_receipt(
        &mut batch,
        "media_multimodal_timeline_char_count",
        timeline_char_count.to_string(),
        Some(probe_source.clone()),
        Some(timestamp_ms),
        Some(timeline_char_count_satisfied),
    );
    push_environment_receipt(
        &mut batch,
        "media_multimodal_timeline_hash",
        timeline_hash,
        Some(probe_source.clone()),
        Some(timestamp_ms),
        Some(timeline_hash_satisfied),
    );
    push_environment_receipt(
        &mut batch,
        "media_multimodal_visual_provider_id",
        visual_provider_id,
        Some(probe_source.clone()),
        Some(timestamp_ms),
        Some(visual_provider_id_satisfied && visual_provider_binary_satisfied),
    );
    push_environment_receipt(
        &mut batch,
        "media_multimodal_visual_provider_version",
        receipt.visual_provider_version.unwrap_or_default(),
        Some(probe_source.clone()),
        Some(timestamp_ms),
        Some(visual_provider_version_satisfied),
    );
    push_environment_receipt(
        &mut batch,
        "media_multimodal_visual_provider_binary_path",
        visual_provider_binary_path,
        Some(probe_source.clone()),
        Some(timestamp_ms),
        Some(visual_provider_binary_satisfied),
    );
    push_environment_receipt(
        &mut batch,
        "media_multimodal_visual_ffprobe_path",
        visual_ffprobe_path,
        Some(probe_source.clone()),
        Some(timestamp_ms),
        Some(visual_ffprobe_satisfied),
    );
    push_environment_receipt(
        &mut batch,
        "media_multimodal_visual_frame_count",
        visual_frame_count.to_string(),
        Some(probe_source.clone()),
        Some(timestamp_ms),
        Some(visual_frame_count_satisfied),
    );
    push_environment_receipt(
        &mut batch,
        "media_multimodal_visual_char_count",
        visual_char_count.to_string(),
        Some(probe_source.clone()),
        Some(timestamp_ms),
        Some(visual_char_count_satisfied),
    );
    push_environment_receipt(
        &mut batch,
        "media_multimodal_visual_hash",
        visual_hash,
        Some(probe_source.clone()),
        Some(timestamp_ms),
        Some(visual_hash_satisfied),
    );
    push_environment_receipt(
        &mut batch,
        "media_multimodal_selected_modalities",
        selected_modalities_value,
        Some(probe_source.clone()),
        Some(timestamp_ms),
        Some(selected_modalities_satisfied),
    );
    push_environment_observation(
        &mut batch,
        "media_multimodal_retrieved_at_ms",
        receipt.retrieved_at_ms.to_string(),
    );
    push_environment_metadata(
        &mut batch,
        "media_multimodal_scope",
        Some(probe_source),
        Some(timestamp_ms),
        Some(scope_satisfied),
    );
    batch
}

fn media_transcript_fixture_cleanup_checks(
    fixture: &MediaTranscriptFixtureRuntime,
) -> EnvironmentEvidenceBatch {
    let timestamp_ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64;
    let probe_source = format!(
        "{}.cleanup_probe",
        MEDIA_TRANSCRIPT_SUMMARY_FIXTURE_PROBE_SOURCE
    );
    let _ = std::fs::remove_dir_all(&fixture.fixture_root);
    let fixture_root_exists_after_cleanup = fixture.fixture_root.exists();
    let receipt_exists_after_cleanup = fixture.receipt_path.exists();
    let cleanup_satisfied = !fixture_root_exists_after_cleanup && !receipt_exists_after_cleanup;
    let mut batch = EnvironmentEvidenceBatch::default();
    push_environment_observation(
        &mut batch,
        "media_multimodal_cleanup_fixture_root_exists",
        fixture_root_exists_after_cleanup.to_string(),
    );
    push_environment_observation(
        &mut batch,
        "media_multimodal_cleanup_receipt_exists",
        receipt_exists_after_cleanup.to_string(),
    );
    push_environment_metadata(
        &mut batch,
        "media_multimodal_cleanup",
        Some(probe_source),
        Some(timestamp_ms),
        Some(cleanup_satisfied),
    );
    batch
}

fn bootstrap_shutdown_schedule_fixture_runtime(
    run_unique_num: &str,
) -> Result<ShutdownScheduleFixtureRuntime> {
    let temp_dir = tempdir()?;
    let fixture_root = temp_dir
        .path()
        .join(format!("shutdown_schedule_{}", run_unique_num));
    let fixture_bin = fixture_root.join("bin");
    let fixture_receipts = fixture_root.join("receipts");
    std::fs::create_dir_all(&fixture_bin)?;
    std::fs::create_dir_all(&fixture_receipts)?;

    let probe_script_path = fixture_bin.join(SHUTDOWN_SCHEDULE_PROBE_SCRIPT_NAME);
    let receipt_path = fixture_receipts.join("shutdown_schedule_receipt.txt");
    let provider_receipt_path = fixture_receipts.join("shutdown_provider_receipt.txt");
    let _ = std::fs::remove_file(&receipt_path);
    let _ = std::fs::remove_file(&provider_receipt_path);

    let sudo_script = r#"#!/usr/bin/env bash
set -euo pipefail
if [ "$#" -eq 0 ]; then
  exit 0
fi
args=()
for arg in "$@"; do
  case "$arg" in
    -n|-S|-k|--) ;;
    *) args+=("$arg") ;;
  esac
done
if [ "${#args[@]}" -eq 0 ]; then
  exit 0
fi
exec "${args[@]}"
"#;
    write_executable_script(&fixture_bin.join("sudo"), sudo_script)?;

    let provider_script = r#"#!/usr/bin/env bash
set -euo pipefail

provider="${1:-}"
if [ -z "$provider" ]; then
  echo "shutdown schedule fixture: missing provider id" >&2
  exit 2
fi
shift || true

provider_receipt_path="${IOI_SHUTDOWN_SCHEDULE_PROVIDER_RECEIPT_PATH:-}"
if [ -z "$provider_receipt_path" ]; then
  echo "shutdown schedule fixture: IOI_SHUTDOWN_SCHEDULE_PROVIDER_RECEIPT_PATH missing" >&2
  exit 3
fi

mkdir -p "$(dirname "$provider_receipt_path")"
{
  echo "provider=${provider}"
  echo "provider_invoked=true"
  echo "provider_args=$*"
} > "$provider_receipt_path"

case "$provider" in
  shutdown|systemctl|at)
    exit 0
    ;;
  *)
    echo "shutdown schedule fixture: unsupported provider '$provider'" >&2
    exit 2
    ;;
esac
"#;
    write_executable_script(
        &fixture_bin.join("shutdown_fixture_provider"),
        provider_script,
    )?;

    write_executable_script(
        &fixture_bin.join("shutdown"),
        "#!/usr/bin/env bash\nset -euo pipefail\nexec shutdown_fixture_provider shutdown \"$@\"\n",
    )?;
    write_executable_script(
        &fixture_bin.join("systemctl"),
        "#!/usr/bin/env bash\nset -euo pipefail\nexec shutdown_fixture_provider systemctl \"$@\"\n",
    )?;
    write_executable_script(
        &fixture_bin.join("at"),
        "#!/usr/bin/env bash\nset -euo pipefail\nexec shutdown_fixture_provider at \"$@\"\n",
    )?;
    write_executable_script(
        &fixture_bin.join("poweroff"),
        "#!/usr/bin/env bash\nset -euo pipefail\nexec shutdown_fixture_provider shutdown poweroff \"$@\"\n",
    )?;
    write_executable_script(
        &fixture_bin.join("halt"),
        "#!/usr/bin/env bash\nset -euo pipefail\nexec shutdown_fixture_provider shutdown halt \"$@\"\n",
    )?;
    write_executable_script(
        &fixture_bin.join("reboot"),
        "#!/usr/bin/env bash\nset -euo pipefail\nexec shutdown_fixture_provider shutdown reboot \"$@\"\n",
    )?;

    let probe_script = r##"#!/usr/bin/env bash
set -euo pipefail

if [ "${1:-}" != "--target-local" ]; then
  echo "expected usage: shutdown_schedule_probe --target-local <HH:MM>" >&2
  exit 2
fi
target_local="${2:-}"
if [ -z "$target_local" ]; then
  echo "missing --target-local value" >&2
  exit 2
fi
if ! [[ "$target_local" =~ ^([0-1][0-9]|2[0-3]):[0-5][0-9]$ ]]; then
  echo "invalid target time format '$target_local'; expected HH:MM" >&2
  exit 2
fi

receipt_path="${IOI_SHUTDOWN_SCHEDULE_RECEIPT_PATH:-}"
run_unique_num="${IOI_SHUTDOWN_SCHEDULE_RUN_UNIQUE_NUM:-}"
if [ -z "$receipt_path" ]; then
  echo "missing IOI_SHUTDOWN_SCHEDULE_RECEIPT_PATH" >&2
  exit 3
fi
if [ -z "$run_unique_num" ]; then
  echo "missing IOI_SHUTDOWN_SCHEDULE_RUN_UNIQUE_NUM" >&2
  exit 3
fi

for required in date shutdown_fixture_provider; do
  if ! command -v "$required" >/dev/null 2>&1; then
    echo "missing required provider binary: $required" >&2
    exit 4
  fi
done

provider=""
for candidate in shutdown systemctl at; do
  if command -v "$candidate" >/dev/null 2>&1; then
    provider="$candidate"
    break
  fi
done
if [ -z "$provider" ]; then
  echo "no supported shutdown scheduling provider found" >&2
  exit 5
fi

now_epoch="$(date +%s 2>/dev/null || true)"
today_date="$(date +%F 2>/dev/null || true)"
target_today_epoch="$(date -d "${today_date} ${target_local}:00" +%s 2>/dev/null || true)"
if [ -z "$now_epoch" ] || [ -z "$today_date" ] || [ -z "$target_today_epoch" ]; then
  echo "date provider did not return required values" >&2
  exit 6
fi
if ! [[ "$now_epoch" =~ ^-?[0-9]+$ ]] || ! [[ "$target_today_epoch" =~ ^-?[0-9]+$ ]]; then
  echo "date provider returned non-numeric epoch values" >&2
  exit 6
fi

target_epoch="$target_today_epoch"
rollover_to_next_day=false
if [ "$target_epoch" -le "$now_epoch" ]; then
  target_epoch="$((target_today_epoch + 86400))"
  rollover_to_next_day=true
fi
delay_seconds="$((target_epoch - now_epoch))"
if [ "$delay_seconds" -le 0 ]; then
  echo "computed delay_seconds must be positive" >&2
  exit 7
fi
target_local_date="$(date -d "@${target_epoch}" +%F 2>/dev/null || true)"
if [ -z "$target_local_date" ]; then
  echo "failed to compute local target date" >&2
  exit 7
fi

case "$provider" in
  shutdown)
    shutdown -h "$target_local"
    ;;
  systemctl)
    systemctl poweroff "--when=${target_local}"
    ;;
  at)
    at "$target_local" </dev/null
    ;;
  *)
    echo "unsupported provider '$provider'" >&2
    exit 8
    ;;
esac

mkdir -p "$(dirname "$receipt_path")"
{
  echo "provider=${provider}"
  echo "target_local_time=${target_local}"
  echo "target_local_date=${target_local_date}"
  echo "now_epoch_sec=${now_epoch}"
  echo "target_epoch_sec=${target_epoch}"
  echo "delay_seconds=${delay_seconds}"
  echo "rollover_to_next_day=${rollover_to_next_day}"
  echo "run_unique_num=${run_unique_num}"
  echo "scheduled=true"
} > "$receipt_path"

cat "$receipt_path"
"##;
    write_executable_script(&probe_script_path, probe_script)?;

    let inherited_path = std::env::var("PATH").unwrap_or_default();
    let fixture_path = format!("{}:{}", fixture_bin.to_string_lossy(), inherited_path);
    let env_path = ScopedEnvVar::set("PATH", fixture_path);
    let env_fixture_mode = ScopedEnvVar::set(
        "IOI_SHUTDOWN_SCHEDULE_FIXTURE_MODE",
        SHUTDOWN_SCHEDULE_FIXTURE_MODE,
    );
    let env_receipt_path = ScopedEnvVar::set(
        "IOI_SHUTDOWN_SCHEDULE_RECEIPT_PATH",
        receipt_path.to_string_lossy().to_string(),
    );
    let env_provider_receipt_path = ScopedEnvVar::set(
        "IOI_SHUTDOWN_SCHEDULE_PROVIDER_RECEIPT_PATH",
        provider_receipt_path.to_string_lossy().to_string(),
    );
    let env_run_unique_num = ScopedEnvVar::set(
        "IOI_SHUTDOWN_SCHEDULE_RUN_UNIQUE_NUM",
        run_unique_num.to_string(),
    );

    Ok(ShutdownScheduleFixtureRuntime {
        _temp_dir: temp_dir,
        _env_path: env_path,
        _env_fixture_mode: env_fixture_mode,
        _env_receipt_path: env_receipt_path,
        _env_provider_receipt_path: env_provider_receipt_path,
        _env_run_unique_num: env_run_unique_num,
        fixture_root,
        probe_script_path,
        receipt_path,
        provider_receipt_path,
    })
}

fn shutdown_schedule_fixture_preflight_checks(
    fixture: &ShutdownScheduleFixtureRuntime,
    run_unique_num: &str,
    run_timestamp_ms: u64,
) -> EnvironmentEvidenceBatch {
    let run_unique_satisfied = fixture
        .fixture_root
        .file_name()
        .and_then(|name| name.to_str())
        .map(|name| name.ends_with(run_unique_num))
        .unwrap_or(false);
    let probe_script_seeded_satisfied = fixture.probe_script_path.is_file();
    let receipt_absent_satisfied = !fixture.receipt_path.exists();
    let provider_receipt_absent_satisfied = !fixture.provider_receipt_path.exists();
    let fixture_satisfied = run_unique_satisfied
        && probe_script_seeded_satisfied
        && receipt_absent_satisfied
        && provider_receipt_absent_satisfied;
    let mut batch = EnvironmentEvidenceBatch::default();
    push_environment_observation(
        &mut batch,
        "shutdown_schedule_fixture_mode",
        SHUTDOWN_SCHEDULE_FIXTURE_MODE,
    );
    push_environment_observation(
        &mut batch,
        "shutdown_schedule_fixture_root",
        fixture.fixture_root.to_string_lossy().to_string(),
    );
    push_environment_observation(
        &mut batch,
        "shutdown_schedule_probe_script_path",
        fixture.probe_script_path.to_string_lossy().to_string(),
    );
    push_environment_observation(
        &mut batch,
        "shutdown_schedule_receipt_path",
        fixture.receipt_path.to_string_lossy().to_string(),
    );
    push_environment_observation(
        &mut batch,
        "shutdown_schedule_provider_receipt_path",
        fixture.provider_receipt_path.to_string_lossy().to_string(),
    );
    push_environment_observation(
        &mut batch,
        "shutdown_schedule_run_unique_num",
        run_unique_num.to_string(),
    );
    push_environment_metadata(
        &mut batch,
        "shutdown_schedule_run_unique",
        Some(SHUTDOWN_SCHEDULE_FIXTURE_PROBE_SOURCE.to_string()),
        Some(run_timestamp_ms),
        Some(run_unique_satisfied),
    );
    push_environment_metadata(
        &mut batch,
        "shutdown_schedule_probe_script_seeded",
        Some(SHUTDOWN_SCHEDULE_FIXTURE_PROBE_SOURCE.to_string()),
        Some(run_timestamp_ms),
        Some(probe_script_seeded_satisfied),
    );
    push_environment_metadata(
        &mut batch,
        "shutdown_schedule_receipt_absent",
        Some(SHUTDOWN_SCHEDULE_FIXTURE_PROBE_SOURCE.to_string()),
        Some(run_timestamp_ms),
        Some(receipt_absent_satisfied),
    );
    push_environment_metadata(
        &mut batch,
        "shutdown_schedule_provider_receipt_absent",
        Some(SHUTDOWN_SCHEDULE_FIXTURE_PROBE_SOURCE.to_string()),
        Some(run_timestamp_ms),
        Some(provider_receipt_absent_satisfied),
    );
    push_environment_metadata(
        &mut batch,
        "shutdown_schedule_fixture",
        Some(SHUTDOWN_SCHEDULE_FIXTURE_PROBE_SOURCE.to_string()),
        Some(run_timestamp_ms),
        Some(fixture_satisfied),
    );
    batch
}

fn parse_shutdown_schedule_probe_receipt(path: &Path) -> ShutdownScheduleProbeReceipt {
    let mut receipt = ShutdownScheduleProbeReceipt::default();
    let raw = std::fs::read_to_string(path).unwrap_or_default();
    for line in raw.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        let Some((key, value)) = trimmed.split_once('=') else {
            continue;
        };
        let key = key.trim();
        let value = value.trim();
        match key {
            "provider" => receipt.provider = value.to_string(),
            "target_local_time" => receipt.target_local_time = value.to_string(),
            "target_local_date" => receipt.target_local_date = value.to_string(),
            "now_epoch_sec" => receipt.now_epoch_sec = value.parse::<i64>().unwrap_or_default(),
            "target_epoch_sec" => {
                receipt.target_epoch_sec = value.parse::<i64>().unwrap_or_default()
            }
            "delay_seconds" => receipt.delay_seconds = value.parse::<i64>().unwrap_or_default(),
            "rollover_to_next_day" => {
                receipt.rollover_to_next_day = value.eq_ignore_ascii_case("true")
            }
            "run_unique_num" => receipt.run_unique_num = value.to_string(),
            "scheduled" => receipt.scheduled = value.eq_ignore_ascii_case("true"),
            _ => {}
        }
    }
    receipt
}

fn shutdown_schedule_fixture_post_run_checks(
    fixture: &ShutdownScheduleFixtureRuntime,
) -> EnvironmentEvidenceBatch {
    let timestamp_ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64;
    let probe_source = format!("{}.receipt_probe", SHUTDOWN_SCHEDULE_FIXTURE_PROBE_SOURCE);

    let receipt_path_satisfied = fixture.receipt_path.is_file();
    let provider_receipt_path_satisfied = fixture.provider_receipt_path.is_file();
    let receipt = if receipt_path_satisfied {
        parse_shutdown_schedule_probe_receipt(&fixture.receipt_path)
    } else {
        ShutdownScheduleProbeReceipt::default()
    };
    let provider_receipt = if provider_receipt_path_satisfied {
        parse_shutdown_provider_invocation_receipt(&fixture.provider_receipt_path)
    } else {
        ShutdownProviderInvocationReceipt::default()
    };

    let provider_satisfied = SHUTDOWN_SCHEDULE_PROVIDER_IDS
        .iter()
        .any(|provider| receipt.provider.eq_ignore_ascii_case(provider));
    let target_local_time_satisfied =
        receipt.target_local_time == SHUTDOWN_SCHEDULE_TARGET_LOCAL_TIME;
    let target_after_run_satisfied = receipt.target_epoch_sec > 0
        && receipt.now_epoch_sec > 0
        && receipt.target_epoch_sec > receipt.now_epoch_sec;
    let expected_delay = receipt
        .target_epoch_sec
        .saturating_sub(receipt.now_epoch_sec);
    let delay_window_satisfied = target_after_run_satisfied
        && expected_delay == receipt.delay_seconds
        && receipt.delay_seconds > 0
        && receipt.delay_seconds <= 86_400;
    let run_unique_match_satisfied = !receipt.run_unique_num.trim().is_empty()
        && fixture
            .fixture_root
            .file_name()
            .and_then(|name| name.to_str())
            .map(|name| name.ends_with(&receipt.run_unique_num))
            .unwrap_or(false);
    let provider_invoked_satisfied = provider_receipt.provider_invoked
        && provider_receipt
            .provider
            .eq_ignore_ascii_case(&receipt.provider);
    let provider_args_target_satisfied = provider_receipt
        .provider_args
        .contains(SHUTDOWN_SCHEDULE_TARGET_LOCAL_TIME);
    let scheduled_satisfied = receipt.scheduled;
    let scope_satisfied = provider_satisfied
        && target_local_time_satisfied
        && target_after_run_satisfied
        && delay_window_satisfied
        && run_unique_match_satisfied
        && scheduled_satisfied
        && provider_invoked_satisfied
        && provider_args_target_satisfied
        && receipt_path_satisfied
        && provider_receipt_path_satisfied;
    let mut batch = EnvironmentEvidenceBatch::default();
    push_environment_receipt(
        &mut batch,
        "shutdown_schedule_provider",
        receipt.provider,
        Some(probe_source.clone()),
        Some(timestamp_ms),
        Some(provider_satisfied),
    );
    push_environment_receipt(
        &mut batch,
        "shutdown_schedule_target_local_time",
        receipt.target_local_time,
        None,
        None,
        Some(target_local_time_satisfied),
    );
    push_environment_observation(
        &mut batch,
        "shutdown_schedule_target_local_date",
        receipt.target_local_date,
    );
    push_environment_observation(
        &mut batch,
        "shutdown_schedule_now_epoch_sec",
        receipt.now_epoch_sec.to_string(),
    );
    push_environment_observation(
        &mut batch,
        "shutdown_schedule_target_epoch_sec",
        receipt.target_epoch_sec.to_string(),
    );
    push_environment_observation(
        &mut batch,
        "shutdown_schedule_delay_seconds",
        receipt.delay_seconds.to_string(),
    );
    push_environment_metadata(
        &mut batch,
        "shutdown_schedule_delay_window",
        Some(probe_source.clone()),
        Some(timestamp_ms),
        Some(delay_window_satisfied),
    );
    push_environment_metadata(
        &mut batch,
        "shutdown_schedule_target_after_run",
        Some(probe_source.clone()),
        Some(timestamp_ms),
        Some(target_after_run_satisfied),
    );
    push_environment_observation(
        &mut batch,
        "shutdown_schedule_rollover_to_next_day",
        receipt.rollover_to_next_day.to_string(),
    );
    push_environment_observation(
        &mut batch,
        "shutdown_schedule_run_unique_observed",
        receipt.run_unique_num,
    );
    push_environment_metadata(
        &mut batch,
        "shutdown_schedule_run_unique_match",
        Some(probe_source.clone()),
        Some(timestamp_ms),
        Some(run_unique_match_satisfied),
    );
    push_environment_metadata(
        &mut batch,
        "shutdown_schedule_scheduled",
        Some(probe_source.clone()),
        Some(timestamp_ms),
        Some(scheduled_satisfied),
    );
    push_environment_observation(
        &mut batch,
        "shutdown_schedule_provider_receipt_provider",
        provider_receipt.provider,
    );
    push_environment_observation(
        &mut batch,
        "shutdown_schedule_provider_args",
        provider_receipt.provider_args,
    );
    push_environment_metadata(
        &mut batch,
        "shutdown_schedule_provider_receipt",
        Some(probe_source.clone()),
        Some(timestamp_ms),
        Some(provider_receipt_path_satisfied),
    );
    push_environment_metadata(
        &mut batch,
        "shutdown_schedule_provider_invoked",
        Some(probe_source.clone()),
        Some(timestamp_ms),
        Some(provider_invoked_satisfied),
    );
    push_environment_metadata(
        &mut batch,
        "shutdown_schedule_provider_args_target",
        Some(probe_source.clone()),
        Some(timestamp_ms),
        Some(provider_args_target_satisfied),
    );
    push_environment_observation(
        &mut batch,
        "shutdown_schedule_receipt_path",
        fixture.receipt_path.to_string_lossy().to_string(),
    );
    push_environment_observation(
        &mut batch,
        "shutdown_schedule_provider_receipt_path",
        fixture.provider_receipt_path.to_string_lossy().to_string(),
    );
    push_environment_metadata(
        &mut batch,
        "shutdown_schedule_receipt_path",
        Some(probe_source.clone()),
        Some(timestamp_ms),
        Some(receipt_path_satisfied),
    );
    push_environment_metadata(
        &mut batch,
        "shutdown_schedule_provider_receipt_path",
        Some(probe_source.clone()),
        Some(timestamp_ms),
        Some(provider_receipt_path_satisfied),
    );
    push_environment_metadata(
        &mut batch,
        "shutdown_schedule_scope",
        Some(probe_source),
        Some(timestamp_ms),
        Some(scope_satisfied),
    );
    batch
}

fn shutdown_schedule_fixture_cleanup_checks(
    fixture: &ShutdownScheduleFixtureRuntime,
) -> EnvironmentEvidenceBatch {
    let timestamp_ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64;
    let probe_source = format!("{}.cleanup_probe", SHUTDOWN_SCHEDULE_FIXTURE_PROBE_SOURCE);
    let _ = std::fs::remove_file(&fixture.receipt_path);
    let _ = std::fs::remove_file(&fixture.provider_receipt_path);
    let _ = std::fs::remove_dir_all(&fixture.fixture_root);
    let fixture_root_exists_after_cleanup = fixture.fixture_root.exists();
    let receipt_exists_after_cleanup = fixture.receipt_path.exists();
    let provider_receipt_exists_after_cleanup = fixture.provider_receipt_path.exists();
    let cleanup_satisfied = !fixture_root_exists_after_cleanup
        && !receipt_exists_after_cleanup
        && !provider_receipt_exists_after_cleanup;
    let mut batch = EnvironmentEvidenceBatch::default();
    push_environment_observation(
        &mut batch,
        "shutdown_schedule_cleanup_fixture_root_exists",
        fixture_root_exists_after_cleanup.to_string(),
    );
    push_environment_observation(
        &mut batch,
        "shutdown_schedule_cleanup_receipt_exists",
        receipt_exists_after_cleanup.to_string(),
    );
    push_environment_observation(
        &mut batch,
        "shutdown_schedule_cleanup_provider_receipt_exists",
        provider_receipt_exists_after_cleanup.to_string(),
    );
    push_environment_metadata(
        &mut batch,
        "shutdown_schedule_cleanup",
        Some(probe_source),
        Some(timestamp_ms),
        Some(cleanup_satisfied),
    );
    batch
}

fn bootstrap_hacker_news_monitor_fixture_runtime(
    run_unique_num: &str,
) -> Result<HackerNewsMonitorFixtureRuntime> {
    let temp_dir = tempdir()?;
    let fixture_root = temp_dir
        .path()
        .join(format!("ioi_hn_front_page_monitor_{}", run_unique_num));
    let automation_root = fixture_root.join("automation");
    std::fs::create_dir_all(&automation_root)?;
    let manifest_path = fixture_root.join(HACKER_NEWS_MONITOR_FIXTURE_MANIFEST_NAME);
    std::fs::write(
        &manifest_path,
        format!(
            "mode={}\nrun_unique_num={}\nautomation_root={}\n",
            HACKER_NEWS_MONITOR_FIXTURE_MODE,
            run_unique_num,
            automation_root.to_string_lossy()
        ),
    )?;

    let env_automation_root = ScopedEnvVar::set(
        ioi_services::agentic::automation::AUTOMATION_ROOT_ENV_VAR,
        automation_root.to_string_lossy().to_string(),
    );
    let env_fixture_mode = ScopedEnvVar::set(
        "IOI_HACKER_NEWS_MONITOR_FIXTURE_MODE",
        HACKER_NEWS_MONITOR_FIXTURE_MODE,
    );
    let env_run_unique_num = ScopedEnvVar::set(
        "IOI_HACKER_NEWS_MONITOR_RUN_UNIQUE_NUM",
        run_unique_num.to_string(),
    );

    Ok(HackerNewsMonitorFixtureRuntime {
        _temp_dir: temp_dir,
        _env_automation_root: env_automation_root,
        _env_fixture_mode: env_fixture_mode,
        _env_run_unique_num: env_run_unique_num,
        fixture_root,
        automation_root,
        manifest_path,
    })
}

fn hacker_news_monitor_fixture_preflight_checks(
    fixture: &HackerNewsMonitorFixtureRuntime,
    run_unique_num: &str,
    run_timestamp_ms: u64,
) -> EnvironmentEvidenceBatch {
    let registry_path =
        ioi_services::agentic::automation::registry_path_for(&fixture.automation_root);
    let receipts_root = fixture.automation_root.join("receipts");
    let run_unique_satisfied = fixture
        .fixture_root
        .file_name()
        .and_then(|name| name.to_str())
        .map(|name| name.ends_with(run_unique_num))
        .unwrap_or(false);
    let automation_root_seeded_satisfied = fixture.automation_root.is_dir();
    let manifest_seeded_satisfied = fixture.manifest_path.is_file();
    let registry_absent_satisfied = !registry_path.exists();
    let receipts_absent_satisfied = !receipts_root.exists();
    let fixture_satisfied = run_unique_satisfied
        && automation_root_seeded_satisfied
        && manifest_seeded_satisfied
        && registry_absent_satisfied
        && receipts_absent_satisfied;

    let mut batch = EnvironmentEvidenceBatch::default();
    push_environment_observation(
        &mut batch,
        "hacker_news_monitor_fixture_mode",
        HACKER_NEWS_MONITOR_FIXTURE_MODE,
    );
    push_environment_observation(
        &mut batch,
        "hacker_news_monitor_fixture_root",
        fixture.fixture_root.to_string_lossy().to_string(),
    );
    push_environment_observation(
        &mut batch,
        "hacker_news_monitor_automation_root",
        fixture.automation_root.to_string_lossy().to_string(),
    );
    push_environment_observation(
        &mut batch,
        "hacker_news_monitor_fixture_manifest_path",
        fixture.manifest_path.to_string_lossy().to_string(),
    );
    push_environment_observation(
        &mut batch,
        "hacker_news_monitor_registry_path",
        registry_path.to_string_lossy().to_string(),
    );
    push_environment_observation(
        &mut batch,
        "hacker_news_monitor_run_unique_num",
        run_unique_num.to_string(),
    );
    push_environment_metadata(
        &mut batch,
        "hacker_news_monitor_run_unique",
        Some(HACKER_NEWS_MONITOR_FIXTURE_PROBE_SOURCE.to_string()),
        Some(run_timestamp_ms),
        Some(run_unique_satisfied),
    );
    push_environment_metadata(
        &mut batch,
        "hacker_news_monitor_automation_root_seeded",
        Some(HACKER_NEWS_MONITOR_FIXTURE_PROBE_SOURCE.to_string()),
        Some(run_timestamp_ms),
        Some(automation_root_seeded_satisfied),
    );
    push_environment_metadata(
        &mut batch,
        "hacker_news_monitor_fixture_manifest_seeded",
        Some(HACKER_NEWS_MONITOR_FIXTURE_PROBE_SOURCE.to_string()),
        Some(run_timestamp_ms),
        Some(manifest_seeded_satisfied),
    );
    push_environment_metadata(
        &mut batch,
        "hacker_news_monitor_registry_absent",
        Some(HACKER_NEWS_MONITOR_FIXTURE_PROBE_SOURCE.to_string()),
        Some(run_timestamp_ms),
        Some(registry_absent_satisfied),
    );
    push_environment_metadata(
        &mut batch,
        "hacker_news_monitor_receipts_absent",
        Some(HACKER_NEWS_MONITOR_FIXTURE_PROBE_SOURCE.to_string()),
        Some(run_timestamp_ms),
        Some(receipts_absent_satisfied),
    );
    push_environment_metadata(
        &mut batch,
        "hacker_news_monitor_fixture",
        Some(HACKER_NEWS_MONITOR_FIXTURE_PROBE_SOURCE.to_string()),
        Some(run_timestamp_ms),
        Some(fixture_satisfied),
    );
    batch
}

fn parse_hacker_news_monitor_json<T>(path: &Path) -> Option<T>
where
    T: for<'de> Deserialize<'de>,
{
    let bytes = std::fs::read(path).ok()?;
    serde_json::from_slice::<T>(&bytes).ok()
}

fn normalize_hacker_news_monitor_keywords(values: &[String]) -> Vec<String> {
    let mut normalized = values
        .iter()
        .map(|value| value.trim().to_ascii_lowercase())
        .filter(|value| !value.is_empty())
        .collect::<Vec<_>>();
    normalized.sort();
    normalized.dedup();
    normalized
}

fn hacker_news_monitor_graph_kinds(
    artifact: &ioi_services::agentic::automation::WorkflowArtifact,
) -> Vec<String> {
    artifact
        .graph
        .nodes
        .iter()
        .map(|node| node.kind.clone())
        .collect()
}

fn hacker_news_monitor_fixture_post_run_checks(
    fixture: &HackerNewsMonitorFixtureRuntime,
) -> EnvironmentEvidenceBatch {
    let timestamp_ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64;
    let probe_source = format!("{}.receipt_probe", HACKER_NEWS_MONITOR_FIXTURE_PROBE_SOURCE);
    let registry_path =
        ioi_services::agentic::automation::registry_path_for(&fixture.automation_root);
    let registry_path_satisfied = registry_path.is_file();
    let registry = parse_hacker_news_monitor_json::<HackerNewsMonitorRegistry>(&registry_path)
        .unwrap_or_default();
    let registry_count = registry.workflows.len();
    let single_workflow_satisfied = registry_count == 1;
    let workflow_record = registry.workflows.into_iter().next().unwrap_or_default();
    let workflow_id = workflow_record.workflow_id.clone();
    let workflow_id_present = !workflow_id.trim().is_empty();
    let artifact_path = if workflow_id_present {
        ioi_services::agentic::automation::artifact_path_for(&fixture.automation_root, &workflow_id)
    } else {
        PathBuf::new()
    };
    let state_path = if workflow_id_present {
        ioi_services::agentic::automation::state_path_for(&fixture.automation_root, &workflow_id)
    } else {
        PathBuf::new()
    };
    let install_receipt_path = if workflow_id_present {
        fixture
            .automation_root
            .join("receipts")
            .join(&workflow_id)
            .join("install.json")
    } else {
        PathBuf::new()
    };
    let artifact_path_satisfied =
        artifact_path.is_file() && artifact_path.starts_with(&fixture.automation_root);
    let state_path_satisfied =
        state_path.is_file() && state_path.starts_with(&fixture.automation_root);
    let install_receipt_path_satisfied = install_receipt_path.is_file()
        && install_receipt_path.starts_with(&fixture.automation_root);

    let artifact = if artifact_path_satisfied {
        parse_hacker_news_monitor_json::<ioi_services::agentic::automation::WorkflowArtifact>(
            &artifact_path,
        )
    } else {
        None
    };
    let state = if state_path_satisfied {
        parse_hacker_news_monitor_json::<ioi_services::agentic::automation::WorkflowRuntimeState>(
            &state_path,
        )
    } else {
        None
    };
    let install_receipt = if install_receipt_path_satisfied {
        parse_hacker_news_monitor_json::<ioi_services::agentic::automation::WorkflowInstallReceipt>(
            &install_receipt_path,
        )
    } else {
        None
    };

    let spec_version = artifact
        .as_ref()
        .map(|value| value.spec_version.clone())
        .unwrap_or_default();
    let spec_version_satisfied =
        spec_version == "workflow.v1" && workflow_record.spec_version == "workflow.v1";
    let workflow_status_satisfied = workflow_record.status.eq_ignore_ascii_case("active");
    let source_url = artifact
        .as_ref()
        .map(|value| value.monitor.source.url.clone())
        .unwrap_or_default();
    let source_url_satisfied = source_url == "https://news.ycombinator.com/";
    let source_type = artifact
        .as_ref()
        .map(|value| value.monitor.source.source_type.clone())
        .unwrap_or_default();
    let source_type_satisfied = source_type == "hacker_news_front_page";
    let extractor_type = artifact
        .as_ref()
        .map(|value| value.monitor.extractor.extractor_type.clone())
        .unwrap_or_default();
    let extractor_type_satisfied = extractor_type == "hacker_news_front_page_titles";
    let extractor_selector = artifact
        .as_ref()
        .and_then(|value| value.monitor.extractor.selector.clone())
        .unwrap_or_default();
    let extractor_selector_satisfied = extractor_selector == "span.titleline > a";
    let predicate_type = artifact
        .as_ref()
        .map(|value| value.monitor.predicate.predicate_type.clone())
        .unwrap_or_default();
    let predicate_type_satisfied = predicate_type == "contains_any_title";
    let keywords = artifact
        .as_ref()
        .map(|value| normalize_hacker_news_monitor_keywords(&value.monitor.predicate.keywords))
        .unwrap_or_default();
    let keywords_normalized = keywords.join("|");
    let keywords_satisfied = keywords_normalized == "post-quantum cryptography|web4"
        && normalize_hacker_news_monitor_keywords(&workflow_record.keywords) == keywords;
    let poll_interval_seconds = artifact
        .as_ref()
        .map(|value| value.trigger.every_seconds)
        .unwrap_or_default();
    let poll_interval_satisfied =
        poll_interval_seconds == 300 && workflow_record.poll_interval_seconds == 300;
    let sink_type = artifact
        .as_ref()
        .map(|value| value.monitor.sink.sink_type.clone())
        .unwrap_or_default();
    let sink_rail = artifact
        .as_ref()
        .map(|value| value.monitor.sink.rail.clone())
        .unwrap_or_default();
    let sink_notification_class = artifact
        .as_ref()
        .map(|value| value.monitor.sink.notification_class.clone())
        .unwrap_or_default();
    let sink_satisfied = sink_type == "assistant_notification"
        && sink_rail == "assistant"
        && sink_notification_class == "digest";
    let allowlist = artifact
        .as_ref()
        .map(|value| value.policy.network_allowlist.clone())
        .unwrap_or_default();
    let allowlist_satisfied = allowlist
        .iter()
        .any(|entry| entry.eq_ignore_ascii_case("news.ycombinator.com"));
    let graph_kinds = artifact
        .as_ref()
        .map(hacker_news_monitor_graph_kinds)
        .unwrap_or_default();
    let graph_shape_satisfied = [
        "trigger.interval",
        "source.web.read",
        "extract.hacker_news_front_page",
        "predicate.contains_any",
        "state.seen_set",
        "sink.notification.send",
    ]
    .iter()
    .all(|expected| graph_kinds.iter().any(|kind| kind == expected));
    let source_prompt_present = artifact
        .as_ref()
        .and_then(|value| value.provenance.source_prompt.clone())
        .map(|value| !value.trim().is_empty())
        .unwrap_or(false);
    let source_prompt_hash_present = artifact
        .as_ref()
        .and_then(|value| value.provenance.source_prompt_hash.clone())
        .map(|value| value.len() == 64 && value.chars().all(|ch| ch.is_ascii_hexdigit()))
        .unwrap_or(false);
    let source_prompt_satisfied = source_prompt_present && source_prompt_hash_present;
    let next_run_at_ms = workflow_record.next_run_at_ms.unwrap_or_default();
    let next_run_satisfied = next_run_at_ms > 0;
    let state_seen_key_count = state
        .as_ref()
        .map(|value| value.seen_keys.len())
        .unwrap_or_default();
    let state_last_run_ms = state
        .as_ref()
        .and_then(|value| value.last_run_ms)
        .unwrap_or_default();
    let state_last_success_ms = state
        .as_ref()
        .and_then(|value| value.last_success_ms)
        .unwrap_or_default();
    let state_failure_count = state
        .as_ref()
        .map(|value| value.failure_count)
        .unwrap_or_default();
    let state_satisfied = state
        .as_ref()
        .map(|value| {
            value.workflow_id == workflow_id
                && value.seen_keys.is_empty()
                && value.last_run_ms.is_none()
                && value.last_success_ms.is_none()
                && value.failure_count == 0
        })
        .unwrap_or(false);
    let install_authoring_tool = install_receipt
        .as_ref()
        .map(|value| value.authoring_tool.clone())
        .unwrap_or_default();
    let install_trigger_kind = install_receipt
        .as_ref()
        .map(|value| value.trigger_kind.clone())
        .unwrap_or_default();
    let install_valid = install_receipt
        .as_ref()
        .map(|value| value.valid)
        .unwrap_or(false);
    let install_receipt_satisfied = install_receipt
        .as_ref()
        .map(|value| {
            value.workflow_id == workflow_id
                && value.valid
                && value.authoring_tool == "automation.create_monitor"
                && value.trigger_kind == "interval"
        })
        .unwrap_or(false);
    let run_unique_match_satisfied = fixture
        .fixture_root
        .file_name()
        .and_then(|name| name.to_str())
        .map(|name| {
            name.ends_with(
                &std::env::var("IOI_HACKER_NEWS_MONITOR_RUN_UNIQUE_NUM").unwrap_or_default(),
            )
        })
        .unwrap_or(false);
    let scope_satisfied = registry_path_satisfied
        && single_workflow_satisfied
        && workflow_id_present
        && artifact_path_satisfied
        && state_path_satisfied
        && install_receipt_path_satisfied
        && spec_version_satisfied
        && workflow_status_satisfied
        && source_url_satisfied
        && source_type_satisfied
        && extractor_type_satisfied
        && extractor_selector_satisfied
        && predicate_type_satisfied
        && keywords_satisfied
        && poll_interval_satisfied
        && sink_satisfied
        && allowlist_satisfied
        && graph_shape_satisfied
        && source_prompt_satisfied
        && next_run_satisfied
        && state_satisfied
        && install_receipt_satisfied
        && run_unique_match_satisfied;

    let mut batch = EnvironmentEvidenceBatch::default();
    push_environment_receipt(
        &mut batch,
        "hacker_news_monitor_workflow_id",
        workflow_id,
        Some(probe_source.clone()),
        Some(timestamp_ms),
        Some(workflow_id_present),
    );
    push_environment_receipt(
        &mut batch,
        "hacker_news_monitor_registry_path",
        registry_path.to_string_lossy().to_string(),
        Some(probe_source.clone()),
        Some(timestamp_ms),
        Some(registry_path_satisfied),
    );
    push_environment_receipt(
        &mut batch,
        "hacker_news_monitor_registry_count",
        registry_count.to_string(),
        Some(probe_source.clone()),
        Some(timestamp_ms),
        Some(single_workflow_satisfied),
    );
    push_environment_receipt(
        &mut batch,
        "hacker_news_monitor_workflow_status",
        workflow_record.status,
        Some(probe_source.clone()),
        Some(timestamp_ms),
        Some(workflow_status_satisfied),
    );
    push_environment_receipt(
        &mut batch,
        "hacker_news_monitor_source_url",
        source_url,
        Some(probe_source.clone()),
        Some(timestamp_ms),
        Some(source_url_satisfied),
    );
    push_environment_receipt(
        &mut batch,
        "hacker_news_monitor_source_type",
        source_type,
        Some(probe_source.clone()),
        Some(timestamp_ms),
        Some(source_type_satisfied),
    );
    push_environment_receipt(
        &mut batch,
        "hacker_news_monitor_extractor_type",
        extractor_type,
        Some(probe_source.clone()),
        Some(timestamp_ms),
        Some(extractor_type_satisfied),
    );
    push_environment_receipt(
        &mut batch,
        "hacker_news_monitor_extractor_selector",
        extractor_selector,
        Some(probe_source.clone()),
        Some(timestamp_ms),
        Some(extractor_selector_satisfied),
    );
    push_environment_receipt(
        &mut batch,
        "hacker_news_monitor_predicate_type",
        predicate_type,
        Some(probe_source.clone()),
        Some(timestamp_ms),
        Some(predicate_type_satisfied),
    );
    push_environment_receipt(
        &mut batch,
        "hacker_news_monitor_keywords_normalized",
        keywords_normalized,
        Some(probe_source.clone()),
        Some(timestamp_ms),
        Some(keywords_satisfied),
    );
    push_environment_observation(
        &mut batch,
        "hacker_news_monitor_keywords_json",
        serde_json::to_string(&keywords).unwrap_or_else(|_| "[]".to_string()),
    );
    push_environment_receipt(
        &mut batch,
        "hacker_news_monitor_artifact_path",
        artifact_path.to_string_lossy().to_string(),
        Some(probe_source.clone()),
        Some(timestamp_ms),
        Some(artifact_path_satisfied),
    );
    push_environment_receipt(
        &mut batch,
        "hacker_news_monitor_spec_version",
        spec_version,
        Some(probe_source.clone()),
        Some(timestamp_ms),
        Some(spec_version_satisfied),
    );
    push_environment_observation(
        &mut batch,
        "hacker_news_monitor_graph_node_kinds_json",
        serde_json::to_string(&graph_kinds).unwrap_or_else(|_| "[]".to_string()),
    );
    push_environment_metadata(
        &mut batch,
        "hacker_news_monitor_graph_shape",
        Some(probe_source.clone()),
        Some(timestamp_ms),
        Some(graph_shape_satisfied),
    );
    push_environment_receipt(
        &mut batch,
        "hacker_news_monitor_poll_interval_seconds",
        poll_interval_seconds.to_string(),
        Some(probe_source.clone()),
        Some(timestamp_ms),
        Some(poll_interval_satisfied),
    );
    push_environment_receipt(
        &mut batch,
        "hacker_news_monitor_sink_type",
        sink_type,
        Some(probe_source.clone()),
        Some(timestamp_ms),
        Some(sink_satisfied),
    );
    push_environment_receipt(
        &mut batch,
        "hacker_news_monitor_sink_rail",
        sink_rail,
        Some(probe_source.clone()),
        Some(timestamp_ms),
        Some(sink_satisfied),
    );
    push_environment_receipt(
        &mut batch,
        "hacker_news_monitor_sink_notification_class",
        sink_notification_class,
        Some(probe_source.clone()),
        Some(timestamp_ms),
        Some(sink_satisfied),
    );
    push_environment_observation(
        &mut batch,
        "hacker_news_monitor_allowlist_json",
        serde_json::to_string(&allowlist).unwrap_or_else(|_| "[]".to_string()),
    );
    push_environment_metadata(
        &mut batch,
        "hacker_news_monitor_allowlist",
        Some(probe_source.clone()),
        Some(timestamp_ms),
        Some(allowlist_satisfied),
    );
    push_environment_receipt(
        &mut batch,
        "hacker_news_monitor_next_run_at_ms",
        next_run_at_ms.to_string(),
        Some(probe_source.clone()),
        Some(timestamp_ms),
        Some(next_run_satisfied),
    );
    push_environment_receipt(
        &mut batch,
        "hacker_news_monitor_state_path",
        state_path.to_string_lossy().to_string(),
        Some(probe_source.clone()),
        Some(timestamp_ms),
        Some(state_path_satisfied),
    );
    push_environment_receipt(
        &mut batch,
        "hacker_news_monitor_state_seen_key_count",
        state_seen_key_count.to_string(),
        Some(probe_source.clone()),
        Some(timestamp_ms),
        Some(state_satisfied),
    );
    push_environment_receipt(
        &mut batch,
        "hacker_news_monitor_state_last_run_ms",
        state_last_run_ms.to_string(),
        Some(probe_source.clone()),
        Some(timestamp_ms),
        Some(state_satisfied),
    );
    push_environment_receipt(
        &mut batch,
        "hacker_news_monitor_state_last_success_ms",
        state_last_success_ms.to_string(),
        Some(probe_source.clone()),
        Some(timestamp_ms),
        Some(state_satisfied),
    );
    push_environment_receipt(
        &mut batch,
        "hacker_news_monitor_state_failure_count",
        state_failure_count.to_string(),
        Some(probe_source.clone()),
        Some(timestamp_ms),
        Some(state_satisfied),
    );
    push_environment_metadata(
        &mut batch,
        "hacker_news_monitor_state",
        Some(probe_source.clone()),
        Some(timestamp_ms),
        Some(state_satisfied),
    );
    push_environment_receipt(
        &mut batch,
        "hacker_news_monitor_install_receipt_path",
        install_receipt_path.to_string_lossy().to_string(),
        Some(probe_source.clone()),
        Some(timestamp_ms),
        Some(install_receipt_path_satisfied),
    );
    push_environment_receipt(
        &mut batch,
        "hacker_news_monitor_install_authoring_tool",
        install_authoring_tool,
        Some(probe_source.clone()),
        Some(timestamp_ms),
        Some(install_receipt_satisfied),
    );
    push_environment_receipt(
        &mut batch,
        "hacker_news_monitor_install_trigger_kind",
        install_trigger_kind,
        Some(probe_source.clone()),
        Some(timestamp_ms),
        Some(install_receipt_satisfied),
    );
    push_environment_receipt(
        &mut batch,
        "hacker_news_monitor_install_valid",
        install_valid.to_string(),
        Some(probe_source.clone()),
        Some(timestamp_ms),
        Some(install_receipt_satisfied),
    );
    push_environment_metadata(
        &mut batch,
        "hacker_news_monitor_install_receipt",
        Some(probe_source.clone()),
        Some(timestamp_ms),
        Some(install_receipt_satisfied),
    );
    push_environment_receipt(
        &mut batch,
        "hacker_news_monitor_source_prompt_present",
        source_prompt_present.to_string(),
        Some(probe_source.clone()),
        Some(timestamp_ms),
        Some(source_prompt_satisfied),
    );
    push_environment_receipt(
        &mut batch,
        "hacker_news_monitor_source_prompt_hash_present",
        source_prompt_hash_present.to_string(),
        Some(probe_source.clone()),
        Some(timestamp_ms),
        Some(source_prompt_satisfied),
    );
    push_environment_metadata(
        &mut batch,
        "hacker_news_monitor_source_prompt",
        Some(probe_source.clone()),
        Some(timestamp_ms),
        Some(source_prompt_satisfied),
    );
    push_environment_observation(
        &mut batch,
        "hacker_news_monitor_run_unique_observed",
        std::env::var("IOI_HACKER_NEWS_MONITOR_RUN_UNIQUE_NUM").unwrap_or_default(),
    );
    push_environment_metadata(
        &mut batch,
        "hacker_news_monitor_run_unique_match",
        Some(probe_source.clone()),
        Some(timestamp_ms),
        Some(run_unique_match_satisfied),
    );
    push_environment_metadata(
        &mut batch,
        "hacker_news_monitor_scope",
        Some(probe_source),
        Some(timestamp_ms),
        Some(scope_satisfied),
    );
    batch
}

fn hacker_news_monitor_fixture_cleanup_checks(
    fixture: &HackerNewsMonitorFixtureRuntime,
) -> EnvironmentEvidenceBatch {
    let timestamp_ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64;
    let probe_source = format!("{}.cleanup_probe", HACKER_NEWS_MONITOR_FIXTURE_PROBE_SOURCE);
    let _ = std::fs::remove_dir_all(&fixture.fixture_root);
    let fixture_root_exists_after_cleanup = fixture.fixture_root.exists();
    let automation_root_exists_after_cleanup = fixture.automation_root.exists();
    let manifest_exists_after_cleanup = fixture.manifest_path.exists();
    let cleanup_satisfied = !fixture_root_exists_after_cleanup
        && !automation_root_exists_after_cleanup
        && !manifest_exists_after_cleanup;

    let mut batch = EnvironmentEvidenceBatch::default();
    push_environment_observation(
        &mut batch,
        "hacker_news_monitor_cleanup_fixture_root_exists",
        fixture_root_exists_after_cleanup.to_string(),
    );
    push_environment_observation(
        &mut batch,
        "hacker_news_monitor_cleanup_automation_root_exists",
        automation_root_exists_after_cleanup.to_string(),
    );
    push_environment_observation(
        &mut batch,
        "hacker_news_monitor_cleanup_manifest_exists",
        manifest_exists_after_cleanup.to_string(),
    );
    push_environment_metadata(
        &mut batch,
        "hacker_news_monitor_cleanup",
        Some(probe_source),
        Some(timestamp_ms),
        Some(cleanup_satisfied),
    );
    batch
}

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
            b"mail_connector_get_receipt::".as_slice(),
            request_id.as_slice(),
        ]
        .concat()
    }

    fn wallet_mail_binding_receipt_key(request_id: &[u8; 32]) -> Vec<u8> {
        [
            b"mail_connector_binding_receipt::".as_slice(),
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

fn bootstrap_coding_path_normalizer_fixture_runtime(
    run_unique_num: &str,
) -> Result<CodingPathNormalizerFixtureRuntime> {
    let temp_dir = tempdir()?;
    let home_dir = temp_dir.path().join("home");
    let fixture_root = temp_dir
        .path()
        .join(format!("ioi_coding_path_normalizer_{}", run_unique_num));
    let repo_root = fixture_root.join("path-normalizer-fixture");
    let tests_dir = repo_root.join("tests");
    let source_file = repo_root.join("path_utils.py");
    let test_file = tests_dir.join("test_path_utils.py");
    let readme_path = repo_root.join("README.md");

    std::fs::create_dir_all(&tests_dir)?;
    std::fs::create_dir_all(&home_dir)?;

    let source_contents = r#"def normalize_fixture_path(raw_path: str) -> str:
    """Normalize a repo-relative path coming from mixed slash inputs."""
    return raw_path.strip().replace("\\", "/")
"#;
    let test_contents = r#"import unittest

from path_utils import normalize_fixture_path


class NormalizeFixturePathTests(unittest.TestCase):
    def test_replaces_windows_separators(self) -> None:
        self.assertEqual(
            normalize_fixture_path("docs\\release\\notes.md"),
            "docs/release/notes.md",
        )

    def test_collapses_duplicate_separators(self) -> None:
        self.assertEqual(
            normalize_fixture_path("src//agent\\planner.py"),
            "src/agent/planner.py",
        )

    def test_collapses_mixed_duplicate_runs(self) -> None:
        self.assertEqual(
            normalize_fixture_path("reports\\\\2026///summary.md"),
            "reports/2026/summary.md",
        )


if __name__ == "__main__":
    unittest.main()
"#;
    let readme_contents = format!(
        concat!(
            "# Path Normalizer Fixture\n\n",
            "Run unique: `{}`.\n\n",
            "Patch `path_utils.py` so `normalize_fixture_path` converts backslashes to forward slashes, ",
            "collapses duplicate separators, preserves a leading `./` or `/`, and leaves the tests unchanged.\n"
        ),
        run_unique_num
    );

    std::fs::write(&source_file, source_contents)?;
    std::fs::write(&test_file, test_contents)?;
    std::fs::write(tests_dir.join("__init__.py"), "")?;
    std::fs::write(readme_path, readme_contents)?;

    let env_home = ScopedEnvVar::set("HOME", home_dir.to_string_lossy().to_string());
    let env_userprofile = ScopedEnvVar::set("USERPROFILE", home_dir.to_string_lossy().to_string());

    Ok(CodingPathNormalizerFixtureRuntime {
        _temp_dir: temp_dir,
        _env_home: env_home,
        _env_userprofile: env_userprofile,
        fixture_root,
        repo_root,
        source_file,
        test_file,
        expected_function_name: "normalize_fixture_path".to_string(),
        seeded_test_command: "python3 -m unittest tests.test_path_utils -v".to_string(),
        hidden_probe_command: concat!(
            "python3 -c ",
            "\"from path_utils import normalize_fixture_path; ",
            "print(normalize_fixture_path('./tmp\\\\logs///latest.txt'))\""
        )
        .to_string(),
        baseline_test_contents: test_contents.to_string(),
    })
}

fn coding_path_normalizer_fixture_preflight_checks(
    fixture: &CodingPathNormalizerFixtureRuntime,
    run_unique_num: &str,
    run_timestamp_ms: u64,
) -> EnvironmentEvidenceBatch {
    let probe_source = CODING_PATH_NORMALIZER_FIXTURE_PROBE_SOURCE.to_string();
    let fixture_ready = fixture.repo_root.is_dir()
        && fixture.source_file.is_file()
        && fixture.test_file.is_file()
        && fixture
            .fixture_root
            .to_string_lossy()
            .contains(run_unique_num);
    let mut batch = EnvironmentEvidenceBatch::default();
    push_environment_observation(
        &mut batch,
        "coding_path_normalizer_fixture_mode",
        CODING_PATH_NORMALIZER_FIXTURE_MODE,
    );
    push_environment_observation(
        &mut batch,
        "coding_path_normalizer_repo_root",
        fixture.repo_root.to_string_lossy().to_string(),
    );
    push_environment_observation(
        &mut batch,
        "coding_path_normalizer_source_file",
        fixture.source_file.to_string_lossy().to_string(),
    );
    push_environment_observation(
        &mut batch,
        "coding_path_normalizer_test_file",
        fixture.test_file.to_string_lossy().to_string(),
    );
    push_environment_observation(
        &mut batch,
        "coding_path_normalizer_function_name",
        fixture.expected_function_name.clone(),
    );
    push_environment_observation(
        &mut batch,
        "coding_path_normalizer_targeted_test_command",
        fixture.seeded_test_command.clone(),
    );
    push_environment_observation(
        &mut batch,
        "coding_path_normalizer_hidden_probe_command",
        fixture.hidden_probe_command.clone(),
    );
    push_environment_metadata(
        &mut batch,
        "coding_path_normalizer_fixture",
        Some(probe_source),
        Some(run_timestamp_ms),
        Some(fixture_ready),
    );
    batch
}

fn run_python_fixture_command(
    repo_root: &Path,
    args: &[&str],
) -> (String, Option<std::process::Output>, Option<String>) {
    for candidate in ["python3", "python"] {
        match std::process::Command::new(candidate)
            .args(args)
            .current_dir(repo_root)
            .output()
        {
            Ok(output) => return (candidate.to_string(), Some(output), None),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
            Err(error) => {
                return (
                    candidate.to_string(),
                    None,
                    Some(format!("{}: {}", candidate, error)),
                )
            }
        }
    }

    (
        "python3".to_string(),
        None,
        Some("python3/python not found".to_string()),
    )
}

fn coding_path_normalizer_fixture_post_run_checks(
    fixture: &CodingPathNormalizerFixtureRuntime,
) -> EnvironmentEvidenceBatch {
    let timestamp_ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64;
    let probe_source = format!("{}.fs_probe", CODING_PATH_NORMALIZER_FIXTURE_PROBE_SOURCE);

    let (test_python, test_output, test_error) = run_python_fixture_command(
        &fixture.repo_root,
        &["-m", "unittest", "tests.test_path_utils", "-v"],
    );
    let targeted_exit_code = test_output.as_ref().and_then(|output| output.status.code());
    let targeted_stdout = test_output
        .as_ref()
        .map(|output| String::from_utf8_lossy(&output.stdout).trim().to_string())
        .unwrap_or_default();
    let targeted_stderr = test_output
        .as_ref()
        .map(|output| String::from_utf8_lossy(&output.stderr).trim().to_string())
        .unwrap_or_default();
    let targeted_tests_satisfied = targeted_exit_code == Some(0);

    let (probe_python, probe_output, probe_error) = run_python_fixture_command(
        &fixture.repo_root,
        &[
            "-c",
            "from path_utils import normalize_fixture_path; print(normalize_fixture_path('./tmp\\\\logs///latest.txt'))",
        ],
    );
    let hidden_probe_value = probe_output
        .as_ref()
        .map(|output| String::from_utf8_lossy(&output.stdout).trim().to_string())
        .unwrap_or_default();
    let hidden_probe_satisfied =
        hidden_probe_value == "./tmp/logs/latest.txt"
            && probe_output
                .as_ref()
                .is_some_and(|output| output.status.code() == Some(0));

    let test_file_contents = std::fs::read_to_string(&fixture.test_file).unwrap_or_default();
    let tests_unchanged = test_file_contents == fixture.baseline_test_contents;
    let source_contents = std::fs::read_to_string(&fixture.source_file).unwrap_or_default();
    let source_mentions_function = source_contents.contains(&fixture.expected_function_name);
    let scope_satisfied =
        targeted_tests_satisfied && hidden_probe_satisfied && tests_unchanged && source_mentions_function;

    let mut batch = EnvironmentEvidenceBatch::default();
    push_environment_receipt(
        &mut batch,
        "coding_path_normalizer_targeted_test_runner",
        test_python,
        Some(probe_source.clone()),
        Some(timestamp_ms),
        Some(true),
    );
    push_environment_receipt(
        &mut batch,
        "coding_path_normalizer_targeted_tests_exit_code",
        targeted_exit_code
            .map(|value| value.to_string())
            .unwrap_or_else(|| "spawn_error".to_string()),
        Some(probe_source.clone()),
        Some(timestamp_ms),
        Some(targeted_tests_satisfied),
    );
    push_environment_receipt(
        &mut batch,
        "coding_path_normalizer_targeted_tests_stdout",
        truncate_for_log(&targeted_stdout, 240),
        Some(probe_source.clone()),
        Some(timestamp_ms),
        Some(targeted_tests_satisfied),
    );
    push_environment_receipt(
        &mut batch,
        "coding_path_normalizer_targeted_tests_stderr",
        truncate_for_log(
            &if let Some(error) = test_error {
                error
            } else {
                targeted_stderr
            },
            240,
        ),
        Some(probe_source.clone()),
        Some(timestamp_ms),
        Some(targeted_tests_satisfied),
    );
    push_environment_receipt(
        &mut batch,
        "coding_path_normalizer_hidden_probe_runner",
        probe_python,
        Some(probe_source.clone()),
        Some(timestamp_ms),
        Some(true),
    );
    push_environment_receipt(
        &mut batch,
        "coding_path_normalizer_hidden_probe_output",
        if let Some(error) = probe_error {
            format!("spawn_error={}", error)
        } else {
            hidden_probe_value
        },
        Some(probe_source.clone()),
        Some(timestamp_ms),
        Some(hidden_probe_satisfied),
    );
    push_environment_metadata(
        &mut batch,
        "coding_path_normalizer_tests_unchanged",
        Some(probe_source.clone()),
        Some(timestamp_ms),
        Some(tests_unchanged),
    );
    push_environment_metadata(
        &mut batch,
        "coding_path_normalizer_source_mentions_function",
        Some(probe_source.clone()),
        Some(timestamp_ms),
        Some(source_mentions_function),
    );
    push_environment_metadata(
        &mut batch,
        "coding_path_normalizer_scope",
        Some(probe_source),
        Some(timestamp_ms),
        Some(scope_satisfied),
    );
    batch
}

fn coding_path_normalizer_fixture_cleanup_checks(
    fixture: &CodingPathNormalizerFixtureRuntime,
) -> EnvironmentEvidenceBatch {
    let timestamp_ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64;
    let probe_source = format!("{}.cleanup_probe", CODING_PATH_NORMALIZER_FIXTURE_PROBE_SOURCE);
    let _ = std::fs::remove_dir_all(&fixture.fixture_root);
    let cleanup_satisfied = !fixture.fixture_root.exists();

    let mut batch = EnvironmentEvidenceBatch::default();
    push_environment_metadata(
        &mut batch,
        "coding_path_normalizer_cleanup",
        Some(probe_source),
        Some(timestamp_ms),
        Some(cleanup_satisfied),
    );
    batch
}

fn bootstrap_optional_fixture<T, B, P>(
    enabled: bool,
    bootstrap: B,
    preflight: P,
    setup_checks: &mut Vec<String>,
    setup_receipts: &mut Vec<EnvironmentReceiptObservation>,
) -> Result<Option<T>>
where
    B: FnOnce() -> Result<T>,
    P: FnOnce(&T) -> EnvironmentEvidenceBatch,
{
    if !enabled {
        return Ok(None);
    }
    let fixture = bootstrap()?;
    extend_environment_evidence_batch(setup_checks, setup_receipts, preflight(&fixture));
    Ok(Some(fixture))
}
