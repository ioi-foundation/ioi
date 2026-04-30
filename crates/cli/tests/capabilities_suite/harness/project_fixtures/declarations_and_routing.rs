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

