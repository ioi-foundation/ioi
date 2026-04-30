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

