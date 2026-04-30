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
    let receipts_dir = fixture_root.join("evidence");
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
    let fixture_receipts = fixture_root.join("evidence");
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
    let receipt_path = tool_home.join("evidence").join("last_success.json");
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

