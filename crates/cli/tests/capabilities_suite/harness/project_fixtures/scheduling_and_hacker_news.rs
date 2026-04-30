fn bootstrap_shutdown_schedule_fixture_runtime(
    run_unique_num: &str,
) -> Result<ShutdownScheduleFixtureRuntime> {
    let temp_dir = tempdir()?;
    let fixture_root = temp_dir
        .path()
        .join(format!("shutdown_schedule_{}", run_unique_num));
    let fixture_bin = fixture_root.join("bin");
    let fixture_receipts = fixture_root.join("evidence");
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
    let receipts_root = fixture.automation_root.join("evidence");
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
            .join("evidence")
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

