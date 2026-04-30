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
