use super::{
    duplicate_command_cached_completion_summary, duplicate_command_cached_success_summary,
    duplicate_command_completion_summary, find_matching_command_history_entry,
    verified_command_probe_completion_summary,
};
use crate::agentic::runtime::types::CommandExecution;
use ioi_types::app::agentic::AgentTool;
use std::collections::VecDeque;

#[test]
fn duplicate_detached_timer_terminalizes() {
    let tool = AgentTool::SysExec {
        command: "sleep".to_string(),
        args: vec![
            "900".to_string(),
            "&&".to_string(),
            "notify-send".to_string(),
            "Timer".to_string(),
        ],
        stdin: None,
        wait_ms_before_async: None,
        detach: true,
    };
    let history = CommandExecution {
        command: "sleep 900 && notify-send Timer".to_string(),
        exit_code: 0,
        stdout: "Launched background process '/bin/bash' (PID: 1234)".to_string(),
        stderr: String::new(),
        timestamp_ms: 1_772_000_000_000,
        step_index: 0,
    };
    let summary = duplicate_command_completion_summary(&tool, Some(&history))
        .expect("detached timer should terminalize");
    assert!(summary.contains("Timer scheduled."));
    assert!(summary.contains("Target UTC:"));
}

#[test]
fn duplicate_safe_probe_reuses_prior_success() {
    let tool = AgentTool::SysExec {
        command: "date".to_string(),
        args: vec!["+%Y-%m-%dT%H:%M:%SZ".to_string()],
        stdin: None,
        wait_ms_before_async: None,
        detach: false,
    };
    let history = CommandExecution {
        command: "date +%Y-%m-%dT%H:%M:%SZ".to_string(),
        exit_code: 0,
        stdout: "2026-02-25T06:13:00Z".to_string(),
        stderr: String::new(),
        timestamp_ms: 1_772_000_000_000,
        step_index: 1,
    };
    let summary = duplicate_command_cached_success_summary(&tool, Some(&history))
        .expect("safe probe command should reuse cached success");
    assert!(summary.contains("Reused prior successful command result"));
    assert!(summary.contains("Stdout: 2026-02-25T06:13:00Z"));
}

#[test]
fn duplicate_safe_probe_completion_prefers_stdout_line() {
    let tool = AgentTool::SysExec {
        command: "echo".to_string(),
        args: vec!["$((247 * 38))".to_string()],
        stdin: None,
        wait_ms_before_async: None,
        detach: false,
    };
    let history = CommandExecution {
        command: "echo $((247 * 38))".to_string(),
        exit_code: 0,
        stdout: "9386\n".to_string(),
        stderr: String::new(),
        timestamp_ms: 1_772_000_000_000,
        step_index: 1,
    };
    let summary = duplicate_command_cached_completion_summary(&tool, Some(&history))
        .expect("completion summary should be derived from cached stdout");
    assert_eq!(summary, "9386");
}

#[test]
fn matching_history_entry_finds_equivalent_command() {
    let tool = AgentTool::SysExec {
        command: "date".to_string(),
        args: vec!["-u".to_string()],
        stdin: None,
        wait_ms_before_async: None,
        detach: false,
    };
    let history = VecDeque::from(vec![
        CommandExecution {
            command: "sleep 900 && notify-send Timer".to_string(),
            exit_code: 0,
            stdout: String::new(),
            stderr: String::new(),
            timestamp_ms: 1_772_000_000_000,
            step_index: 0,
        },
        CommandExecution {
            command: "date -u".to_string(),
            exit_code: 0,
            stdout: "Wed Feb 25 07:13:57 UTC 2026".to_string(),
            stderr: String::new(),
            timestamp_ms: 1_772_000_001_000,
            step_index: 1,
        },
    ]);
    let matched = find_matching_command_history_entry(&tool, &history)
        .expect("expected to find matching date -u history entry");
    assert_eq!(matched.command, "date -u");
}

#[test]
fn duplicate_find_probe_reuses_prior_success() {
    let tool = AgentTool::SysExec {
        command: "find".to_string(),
        args: vec![
            "/home/user".to_string(),
            "-type".to_string(),
            "f".to_string(),
            "-name".to_string(),
            "*.pdf".to_string(),
            "-mtime".to_string(),
            "-7".to_string(),
        ],
        stdin: None,
        wait_ms_before_async: None,
        detach: false,
    };
    let history = CommandExecution {
        command: "find /home/user -type f -name *.pdf -mtime -7".to_string(),
        exit_code: 0,
        stdout: "/home/user/report.pdf".to_string(),
        stderr: String::new(),
        timestamp_ms: 1_772_000_000_000,
        step_index: 1,
    };
    let summary = duplicate_command_cached_success_summary(&tool, Some(&history))
        .expect("safe find probe command should reuse cached success");
    assert!(summary.contains("Reused prior successful command result"));
    assert!(summary.contains("Stdout: /home/user/report.pdf"));
}

#[test]
fn duplicate_find_with_delete_is_not_reused() {
    let tool = AgentTool::SysExec {
        command: "find".to_string(),
        args: vec![
            "/home/user".to_string(),
            "-type".to_string(),
            "f".to_string(),
            "-name".to_string(),
            "*.pdf".to_string(),
            "-delete".to_string(),
        ],
        stdin: None,
        wait_ms_before_async: None,
        detach: false,
    };
    let history = CommandExecution {
        command: "find /home/user -type f -name *.pdf -delete".to_string(),
        exit_code: 0,
        stdout: String::new(),
        stderr: String::new(),
        timestamp_ms: 1_772_000_000_000,
        step_index: 1,
    };
    assert!(duplicate_command_cached_success_summary(&tool, Some(&history)).is_none());
}

#[test]
fn duplicate_find_completion_returns_full_stdout() {
    let tool = AgentTool::SysExec {
        command: "find".to_string(),
        args: vec![
            "/home/user".to_string(),
            "-type".to_string(),
            "f".to_string(),
            "-name".to_string(),
            "*.pdf".to_string(),
            "-mtime".to_string(),
            "-7".to_string(),
        ],
        stdin: None,
        wait_ms_before_async: None,
        detach: false,
    };
    let history = CommandExecution {
        command: "find /home/user -type f -name *.pdf -mtime -7".to_string(),
        exit_code: 0,
        stdout: "/home/user/a.pdf\n/home/user/b.pdf\n".to_string(),
        stderr: String::new(),
        timestamp_ms: 1_772_000_000_000,
        step_index: 1,
    };
    let summary = duplicate_command_cached_completion_summary(&tool, Some(&history))
        .expect("safe find completion should use full stdout");
    assert_eq!(summary, "/home/user/a.pdf\n/home/user/b.pdf");
}

#[test]
fn duplicate_probe_completion_extracts_provider_and_target_time() {
    let tool = AgentTool::SysExec {
        command: "/tmp/demo/shutdown_schedule_probe".to_string(),
        args: vec!["--target-local".to_string(), "23:00".to_string()],
        stdin: None,
        wait_ms_before_async: None,
        detach: false,
    };
    let history = CommandExecution {
        command: "/tmp/demo/shutdown_schedule_probe --target-local 23:00".to_string(),
        exit_code: 0,
        stdout: "provider=shutdown\ntarget_local_time=23:00\nscheduled=true\n".to_string(),
        stderr: String::new(),
        timestamp_ms: 1_772_000_000_000,
        step_index: 2,
    };

    let summary = duplicate_command_cached_completion_summary(&tool, Some(&history))
        .expect("probe completion should be synthesized");
    assert!(summary.contains("provider 'shutdown'"));
    assert!(summary.contains("23:00"));
}

#[test]
fn duplicate_probe_completion_includes_ranked_memory_rows() {
    let tool = AgentTool::SysExec {
        command: "/tmp/demo/top_memory_apps_probe".to_string(),
        args: vec!["5".to_string()],
        stdin: None,
        wait_ms_before_async: None,
        detach: false,
    };
    let history = CommandExecution {
        command: "/tmp/demo/top_memory_apps_probe 5".to_string(),
        exit_code: 0,
        stdout: "provider=ps\nrow|1|firefox-bin|6795|892632\nrow|2|soffice.bin|58757|795564\n"
            .to_string(),
        stderr: String::new(),
        timestamp_ms: 1_772_000_000_000,
        step_index: 2,
    };

    let summary = duplicate_command_cached_completion_summary(&tool, Some(&history))
        .expect("top-memory probe completion should include ranked rows");
    assert!(summary.contains("Top memory apps"));
    assert!(summary.contains("firefox-bin"));
    assert!(summary.contains("pid 6795"));
    assert!(summary.contains("rss_kb 892632"));
    assert!(summary.contains("soffice.bin"));
}

#[test]
fn verified_probe_completion_requires_prior_side_effecting_success() {
    let tool = AgentTool::SysExec {
        command: "ls".to_string(),
        args: vec!["/home/user/Desktop".to_string()],
        stdin: None,
        wait_ms_before_async: None,
        detach: false,
    };
    let history = VecDeque::from(vec![
        CommandExecution {
            command: "mkdir /home/user/Desktop/Project_42".to_string(),
            exit_code: 0,
            stdout: String::new(),
            stderr: String::new(),
            timestamp_ms: 1_772_000_000_000,
            step_index: 0,
        },
        CommandExecution {
            command: "ls /home/user/Desktop".to_string(),
            exit_code: 0,
            stdout: "Notes\nProject_42\n".to_string(),
            stderr: String::new(),
            timestamp_ms: 1_772_000_001_000,
            step_index: 1,
        },
    ]);

    let summary = verified_command_probe_completion_summary(&tool, &history)
        .expect("safe verification probe should terminalize after prior side effect");
    assert_eq!(summary, "Project_42");
}

#[test]
fn verified_probe_completion_rejects_probe_only_history() {
    let tool = AgentTool::SysExec {
        command: "ls".to_string(),
        args: vec!["/home/user/Desktop".to_string()],
        stdin: None,
        wait_ms_before_async: None,
        detach: false,
    };
    let history = VecDeque::from(vec![CommandExecution {
        command: "ls /home/user/Desktop".to_string(),
        exit_code: 0,
        stdout: "Notes\nProject_42\n".to_string(),
        stderr: String::new(),
        timestamp_ms: 1_772_000_001_000,
        step_index: 1,
    }]);

    assert!(verified_command_probe_completion_summary(&tool, &history).is_none());
}
